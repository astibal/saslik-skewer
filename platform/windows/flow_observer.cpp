#include "flow_observer.hpp"
#include <array>
#include <bit>
#include <stdexcept>
#include <system_error>
#include <utility>
// Older SDK headers define SAL-like macros: keep this after standard headers.
#include <windivert.h>

namespace skewer::windows::traffic {
namespace {
[[noreturn]] void fail(const char* operation, DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}

template <typename Function> Function resolve(HMODULE library, const char* name) {
    const auto symbol = GetProcAddress(library, name);
    if (!symbol) {
        fail(name);
    }
    return std::bit_cast<Function>(symbol);
}

class Api final {
public:
    explicit Api(const std::wstring& path) {
        const bool drive =
            !path.empty() && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
        if (path.size() < 4 || !drive || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
            path.find(L'\0') != std::wstring::npos) {
            throw std::invalid_argument("WinDivert DLL requires an absolute local installation path");
        }
        const auto library = LoadLibraryExW(path.c_str(), nullptr,
                                            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!library) {
            fail("LoadLibraryExW(WinDivert)");
        }
        library_ =
            std::shared_ptr<void>(library, [](void* value) { FreeLibrary(static_cast<HMODULE>(value)); });
        open = resolve<decltype(open)>(library, "WinDivertOpen");
        receive = resolve<decltype(receive)>(library, "WinDivertRecvEx");
        close = resolve<decltype(close)>(library, "WinDivertClose");
        format_address = resolve<decltype(format_address)>(library, "WinDivertHelperFormatIPv6Address");
    }

    decltype(&WinDivertOpen) open{};
    decltype(&WinDivertRecvEx) receive{};
    decltype(&WinDivertClose) close{};
    decltype(&WinDivertHelperFormatIPv6Address) format_address{};

private:
    std::shared_ptr<void> library_;
};

FlowEndpoint endpoint(const Api& api, const UINT32* address, UINT16 port) {
    std::array<char, 64> text{};
    if (!api.format_address(address, text.data(), static_cast<UINT>(text.size()))) {
        fail("Format flow address");
    }
    return {text.data(), port};
}
} // namespace

class FlowObserver::Impl final {
public:
    static std::unique_ptr<ProcessTarget> checked(std::unique_ptr<ProcessTarget> target) {
        if (!target || !target->running()) {
            throw std::invalid_argument("Flow observer requires a live verified process");
        }
        return target;
    }
    Impl(const std::wstring& path, std::unique_ptr<ProcessTarget> target, Mode mode)
        : target_(checked(std::move(target))), mode_(mode), api_(path),
          event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        if (!event_) {
            fail("Create flow read event");
        }
        // No caller-supplied filter language and no path-to-PID inference.
        if (mode != Mode::EstablishedFlows && mode != Mode::ConnectAttempts &&
            mode != Mode::SocketLifecycle) {
            throw std::invalid_argument("Invalid observer mode");
        }
        auto filter =
            "processId == " + std::to_string(target_->key().pid) + " and (protocol == 6 or protocol == 17)";
        if (mode == Mode::ConnectAttempts) {
            filter += " and event == CONNECT";
        } else if (mode == Mode::SocketLifecycle) {
            filter += " and (event == CONNECT or event == CLOSE)";
        }
        handle_ = api_.open(filter.c_str(),
                            mode != Mode::EstablishedFlows ? WINDIVERT_LAYER_SOCKET : WINDIVERT_LAYER_FLOW, 0,
                            WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
        if (handle_ == INVALID_HANDLE_VALUE) {
            fail("Open passive WinDivert flow observer");
        }
    }

    ~Impl() {
        cancelRead();
        api_.close(handle_);
    }

    bool targetRunning() const { return target_->running(); }

    Result next(HANDLE cancellation, DWORD timeout_ms) {
        if (terminal_) {
            return {*terminal_, std::nullopt};
        }
        // Avoid starting new I/O for an already cancelled/exited selection.
        const HANDLE controls[]{cancellation, target_->waitHandle()};
        const auto control = WaitForMultipleObjects(2, controls, FALSE, 0);
        if (control == WAIT_OBJECT_0 || control == WAIT_OBJECT_0 + 1) {
            return finish(control == WAIT_OBJECT_0 ? Status::Cancelled : Status::TargetExited);
        }
        if (control != WAIT_TIMEOUT) {
            fail("Wait for flow observer controls");
        }
        if (!pending_) {
            beginRead();
        }
        const HANDLE events[]{cancellation, target_->waitHandle(), event_.get()};
        const auto ready = WaitForMultipleObjects(3, events, FALSE, timeout_ms);
        switch (ready) {
        case WAIT_OBJECT_0:
            return finish(Status::Cancelled);
        case WAIT_OBJECT_0 + 1:
            return finish(Status::TargetExited);
        case WAIT_OBJECT_0 + 2:
            return receiveEvent();
        case WAIT_TIMEOUT:
            return {Status::Timeout, std::nullopt};
        default:
            fail("Wait for flow event");
        }
    }

private:
    void beginRead() {
        address_ = {};
        address_length_ = sizeof(address_);
        received_ = 0;
        overlapped_ = {};
        overlapped_.hEvent = event_.get();
        if (!ResetEvent(event_.get())) {
            fail("Reset flow read event");
        }
        const auto ok =
            api_.receive(handle_, nullptr, 0, &received_, 0, &address_, &address_length_, &overlapped_);
        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            fail("Receive flow event");
        }
        pending_ = true;
    }

    void cancelRead() noexcept {
        if (!pending_) {
            return;
        }
        // Cancellation can race successful completion. In either case, drain
        // this exact request before releasing its address/OVERLAPPED storage.
        CancelIoEx(handle_, &overlapped_);
        DWORD transferred{};
        GetOverlappedResult(handle_, &overlapped_, &transferred, TRUE);
        pending_ = false;
    }

    Result finish(Status reason) {
        cancelRead();
        terminal_ = reason;
        return {reason, std::nullopt};
    }

    Result receiveEvent() {
        DWORD transferred{};
        const auto ok = GetOverlappedResult(handle_, &overlapped_, &transferred, FALSE);
        const auto error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error == ERROR_IO_INCOMPLETE) {
            fail("Incomplete signalled flow read", error);
        }
        pending_ = false;
        if (!ok) {
            fail("Complete flow read", error);
        }
        if (mode_ != Mode::EstablishedFlows) {
            if (address_length_ != sizeof(address_) || address_.Layer != WINDIVERT_LAYER_SOCKET ||
                (address_.Event != WINDIVERT_EVENT_SOCKET_CONNECT &&
                 !(mode_ == Mode::SocketLifecycle && address_.Event == WINDIVERT_EVENT_SOCKET_CLOSE)) ||
                address_.Socket.ProcessId != target_->key().pid ||
                (address_.Socket.Protocol != 6 && address_.Socket.Protocol != 17)) {
                throw std::runtime_error("Unexpected WinDivert CONNECT metadata");
            }
            FlowEvent event;
            event.kind = address_.Event == WINDIVERT_EVENT_SOCKET_CONNECT ? FlowEvent::Kind::ConnectAttempt
                                                                          : FlowEvent::Kind::SocketClosed;
            event.process = target_->key();
            event.endpoint_id = address_.Socket.EndpointId;
            event.parent_endpoint_id = address_.Socket.ParentEndpointId;
            event.timestamp_ticks = address_.Timestamp;
            event.protocol = address_.Socket.Protocol;
            event.ipv6 = address_.IPv6;
            event.outbound = address_.Outbound;
            event.loopback = address_.Loopback;
            event.local = endpoint(api_, address_.Socket.LocalAddr, address_.Socket.LocalPort);
            event.remote = endpoint(api_, address_.Socket.RemoteAddr, address_.Socket.RemotePort);
            return {Status::Event, std::move(event)};
        }
        if (address_length_ != sizeof(address_) || address_.Layer != WINDIVERT_LAYER_FLOW ||
            address_.Flow.ProcessId != target_->key().pid ||
            (address_.Event != WINDIVERT_EVENT_FLOW_ESTABLISHED &&
             address_.Event != WINDIVERT_EVENT_FLOW_DELETED) ||
            (address_.Flow.Protocol != 6 && address_.Flow.Protocol != 17)) {
            throw std::runtime_error("Unexpected WinDivert flow metadata");
        }
        FlowEvent event;
        event.kind = address_.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED ? FlowEvent::Kind::Established
                                                                        : FlowEvent::Kind::Deleted;
        event.process = target_->key();
        event.endpoint_id = address_.Flow.EndpointId;
        event.parent_endpoint_id = address_.Flow.ParentEndpointId;
        event.timestamp_ticks = address_.Timestamp;
        event.protocol = address_.Flow.Protocol;
        event.ipv6 = address_.IPv6;
        event.outbound = address_.Outbound;
        event.loopback = address_.Loopback;
        event.local = endpoint(api_, address_.Flow.LocalAddr, address_.Flow.LocalPort);
        event.remote = endpoint(api_, address_.Flow.RemoteAddr, address_.Flow.RemotePort);
        return {Status::Event, std::move(event)};
    }

    std::unique_ptr<ProcessTarget> target_;
    const Mode mode_;
    Api api_;
    Handle event_;
    HANDLE handle_{INVALID_HANDLE_VALUE};
    OVERLAPPED overlapped_{};
    WINDIVERT_ADDRESS address_{};
    UINT address_length_{}, received_{};
    bool pending_{};
    std::optional<Status> terminal_;
};

FlowObserver::FlowObserver(const std::wstring& path, ProcessKey target, Mode mode)
    : FlowObserver(path, std::make_unique<ProcessTarget>(target), mode) {}
FlowObserver::FlowObserver(const std::wstring& path, std::unique_ptr<ProcessTarget> target, Mode mode)
    : impl_(std::make_unique<Impl>(path, std::move(target), mode)) {}
bool FlowObserver::targetRunning() const {
    return impl_->targetRunning();
}
FlowObserver::~FlowObserver() = default;

FlowObserver::Result FlowObserver::next(HANDLE cancellation, DWORD timeout_ms) {
    return impl_->next(cancellation, timeout_ms);
}

} // namespace skewer::windows::traffic
