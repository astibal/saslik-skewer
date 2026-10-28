#include "packet_capture.hpp"
#include <array>
#include <bit>
#include <stdexcept>
#include <system_error>

namespace skewer::windows::traffic {
namespace {
[[noreturn]] void fail(const char* operation) {
    throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), operation);
}
template <typename T> T resolve(HMODULE module, const char* name) {
    const auto symbol = GetProcAddress(module, name);
    if (!symbol) {
        fail(name);
    }
    return std::bit_cast<T>(symbol);
}
} // namespace

class PacketCapture::Impl final {
public:
    Impl(const std::wstring& path, const std::string& filter)
        : event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
        const bool drive =
            !path.empty() && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
        if (path.size() < 4 || !drive || path[1] != L':' || path[2] != L'\\' ||
            path.find(L'\0') != std::wstring::npos || filter.empty() ||
            filter.find('\0') != std::string::npos) {
            throw std::invalid_argument("Absolute local DLL and nonempty trusted filter required");
        }
        if (!event_) {
            fail("Create capture event");
        }
        const auto module = LoadLibraryExW(path.c_str(), nullptr,
                                           LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module) {
            fail("Load packet capture DLL");
        }
        library_ =
            std::shared_ptr<void>(module, [](void* value) { FreeLibrary(static_cast<HMODULE>(value)); });
        const auto open = resolve<decltype(&WinDivertOpen)>(module, "WinDivertOpen");
        const auto compile =
            resolve<decltype(&WinDivertHelperCompileFilter)>(module, "WinDivertHelperCompileFilter");
        const char* filter_error{};
        UINT error_position{};
        if (!compile(filter.c_str(), WINDIVERT_LAYER_NETWORK, nullptr, 0, &filter_error, &error_position)) {
            throw std::invalid_argument("NETWORK filter at " + std::to_string(error_position) + ": " +
                                        (filter_error ? filter_error : "invalid expression"));
        }
        close_ = resolve<decltype(close_)>(module, "WinDivertClose");
        receive_ = resolve<decltype(receive_)>(module, "WinDivertRecvEx");
        send_ = resolve<decltype(send_)>(module, "WinDivertSend");
        checksums_ = resolve<decltype(checksums_)>(module, "WinDivertHelperCalcChecksums");
        handle_ = open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE) {
            fail("Open NETWORK capture");
        }
    }
    ~Impl() {
        cancelRead();
        close_(handle_);
    }

    Result next(HANDLE cancellation, DWORD timeout) {
        if (cancelled_) {
            return {Status::Cancelled, std::nullopt};
        }
        const auto control = WaitForSingleObject(cancellation, 0);
        if (control == WAIT_OBJECT_0) {
            return cancel();
        }
        if (control != WAIT_TIMEOUT) {
            fail("Check capture cancellation");
        }
        if (!pending_) {
            address_ = {};
            address_size_ = sizeof(address_);
            operation_ = {};
            operation_.hEvent = event_.get();
            if (!ResetEvent(event_.get())) {
                fail("Reset capture event");
            }
            const auto ok = receive_(handle_, buffer_.data(), buffer_.size(), nullptr, 0, &address_,
                                     &address_size_, &operation_);
            if (!ok && GetLastError() != ERROR_IO_PENDING) {
                fail("Start packet capture");
            }
            pending_ = true;
        }
        const HANDLE events[]{cancellation, event_.get()};
        const auto ready = WaitForMultipleObjects(2, events, FALSE, timeout);
        if (ready == WAIT_OBJECT_0) {
            return cancel();
        }
        if (ready == WAIT_TIMEOUT) {
            return {Status::Timeout, std::nullopt};
        }
        if (ready != WAIT_OBJECT_0 + 1) {
            fail("Wait for packet capture");
        }
        DWORD received{};
        if (!GetOverlappedResult(handle_, &operation_, &received, FALSE)) {
            // Keep the request marked pending until destructor has drained it.
            fail("Complete packet capture");
        }
        pending_ = false;
        if (!received || received > buffer_.size() || address_size_ != sizeof(address_) ||
            address_.Layer != WINDIVERT_LAYER_NETWORK || address_.Event != WINDIVERT_EVENT_NETWORK_PACKET) {
            throw std::runtime_error("Unexpected NETWORK capture metadata");
        }
        Packet packet{{buffer_.begin(), buffer_.begin() + received}, address_};
        ++stats_.captured_packets;
        stats_.captured_bytes += received;
        return {Status::Packet, std::move(packet)};
    }

    void reinject(Packet packet) {
        if (cancelled_) {
            throw std::logic_error("Capture is cancelled");
        }
        if (packet.bytes.empty() || packet.bytes.size() > buffer_.size() ||
            packet.address.Layer != WINDIVERT_LAYER_NETWORK ||
            packet.address.Event != WINDIVERT_EVENT_NETWORK_PACKET) {
            throw std::invalid_argument("Invalid captured packet");
        }
        const auto size = static_cast<UINT>(packet.bytes.size());
        if (!checksums_(packet.bytes.data(), size, &packet.address, 0)) {
            fail("Calculate checksums");
        }
        UINT sent{};
        if (!send_(handle_, packet.bytes.data(), size, &sent, &packet.address)) {
            fail("Reinject packet");
        }
        if (sent != size) {
            throw std::runtime_error("Partial packet injection");
        }
        ++stats_.injected_packets;
        stats_.injected_bytes += sent;
    }
    Stats stats() const { return stats_; }
    HANDLE readEvent() const { return event_.get(); }

private:
    void cancelRead() noexcept {
        if (!pending_) {
            return;
        }
        CancelIoEx(handle_, &operation_);
        DWORD ignored{};
        GetOverlappedResult(handle_, &operation_, &ignored, TRUE);
        pending_ = false;
    }
    Result cancel() {
        cancelRead();
        cancelled_ = true;
        return {Status::Cancelled, std::nullopt};
    }
    Handle event_;
    std::shared_ptr<void> library_;
    decltype(&WinDivertClose) close_{};
    decltype(&WinDivertRecvEx) receive_{};
    decltype(&WinDivertSend) send_{};
    decltype(&WinDivertHelperCalcChecksums) checksums_{};
    HANDLE handle_{INVALID_HANDLE_VALUE};
    std::array<std::uint8_t, 65535> buffer_{};
    WINDIVERT_ADDRESS address_{};
    UINT address_size_{};
    OVERLAPPED operation_{};
    bool pending_{}, cancelled_{};
    Stats stats_;
};
PacketCapture::PacketCapture(const std::wstring& dll, const std::string& filter)
    : impl_(std::make_unique<Impl>(dll, filter)) {}
PacketCapture::~PacketCapture() = default;
PacketCapture::Result PacketCapture::next(HANDLE cancellation, DWORD timeout_ms) {
    return impl_->next(cancellation, timeout_ms);
}
void PacketCapture::reinject(Packet packet) {
    impl_->reinject(std::move(packet));
}
PacketCapture::Stats PacketCapture::stats() const {
    return impl_->stats();
}
HANDLE PacketCapture::readEvent() const {
    return impl_->readEvent();
}
} // namespace skewer::windows::traffic
