#include "wintun_device.hpp"
#include <bit>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace skewer::windows {
namespace {
[[noreturn]] void fail(const char* operation, DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}

template <typename Function> Function resolve(HMODULE library, const char* name) {
    const auto address = GetProcAddress(library, name);
    if (!address) {
        fail(name);
    }
    return std::bit_cast<Function>(address);
}
} // namespace

std::shared_ptr<const WintunApi> loadWintun(const std::wstring& path) {
    // Reject relative paths and network shares at this privileged load boundary.
    const bool drive =
        !path.empty() && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
    if (path.size() < 4 || !drive || path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') ||
        path.find(L'\0') != std::wstring::npos) {
        throw std::invalid_argument("Wintun DLL requires an absolute local installation path");
    }
    auto api = std::make_shared<WintunApi>();
    const auto library = LoadLibraryExW(path.c_str(), nullptr,
                                        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) {
        fail("LoadLibraryExW(wintun)");
    }
    api->library =
        std::shared_ptr<void>(library, [](void* value) { FreeLibrary(static_cast<HMODULE>(value)); });
    api->create = resolve<WINTUN_CREATE_ADAPTER_FUNC*>(library, "WintunCreateAdapter");
    api->close = resolve<WINTUN_CLOSE_ADAPTER_FUNC*>(library, "WintunCloseAdapter");
    api->start = resolve<WINTUN_START_SESSION_FUNC*>(library, "WintunStartSession");
    api->end = resolve<WINTUN_END_SESSION_FUNC*>(library, "WintunEndSession");
    api->read_event = resolve<WINTUN_GET_READ_WAIT_EVENT_FUNC*>(library, "WintunGetReadWaitEvent");
    api->receive = resolve<WINTUN_RECEIVE_PACKET_FUNC*>(library, "WintunReceivePacket");
    api->release = resolve<WINTUN_RELEASE_RECEIVE_PACKET_FUNC*>(library, "WintunReleaseReceivePacket");
    api->allocate = resolve<WINTUN_ALLOCATE_SEND_PACKET_FUNC*>(library, "WintunAllocateSendPacket");
    api->send = resolve<WINTUN_SEND_PACKET_FUNC*>(library, "WintunSendPacket");
    // The 0.14.1 DLL exports uppercase LUID, despite the README's spelling.
    api->luid = resolve<WINTUN_GET_ADAPTER_LUID_FUNC*>(library, "WintunGetAdapterLUID");
    return api;
}

WintunDevice::WintunDevice(std::shared_ptr<const WintunApi> api, const std::wstring& name, DWORD capacity)
    : api_(std::move(api)) {
    if (!api_ || !api_->create || !api_->close || !api_->start || !api_->end || !api_->read_event ||
        !api_->receive || !api_->release || !api_->allocate || !api_->send || !api_->luid) {
        throw std::invalid_argument("Incomplete Wintun API");
    }
    if (name.empty() || name.size() >= 128 || name.find(L'\0') != std::wstring::npos) {
        throw std::invalid_argument("Invalid Wintun adapter name");
    }
    if (capacity < WINTUN_MIN_RING_CAPACITY || capacity > WINTUN_MAX_RING_CAPACITY ||
        (capacity & (capacity - 1)) != 0) {
        throw std::invalid_argument("Invalid Wintun ring capacity");
    }
    // Create only; never silently adopt another component's existing adapter.
    adapter_ = api_->create(name.c_str(), L"Skewer", nullptr);
    if (!adapter_) {
        fail("WintunCreateAdapter");
    }
    try {
        session_ = api_->start(adapter_, capacity);
        if (!session_) {
            fail("WintunStartSession");
        }
        read_event_ = api_->read_event(session_);
        if (!read_event_ || read_event_ == INVALID_HANDLE_VALUE) {
            fail("WintunGetReadWaitEvent");
        }
    } catch (...) {
        close();
        throw;
    }
}

WintunDevice::~WintunDevice() {
    // The owner must cancel/join packet workers before destroying this object.
    close();
}

void WintunDevice::close() noexcept {
    if (session_) {
        api_->end(session_);
        session_ = nullptr;
    }
    if (adapter_) {
        api_->close(adapter_);
        adapter_ = nullptr;
    }
    read_event_ = nullptr;
}

std::optional<size_t> WintunDevice::readPacket(std::span<BYTE> buffer) {
    DWORD size = 0;
    auto* packet = api_->receive(session_, &size);
    if (!packet) {
        const auto error = GetLastError();
        if (error == ERROR_NO_MORE_ITEMS) {
            return std::nullopt;
        }
        fail("WintunReceivePacket", error);
    }
    // Always release the ring slot, including malformed/oversized packets.
    if (!size || size > WINTUN_MAX_IP_PACKET_SIZE || size > buffer.size()) {
        api_->release(session_, packet);
        throw std::length_error("Wintun packet does not fit the receive buffer");
    }
    std::memcpy(buffer.data(), packet, size);
    api_->release(session_, packet);
    return size;
}

bool WintunDevice::writePacket(std::span<const BYTE> packet) {
    if (packet.empty() || packet.size() > WINTUN_MAX_IP_PACKET_SIZE) {
        throw std::length_error("Invalid Wintun packet size");
    }
    auto* buffer = api_->allocate(session_, static_cast<DWORD>(packet.size()));
    if (!buffer) {
        const auto error = GetLastError();
        if (error == ERROR_BUFFER_OVERFLOW) {
            return false;
        }
        fail("WintunAllocateSendPacket", error);
    }
    std::memcpy(buffer, packet.data(), packet.size());
    api_->send(session_, buffer);
    return true;
}

WintunDevice::Wait WintunDevice::waitReadable(HANDLE cancellation, DWORD timeout_ms) const {
    const HANDLE events[]{cancellation, read_event_};
    // Cancellation wins when both events are signaled; no uninterruptible wait.
    switch (WaitForMultipleObjects(2, events, FALSE, timeout_ms)) {
    case WAIT_OBJECT_0:
        return Wait::Cancelled;
    case WAIT_OBJECT_0 + 1:
        return Wait::Ready;
    case WAIT_TIMEOUT:
        return Wait::Timeout;
    default:
        fail("WaitForMultipleObjects(wintun)");
    }
}

NET_LUID WintunDevice::luid() const {
    NET_LUID result{};
    api_->luid(adapter_, &result);
    return result;
}
} // namespace skewer::windows
