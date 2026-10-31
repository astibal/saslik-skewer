#pragma once

#include <wintun.h>
#include "packet_device.hpp"
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace skewer::windows {

// The function table is injectable for lifecycle/error tests. Keeping it alive
// also keeps the DLL loaded until every adapter/session has been released.
struct WintunApi {
    std::shared_ptr<void> library;
    WINTUN_CREATE_ADAPTER_FUNC* create{};
    WINTUN_CLOSE_ADAPTER_FUNC* close{};
    WINTUN_START_SESSION_FUNC* start{};
    WINTUN_END_SESSION_FUNC* end{};
    WINTUN_GET_READ_WAIT_EVENT_FUNC* read_event{};
    WINTUN_RECEIVE_PACKET_FUNC* receive{};
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release{};
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* allocate{};
    WINTUN_SEND_PACKET_FUNC* send{};
    WINTUN_GET_ADAPTER_LUID_FUNC* luid{};
};

// The caller must supply a trusted, administrator-controlled installation path.
// No PATH/current-directory lookup or automatic driver download is performed.
std::shared_ptr<const WintunApi> loadWintun(const std::wstring& absolute_dll);

class WintunDevice final : public PacketDevice {
public:
    enum class Wait { Ready, Cancelled, Timeout };
    WintunDevice(std::shared_ptr<const WintunApi> api, const std::wstring& name, DWORD capacity = 0x400000);
    ~WintunDevice() override;
    WintunDevice(const WintunDevice&) = delete;
    WintunDevice& operator=(const WintunDevice&) = delete;

    // Read host egress for encapsulation; write decapsulated ingress to the host.
    // An empty receive and a full send ring are normal backpressure, not success.
    std::optional<size_t> readPacket(std::span<BYTE> buffer) override;
    bool writePacket(std::span<const BYTE> packet) override;
    HANDLE readEvent() const override { return read_event_; }
    Wait waitReadable(HANDLE cancellation, DWORD timeout_ms) const;
    NET_LUID luid() const;

private:
    void close() noexcept;
    std::shared_ptr<const WintunApi> api_;
    WINTUN_ADAPTER_HANDLE adapter_{};
    WINTUN_SESSION_HANDLE session_{};
    HANDLE read_event_{}; // Borrowed from Wintun: never CloseHandle this event.
};

} // namespace skewer::windows
