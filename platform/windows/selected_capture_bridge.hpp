#pragma once
#include "packet_capture.hpp"
#include "selected_tunnel_device.hpp"
#include <map>

namespace skewer::windows {
// Single packet worker only. Resolver must authorize the full captured tuple;
// diagnostic PID candidates alone are not sufficient. Unknown captures drop.
// Capture remains owned by the supervisor and must outlive stop/failed cleanup.
class SelectedCaptureBridge final {
public:
    using Identity = SelectedTunnelDevice::Identity;
    enum class Disposition { Hold, Tunnel, Direct };
    struct Resolution {
        Disposition disposition{Disposition::Hold};
        std::optional<Identity> owner;
    };
    using Resolver = std::function<Resolution(const skewer::traffic::PacketTuple&)>;
    SelectedCaptureBridge(traffic::PacketCapture& capture, SelectedTunnelDevice& device, Resolver resolve,
                          SelectedTunnelDevice::Live live, std::function<bool()> healthy,
                          std::size_t capacity = 4096);
    bool accept(traffic::PacketCapture::Packet packet);
    // One bounded capture wait followed by at most 64 reply deliveries. The
    // caller interleaves this with TunnelPump::step; no thread is created here.
    void step(HANDLE cancel, DWORD timeout_ms);
    std::size_t deliver();
    void stop();

private:
    struct Less {
        bool operator()(const skewer::traffic::PacketTuple& a, const skewer::traffic::PacketTuple& b) const;
    };
    struct Origin {
        Identity owner;
        traffic::PacketCapture::Packet capture;
    };
    traffic::PacketCapture& capture_;
    SelectedTunnelDevice& device_;
    Resolver resolve_;
    SelectedTunnelDevice::Live live_;
    std::function<bool()> healthy_;
    const std::size_t capacity_;
    bool stopped_{};
    std::map<skewer::traffic::PacketTuple, Origin, Less> origins_;
};
} // namespace skewer::windows
