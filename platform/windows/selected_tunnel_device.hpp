#pragma once
#include "../traffic/tunnel_flows.hpp"
#include "packet_device.hpp"
#include "processes.hpp"
#include <deque>
#include <functional>
#include <vector>

namespace skewer::windows {
// Single-worker adapter between authorized captures and TunnelPump. The owner
// arms its external guard first and enqueues only after authenticated readiness.
// No direct-network fallback. Callback failures permanently retire this epoch.
class SelectedTunnelDevice final : public PacketDevice {
public:
    using Identity = skewer::traffic::FlowIdentity;
    using Clock = skewer::traffic::FlowIndex::Clock;
    struct Packet {
        Identity owner;
        std::vector<std::uint8_t> bytes;
        Clock::time_point queued;
    };
    using Live = std::function<bool(Identity)>;
    SelectedTunnelDevice(std::array<std::uint8_t, 4> address, Live live, std::function<bool()> healthy,
                         std::size_t capacity = 64);
    bool enqueue(Identity owner, std::span<const std::uint8_t> packet);
    std::optional<Packet> takeReceived();
    std::optional<std::size_t> readPacket(std::span<std::uint8_t> buffer) override;
    bool writePacket(std::span<const std::uint8_t> packet) override;
    HANDLE readEvent() const override { return event_.get(); }
    void release(Identity owner);
    void releaseProcess(skewer::traffic::ProcessIdentity process);
    // Packet-worker only. Pause drops queued and newly arriving data without
    // releasing flow ownership. Resume never revives a retired tunnel epoch.
    void setPaused(bool paused);
    void stop();

private:
    bool allowed(Identity owner);
    void syncEvent();
    skewer::traffic::TunnelFlows flows_;
    Live live_;
    std::function<bool()> healthy_;
    const std::size_t capacity_;
    Handle event_;
    bool stopped_{};
    bool paused_{};
    std::deque<Packet> outbound_, inbound_;
};
} // namespace skewer::windows
