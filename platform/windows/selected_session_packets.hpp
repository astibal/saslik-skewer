#pragma once
#include "paired_tunnel.hpp"
#include "selected_capture_bridge.hpp"

namespace skewer::windows {
// One session thread owns this adapter, the resolver and the capture handle.
// Capture is external so blocked-mode polling can outlive runPairedTunnel.
// After block(), poll still processes explicit Direct decisions, never selected
// packets. A new tunnel generation requires a new adapter.
class SelectedSessionPackets final : public PacketDevice, public TunnelPacketWorker {
public:
    SelectedSessionPackets(traffic::PacketCapture& capture, SelectedCaptureBridge::Resolver resolver,
                           SelectedTunnelDevice::Live live, HANDLE cancel, std::atomic_bool& ready);
    void prepare(const Tuntom::Endpoint& endpoint) override;
    void poll() override;
    void block() noexcept override;
    bool blocked() const { return blocked_ || (bridge_ && bridge_->tunnelBlocked()); }
    HANDLE captureEvent() const override { return capture_.readEvent(); }
    HANDLE readEvent() const override;
    std::optional<std::size_t> readPacket(std::span<std::uint8_t> buffer) override;
    bool writePacket(std::span<const std::uint8_t> packet) override;

private:
    traffic::PacketCapture& capture_;
    SelectedCaptureBridge::Resolver resolver_;
    SelectedTunnelDevice::Live live_;
    HANDLE cancel_;
    std::atomic_bool& ready_;
    bool prepared_{}, blocked_{};
    std::unique_ptr<SelectedTunnelDevice> device_;
    std::unique_ptr<SelectedCaptureBridge> bridge_;
};
} // namespace skewer::windows
