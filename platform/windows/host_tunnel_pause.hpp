#pragma once

#include "paired_tunnel.hpp"
#include "routing_control.hpp"
#include <array>

namespace skewer::windows {

// Owned by the tunnel packet thread. Pause never releases the host guard or
// changes routes; only payload admission changes. Control/keepalive stays live.
class HostTunnelPause final : public TunnelPacketWorker {
public:
    HostTunnelPause(PacketDevice& device, RoutingSignals& state)
        : device_(device), signals_(state) {
        signals_.pause_supported = true;
    }

    void prepare(const Tuntom::Endpoint&) override {}
    bool dataAllowed() override { return !signals_.paused.load(); }

    void pollControl() override {
        if (!pending_) {
            auto request = signals_.pause_change.load();
            if (!request || !request->claim()) return;
            pending_ = std::move(request);
            // Hold both directions before acknowledging Pause or draining for
            // Resume. Retain this intent across transport recovery.
            signals_.paused = true;
        }
        if (pending_->paused) {
            pending_->complete();
            pending_.reset();
            return;
        }
        // A bounded drain preserves command responsiveness under continuous
        // traffic. Never replay queued host packets when reopening the gate.
        std::array<std::uint8_t, 65536> packet{};
        for (unsigned count = 0; count < 256; ++count) {
            if (device_.readPacket(packet)) continue;
            signals_.paused = false;
            pending_->complete();
            pending_.reset();
            return;
        }
    }

    void poll() override { pollControl(); }
    void block() noexcept override {}

private:
    PacketDevice& device_;
    RoutingSignals& signals_;
    std::shared_ptr<PauseChange> pending_;
};

} // namespace skewer::windows
