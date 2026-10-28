#include "selected_capture_bridge.hpp"
#include <tuple>

namespace skewer::windows {
bool SelectedCaptureBridge::Less::operator()(const skewer::traffic::PacketTuple& a,
                                             const skewer::traffic::PacketTuple& b) const {
    const auto fields = [](const auto& t) {
        return std::tie(t.ipv6, t.protocol, t.source, t.destination, t.source_port, t.destination_port);
    };
    return fields(a) < fields(b);
}
SelectedCaptureBridge::SelectedCaptureBridge(traffic::PacketCapture& capture, SelectedTunnelDevice& device,
                                             Resolver resolve, SelectedTunnelDevice::Live live,
                                             std::function<bool()> healthy, std::size_t capacity)
    : capture_(capture), device_(device), resolve_(std::move(resolve)), live_(std::move(live)),
      healthy_(std::move(healthy)), capacity_(capacity) {
    if (!resolve_ || !live_ || !healthy_ || !capacity || capacity > 65535) {
        throw std::invalid_argument("Invalid selected capture bridge configuration");
    }
}
void SelectedCaptureBridge::stop() {
    stopped_ = true;
    origins_.clear();
    device_.stop();
}
bool SelectedCaptureBridge::accept(traffic::PacketCapture::Packet packet) try {
    if (stopped_) {
        return false;
    }
    if (!healthy_()) {
        stop();
        return false;
    }
    const auto tuple = skewer::traffic::parsePacketTuple(packet.bytes);
    if (!tuple.tuple || tuple.tuple->ipv6 || packet.bytes.size() > 1280 ||
        packet.address.Layer != WINDIVERT_LAYER_NETWORK || !packet.address.Outbound || packet.address.IPv6 ||
        (!packet.address.Loopback && !packet.address.Network.IfIdx)) {
        return false;
    }
    const auto owner = resolve_(*tuple.tuple);
    if (!owner || !live_(*owner)) {
        return false;
    }
    if (!healthy_()) {
        stop();
        return false;
    }
    auto found = origins_.find(*tuple.tuple);
    // Never overwrite reverse-delivery metadata with another process/socket.
    // That requires an explicitly retired tunnel epoch, not a PID-only match.
    if (found != origins_.end() && found->second.owner != *owner) {
        return false;
    }
    if (found == origins_.end()) {
        if (origins_.size() >= capacity_) {
            return false;
        }
        found = origins_.emplace(*tuple.tuple, Origin{*owner, std::move(packet)}).first;
    } else {
        // Route changes retire this bridge instead of silently switching the
        // interface used by delayed replies from the same translated flow.
        const auto& old = found->second.capture.address;
        if (old.Loopback != packet.address.Loopback || old.Network.IfIdx != packet.address.Network.IfIdx ||
            old.Network.SubIfIdx != packet.address.Network.SubIfIdx) {
            stop();
            return false;
        }
        found->second.capture = std::move(packet);
    }
    return device_.enqueue(*owner, found->second.capture.bytes);
} catch (...) {
    stop();
    throw;
}

std::size_t SelectedCaptureBridge::deliver() try {
    if (stopped_) {
        return 0;
    }
    if (!healthy_()) {
        stop();
        return 0;
    }
    std::size_t count{};
    for (unsigned i = 0; i < 64; ++i) {
        auto reply = device_.takeReceived();
        if (!reply) {
            break;
        }
        const auto tuple = skewer::traffic::parsePacketTuple(reply->bytes);
        if (!tuple.tuple) {
            continue;
        }
        const auto found = origins_.find(tuple.tuple->reversed());
        if (found == origins_.end() || found->second.owner != reply->owner || !live_(reply->owner)) {
            continue;
        }
        if (!healthy_()) {
            stop();
            break;
        }
        capture_.reinject(traffic::restoredReply(found->second.capture, std::move(reply->bytes)));
        ++count;
    }
    return count;
} catch (...) {
    stop();
    throw;
}

void SelectedCaptureBridge::step(HANDLE cancel, DWORD timeout_ms) try {
    if (stopped_) {
        return;
    }
    const auto result = WaitForSingleObject(cancel, 0);
    if (result == WAIT_OBJECT_0) {
        stop();
        return;
    }
    if (result != WAIT_TIMEOUT) {
        throw std::runtime_error("Invalid bridge cancellation event");
    }
    auto captured = capture_.next(cancel, timeout_ms);
    if (captured.status == traffic::PacketCapture::Status::Cancelled) {
        stop();
        return;
    }
    if (captured.packet) {
        accept(std::move(*captured.packet));
    }
    // Cancellation wins even when a capture and replies become ready together.
    if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
        stop();
        return;
    }
    deliver();
} catch (...) {
    stop();
    throw;
}
} // namespace skewer::windows
