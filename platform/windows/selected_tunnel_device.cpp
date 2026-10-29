#include "selected_tunnel_device.hpp"
#include <algorithm>
#include <stdexcept>

namespace skewer::windows {
SelectedTunnelDevice::SelectedTunnelDevice(std::array<std::uint8_t, 4> address, Live live,
                                           std::function<bool()> healthy, std::size_t capacity)
    : flows_(address), live_(std::move(live)), healthy_(std::move(healthy)), capacity_(capacity),
      event_(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
    if (!live_ || !healthy_ || !capacity || capacity > 4096 || !event_) {
        throw std::invalid_argument("Invalid selected tunnel device configuration");
    }
}
void SelectedTunnelDevice::stop() {
    stopped_ = true;
    outbound_.clear();
    inbound_.clear();
    flows_.stop();
    ResetEvent(event_.get());
}
void SelectedTunnelDevice::syncEvent() {
    if (!(outbound_.empty() ? ResetEvent(event_.get()) : SetEvent(event_.get()))) {
        stop();
        throw std::runtime_error("Selected packet event failed");
    }
}
void SelectedTunnelDevice::setPaused(bool paused) {
    paused_ = paused;
    if (paused) {
        // Neither direction may replay data buffered before acknowledgement.
        // Keep translations so a healthy resumed connection retains identity.
        outbound_.clear();
        inbound_.clear();
    }
    syncEvent();
}
void SelectedTunnelDevice::release(Identity owner) {
    flows_.release(owner);
    std::erase_if(outbound_, [&](const auto& packet) { return packet.owner == owner; });
    std::erase_if(inbound_, [&](const auto& packet) { return packet.owner == owner; });
    syncEvent();
}
void SelectedTunnelDevice::releaseProcess(skewer::traffic::ProcessIdentity process) {
    flows_.releaseProcess(process);
    std::erase_if(outbound_, [&](const auto& packet) { return packet.owner.process == process; });
    std::erase_if(inbound_, [&](const auto& packet) { return packet.owner.process == process; });
    syncEvent();
}
bool SelectedTunnelDevice::allowed(Identity owner) try {
    if (stopped_) {
        return false;
    }
    if (!healthy_()) {
        stop();
        return false;
    }
    if (paused_) return false;
    if (!live_(owner)) {
        release(owner);
        return false;
    }
    // The liveness resolver may perform OS queries. Recheck health afterwards.
    if (!healthy_()) {
        stop();
        return false;
    }
    return true;
} catch (...) {
    stop();
    throw;
}
bool SelectedTunnelDevice::enqueue(Identity owner, std::span<const std::uint8_t> packet) {
    if (packet.empty() || packet.size() > 1280 || outbound_.size() >= capacity_ || !allowed(owner)) {
        return false;
    }
    const auto parsed = skewer::traffic::parsePacketTuple(packet);
    if (!parsed.tuple || parsed.tuple->ipv6) {
        return false;
    }
    outbound_.push_back({owner, {packet.begin(), packet.end()}, Clock::now()});
    syncEvent();
    return true;
}
std::optional<std::size_t> SelectedTunnelDevice::readPacket(std::span<std::uint8_t> buffer) {
    while (!outbound_.empty()) {
        if (buffer.size() < outbound_.front().bytes.size()) {
            throw std::invalid_argument("Selected packet buffer too small");
        }
        auto packet = std::move(outbound_.front());
        outbound_.pop_front();
        syncEvent();
        if (!allowed(packet.owner)) {
            continue;
        }
        const auto now = Clock::now();
        if (now - packet.queued >= std::chrono::seconds(3)) {
            continue;
        }
        flows_.expire(now);
        if (!skewer::traffic::clampIpv4TcpMss(packet.bytes, 1240)) { continue; }
        if (!flows_.outbound(packet.owner, packet.bytes, now) || !allowed(packet.owner)) {
            continue;
        }
        std::copy(packet.bytes.begin(), packet.bytes.end(), buffer.begin());
        return packet.bytes.size();
    }
    return std::nullopt;
}
bool SelectedTunnelDevice::writePacket(std::span<const std::uint8_t> packet) {
    if (stopped_ || paused_ || packet.empty() || packet.size() > 1280 || inbound_.size() >= capacity_) {
        return false;
    }
    std::vector<std::uint8_t> bytes(packet.begin(), packet.end());
    if (!skewer::traffic::clampIpv4TcpMss(bytes, 1240)) { return false; }
    const auto now = Clock::now();
    flows_.expire(now);
    const auto owner = flows_.inbound(bytes, now);
    if (!owner || !allowed(*owner)) {
        return false;
    }
    inbound_.push_back({*owner, std::move(bytes), now});
    return true;
}
std::optional<SelectedTunnelDevice::Packet> SelectedTunnelDevice::takeReceived() {
    while (!inbound_.empty()) {
        auto packet = std::move(inbound_.front());
        inbound_.pop_front();
        if (allowed(packet.owner) && Clock::now() - packet.queued < std::chrono::seconds(3)) {
            return packet;
        }
    }
    return std::nullopt;
}
} // namespace skewer::windows
