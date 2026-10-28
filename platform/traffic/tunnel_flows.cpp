#include "tunnel_flows.hpp"
#include <algorithm>
#include <stdexcept>
#include <tuple>

namespace skewer::traffic {
bool TunnelFlows::Key::operator<(const Key& other) const {
    const auto fields = [](const Key& key) {
        return std::tie(key.owner, key.tuple.protocol, key.tuple.source, key.tuple.destination,
                        key.tuple.source_port, key.tuple.destination_port);
    };
    return fields(*this) < fields(other);
}
TunnelFlows::TunnelFlows(std::array<std::uint8_t, 4> address, std::size_t capacity,
                         FlowIndex::Clock::duration idle, std::uint16_t first_port)
    : address_(address), capacity_(capacity), idle_(idle), next_port_(first_port) {
    if (!capacity || capacity > 65535 || idle <= FlowIndex::Clock::duration::zero() || !first_port ||
        !address[0] || address[0] >= 224) {
        throw std::invalid_argument("Invalid tunnel flow limits/address");
    }
}
void TunnelFlows::stop() {
    stopped_ = true;
    flows_.clear();
    reverse_.clear();
}
bool TunnelFlows::advance(Time now) {
    if (stopped_) {
        return false;
    }
    if (last_ && now < *last_) {
        stop();
        return false;
    }
    last_ = now;
    return true;
}
void TunnelFlows::expire(Time now) {
    if (!advance(now)) {
        return;
    }
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.touched >= idle_) {
            reverse_.erase(it->second.translated.source_port);
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}
void TunnelFlows::release(FlowIdentity owner) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (it->first.owner == owner) {
            reverse_.erase(it->second.translated.source_port);
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}
bool TunnelFlows::outbound(FlowIdentity owner, std::span<std::uint8_t> packet, Time now) {
    if (!advance(now) || !owner.process.pid || !owner.process.created || !owner.endpoint) {
        return false;
    }
    const auto parsed = parsePacketTuple(packet);
    if (!parsed.tuple || parsed.tuple->ipv6) {
        return false;
    }
    const Key key{owner, *parsed.tuple};
    auto it = flows_.find(key);
    if (it != flows_.end() && now - it->second.touched >= idle_) {
        reverse_.erase(it->second.translated.source_port);
        flows_.erase(it);
        it = flows_.end();
    }
    if (it == flows_.end()) {
        if (flows_.size() >= capacity_ || next_port_ > 65535) {
            return false;
        }
        auto translated = *parsed.tuple;
        std::copy(address_.begin(), address_.end(), translated.source.begin());
        translated.source_port = static_cast<std::uint16_t>(next_port_++);
        it = flows_.emplace(key, Mapping{*parsed.tuple, translated, now}).first;
        try {
            reverse_.emplace(translated.source_port, key);
        } catch (...) {
            flows_.erase(it);
            throw;
        }
    }
    auto& mapping = it->second;
    if (!rewriteIpv4Endpoint(packet, mapping.original, RewriteSide::Source,
                             {address_, mapping.translated.source_port})) {
        return false;
    }
    mapping.touched = now;
    return true;
}
std::optional<FlowIdentity> TunnelFlows::inbound(std::span<std::uint8_t> packet, Time now) {
    if (!advance(now)) {
        return std::nullopt;
    }
    const auto parsed = parsePacketTuple(packet);
    if (!parsed.tuple || parsed.tuple->ipv6) {
        return std::nullopt;
    }
    const auto found = reverse_.find(parsed.tuple->destination_port);
    if (found == reverse_.end()) {
        return std::nullopt;
    }
    const auto key = found->second;
    auto& mapping = flows_.at(key);
    if (now - mapping.touched >= idle_) {
        reverse_.erase(found);
        flows_.erase(key);
        return std::nullopt;
    }
    std::array<std::uint8_t, 4> originalAddress;
    std::copy_n(mapping.original.source.begin(), 4, originalAddress.begin());
    if (!rewriteIpv4Endpoint(packet, mapping.translated.reversed(), RewriteSide::Destination,
                             {originalAddress, mapping.original.source_port})) {
        return std::nullopt;
    }
    mapping.touched = now;
    return key.owner;
}
} // namespace skewer::traffic
