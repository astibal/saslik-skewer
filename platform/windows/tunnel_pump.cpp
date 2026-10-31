#include "tunnel_pump.hpp"
#include <array>
#include <system_error>

namespace skewer::windows {
namespace {
bool validIp(std::span<const uint8_t> packet) {
    if (packet.size() >= 20 && packet.front() >> 4 == 4) {
        const size_t header = (packet.front() & 15) * 4;
        const size_t length = (static_cast<size_t>(packet[2]) << 8) | packet[3];
        return header >= 20 && header <= packet.size() && length == packet.size();
    }
    if (packet.size() >= 40 && packet.front() >> 4 == 6) {
        const size_t payload = (static_cast<size_t>(packet[4]) << 8) | packet[5];
        return payload + 40 == packet.size();
    }
    return false;
}
} // namespace

TunnelPump::TunnelPump(PacketDevice& device, UdpEndpoint& udp, UdpAddress peer, uint16_t id,
                       const tuntom::ascon::key_type& key, bool server, std::function<bool()> data_allowed)
    : device_(device), udp_(udp), peer_(peer), id_(id),
      session_(id, key, server, inner_mtu, true, 300, true), data_allowed_(std::move(data_allowed)) {
    if (id == 0 || peer.port() == 0 || peer.family() != udp.localAddress().family()) {
        throw std::invalid_argument("Invalid tunnel ID or fixed UDP peer");
    }
}

bool TunnelPump::healthy(Time now) const {
    return confirmed_ && session_.ready() && now >= last_received_ && now - last_received_ < health_timeout;
}

void TunnelPump::synchronizeKeys() {
    const auto generation = session_.transmit_generation();
    if (generation != generation_) {
        generation_ = generation;
        confirmed_ = false;
    }
}

bool TunnelPump::send(const std::vector<uint8_t>& wire) {
    // No deferred ciphertext survives a key change or health transition.
    // UDP/Wintun backpressure drops packets; protocol flights retry via tick().
    if (wire.empty()) {
        return false;
    }
    if (!udp_.send(wire, peer_)) {
        ++counters_.backpressure;
        return false;
    }
    return true;
}

void TunnelPump::receive(Time now) {
    std::array<uint8_t, 65536> buffer{};
    for (unsigned batch = 0; batch != 16; ++batch) {
        const auto datagram = udp_.receive(buffer);
        if (!datagram) {
            return;
        }
        if (!(datagram->source == peer_)) {
            ++counters_.foreign_peer;
            continue;
        }
        tuntom::Packet packet;
        std::vector<uint8_t> scratch;
        auto result = session_.receive(buffer.data(), datagram->size, packet, scratch, now);
        synchronizeKeys();
        if (result.activated) {
            confirmed_ = true;
        }
        if (result.activated || (result.data && result.session->exchange == session_.active_exchange())) {
            last_received_ = now;
        }
        send(result.reply);
        if (!result.data) {
            continue;
        }
        if (packet.type >= tuntom::PacketType::auth_challenge) {
            throw std::runtime_error("VPN AUTH/config extensions are not supported by this transport yet");
        }
        if (packet.type == tuntom::PacketType::ping && packet.message_id != 0 && healthy(now)) {
            // Reply only to authenticated probes; preserve the peer's correlation ID.
            tuntom::Packet reply;
            reply.type = tuntom::PacketType::pong;
            reply.tunnel_id = id_;
            reply.message_id = packet.message_id;
            send(session_.encode(reply));
        }
        if (packet.type != tuntom::PacketType::data) {
            continue;
        }
        if (!healthy(now)) {
            ++counters_.not_ready;
            continue;
        }
        std::vector<uint8_t> complete;
        if (!result.session->reassembly.accept(packet, complete, nullptr, now)) {
            continue;
        }
        if (complete.size() > inner_mtu || !validIp(complete)) {
            ++counters_.invalid;
            continue;
        }
        if (data_allowed_ && !data_allowed_()) {
            ++counters_.not_ready;
            continue;
        }
        if (device_.writePacket(complete)) {
            ++counters_.rx;
        } else {
            ++counters_.backpressure;
        }
    }
}

void TunnelPump::transmit(Time now) {
    std::array<uint8_t, 65535> buffer{};
    for (unsigned batch = 0; batch != 16; ++batch) {
        auto size = device_.readPacket(buffer);
        if (!size) {
            return;
        }
        if (!healthy(now)) {
            ++counters_.not_ready;
            continue;
        }
        if (*size > inner_mtu) {
            ++counters_.oversized;
            continue;
        }
        if (!validIp(std::span(buffer).first(*size))) {
            ++counters_.invalid;
            continue;
        }
        tuntom::Packet packet;
        packet.tunnel_id = id_;
        packet.message_id = ++message_id_;
        packet.original_length = static_cast<uint32_t>(*size);
        packet.payload.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*size));
        const auto wire = session_.encode(packet);
        if (data_allowed_ && !data_allowed_()) {
            ++counters_.not_ready;
            continue;
        }
        if (send(wire)) {
            ++counters_.tx;
        }
    }
}

void TunnelPump::step(Time now) try {
    auto flight = session_.tick(now);
    synchronizeKeys();
    send(flight);
    receive(now);
    session_.cleanup(now);
    // Linux keepalives are less frequent than our health deadline. Solicit an
    // authenticated reply instead of assuming that outgoing traffic proves life.
    // Continue probing while the data gate is closed so the peer can recover.
    if (confirmed_ && session_.ready() && now - last_keepalive_ >= std::chrono::seconds(1)) {
        tuntom::Packet keepalive;
        keepalive.type = tuntom::PacketType::ping;
        keepalive.tunnel_id = id_;
        keepalive.message_id = ++message_id_;
        send(session_.encode(keepalive));
        last_keepalive_ = now;
    }
    transmit(now);
} catch (...) {
    confirmed_ = false;
    throw;
}

void TunnelPump::run(HANDLE stop) {
    struct ResetHealth {
        bool& confirmed;
        ~ResetHealth() { confirmed = false; }
    } reset{confirmed_};
    while (true) {
        const DWORD state = WaitForSingleObject(stop, 0);
        if (state == WAIT_OBJECT_0) {
            return;
        }
        if (state != WAIT_TIMEOUT) {
            throw std::system_error(GetLastError(), std::system_category(), "Tunnel cancellation");
        }
        step(Clock::now());
        if (udp_.wait(stop, 50, device_.readEvent()) == UdpEndpoint::Wait::Cancelled) {
            return;
        }
    }
}

} // namespace skewer::windows
