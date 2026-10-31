#pragma once

#include "udp_endpoint.hpp"
#include "packet_device.hpp"
#include <session.hpp>
#include <functional>

namespace skewer::windows {

// Experimental fixed-peer PSK transport, not an application kill switch.
// No routes, DNS, leases or WFP filters are installed here. The owner must keep
// external protection armed before exposing the device to application traffic.
class TunnelPump final {
public:
    using Clock = tuntom::SessionProtocol::Clock;
    using Time = Clock::time_point;
    static constexpr size_t inner_mtu = 1280;
    static constexpr auto health_timeout = std::chrono::seconds(5);
    struct Counters {
        uint64_t tx{}, rx{}, not_ready{}, oversized{}, foreign_peer{}, backpressure{}, invalid{};
    };

    TunnelPump(PacketDevice& device, UdpEndpoint& udp, UdpAddress peer, uint16_t id,
               const tuntom::ascon::key_type& key, bool server = false,
               std::function<bool()> data_allowed = {});
    // Deterministic bounded iteration for the supervisor and tests; one owner.
    void step(Time now);
    void run(HANDLE stop);
    bool healthy(Time now) const;
    const Counters& counters() const { return counters_; }

private:
    void synchronizeKeys();
    bool send(const std::vector<uint8_t>& wire);
    void receive(Time now);
    void transmit(Time now);
    PacketDevice& device_;
    UdpEndpoint& udp_;
    UdpAddress peer_;
    uint16_t id_;
    tuntom::SessionProtocol session_;
    uint64_t generation_{};
    bool confirmed_{};
    Time last_received_{}, last_keepalive_{};
    uint64_t message_id_{};
    Counters counters_;
    // Invoked by the pump owner at packet boundaries, never by a control worker.
    std::function<bool()> data_allowed_;
};

} // namespace skewer::windows
