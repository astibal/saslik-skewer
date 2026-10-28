#pragma once
#include "packet_tuple.hpp"

namespace skewer::traffic {
struct Ipv4Endpoint {
    std::array<std::uint8_t, 4> address{};
    std::uint16_t port{};
};
enum class RewriteSide { Source, Destination };

// Rewrite one endpoint of a complete, unfragmented IPv4 TCP/UDP packet.
// The expected tuple binds the operation to a previously selected flow. This
// is translation only, never an ownership decision or authorization to send.
// Recompute checksums from bytes: captured packets may carry offload placeholders.
// Failure leaves the packet unchanged. IPv6, IP options and fragments are rejected.
bool rewriteIpv4Endpoint(std::span<std::uint8_t> packet, const PacketTuple& expected, RewriteSide side,
                         Ipv4Endpoint replacement);
// Clamp SYN/SYN-ACK MSS in both directions before forwarding through a smaller
// tunnel. Validate the complete option list before mutation; recompute checksums.
bool clampIpv4TcpMss(std::span<std::uint8_t> packet, std::uint16_t maximum);
} // namespace skewer::traffic
