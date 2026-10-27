#pragma once
#include "packet_tuple.hpp"
#include <span>
#include <vector>

namespace skewer::windows::traffic {
struct UdpOwnerRow {
    bool ipv6{};
    std::array<std::uint8_t, 16> local_address{};
    std::uint16_t local_port{};
    std::uint32_t pid{};
};

struct UdpOwnerCandidates {
    std::vector<std::uint32_t> pids;
    bool unknown_owner{};
};

// Candidate evidence only, never authorization. UDP tables describe binds,
// not remote peers or the identity of the thread sending a particular datagram.
// Wildcard and exact binds are both retained; neither overrides the other.
// IPv6 wildcard/mapped binds also compete with IPv4: V6ONLY is not in the table.
// Scope/compartment distinctions cannot be recovered from an L3 tuple.
UdpOwnerCandidates udpOwnerCandidates(std::span<const UdpOwnerRow> rows,
                                      const skewer::traffic::PacketTuple& outbound);
} // namespace skewer::windows::traffic
