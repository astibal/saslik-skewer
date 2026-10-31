#pragma once
#include "packet_tuple.hpp"
#include <cstddef>
#include <chrono>
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
    // Preserve row multiplicity: distinct-PID de-duplication alone cannot
    // prove that one process does not share a UDP bind with another socket.
    std::size_t matching_rows{};

    // Snapshot evidence only: lifecycle and freshness still need validation.
    bool uniqueBind() const {
        return matching_rows == 1 && !unknown_owner && pids.size() == 1 && pids.front() != 0;
    }
};

struct UdpOwnerSnapshot {
    using Clock = std::chrono::steady_clock;
    Clock::time_point started, completed;
    std::vector<UdpOwnerRow> rows;
};

// Both families must succeed. Preserve PID zero as unavailable ownership.
// Sequential snapshots are evidence, not an atomic view of packet ownership.
UdpOwnerSnapshot captureUdpOwners();

// Candidate evidence only, never authorization. UDP tables describe binds,
// not remote peers or the identity of the thread sending a particular datagram.
// Wildcard and exact binds are both retained; neither overrides the other.
// IPv6 wildcard/mapped binds also compete with IPv4: V6ONLY is not in the table.
// Scope/compartment distinctions cannot be recovered from an L3 tuple.
UdpOwnerCandidates udpOwnerCandidates(std::span<const UdpOwnerRow> rows,
                                      const skewer::traffic::PacketTuple& outbound);
} // namespace skewer::windows::traffic
