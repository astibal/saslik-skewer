#pragma once
#include "packet_tuple.hpp"
#include <chrono>
#include <span>
#include <string>
#include <vector>

namespace skewer::windows {
struct ProcessKey;
}

namespace skewer::windows::traffic {
struct TcpOwnerRow {
    skewer::traffic::PacketTuple tuple;
    std::uint32_t pid{};
    std::uint32_t state{}; // MIB_TCP_STATE_* from the same IP Helper row.
};
struct TcpOwnerSnapshot {
    using Clock = std::chrono::steady_clock;
    Clock::time_point started, completed;
    std::vector<TcpOwnerRow> rows;
    std::string error; // Presentation snapshots may report a bounded collection failure.
};
// Reads both IP Helper owner-PID tables, not a selected-process filter.
// Bounded retries/size; any error rejects the entire snapshot. No driver needed.
TcpOwnerSnapshot captureTcpOwners();

// Outbound tuple only. The caller explicitly reverses inbound packets.
// Returns distinct observed PIDs (zero means unavailable ownership), NOT authenticated identities or
// proof of uniqueness. Tables are not atomic with each other or with packets;
// PID reuse, compartments and concurrent socket changes remain external checks.
std::vector<std::uint32_t> tcpOwnerCandidates(std::span<const TcpOwnerRow> rows,
                                              const skewer::traffic::PacketTuple& tuple);
// Candidate predicate only. Freshness, selected process liveness and lifecycle
// disagreement must still be checked by the policy before any direct delivery.
bool excludesSelectedTcpOwner(std::span<const std::uint32_t> candidates, std::uint32_t selected);

// Resets only live non-listening IPv4 TCP endpoints owned by retained process
// identities. This is used after fail-closed guards are installed, so an
// attached application's next connection cannot race out through the old path.
// IPv6 and UDP remain explicitly outside this cleanup contract.
std::vector<TcpOwnerRow> ownedIpv4TcpRows(
    std::span<const TcpOwnerRow> rows,
    std::span<const skewer::windows::ProcessKey> processes);
std::size_t resetOwnedIpv4Tcp(std::span<const skewer::windows::ProcessKey> processes);
} // namespace skewer::windows::traffic
