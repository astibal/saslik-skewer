#include "udp_owners.hpp"
#include <algorithm>
#include <stdexcept>

namespace skewer::windows::traffic {
namespace {
bool zero(std::span<const std::uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](auto byte) { return byte == 0; });
}

bool matchesAddress(const UdpOwnerRow& row, const skewer::traffic::PacketTuple& packet) {
    if (row.ipv6 == packet.ipv6) {
        return zero(row.local_address) || row.local_address == packet.source;
    }
    if (!row.ipv6) {
        return false;
    }
    // The owner table does not expose IPV6_V6ONLY. Preserve possible dual-stack
    // competition instead of incorrectly declaring an IPv4 socket exclusive.
    const auto& address = row.local_address;
    if (zero(address)) {
        return true;
    }
    const bool mapped = zero(std::span(address).first(10)) && address[10] == 0xff && address[11] == 0xff;
    return mapped && std::equal(address.begin() + 12, address.end(), packet.source.begin());
}
} // namespace

UdpOwnerCandidates udpOwnerCandidates(std::span<const UdpOwnerRow> rows,
                                      const skewer::traffic::PacketTuple& outbound) {
    if (outbound.protocol != 17 || outbound.source_port == 0) {
        throw std::invalid_argument("UDP owner lookup requires a UDP source port");
    }
    UdpOwnerCandidates result;
    for (const auto& row : rows) {
        if (row.local_port != outbound.source_port || !matchesAddress(row, outbound)) {
            continue;
        }
        ++result.matching_rows;
        if (row.pid == 0) {
            result.unknown_owner = true;
        } else {
            result.pids.push_back(row.pid);
        }
    }
    std::sort(result.pids.begin(), result.pids.end());
    result.pids.erase(std::unique(result.pids.begin(), result.pids.end()), result.pids.end());
    return result;
}
} // namespace skewer::windows::traffic
