#include "packet_rewrite.hpp"
#include <algorithm>

namespace skewer::traffic {
namespace {
std::uint32_t sumWords(std::span<const std::uint8_t> bytes) {
    std::uint32_t sum{};
    std::size_t i{};
    for (; i + 1 < bytes.size(); i += 2) {
        sum += (static_cast<std::uint32_t>(bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.size()) {
        sum += static_cast<std::uint32_t>(bytes[i]) << 8;
    }
    return sum;
}
std::uint16_t checksum(std::uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}
void store(std::span<std::uint8_t> bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}
} // namespace

bool rewriteIpv4Endpoint(std::span<std::uint8_t> packet, const PacketTuple& expected, RewriteSide side,
                         Ipv4Endpoint replacement) {
    const auto parsed = parsePacketTuple(packet);
    if (!parsed.tuple || parsed.tuple->ipv6 || *parsed.tuple != expected ||
        (side != RewriteSide::Source && side != RewriteSide::Destination) || !replacement.port ||
        replacement.address[0] == 0 || replacement.address[0] >= 224) {
        return false;
    }
    // Parsing established a fixed 20-byte IP header and a complete TCP/UDP header.
    const auto addressOffset = side == RewriteSide::Source ? 12 : 16;
    const auto portOffset = side == RewriteSide::Source ? 20 : 22;
    std::copy(replacement.address.begin(), replacement.address.end(), packet.begin() + addressOffset);
    store(packet, portOffset, replacement.port);
    store(packet, 10, 0);
    store(packet, 10, checksum(sumWords(packet.first(20))));

    const auto checksumOffset = expected.protocol == 6 ? 36 : 26;
    store(packet, checksumOffset, 0);
    const auto length = static_cast<std::uint16_t>(packet.size() - 20);
    const auto pseudo = sumWords(packet.subspan(12, 8)) + expected.protocol + length;
    auto result = checksum(pseudo + sumWords(packet.subspan(20)));
    // UDP zero means "checksum absent", not the checksum value zero.
    if (expected.protocol == 17 && result == 0) {
        result = 0xffff;
    }
    store(packet, checksumOffset, result);
    return true;
}
} // namespace skewer::traffic
