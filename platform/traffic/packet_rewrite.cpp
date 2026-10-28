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

bool clampIpv4TcpMss(std::span<std::uint8_t> packet, std::uint16_t maximum) {
    const auto parsed = parsePacketTuple(packet);
    if (!maximum || !parsed.tuple || parsed.tuple->ipv6) {
        return false;
    }
    if (parsed.tuple->protocol != 6 || !(packet[33] & 2)) {
        return true;
    }
    const std::size_t end = 20 + (packet[32] >> 4) * 4;
    std::optional<std::size_t> mss;
    for (std::size_t i = 40; i < end;) {
        const auto kind = packet[i];
        if (!kind) {
            break;
        }
        if (kind == 1) {
            ++i;
            continue;
        }
        if (i + 1 >= end || packet[i + 1] < 2 || i + packet[i + 1] > end) {
            return false;
        }
        if (kind == 2) {
            if (packet[i + 1] != 4 || mss || (packet[i + 2] == 0 && packet[i + 3] == 0)) {
                return false;
            }
            mss = i + 2;
        }
        i += packet[i + 1];
    }
    if (!mss || ((unsigned(packet[*mss]) << 8) | packet[*mss + 1]) <= maximum) {
        return true;
    }
    if (!parsed.tuple->source_port || !parsed.tuple->source[0] || parsed.tuple->source[0] >= 224) {
        return false;
    }
    store(packet, *mss, maximum);
    std::array<std::uint8_t, 4> source;
    std::copy_n(parsed.tuple->source.begin(), 4, source.begin());
    return rewriteIpv4Endpoint(packet, *parsed.tuple, RewriteSide::Source,
                               {source, parsed.tuple->source_port});
}

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
