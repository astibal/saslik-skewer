#include "packet_tuple.hpp"
#include <algorithm>
#include <utility>

namespace skewer::traffic {
namespace {
std::uint16_t word(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(bytes[offset]) << 8) | bytes[offset + 1]);
}
TupleResult failure(TupleStatus status) { return {status, std::nullopt}; }

TupleResult transport(PacketTuple tuple, std::span<const std::uint8_t> bytes) {
    if (tuple.protocol == 6) {
        if (bytes.size() < 20) {
            return failure(TupleStatus::Malformed);
        }
        const std::size_t header = (bytes[12] >> 4) * 4;
        if (header < 20 || header > bytes.size()) {
            return failure(TupleStatus::Malformed);
        }
    } else if (tuple.protocol == 17) {
        if (bytes.size() < 8 || word(bytes, 4) != bytes.size()) {
            return failure(TupleStatus::Malformed);
        }
    } else {
        return failure(TupleStatus::Unsupported);
    }
    tuple.source_port = word(bytes, 0);
    tuple.destination_port = word(bytes, 2);
    return {TupleStatus::Parsed, tuple};
}

TupleResult ipv4(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 20) {
        return failure(TupleStatus::Malformed);
    }
    const std::size_t header = (bytes[0] & 15) * 4;
    if (header < 20 || header > bytes.size() || word(bytes, 2) != bytes.size()) {
        return failure(TupleStatus::Malformed);
    }
    const auto fragment = word(bytes, 6);
    if (fragment & 0x8000) {
        return failure(TupleStatus::Malformed);
    }
    if (fragment & 0x3fff) {
        return failure(TupleStatus::Fragmented);
    }
    // Source-routing options change endpoint semantics. Reject all options
    // until their semantics are implemented, rather than misattribute packets.
    if (header != 20) {
        return failure(TupleStatus::Unsupported);
    }
    PacketTuple tuple;
    tuple.protocol = bytes[9];
    std::copy_n(bytes.begin() + 12, 4, tuple.source.begin());
    std::copy_n(bytes.begin() + 16, 4, tuple.destination.begin());
    return transport(tuple, bytes.subspan(header));
}

TupleResult ipv6(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 40 || word(bytes, 4) + std::size_t{40} != bytes.size()) {
        return failure(TupleStatus::Malformed);
    }
    PacketTuple tuple;
    tuple.ipv6 = true;
    std::copy_n(bytes.begin() + 8, 16, tuple.source.begin());
    std::copy_n(bytes.begin() + 24, 16, tuple.destination.begin());
    auto next = bytes[6];
    std::size_t offset = 40;
    unsigned extensions = 0;
    while (next == 0 || next == 60) {
        if (++extensions > 8) {
            return failure(TupleStatus::ExtensionLimit);
        }
        if ((next == 0 && offset != 40) || bytes.size() - offset < 8) {
            return failure(TupleStatus::Malformed);
        }
        const std::size_t length = (static_cast<std::size_t>(bytes[offset + 1]) + 1) * 8;
        if (length > bytes.size() - offset) {
            return failure(TupleStatus::Malformed);
        }
        // Only padding is understood. Home Address and Jumbo Payload options
        // must not silently change the interpreted endpoints or packet length.
        for (std::size_t option = offset + 2; option < offset + length;) {
            const auto type = bytes[option++];
            if (type == 0) {
                continue; // Pad1.
            }
            if (option >= offset + length) {
                return failure(TupleStatus::Malformed);
            }
            const auto count = bytes[option++];
            if (count > offset + length - option) {
                return failure(TupleStatus::Malformed);
            }
            if (type != 1) {
                return failure(TupleStatus::Unsupported);
            }
            option += count; // PadN.
        }
        next = bytes[offset];
        offset += length;
    }
    if (next == 44) {
        // Also reject atomic fragments; there is no fragment reassembly here.
        return failure(TupleStatus::Fragmented);
    }
    tuple.protocol = next;
    // Routing headers, AH/ESP and other protocols stay explicitly unsupported.
    return transport(tuple, bytes.subspan(offset));
}
} // namespace

PacketTuple PacketTuple::reversed() const {
    auto tuple = *this;
    std::swap(tuple.source, tuple.destination);
    std::swap(tuple.source_port, tuple.destination_port);
    return tuple;
}
TupleResult parsePacketTuple(std::span<const std::uint8_t> packet) {
    if (packet.empty()) {
        return failure(TupleStatus::Malformed);
    }
    switch (packet[0] >> 4) {
    case 4:
        return ipv4(packet);
    case 6:
        return ipv6(packet);
    default:
        return failure(TupleStatus::Unsupported);
    }
}
} // namespace skewer::traffic
