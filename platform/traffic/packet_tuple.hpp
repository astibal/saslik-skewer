#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace skewer::traffic {
struct PacketTuple {
    bool ipv6{};
    std::uint8_t protocol{};
    // Network-order bytes; IPv4 uses the first four bytes, then zeroes.
    std::array<std::uint8_t, 16> source{}, destination{};
    std::uint16_t source_port{}, destination_port{}; // Host byte order.
    bool operator==(const PacketTuple &) const = default;
    PacketTuple reversed() const;
};
enum class TupleStatus { Parsed, Malformed, Fragmented, Unsupported, ExtensionLimit };
struct TupleResult {
    TupleStatus status;
    std::optional<PacketTuple> tuple; // Present only when Parsed.
};
// One complete L3 packet, not Ethernet. No allocation, struct casts, checksum
// validation or reassembly. Outbound checksums may await hardware offload.
// A tuple is not proof of process ownership and must not authorize egress.
TupleResult parsePacketTuple(std::span<const std::uint8_t> packet);
} // namespace skewer::traffic
