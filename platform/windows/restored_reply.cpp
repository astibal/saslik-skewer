#include "packet_capture.hpp"
#include "../traffic/packet_tuple.hpp"
#include <stdexcept>

namespace skewer::windows::traffic {
PacketCapture::Packet restoredReply(const PacketCapture::Packet& original,
                                    std::vector<std::uint8_t> restored) {
    const auto sent = skewer::traffic::parsePacketTuple(original.bytes);
    const auto reply = skewer::traffic::parsePacketTuple(restored);
    const auto& metadata = original.address;
    if (!sent.tuple || sent.tuple->ipv6 || !reply.tuple || *reply.tuple != sent.tuple->reversed() ||
        metadata.Layer != WINDIVERT_LAYER_NETWORK || !metadata.Outbound || metadata.IPv6 ||
        (!metadata.Loopback && !metadata.Network.IfIdx)) {
        throw std::invalid_argument("Restored reply does not match retained IPv4 capture");
    }
    auto incoming = metadata;
    // Windows represents both directions of loopback traffic as outbound.
    incoming.Outbound = incoming.Loopback;
    incoming.Sniffed = false;
    incoming.Impostor = false;
    return {std::move(restored), incoming};
}
} // namespace skewer::windows::traffic
