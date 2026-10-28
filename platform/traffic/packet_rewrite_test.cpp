#include "packet_rewrite.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace skewer::traffic;
namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
void word(std::vector<std::uint8_t>& bytes, unsigned offset, unsigned value) {
    bytes[offset] = value >> 8;
    bytes[offset + 1] = value;
}
std::vector<std::uint8_t> packet(bool tcp, unsigned payload) {
    const auto header = tcp ? 20u : 8u;
    std::vector<std::uint8_t> bytes(20 + header + payload, 0);
    bytes[0] = 0x45;
    word(bytes, 2, bytes.size());
    bytes[8] = 64;
    bytes[9] = tcp ? 6 : 17;
    bytes[12] = 192;
    bytes[13] = 168;
    bytes[14] = 199;
    bytes[15] = 131;
    bytes[16] = 1;
    bytes[17] = 1;
    bytes[18] = 1;
    bytes[19] = 1;
    word(bytes, 20, 50000);
    word(bytes, 22, 443);
    if (tcp) {
        bytes[32] = 0x50;
    } else {
        word(bytes, 24, header + payload);
    }
    for (unsigned i = 20 + header; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(i * 7);
    }
    return bytes;
}
// Independent byte-wise one's-complement verification, including odd payloads.
unsigned residue(std::span<const std::uint8_t> bytes, unsigned sum = 0) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        sum += unsigned(bytes[i]) << (i % 2 ? 0 : 8);
        sum = (sum & 65535) + (sum >> 16);
    }
    return (sum & 65535) + (sum >> 16);
}
void verify(const std::vector<std::uint8_t>& bytes) {
    auto span = std::span(bytes);
    require(residue(span.first(20)) == 65535, "Invalid IPv4 checksum");
    const auto pseudo = residue(span.subspan(12, 8)) + bytes[9] + bytes.size() - 20;
    require(residue(span.subspan(20), pseudo) == 65535, "Invalid transport checksum");
}
} // namespace
int main() {
    try {
        for (const bool tcp : {false, true}) {
            for (const unsigned length : {0u, 1u, 2u, 1279u, 60001u}) {
                auto bytes = packet(tcp, length);
                const auto original = *parsePacketTuple(bytes).tuple;
                const auto payload = std::vector(bytes.begin() + (tcp ? 40 : 28), bytes.end());
                require(rewriteIpv4Endpoint(bytes, original, RewriteSide::Source, {{10, 253, 0, 10}, 40001}),
                        "Source translation rejected");
                verify(bytes);
                auto translated = *parsePacketTuple(bytes).tuple;
                require(translated.source[0] == 10 && translated.source_port == 40001 &&
                            translated.destination == original.destination,
                        "Wrong translated tuple");
                require(std::vector(bytes.begin() + (tcp ? 40 : 28), bytes.end()) == payload,
                        "Payload changed");
                require(rewriteIpv4Endpoint(bytes, translated, RewriteSide::Source,
                                            {{192, 168, 199, 131}, 50000}),
                        "Round trip rejected");
                verify(bytes);
                require(*parsePacketTuple(bytes).tuple == original, "Round trip changed tuple");
                require(
                    rewriteIpv4Endpoint(bytes, original, RewriteSide::Destination, {{10, 253, 0, 10}, 40001}),
                    "Destination translation rejected");
                verify(bytes);
                const auto saved = bytes;
                require(!rewriteIpv4Endpoint(bytes, original, RewriteSide::Source, {{10, 0, 0, 1}, 1}) &&
                            bytes == saved,
                        "Mismatched flow mutated packet");
            }
        }
        auto bytes = packet(false, 0);
        const auto original = *parsePacketTuple(bytes).tuple;
        for (const auto replacement : {Ipv4Endpoint{{224, 0, 0, 1}, 1}, Ipv4Endpoint{{10, 0, 0, 1}, 0}}) {
            const auto saved = bytes;
            require(!rewriteIpv4Endpoint(bytes, original, RewriteSide::Source, replacement) && bytes == saved,
                    "Invalid endpoint mutated packet");
        }
        bytes[6] = 0x20;
        const auto fragmented = bytes;
        require(!rewriteIpv4Endpoint(bytes, original, RewriteSide::Source, {{10, 0, 0, 1}, 1}) &&
                    bytes == fragmented,
                "Fragment was translated");
        for (const unsigned size : {0u, 1u, 19u, 27u}) {
            auto shortPacket = packet(false, 0);
            shortPacket.resize(size);
            const auto saved = shortPacket;
            require(!rewriteIpv4Endpoint(shortPacket, original, RewriteSide::Source, {{10, 0, 0, 1}, 1}) &&
                        shortPacket == saved, "Truncated packet was mutated");
        }
        bool zeroEncoded = false;
        for (unsigned value = 0; value <= 65535; ++value) {
            auto udp = packet(false, 2);
            word(udp, 28, value);
            require(rewriteIpv4Endpoint(udp, *parsePacketTuple(udp).tuple, RewriteSide::Source,
                                        {{10, 0, 0, 1}, 1}), "UDP checksum search failed");
            if (udp[26] == 255 && udp[27] == 255) {
                verify(udp);
                zeroEncoded = true;
                break;
            }
        }
        require(zeroEncoded, "UDP zero checksum was not encoded as all ones");
        std::cout << "PASS: IPv4 endpoint translation and offload-safe checksums\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
