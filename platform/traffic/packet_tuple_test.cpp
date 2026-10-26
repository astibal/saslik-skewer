#include "packet_tuple.hpp"
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

using namespace skewer::traffic;
namespace {
using Bytes = std::vector<std::uint8_t>;
void require(bool ok, const char *message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
void put(Bytes &bytes, std::size_t offset, std::size_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8);
    bytes[offset + 1] = static_cast<std::uint8_t>(value);
}
void length(Bytes &bytes, bool v6) { put(bytes, v6 ? 4 : 2, bytes.size() - (v6 ? 40 : 0)); }
Bytes packet(bool v6, bool tcp) {
    const std::size_t ip = v6 ? 40 : 20;
    Bytes bytes(ip + (tcp ? 20 : 8), 0);
    bytes[0] = v6 ? 0x60 : 0x45;
    bytes[v6 ? 6 : 9] = tcp ? 6 : 17;
    bytes[v6 ? 8 : 12] = 10;
    bytes[v6 ? 24 : 16] = 20;
    length(bytes, v6);
    put(bytes, ip, 12345);
    put(bytes, ip + 2, 443);
    if (tcp) {
        bytes[ip + 12] = 0x50;
    } else {
        put(bytes, ip + 4, 8);
    }
    return bytes;
}
void expect(const Bytes &bytes, TupleStatus expected) {
    const auto result = parsePacketTuple(bytes);
    require(result.status == expected, "Unexpected parse status");
    require(result.tuple.has_value() == (expected == TupleStatus::Parsed), "Invalid result invariant");
}
void validAndTruncated() {
    for (const bool v6 : {false, true}) {
        for (const bool tcp : {false, true}) {
            auto bytes = packet(v6, tcp);
            const auto result = parsePacketTuple(bytes);
            require(result.tuple.has_value(), "Valid packet rejected");
            const auto &tuple = *result.tuple;
            require(tuple.ipv6 == v6 && tuple.protocol == (tcp ? 6 : 17), "Wrong protocol");
            require(tuple.source[0] == 10 && tuple.destination[0] == 20, "Wrong IP bytes");
            require(tuple.source_port == 12345 && tuple.destination_port == 443, "Wrong port order");
            require(tuple.reversed().source == tuple.destination && tuple.reversed().source_port == 443 &&
                        tuple.reversed().reversed() == tuple,
                    "Reverse tuple corrupted identity");
            for (std::size_t size = 0; size < bytes.size(); ++size) {
                require(!parsePacketTuple(std::span(bytes).first(size)).tuple, "Truncated packet accepted");
            }
            bytes.push_back(0);
            expect(bytes, TupleStatus::Malformed); // No capture padding accepted.
            length(bytes, v6);
            if (!tcp) {
                expect(bytes, TupleStatus::Malformed); // UDP length must agree too.
                put(bytes, (v6 ? 40 : 20) + 4, 9);
            }
            expect(bytes, TupleStatus::Parsed);
            if (tcp) {
                bytes[(v6 ? 40 : 20) + 12] = 0x40;
                expect(bytes, TupleStatus::Malformed);
                bytes[(v6 ? 40 : 20) + 12] = 0xf0;
                expect(bytes, TupleStatus::Malformed);
            }
        }
    }
}
void fragmentsAndOptions() {
    auto bytes = packet(false, false);
    bytes[6] = 0x40; // DF alone is not fragmentation.
    expect(bytes, TupleStatus::Parsed);
    bytes[6] = 0x20;
    expect(bytes, TupleStatus::Fragmented);
    bytes[6] = 0;
    bytes[7] = 1;
    expect(bytes, TupleStatus::Fragmented);
    bytes[6] = 0x80;
    expect(bytes, TupleStatus::Malformed);
    bytes = packet(false, false);
    bytes[0] = 0x44;
    expect(bytes, TupleStatus::Malformed);
    bytes[0] = 0x4f;
    expect(bytes, TupleStatus::Malformed);
    bytes = packet(false, false);
    bytes.insert(bytes.begin() + 20, 4, 0);
    bytes[0] = 0x46;
    length(bytes, false);
    expect(bytes, TupleStatus::Unsupported);

    bytes = packet(true, false);
    for (const auto protocol : {44, 43, 50, 51, 58, 59}) {
        bytes[6] = static_cast<std::uint8_t>(protocol);
        expect(bytes, protocol == 44 ? TupleStatus::Fragmented : TupleStatus::Unsupported);
    }
    bytes[6] = 0; // Hop-by-hop, followed by UDP, all Pad1 options.
    bytes.insert(bytes.begin() + 40, 8, 0);
    bytes[40] = 17;
    length(bytes, true);
    expect(bytes, TupleStatus::Parsed);
    bytes[42] = 1;
    bytes[43] = 4; // PadN.
    expect(bytes, TupleStatus::Parsed);
    bytes[43] = 5;
    expect(bytes, TupleStatus::Malformed);
    bytes[43] = 4;
    bytes[42] = 201; // Home Address option is not padding.
    expect(bytes, TupleStatus::Unsupported);
    bytes[42] = 0;
    bytes[43] = 0;
    bytes[41] = 255;
    expect(bytes, TupleStatus::Malformed);
    bytes[41] = 0;
    bytes[40] = 0; // Another hop-by-hop header is not allowed here.
    expect(bytes, TupleStatus::Malformed);
    bytes = packet(true, true);
    bytes[6] = 60;
    bytes.insert(bytes.begin() + 40, 9 * 8, 0);
    for (unsigned i = 0; i < 9; ++i) {
        bytes[40 + i * 8] = i == 8 ? 6 : 60;
    }
    length(bytes, true);
    expect(bytes, TupleStatus::ExtensionLimit);
}
void hostileBuffers() {
    // Deterministic malformed corpus, useful under ASan/UBSan on Linux too.
    std::mt19937 random(0x534b4557);
    for (unsigned i = 0; i < 30000; ++i) {
        Bytes bytes(random() % 256);
        for (auto &byte : bytes) {
            byte = static_cast<std::uint8_t>(random());
        }
        if (!bytes.empty() && i % 2 == 0) {
            const bool v6 = i % 4 == 0;
            bytes[0] = v6 ? 0x60 : 0x45;
            if (bytes.size() >= (v6 ? 40u : 20u)) {
                length(bytes, v6);
            }
        }
        const auto result = parsePacketTuple(bytes);
        require(result.tuple.has_value() == (result.status == TupleStatus::Parsed), "Corpus invariant");
    }
}
} // namespace
int main() {
    try {
        validAndTruncated();
        fragmentsAndOptions();
        hostileBuffers();
        std::cout
            << "PASS: IPv4/IPv6 TCP/UDP tuples, truncation, fragments, extension bounds and hostile corpus\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
