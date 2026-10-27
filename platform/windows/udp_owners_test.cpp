#include "udp_owners.hpp"
#include <iostream>
#include <stdexcept>

using namespace skewer::windows::traffic;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
void check(bool ipv6) {
    skewer::traffic::PacketTuple packet;
    packet.protocol = 17;
    packet.ipv6 = ipv6;
    packet.source[0] = 1;
    packet.source_port = 1234;
    packet.destination_port = 53;
    UdpOwnerRow exact{ipv6, packet.source, 1234, 42};
    UdpOwnerRow wildcard{ipv6, {}, 1234, 99};
    UdpOwnerRow unknown{ipv6, {}, 1234, 0};
    auto other = exact;
    other.local_address[0] = 2;
    other.pid = 123;
    std::vector<UdpOwnerRow> rows{exact, wildcard, exact, unknown, other};
    auto match = udpOwnerCandidates(rows, packet);
    require(match.pids == std::vector<std::uint32_t>({42, 99}) && match.unknown_owner,
            "Wildcard, competing or unavailable owner lost");
    packet.destination_port = 443;
    packet.destination[0] = 9;
    require(udpOwnerCandidates(rows, packet).pids == match.pids, "Remote peer narrowed bind candidates");
    packet.source_port++;
    match = udpOwnerCandidates(rows, packet);
    require(match.pids.empty() && !match.unknown_owner, "Different port matched");
    packet.source_port--;
    rows = {{true, {}, 1234, 77}};
    require(udpOwnerCandidates(rows, packet).pids == std::vector<std::uint32_t>({77}),
            "Potential dual-stack wildcard lost");
    if (!ipv6) {
        rows[0].local_address[10] = rows[0].local_address[11] = 0xff;
        rows[0].local_address[12] = packet.source[0];
        require(!udpOwnerCandidates(rows, packet).pids.empty(), "Mapped bind lost");
        rows[0].local_address[12]++;
        require(udpOwnerCandidates(rows, packet).pids.empty(), "Different mapped bind matched");
    } else {
        rows = {{false, {}, 1234, 88}};
        require(udpOwnerCandidates(rows, packet).pids.empty(), "IPv4 wildcard matched native IPv6");
    }
    rows = {{ipv6, {}, 1234, 0}};
    match = udpOwnerCandidates(rows, packet);
    require(match.pids.empty() && match.unknown_owner, "Unknown owner became an empty safe result");
    packet.protocol = 6;
    bool rejected = false;
    try {
        udpOwnerCandidates(rows, packet);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "TCP accepted as UDP");
    packet.protocol = 17;
    packet.source_port = 0;
    rejected = false;
    try {
        udpOwnerCandidates(rows, packet);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "Unidentifiable UDP source port accepted");
}
} // namespace
int main() {
    try {
        check(false);
        check(true);
        std::cout << "PASS: conservative UDP bind candidates\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
