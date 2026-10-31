#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif
#include "udp_owners.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace skewer::windows::traffic;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
#ifdef _WIN32
void checkLiveWildcard(bool ipv6) {
    struct Socket {
        SOCKET value;
        ~Socket() {
            if (value != INVALID_SOCKET) {
                closesocket(value);
            }
        }
    } socket{::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    require(socket.value != INVALID_SOCKET, "Create wildcard UDP socket failed");
    const BOOL reuse = TRUE;
    require(setsockopt(socket.value, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&reuse), sizeof(reuse)) == 0,
            "Enable UDP bind sharing failed");
    sockaddr_storage address{};
    auto* v4 = reinterpret_cast<sockaddr_in*>(&address);
    auto* v6 = reinterpret_cast<sockaddr_in6*>(&address);
    int size = ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    address.ss_family = ipv6 ? AF_INET6 : AF_INET;
    require(bind(socket.value, reinterpret_cast<sockaddr*>(&address), size) == 0, "Wildcard bind failed");
    require(getsockname(socket.value, reinterpret_cast<sockaddr*>(&address), &size) == 0,
            "Get UDP port failed");
    skewer::traffic::PacketTuple packet;
    packet.protocol = 17;
    packet.ipv6 = ipv6;
    packet.source_port = ntohs(ipv6 ? v6->sin6_port : v4->sin_port);
    if (ipv6) {
        packet.source[15] = 1;
    } else {
        packet.source[0] = 127;
        packet.source[3] = 1;
    }
    const auto snapshot = captureUdpOwners();
    require(snapshot.completed >= snapshot.started, "UDP snapshot timing invalid");
    const auto candidates = udpOwnerCandidates(snapshot.rows, packet);
    require(std::find(candidates.pids.begin(), candidates.pids.end(), GetCurrentProcessId()) !=
                candidates.pids.end(),
            "Live wildcard owner missing");
    require(candidates.uniqueBind(), "Fresh live UDP bind is not unique");

    {
        // Sharing one port within one process must preserve two table rows,
        // even though the candidate PID list deliberately removes duplicates.
        Socket shared{::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
        require(shared.value != INVALID_SOCKET, "Create shared UDP socket failed");
        require(setsockopt(shared.value, SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&reuse), sizeof(reuse)) == 0,
                "Enable second UDP bind sharing failed");
        require(bind(shared.value, reinterpret_cast<sockaddr*>(&address), size) == 0,
                "Second live UDP bind failed");
        const auto shared_snapshot = captureUdpOwners();
        const auto owners = udpOwnerCandidates(shared_snapshot.rows, packet);
        require(owners.pids == std::vector<std::uint32_t>{GetCurrentProcessId()} &&
                    owners.matching_rows == 2 && !owners.uniqueBind(),
                "Live same-PID shared UDP bind was not recognized as ambiguous");
    }
    const auto released_snapshot = captureUdpOwners();
    require(udpOwnerCandidates(released_snapshot.rows, packet).uniqueBind(),
            "Closing competing UDP socket did not restore unique bind evidence");
}
#endif
void check(bool ipv6) {
    skewer::traffic::PacketTuple packet;
    packet.protocol = 17;
    packet.ipv6 = ipv6;
    packet.source[0] = 1;
    packet.source_port = 1234;
    packet.destination_port = 53;
    UdpOwnerRow exact{ipv6, packet.source, 1234, 42};
    require(udpOwnerCandidates(std::vector<UdpOwnerRow>{exact}, packet).uniqueBind(),
            "Unique known bind rejected");
    const auto shared = udpOwnerCandidates(std::vector<UdpOwnerRow>{exact, exact}, packet);
    require(shared.pids.size() == 1 && !shared.uniqueBind(),
            "Same-PID shared bind became unique after PID de-duplication");
    require(!UdpOwnerCandidates{}.uniqueBind(), "Missing snapshot became a unique bind");
    UdpOwnerRow wildcard{ipv6, {}, 1234, 99};
    UdpOwnerRow unknown{ipv6, {}, 1234, 0};
    auto other = exact;
    other.local_address[0] = 2;
    other.pid = 123;
    std::vector<UdpOwnerRow> rows{exact, wildcard, exact, unknown, other};
    auto match = udpOwnerCandidates(rows, packet);
    require(match.pids == std::vector<std::uint32_t>({42, 99}) && match.unknown_owner &&
                match.matching_rows == 4,
            "Wildcard, competing or unavailable owner lost");
    packet.destination_port = 443;
    packet.destination[0] = 9;
    require(udpOwnerCandidates(rows, packet).pids == match.pids, "Remote peer narrowed bind candidates");
    packet.source_port++;
    match = udpOwnerCandidates(rows, packet);
    require(match.pids.empty() && !match.unknown_owner && match.matching_rows == 0,
            "Different port matched");
    packet.source_port--;
    rows = {{true, {}, 1234, 77}};
    require(udpOwnerCandidates(rows, packet).pids == std::vector<std::uint32_t>({77}) &&
                udpOwnerCandidates(rows, packet).matching_rows == 1,
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
    require(match.pids.empty() && match.unknown_owner && match.matching_rows == 1,
            "Unknown owner became an empty safe result");
    require(!match.uniqueBind(), "Unknown owner authorized a unique bind");
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
#ifdef _WIN32
        WSADATA data{};
        require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup failed");
        struct WinsockCleanup {
            ~WinsockCleanup() { WSACleanup(); }
        } cleanup;
        checkLiveWildcard(false);
        checkLiveWildcard(true);
        std::cout << "PASS: live IPv4/IPv6 UDP wildcard, shared bind and close snapshots\n";
#endif
        std::cout << "PASS: conservative UDP bind candidates\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
