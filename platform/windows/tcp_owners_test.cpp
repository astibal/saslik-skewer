#include <winsock2.h>
#include "tcp_owners.hpp"
#include "processes.hpp"
#include <iphlpapi.h>
#include <iostream>
#include <stdexcept>

using namespace skewer::windows::traffic;
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
int main() {
    try {
        require(!excludesSelectedTcpOwner({}, 42), "Unknown owner bypassed");
        const std::vector<std::uint32_t> selected{42}, mixed{99, 42}, unknown{99, 0}, other{99};
        require(!excludesSelectedTcpOwner(selected, 42) && !excludesSelectedTcpOwner(mixed, 42) &&
                    !excludesSelectedTcpOwner(unknown, 42) && !excludesSelectedTcpOwner(other, 0) &&
                    excludesSelectedTcpOwner(other, 42),
                "Incorrect unselected candidate decision");
        for (bool ipv6 : {false, true}) {
            skewer::traffic::PacketTuple tuple;
            tuple.protocol = 6;
            tuple.ipv6 = ipv6;
            tuple.source[0] = 1;
            tuple.destination[0] = 2;
            tuple.source_port = 1234;
            tuple.destination_port = 443;
            std::vector<TcpOwnerRow> rows{{tuple, 42}, {tuple, 99}, {tuple, 42}, {tuple.reversed(), 7}};
            require(tcpOwnerCandidates(rows, tuple) == std::vector<std::uint32_t>({42, 99}),
                    "Competing owner disappeared or duplicate survived");
            require(tcpOwnerCandidates(rows, tuple.reversed()) == std::vector<std::uint32_t>({7}),
                    "Reverse tuple was treated as outbound");
            rows.push_back({tuple, 0});
            require(tcpOwnerCandidates(rows, tuple) == std::vector<std::uint32_t>({0, 42, 99}),
                    "Unavailable TCP owner was silently discarded");
            tuple.destination_port++;
            require(tcpOwnerCandidates(rows, tuple).empty(), "Different port matched");
            tuple.protocol = 17;
            bool rejected{};
            try {
                tcpOwnerCandidates(rows, tuple);
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            require(rejected, "UDP was silently resolved through TCP tables");
        }
        skewer::traffic::PacketTuple connected;
        connected.protocol = IPPROTO_TCP;
        connected.source_port = 12345;
        connected.destination_port = 443;
        const std::vector<skewer::windows::ProcessKey> processes{{42, 1000}};
        std::vector<TcpOwnerRow> cleanup_rows{
            {connected, 42, MIB_TCP_STATE_ESTAB},
            {connected, 99, MIB_TCP_STATE_ESTAB},
            {connected, 42, MIB_TCP_STATE_LISTEN},
        };
        auto ipv6 = connected;
        ipv6.ipv6 = true;
        cleanup_rows.push_back({ipv6, 42, MIB_TCP_STATE_ESTAB});
        auto incomplete = connected;
        incomplete.destination_port = 0;
        cleanup_rows.push_back({incomplete, 42, MIB_TCP_STATE_SYN_SENT});
        const auto cleanup = ownedIpv4TcpRows(cleanup_rows, processes);
        require(cleanup.size() == 1 && cleanup.front().pid == 42 &&
                    cleanup.front().state == MIB_TCP_STATE_ESTAB,
                "TCP cleanup selected an unsupported or foreign endpoint");
        const auto snapshot = captureTcpOwners();
        require(snapshot.completed >= snapshot.started, "Snapshot timing invalid");
        std::cout << "PASS: TCP owner snapshot and collision matching, rows=" << snapshot.rows.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
