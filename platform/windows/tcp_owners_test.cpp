#include "tcp_owners.hpp"
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
        const auto snapshot = captureTcpOwners();
        require(snapshot.completed >= snapshot.started, "Snapshot timing invalid");
        std::cout << "PASS: TCP owner snapshot and collision matching, rows=" << snapshot.rows.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
