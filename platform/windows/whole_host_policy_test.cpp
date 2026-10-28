#include "whole_host_policy.hpp"
#include <iostream>
#include <memory>
#include <system_error>

using namespace skewer::windows;
namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

NET_LUID loopbackLuid() {
    PMIB_IF_TABLE2 raw{};
    const auto status = GetIfTable2(&raw);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Read interface table");
    }
    std::unique_ptr<MIB_IF_TABLE2, decltype(&FreeMibTable)> table(raw, FreeMibTable);
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (table->Table[i].Type == IF_TYPE_SOFTWARE_LOOPBACK) {
            return table->Table[i].InterfaceLuid;
        }
    }
    throw std::runtime_error("No Windows loopback interface found");
}

NET_IFINDEX underlayIndex() {
    SOCKADDR_INET destination{};
    destination.si_family = AF_INET;
    require(InetPtonA(AF_INET, "1.1.1.1", &destination.Ipv4.sin_addr) == 1,
            "Cannot parse policy peer");
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    const auto status = GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Find policy underlay");
    }
    return route.InterfaceIndex;
}
} // namespace

int main() {
    try {
        const auto tunnel = loopbackLuid();
        const auto underlay = underlayIndex();
        WholeHostPolicy policy("1.1.1.1", 8766, "192.0.2.1");
        const auto filter = policy.filter(tunnel);
        require(filter.find("ifIdx == " + std::to_string(underlay) +
                            " and udp.SrcPort == 68 and udp.DstPort == 67") != std::string::npos,
                "Whole-host guard does not preserve bounded DHCPv4 renewal");
        require(filter.find("tcp.SrcPort == 22") != std::string::npos,
                "Whole-host guard lost explicit SSH return-path policy");
        require(filter.starts_with("outbound and !loopback") &&
                    filter.find("and (ip and (") != std::string::npos &&
                    filter.ends_with(") ? false : true)"),
                "Whole-host guard lost its deny-by-default physical egress policy");
        Tuntom::Endpoint endpoint;
        endpoint.serverAddress = "10.0.0.1/30";
        const auto routes = policy.routes(tunnel, endpoint);
        require(routes.size() == 3 && routes[0].DestinationPrefix.PrefixLength == 32 &&
                    routes[1].DestinationPrefix.PrefixLength == 1 &&
                    routes[2].DestinationPrefix.PrefixLength == 1,
                "Whole-host route plan lost peer pin or covering routes");
        std::cout << "PASS: peer pin, covering routes, DHCP renewal and bounded management policy\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
