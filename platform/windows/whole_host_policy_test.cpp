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

} // namespace

int main() {
    try {
        const auto tunnel = loopbackLuid();
        WholeHostPolicy policy("1.1.1.1", 8766, "192.0.2.1");
        const auto filter = policy.filter(tunnel);
        require(filter.find("udp.SrcPort == 68 and udp.DstPort == 67") != std::string::npos &&
                    filter.find("ifIdx == ") == std::string::npos,
                "Whole-host guard cannot preserve DHCPv4 across underlay failover");
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

        MIB_IPFORWARD_ROW2 replacement{};
        replacement.InterfaceLuid = tunnel;
        replacement.NextHop.si_family = AF_INET;
        require(InetPtonA(AF_INET, "192.0.2.1", &replacement.NextHop.Ipv4.sin_addr) == 1,
                "Cannot parse replacement gateway");
        const auto plan_tunnel = routes.front().InterfaceLuid;
        const auto replaced = wholeHostRoutePlan("1.1.1.1", replacement, plan_tunnel, endpoint);
        require(replaced.front().InterfaceLuid.Value == replacement.InterfaceLuid.Value &&
                    replaced.front().InterfaceLuid.Value != routes.front().InterfaceLuid.Value,
                "Whole-host route plan retained the original underlay interface");
        bool recursive_rejected{};
        replacement.InterfaceLuid = plan_tunnel;
        try {
            (void)wholeHostRoutePlan("1.1.1.1", replacement, plan_tunnel, endpoint);
        } catch (const std::invalid_argument&) {
            recursive_rejected = true;
        }
        require(recursive_rejected, "Whole-host route plan accepted the tunnel as its underlay");
        std::cout << "PASS: peer pin, underlay failover, DHCP renewal and bounded management policy\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
