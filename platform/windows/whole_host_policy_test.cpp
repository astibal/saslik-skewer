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
        skewer::traffic::Ipv4Prefix private_network;
        require(skewer::traffic::parseIpv4Prefix("192.168.0.0/16", private_network),
                "Cannot parse test exemption");
        WholeHostPolicy policy("1.1.1.1", 8766, "192.0.2.1", {private_network});
        const auto filter = policy.filter(tunnel);
        require(filter.find("udp.SrcPort == 68 and udp.DstPort == 67") != std::string::npos &&
                    filter.find("ifIdx == ") == std::string::npos,
                "Whole-host guard cannot preserve DHCPv4 across underlay failover");
        require(filter.find("tcp.SrcPort == 22") != std::string::npos,
                "Whole-host guard lost explicit SSH return-path policy");
        require(filter.find("ip.DstAddr == 192.168.0.0/16") != std::string::npos,
                "Whole-host guard lost destination exemption");
        require(filter.starts_with("outbound and !loopback") &&
                    filter.find("and (ip and (") != std::string::npos &&
                    filter.ends_with(") ? false : true)"),
                "Whole-host guard lost its deny-by-default physical egress policy");
        Tuntom::Endpoint endpoint;
        endpoint.serverAddress = "10.0.0.1/30";
        const auto routes = policy.routes(tunnel, endpoint);
        require(routes.size() == 4 && routes[0].DestinationPrefix.PrefixLength == 32 &&
                    routes[1].DestinationPrefix.PrefixLength == 16 &&
                    routes[2].DestinationPrefix.PrefixLength == 1 &&
                    routes[3].DestinationPrefix.PrefixLength == 1,
                "Whole-host route plan lost peer pin, exemption or covering routes");

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
        MIB_IPFORWARD_ROW2 bypass_underlay = replacement;
        bypass_underlay.InterfaceLuid = routes.front().InterfaceLuid;
        bypass_underlay.DestinationPrefix.Prefix.si_family = AF_INET;
        bypass_underlay.DestinationPrefix.PrefixLength = 0;
        skewer::traffic::Ipv4Prefix lower_half, all;
        require(skewer::traffic::parseIpv4Prefix("0.0.0.0/1", lower_half) &&
                    skewer::traffic::parseIpv4Prefix("0.0.0.0/0", all),
                "Cannot parse covering exemptions");
        const auto half = wholeHostRoutePlan("1.1.1.1", routes.front(), tunnel, endpoint,
                                             std::span(&lower_half, 1),
                                             std::span(&bypass_underlay, 1));
        require(half.size() == 2 && half.back().DestinationPrefix.PrefixLength == 1 &&
                    ntohl(half.back().DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr) == 0x80000000U,
                "A /1 exemption did not suppress its tunnel half");
        const auto open = wholeHostRoutePlan("1.1.1.1", routes.front(), tunnel, endpoint,
                                             std::span(&all, 1), std::span(&bypass_underlay, 1));
        require(open.size() == 1 && open.front().DestinationPrefix.PrefixLength == 32,
                "A /0 exemption did not suppress both tunnel halves while retaining the peer pin");
        std::cout << "PASS: peer pin, underlay failover, exemptions, DHCP and management policy\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
