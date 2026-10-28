#include "whole_host_policy.hpp"
#include <system_error>

namespace skewer::windows {
namespace {
SOCKADDR_INET numeric(const std::string& text) {
    SOCKADDR_INET address{};
    address.si_family = AF_INET;
    if (text.find('\0') != std::string::npos ||
        InetPtonA(AF_INET, text.c_str(), &address.Ipv4.sin_addr) != 1) {
        throw std::invalid_argument("Expected a numeric IPv4 endpoint");
    }
    const auto ip = ntohl(address.Ipv4.sin_addr.S_un.S_addr);
    if (!ip || (ip >> 24) == 127 || (ip >> 24) >= 224) {
        throw std::invalid_argument("Expected a unicast non-loopback endpoint");
    }
    return address;
}
std::string text(IN_ADDR address) {
    char buffer[INET_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET, &address, buffer, sizeof(buffer))) {
        throw std::runtime_error("Cannot encode IPv4 route address");
    }
    return buffer;
}
MIB_IPFORWARD_ROW2 bestRoute(const std::string& peer) {
    const auto destination = numeric(peer);
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    const auto status = GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Find tunnel underlay route");
    }
    return route;
}
void requireNoConflicts(const std::string& peer) {
    PMIB_IPFORWARD_TABLE2 raw{};
    const auto status = GetIpForwardTable2(AF_INET, &raw);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Inspect existing IPv4 routes");
    }
    std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> table(raw, FreeMibTable);
    const auto peer_ip = numeric(peer).Ipv4.sin_addr.S_un.S_addr;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& prefix = table->Table[i].DestinationPrefix;
        if (prefix.PrefixLength == 1 ||
            (prefix.PrefixLength == 32 && prefix.Prefix.Ipv4.sin_addr.S_un.S_addr == peer_ip)) {
            throw std::runtime_error("Whole-host route plan conflicts with an existing route");
        }
    }
}
} // namespace

WholeHostPolicy::WholeHostPolicy(std::string peer, unsigned port, std::string management)
    : peer_(text(numeric(peer).Ipv4.sin_addr)), control_port_(port),
      management_(management.empty() ? "" : text(numeric(management).Ipv4.sin_addr)) {
    if (!port || port > 65535) {
        throw std::invalid_argument("Invalid tunnel control port");
    }
    requireNoConflicts(peer_);
    underlay_ = bestRoute(peer_);
}

std::string WholeHostPolicy::filter(NET_LUID tunnel) const {
    NET_IFINDEX index{};
    if (!tunnel.Value || tunnel.Value == underlay_.InterfaceLuid.Value ||
        ConvertInterfaceLuidToIndex(&tunnel, &index) != NO_ERROR) {
        throw std::invalid_argument("Invalid tunnel guard interface");
    }
    // UDP ports are bounded by the authenticated protocol's endpoint ID range.
    // These are tuple exemptions, not process isolation. IPv6 physical egress
    // is blocked until a separate IPv6 tunnel policy is implemented.
    auto allowed = "(ip.DstAddr == " + peer_ +
                   " and ((udp.DstPort >= 40001 and udp.DstPort <= 40255)"
                   " or tcp.DstPort == " +
                   std::to_string(control_port_) + "))";
    if (!management_.empty()) {
        allowed += " or (ip.DstAddr == " + management_ + " and tcp.SrcPort == 22)";
    }
    return "outbound and !loopback and ifIdx != " + std::to_string(index) + " and (ip and (" + allowed +
           ") ? false : true)";
}

std::vector<MIB_IPFORWARD_ROW2> WholeHostPolicy::routes(NET_LUID tunnel,
                                                        const Tuntom::Endpoint& endpoint) const {
    const auto current = bestRoute(peer_);
    if (current.InterfaceLuid.Value != underlay_.InterfaceLuid.Value ||
        current.NextHop.Ipv4.sin_addr.S_un.S_addr != underlay_.NextHop.Ipv4.sin_addr.S_un.S_addr) {
        throw std::runtime_error("Tunnel underlay changed during startup");
    }
    requireNoConflicts(peer_);
    if (!endpoint.serverAddress.endsWith("/30")) {
        throw std::invalid_argument("Invalid authenticated tunnel gateway");
    }
    const auto gateway = endpoint.serverAddress.chopped(3).toStdString();
    (void)numeric(gateway);
    return {ipv4Route(underlay_.InterfaceLuid, peer_, 32, text(underlay_.NextHop.Ipv4.sin_addr), 1),
            ipv4Route(tunnel, "0.0.0.0", 1, gateway, 1), ipv4Route(tunnel, "128.0.0.0", 1, gateway, 1)};
}
} // namespace skewer::windows
