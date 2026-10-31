#include "owned_route.hpp"
#include <stdexcept>
#include <system_error>

namespace skewer::windows {
namespace {
IN_ADDR address(const std::string& text) {
    IN_ADDR result{};
    if (text.find('\0') != std::string::npos || InetPtonA(AF_INET, text.c_str(), &result) != 1) {
        throw std::invalid_argument("Expected numeric IPv4 address");
    }
    return result;
}
bool unchanged(const MIB_IPFORWARD_ROW2& current, const MIB_IPFORWARD_ROW2& expected) {
    // Age is volatile. GetIpForwardEntry2 already looks up the full route key.
    // Compare writable policy attributes before removing our original route.
    return current.InterfaceLuid.Value == expected.InterfaceLuid.Value &&
           current.InterfaceIndex == expected.InterfaceIndex && current.Metric == expected.Metric &&
           current.Protocol == expected.Protocol && current.SitePrefixLength == expected.SitePrefixLength &&
           current.ValidLifetime == expected.ValidLifetime &&
           current.PreferredLifetime == expected.PreferredLifetime && current.Loopback == expected.Loopback &&
           current.AutoconfigureAddress == expected.AutoconfigureAddress &&
           current.Publish == expected.Publish && current.Immortal == expected.Immortal;
}
} // namespace

MIB_IPFORWARD_ROW2 ipv4Route(NET_LUID luid, const std::string& network, unsigned prefix,
                             const std::string& next_hop, ULONG metric) {
    if (!luid.Value || prefix > 32) {
        throw std::invalid_argument("Invalid route interface or prefix length");
    }
    const auto destination = address(network);
    const auto mask = prefix ? 0xffffffffU << (32 - prefix) : 0U;
    if (ntohl(destination.S_un.S_addr) & ~mask) {
        throw std::invalid_argument("Route prefix has host bits set");
    }
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = luid;
    const auto status = ConvertInterfaceLuidToIndex(&luid, &row.InterfaceIndex);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Resolve route interface");
    }
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr = destination;
    row.DestinationPrefix.PrefixLength = static_cast<UINT8>(prefix);
    row.NextHop.si_family = AF_INET;
    row.NextHop.Ipv4.sin_addr = address(next_hop);
    row.Metric = metric;
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    // InitializeIpForwardEntry leaves these as unspecified (0xff). Select
    // explicit values so cleanup compares policy, not Windows' defaulting.
    row.SitePrefixLength = 0;
    row.Loopback = FALSE;
    row.AutoconfigureAddress = FALSE;
    row.Publish = FALSE;
    row.Immortal = FALSE;
    return row;
}

OwnedRoute::OwnedRoute(MIB_IPFORWARD_ROW2 route) : route_(route) {
    if (route_.DestinationPrefix.Prefix.si_family != AF_INET || route_.NextHop.si_family != AF_INET ||
        !route_.InterfaceLuid.Value || !route_.InterfaceIndex) {
        throw std::invalid_argument("Invalid owned IPv4 route");
    }
    // Create, never Set: an existing route is a conflict, not ours to overwrite.
    const auto status = CreateIpForwardEntry2(&route_);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), "Create owned route");
    }
    owned_ = true;
}

OwnedRoute::~OwnedRoute() {
    remove();
}

OwnedRoute::Removal OwnedRoute::remove() noexcept {
    if (!owned_) {
        return result_;
    }
    auto current = route_;
    const auto status = GetIpForwardEntry2(&current);
    if (status == ERROR_NOT_FOUND) {
        owned_ = false;
        return result_ = Removal::Missing;
    }
    if (status != NO_ERROR) {
        return result_ = Removal::Failed;
    }
    if (!unchanged(current, route_)) {
        owned_ = false;
        return result_ = Removal::Changed;
    }
    // IP Helper has no compare-and-delete transaction. This detects observed
    // changes, not a simultaneous admin rewrite or identical delete/recreate.
    const auto removed = DeleteIpForwardEntry2(&current);
    if (removed != NO_ERROR && removed != ERROR_NOT_FOUND) {
        return result_ = Removal::Failed;
    }
    owned_ = false;
    return result_ = removed == NO_ERROR ? Removal::Removed : Removal::Missing;
}
} // namespace skewer::windows
