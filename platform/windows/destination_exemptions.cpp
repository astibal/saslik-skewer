#include "destination_exemptions.hpp"

#include <stdexcept>

namespace skewer::windows {
namespace {

std::uint32_t hostAddress(IN_ADDR address) {
    return ntohl(address.S_un.S_addr);
}

std::string addressText(IN_ADDR address) {
    char buffer[INET_ADDRSTRLEN]{};
    if (!InetNtopA(AF_INET, &address, buffer, sizeof(buffer))) {
        throw std::runtime_error("Cannot encode exemption underlay gateway");
    }
    return buffer;
}

bool routeCovers(const MIB_IPFORWARD_ROW2& route, skewer::traffic::Ipv4Prefix prefix) {
    if (route.DestinationPrefix.Prefix.si_family != AF_INET ||
        route.DestinationPrefix.PrefixLength <= 1 ||
        route.DestinationPrefix.PrefixLength > prefix.length) {
        return false;
    }
    skewer::traffic::Ipv4Prefix existing{hostAddress(route.DestinationPrefix.Prefix.Ipv4.sin_addr),
                                         route.DestinationPrefix.PrefixLength};
    return existing.contains(prefix.network);
}

} // namespace

std::string destinationExemptionFilter(std::span<const skewer::traffic::Ipv4Prefix> exemptions) {
    std::string result;
    for (const auto prefix : exemptions) {
        if (!result.empty()) result += " or ";
        result += "ip.DstAddr == " + prefix.text();
    }
    return result;
}

std::vector<MIB_IPFORWARD_ROW2> destinationExemptionRoutes(
    std::span<const skewer::traffic::Ipv4Prefix> exemptions,
    std::span<const MIB_IPFORWARD_ROW2> underlays) {
    if (exemptions.size() != underlays.size()) {
        throw std::invalid_argument("Exemption route inputs differ in size");
    }
    std::vector<MIB_IPFORWARD_ROW2> result;
    for (std::size_t index = 0; index < exemptions.size(); ++index) {
        const auto prefix = exemptions[index];
        if (prefix.length <= 1 || routeCovers(underlays[index], prefix)) continue;
        const auto& underlay = underlays[index];
        if (!underlay.InterfaceLuid.Value || underlay.NextHop.si_family != AF_INET) {
            throw std::invalid_argument("Invalid destination exemption underlay route");
        }
        result.push_back(ipv4Route(underlay.InterfaceLuid, prefix.addressText(), prefix.length,
                                   addressText(underlay.NextHop.Ipv4.sin_addr), 1));
    }
    return result;
}

bool exemptionCoversHalf(std::span<const skewer::traffic::Ipv4Prefix> exemptions, unsigned half) {
    if (half > 1) throw std::invalid_argument("Invalid IPv4 route half");
    const std::uint32_t address = half ? 0x80000000U : 0;
    for (const auto prefix : exemptions) {
        if (prefix.length <= 1 && prefix.contains(address)) return true;
    }
    return false;
}

} // namespace skewer::windows
