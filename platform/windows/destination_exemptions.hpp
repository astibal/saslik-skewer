#pragma once

#include "ipv4_prefix.hpp"
#include "owned_route.hpp"
#include <span>

namespace skewer::windows {

// WinDivert predicate used inside a parenthesized IPv4 allow-list.
std::string destinationExemptionFilter(std::span<const skewer::traffic::Ipv4Prefix> exemptions);

// Add only routes that are not already covered by a more-specific underlay
// route. A /0 or /1 exemption suppresses the corresponding tunnel/direct /1.
std::vector<MIB_IPFORWARD_ROW2> destinationExemptionRoutes(
    std::span<const skewer::traffic::Ipv4Prefix> exemptions,
    std::span<const MIB_IPFORWARD_ROW2> underlays);
bool exemptionCoversHalf(std::span<const skewer::traffic::Ipv4Prefix> exemptions, unsigned half);

} // namespace skewer::windows
