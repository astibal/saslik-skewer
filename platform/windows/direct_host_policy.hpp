#pragma once

#include "destination_exemptions.hpp"
#include "owned_route.hpp"
#include "routing_control.hpp"
#include <array>
#include <string>
#include <vector>

namespace skewer::windows {
// Plans whole-host IPv4 routing through an on-link Saslik gateway. IPv6 stays
// blocked for the generation because the direct backend does not claim it.
class DirectHostPolicy final {
public:
    explicit DirectHostPolicy(std::array<std::uint8_t, 4> gateway,
                              std::vector<skewer::traffic::Ipv4Prefix> exemptions = {});
    const std::string& gateway() const { return gateway_; }
    std::string guardFilter() const;
    std::vector<MIB_IPFORWARD_ROW2> routes() const;

private:
    std::string gateway_;
    std::vector<skewer::traffic::Ipv4Prefix> exemptions_;
    NET_LUID interface_{};
};

void runDirectHostRouting(const std::wstring& divert_dll,
                          std::array<std::uint8_t, 4> gateway,
                          std::vector<skewer::traffic::Ipv4Prefix> exemptions, HANDLE cancel,
                          RoutingSignals& state);
} // namespace skewer::windows
