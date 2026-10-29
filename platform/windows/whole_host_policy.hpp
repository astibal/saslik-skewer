#pragma once
#include "service_tunnel.hpp"

namespace skewer::windows {
// Route-plan boundary used by the policy and deterministic tests. The underlay
// is rediscovered for each protected retry and may differ from the interface
// used when WholeHostPolicy was constructed.
std::vector<MIB_IPFORWARD_ROW2> wholeHostRoutePlan(
    const std::string& peer, const MIB_IPFORWARD_ROW2& underlay, NET_LUID tunnel,
    const Tuntom::Endpoint& endpoint);

// Construct only from administrator-owned service configuration. Management is
// optional, explicit SSH return-path allowance for a lab VM, not a hidden bypass.
class WholeHostPolicy final {
public:
    WholeHostPolicy(std::string peer, unsigned control_port, std::string management = {});
    std::string filter(NET_LUID tunnel) const;
    std::vector<MIB_IPFORWARD_ROW2> routes(NET_LUID tunnel, const Tuntom::Endpoint& endpoint) const;

private:
    std::string peer_;
    unsigned control_port_;
    std::string management_;
    NET_LUID initial_underlay_{};
};
} // namespace skewer::windows
