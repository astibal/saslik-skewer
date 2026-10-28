#pragma once
#include "service_tunnel.hpp"

namespace skewer::windows {
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
    MIB_IPFORWARD_ROW2 underlay_{};
};
} // namespace skewer::windows
