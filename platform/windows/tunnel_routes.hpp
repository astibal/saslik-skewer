#pragma once
#include "owned_route.hpp"
#include "paired_tunnel.hpp"
#include <memory>
#include <vector>

namespace skewer::windows {
// A trusted worker builds the plan after validating authenticated addressing.
// Order matters: pin the transport peer before installing tunnel default routes.
// This object never creates or releases an egress guard.
class TunnelRoutes final : public TunnelRoutePolicy {
public:
    explicit TunnelRoutes(std::vector<MIB_IPFORWARD_ROW2> plan);
    ~TunnelRoutes() override;
    void activate(const Tuntom::Endpoint&) override;
    void withdraw() noexcept override;
    bool clean() const noexcept { return clean_; }

private:
    std::vector<MIB_IPFORWARD_ROW2> plan_;
    std::vector<std::unique_ptr<OwnedRoute>> owned_;
    bool attempted_{};
    bool clean_{true};
};
} // namespace skewer::windows
