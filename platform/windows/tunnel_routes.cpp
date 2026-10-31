#include "tunnel_routes.hpp"
#include <stdexcept>

namespace skewer::windows {
TunnelRoutes::TunnelRoutes(std::vector<MIB_IPFORWARD_ROW2> plan) : plan_(std::move(plan)) {
    if (plan_.empty() || plan_.size() > 16) {
        throw std::invalid_argument("Expected a bounded, nonempty tunnel route plan");
    }
    owned_.reserve(plan_.size());
}
TunnelRoutes::~TunnelRoutes() {
    withdraw();
}
void TunnelRoutes::activate(const Tuntom::Endpoint&) {
    if (attempted_) {
        throw std::logic_error("Tunnel route plan cannot be reactivated");
    }
    attempted_ = true;
    clean_ = false;
    try {
        for (const auto& row : plan_) {
            owned_.push_back(std::make_unique<OwnedRoute>(row));
        }
    } catch (...) {
        withdraw();
        throw;
    }
}
void TunnelRoutes::withdraw() noexcept {
    clean_ = true;
    // Retire default routes first, keeping the peer pin until the last step.
    // Keep ownership objects so failed removals can be retried explicitly.
    for (auto it = owned_.rbegin(); it != owned_.rend(); ++it) {
        const auto result = (*it)->remove();
        if (result == OwnedRoute::Removal::Failed || result == OwnedRoute::Removal::Changed) {
            clean_ = false;
        }
    }
}
} // namespace skewer::windows
