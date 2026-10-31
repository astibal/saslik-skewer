#pragma once
#include <cstddef>

namespace skewer::traffic {
enum class RoutingScope { Applications, WholeHost };
enum class ScopeAdmission { Applications, WholeHost, EmptySelection, Unauthorized, Unsupported, Invalid };

struct ScopeRequest {
    RoutingScope scope{RoutingScope::Applications};
    std::size_t selected_applications{};
};

// Backend-owned facts, never accepted as booleans supplied by an IPC client.
// Whole-host support defaults off until platform egress/rollback tests pass.
struct ScopeAuthority {
    bool whole_host_supported{};
    bool whole_host_authorized{};
};

// Scope admission only: no routes, transport choice or readiness claim.
// A live scope switch still needs transactional backend enforcement.
inline ScopeAdmission admitScope(ScopeRequest request, ScopeAuthority authority) {
    switch (request.scope) {
    case RoutingScope::Applications:
        return request.selected_applications ? ScopeAdmission::Applications : ScopeAdmission::EmptySelection;
    case RoutingScope::WholeHost:
        if (!authority.whole_host_supported) {
            return ScopeAdmission::Unsupported;
        }
        if (!authority.whole_host_authorized) {
            return ScopeAdmission::Unauthorized;
        }
        return ScopeAdmission::WholeHost;
    }
    return ScopeAdmission::Invalid;
}
} // namespace skewer::traffic
