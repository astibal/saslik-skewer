#include "routing_scope.hpp"
#include <iostream>
#include <stdexcept>

using namespace skewer::traffic;
int main() {
    try {
        const auto check = [](ScopeRequest request, ScopeAuthority authority, ScopeAdmission expected) {
            if (admitScope(request, authority) != expected) {
                throw std::runtime_error("Unexpected routing scope admission");
            }
        };
        check({}, {}, ScopeAdmission::EmptySelection);
        for (bool supported : {false, true}) {
            for (bool authorized : {false, true}) {
                for (std::size_t count : {0u, 1u, 100u}) {
                    const ScopeAuthority authority{supported, authorized};
                    check({RoutingScope::Applications, count}, authority,
                          count ? ScopeAdmission::Applications : ScopeAdmission::EmptySelection);
                    check({RoutingScope::WholeHost, count}, authority,
                          !supported ? ScopeAdmission::Unsupported :
                          !authorized ? ScopeAdmission::Unauthorized : ScopeAdmission::WholeHost);
                    check({static_cast<RoutingScope>(99), count}, authority, ScopeAdmission::Invalid);
                }
            }
        }
        std::cout << "PASS: explicit routing scope and backend authority\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
