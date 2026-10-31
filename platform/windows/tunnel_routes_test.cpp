#include "tunnel_routes.hpp"
#include <iostream>
#include <system_error>

using namespace skewer::windows;
namespace {
void require(bool ok, const char* message) {
    if (!ok) {
        throw std::runtime_error(message);
    }
}
bool missing(MIB_IPFORWARD_ROW2 row) {
    return GetIpForwardEntry2(&row) == ERROR_NOT_FOUND;
}
} // namespace

// Explicit elevated VM fixture. No default routes or traffic are involved.
int main(int argc, char** argv) {
    if (argc != 2 || std::string(argv[1]) != "--live") {
        return 2;
    }
    try {
        SOCKADDR_INET destination{}, source{};
        destination.si_family = AF_INET;
        InetPtonA(AF_INET, "203.0.113.254", &destination.Ipv4.sin_addr);
        MIB_IPFORWARD_ROW2 underlay{};
        require(GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &underlay, &source) == NO_ERROR,
                "Cannot inspect underlay");
        char gateway[INET_ADDRSTRLEN]{};
        require(InetNtopA(AF_INET, &underlay.NextHop.Ipv4.sin_addr, gateway, sizeof(gateway)),
                "Format gateway");
        auto first = ipv4Route(underlay.InterfaceLuid, "203.0.113.254", 32, gateway, 4999);
        auto second = ipv4Route(underlay.InterfaceLuid, "203.0.113.253", 32, gateway, 4999);
        require(missing(first) && missing(second), "Fixture route exists; refusing changes");
        Tuntom::Endpoint endpoint;
        {
            TunnelRoutes routes({first, first});
            bool rejected = false;
            try {
                routes.activate(endpoint);
            } catch (const std::system_error&) {
                rejected = true;
            }
            require(rejected && routes.clean() && missing(first), "Partial activation did not roll back");
        }
        {
            TunnelRoutes routes({first, second});
            routes.activate(endpoint);
            require(!routes.clean() && !missing(first) && !missing(second), "Route plan not installed");
            routes.withdraw();
            require(routes.clean() && missing(first) && missing(second), "Route plan not removed");
            routes.withdraw();
            require(routes.clean(), "Repeated withdrawal failed");
            bool rejected = false;
            try {
                routes.activate(endpoint);
            } catch (const std::logic_error&) {
                rejected = true;
            }
            require(rejected, "Retired plan was reactivated");
        }
        std::cout << "PASS: native route plan, partial rollback, withdrawal and no reactivation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
