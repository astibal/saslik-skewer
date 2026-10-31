#include "direct_host_policy.hpp"
#include <iostream>

using namespace skewer::windows;
namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::array<std::uint8_t, 4> defaultGateway() {
    SOCKADDR_INET destination{};
    destination.si_family = AF_INET;
    require(InetPtonA(AF_INET, "1.1.1.1", &destination.Ipv4.sin_addr) == 1,
            "Cannot parse probe destination");
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    const auto status = GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source);
    if (status != NO_ERROR || route.NextHop.Ipv4.sin_addr.S_un.S_addr == INADDR_ANY) {
        throw std::runtime_error("No on-link default gateway available for policy test");
    }
    const auto value = ntohl(route.NextHop.Ipv4.sin_addr.S_un.S_addr);
    return {static_cast<std::uint8_t>(value >> 24), static_cast<std::uint8_t>(value >> 16),
            static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)};
}
} // namespace

int main() {
    try {
        for (const auto invalid : {std::array<std::uint8_t, 4>{},
                                   std::array<std::uint8_t, 4>{127, 0, 0, 1},
                                   std::array<std::uint8_t, 4>{224, 0, 0, 1}}) {
            try {
                DirectHostPolicy policy(invalid);
                throw std::runtime_error("Invalid direct gateway accepted");
            } catch (const std::invalid_argument&) {
            }
        }
        DirectHostPolicy policy(defaultGateway());
        const auto routes = policy.routes();
        require(routes.size() == 2, "Direct policy did not produce two covering routes");
        require(routes[0].DestinationPrefix.PrefixLength == 1 &&
                    routes[1].DestinationPrefix.PrefixLength == 1,
                "Direct policy produced an unexpected prefix");
        require(policy.guardFilter().find("ipv6") != std::string::npos,
                "Direct policy did not retain explicit IPv6 blocking");
        std::cout << "PASS: on-link direct gateway plan, covering IPv4 routes and IPv6 guard\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
