#include "owned_route.hpp"
#include <iostream>
#include <system_error>

using namespace skewer::windows;
namespace {
void require(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}
} // namespace

// Elevated disposable VM only. One TEST-NET /32 via the existing underlay;
// sends no traffic and never modifies the default route or DNS.
int main(int argc, char** argv) {
    if (argc != 2 || std::string(argv[1]) != "--live") {
        std::cerr << "Explicit --live required in disposable elevated VM\n";
        return 2;
    }
    try {
        SOCKADDR_INET destination{}, source{};
        destination.si_family = AF_INET;
        InetPtonA(AF_INET, "203.0.113.254", &destination.Ipv4.sin_addr);
        MIB_IPFORWARD_ROW2 underlay{};
        require(GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &underlay, &source) == NO_ERROR,
                "Cannot inspect underlay route");
        char gateway[INET_ADDRSTRLEN]{};
        require(InetNtopA(AF_INET, &underlay.NextHop.Ipv4.sin_addr, gateway, sizeof(gateway)),
                "Format gateway");
        auto row = ipv4Route(underlay.InterfaceLuid, "203.0.113.254", 32, gateway, 4999);
        auto query = row;
        require(GetIpForwardEntry2(&query) == ERROR_NOT_FOUND,
                "Fixture route already exists; refusing changes");
        {
            OwnedRoute route(row);
            query = row;
            require(GetIpForwardEntry2(&query) == NO_ERROR, "Created route missing");
            const auto diagnostic = [](const char* label, const MIB_IPFORWARD_ROW2& value) {
                std::cout << label << " if=" << value.InterfaceIndex << " luid=" << value.InterfaceLuid.Value
                          << " metric=" << value.Metric << " protocol=" << value.Protocol
                          << " site=" << unsigned(value.SitePrefixLength) << " valid=" << value.ValidLifetime
                          << " preferred=" << value.PreferredLifetime << " loop=" << unsigned(value.Loopback)
                          << " auto=" << unsigned(value.AutoconfigureAddress)
                          << " publish=" << unsigned(value.Publish)
                          << " immortal=" << unsigned(value.Immortal) << '\n';
            };
            diagnostic("requested", row);
            diagnostic("observed", query);
            bool rejected{};
            try {
                OwnedRoute duplicate(row);
            } catch (const std::system_error&) {
                rejected = true;
            }
            require(rejected, "Existing route was adopted or overwritten");
            require(route.remove() == OwnedRoute::Removal::Removed, "Explicit removal failed");
            require(route.remove() == OwnedRoute::Removal::Removed, "Repeated cleanup changed result");
        }
        { OwnedRoute route(row); }
        query = row;
        require(GetIpForwardEntry2(&query) == ERROR_NOT_FOUND, "Destructor left route behind");
        {
            OwnedRoute route(row);
            require(DeleteIpForwardEntry2(&row) == NO_ERROR, "Cannot simulate adapter route deletion");
            require(route.remove() == OwnedRoute::Removal::Missing, "Missing route treated as owned");
        }
        {
            OwnedRoute route(row);
            query = row;
            require(GetIpForwardEntry2(&query) == NO_ERROR, "Read route before mutation");
            ++query.Metric;
            require(SetIpForwardEntry2(&query) == NO_ERROR, "Cannot simulate administrator metric change");
            const auto result = route.remove();
            auto changed = query;
            const auto found = GetIpForwardEntry2(&changed);
            // Only our fixture mutated this unique route. Remove it explicitly,
            // even if assertions below fail; the production owner must refuse it.
            const auto cleanup = DeleteIpForwardEntry2(&query);
            require(result == OwnedRoute::Removal::Changed && found == NO_ERROR &&
                        changed.Metric == query.Metric,
                    "Observed administrator change was not preserved");
            require(cleanup == NO_ERROR, "Cannot remove fixture-modified route");
        }
        std::cout << "PASS: native route create, conflict refusal, cleanup and changed-route preservation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
