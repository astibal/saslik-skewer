#include "direct_host_policy.hpp"
#include "packet_capture.hpp"
#include <memory>
#include <system_error>

namespace skewer::windows {
namespace {
std::string text(std::array<std::uint8_t, 4> bytes) {
    if ((!bytes[0] && !bytes[1] && !bytes[2] && !bytes[3]) || bytes[0] == 127 ||
        bytes[0] >= 224) {
        throw std::invalid_argument("Expected a unicast non-loopback IPv4 gateway");
    }
    return std::to_string(bytes[0]) + '.' + std::to_string(bytes[1]) + '.' +
           std::to_string(bytes[2]) + '.' + std::to_string(bytes[3]);
}

SOCKADDR_INET numeric(const std::string& value) {
    SOCKADDR_INET address{};
    address.si_family = AF_INET;
    if (InetPtonA(AF_INET, value.c_str(), &address.Ipv4.sin_addr) != 1) {
        throw std::invalid_argument("Invalid direct-routing gateway");
    }
    return address;
}

MIB_IPFORWARD_ROW2 routeTo(const std::string& destination) {
    const auto address = numeric(destination);
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    const auto status = GetBestRoute2(nullptr, 0, nullptr, &address, 0, &route, &source);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(),
                                "Find direct gateway route");
    }
    return route;
}

bool unspecified(IN_ADDR address) { return address.S_un.S_addr == INADDR_ANY; }

void requireNoConflicts() {
    PMIB_IPFORWARD_TABLE2 raw{};
    const auto status = GetIpForwardTable2(AF_INET, &raw);
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(),
                                "Inspect existing IPv4 routes");
    }
    std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> table(raw, FreeMibTable);
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        if (table->Table[i].DestinationPrefix.PrefixLength == 1) {
            throw std::runtime_error("Direct route plan conflicts with an existing /1 route");
        }
    }
}

bool removed(OwnedRoute::Removal result) {
    return result == OwnedRoute::Removal::Removed || result == OwnedRoute::Removal::Missing;
}
} // namespace

DirectHostPolicy::DirectHostPolicy(std::array<std::uint8_t, 4> gateway)
    : gateway_(text(gateway)) {
    const auto route = routeTo(gateway_);
    if (!route.InterfaceLuid.Value || !unspecified(route.NextHop.Ipv4.sin_addr)) {
        throw std::invalid_argument("Direct gateway must be reachable on-link");
    }
    interface_ = route.InterfaceLuid;
    requireNoConflicts();
}

std::string DirectHostPolicy::guardFilter() const {
    return "outbound and !loopback and ipv6";
}

std::vector<MIB_IPFORWARD_ROW2> DirectHostPolicy::routes() const {
    requireNoConflicts();
    const auto current = routeTo(gateway_);
    if (current.InterfaceLuid.Value != interface_.Value ||
        !unspecified(current.NextHop.Ipv4.sin_addr)) {
        throw std::runtime_error("Direct gateway path changed during activation");
    }
    return {ipv4Route(interface_, "0.0.0.0", 1, gateway_, 1),
            ipv4Route(interface_, "128.0.0.0", 1, gateway_, 1)};
}

void runDirectHostRouting(const std::wstring& divert_dll,
                          std::array<std::uint8_t, 4> gateway, HANDLE cancel,
                          RoutingSignals& state) {
    state.stage = RoutingStage::Intercepting;
    state.blocked = true;
    DirectHostPolicy policy(gateway);
    traffic::PacketCapture ipv6_guard(divert_dll, policy.guardFilter());
    std::vector<std::unique_ptr<OwnedRoute>> routes;
    for (auto& route : policy.routes()) {
        routes.push_back(std::make_unique<OwnedRoute>(route));
    }
    state.stage = RoutingStage::None;
    state.blocked = false;
    state.ready = true;
    const auto wait = WaitForSingleObject(cancel, INFINITE);
    state.ready = false;
    state.blocked = true;
    bool clean = wait == WAIT_OBJECT_0;
    for (auto it = routes.rbegin(); it != routes.rend(); ++it) {
        clean = removed((*it)->remove()) && clean;
    }
    if (!clean) {
        throw std::runtime_error("Direct routing cleanup did not remove every owned route");
    }
}
} // namespace skewer::windows
