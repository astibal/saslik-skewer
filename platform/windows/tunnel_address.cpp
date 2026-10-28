#include "tunnel_address.hpp"
#include <QHostAddress>
#include <system_error>
#include <algorithm>

namespace skewer::windows {
namespace {
void checked(ULONG status, const char* operation) {
    if (status != NO_ERROR) {
        throw std::system_error(status, std::system_category(), operation);
    }
}
SOCKADDR_INET address(const QString& text) {
    bool ok{};
    const auto value = QHostAddress(text.chopped(3)).toIPv4Address(&ok);
    if (!text.endsWith("/30") || !ok || (value >> 24) != 10) {
        throw std::invalid_argument("Invalid tunnel IPv4 prefix");
    }
    SOCKADDR_INET result{};
    result.si_family = AF_INET;
    result.Ipv4.sin_addr.S_un.S_addr = htonl(value);
    return result;
}
void requireNoOverlap(const SOCKADDR_INET& destination) {
    MIB_IPFORWARD_ROW2 route{};
    SOCKADDR_INET source{};
    checked(GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &route, &source),
            "Inspect tunnel subnet route");
    if (route.DestinationPrefix.PrefixLength != 0) {
        throw std::runtime_error("Tunnel subnet overlaps an existing route");
    }
}
} // namespace
TunnelAddress::TunnelAddress(WintunDevice& device, const Tuntom::Endpoint& endpoint, HANDLE cancel) {
    const auto server = address(endpoint.serverAddress);
    const auto client = address(endpoint.clientAddress);
    const auto server_ip = ntohl(server.Ipv4.sin_addr.S_un.S_addr);
    if ((server_ip & 3) != 1 || ntohl(client.Ipv4.sin_addr.S_un.S_addr) != server_ip + 1) {
        throw std::invalid_argument("Invalid tunnel address pair");
    }
    if (WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT) {
        throw std::runtime_error("Address setup cancelled");
    }
    requireNoOverlap(server);
    requireNoOverlap(client);
    const auto luid = device.luid();
    MIB_IPINTERFACE_ROW ip_interface{};
    InitializeIpInterfaceEntry(&ip_interface);
    ip_interface.Family = AF_INET;
    ip_interface.InterfaceLuid = luid;
    checked(GetIpInterfaceEntry(&ip_interface), "Read owned tunnel interface");
    ip_interface.NlMtu = 1280;
    // IPv4 ignores this IPv6-only field, but SetIpInterfaceEntry validates it.
    ip_interface.SitePrefixLength = 0;
    checked(SetIpInterfaceEntry(&ip_interface), "Set owned tunnel MTU");
    InitializeUnicastIpAddressEntry(&row_);
    row_.InterfaceLuid = luid;
    row_.Address = client;
    row_.OnLinkPrefixLength = 30;
    row_.PrefixOrigin = IpPrefixOriginManual;
    row_.SuffixOrigin = IpSuffixOriginManual;
    row_.SkipAsSource = FALSE;
    checked(CreateUnicastIpAddressEntry(&row_), "Create owned tunnel address");
    owned_ = true;
    try {
        const auto deadline = GetTickCount64() + 8000;
        for (;;) {
            auto observed = row_;
            checked(GetUnicastIpAddressEntry(&observed), "Read owned tunnel address");
            if (observed.DadState == IpDadStatePreferred) {
                break;
            }
            if (observed.DadState == IpDadStateDuplicate || GetTickCount64() >= deadline) {
                throw std::runtime_error("Tunnel address did not become preferred");
            }
            if (WaitForSingleObject(cancel, 50) != WAIT_TIMEOUT) {
                throw std::runtime_error("Address setup cancelled");
            }
        }
    } catch (...) {
        remove();
        throw;
    }
}
TunnelAddress::~TunnelAddress() {
    remove();
}
bool TunnelAddress::remove() noexcept {
    if (!owned_) {
        return true;
    }
    auto observed = row_;
    const auto status = GetUnicastIpAddressEntry(&observed);
    if (status == ERROR_NOT_FOUND) {
        owned_ = false;
        return true;
    }
    // Do not delete an address another administrator has reconfigured. IP Helper
    // has no atomic compare-and-delete; exclusive adapter ownership is required.
    if (status != NO_ERROR || observed.OnLinkPrefixLength != row_.OnLinkPrefixLength ||
        observed.PrefixOrigin != row_.PrefixOrigin || observed.SuffixOrigin != row_.SuffixOrigin ||
        observed.SkipAsSource != row_.SkipAsSource) {
        return false;
    }
    const auto removed = DeleteUnicastIpAddressEntry(&observed);
    if (removed != NO_ERROR && removed != ERROR_NOT_FOUND) {
        return false;
    }
    owned_ = false;
    return true;
}
AddressedTunnelControl::AddressedTunnelControl(TunnelControl& control, WintunDevice& device, HANDLE cancel)
    : control_(control), device_(device), cancel_(cancel) {}
PairedTunnel AddressedTunnelControl::open() {
    if (address_) {
        throw std::logic_error("Addressed control cannot reopen");
    }
    auto value = control_.open();
    try {
        address_ = std::make_unique<TunnelAddress>(device_, value.endpoint, cancel_);
    } catch (...) {
        std::fill(value.key.begin(), value.key.end(), '\0');
        try {
            control_.close(value.endpoint);
        } catch (...) {
            // Preserve the setup error; the server also expires abandoned leases.
        }
        throw;
    }
    return value;
}
void AddressedTunnelControl::renew(const Tuntom::Endpoint& endpoint) {
    control_.renew(endpoint);
}
void AddressedTunnelControl::close(const Tuntom::Endpoint& endpoint) {
    control_.close(endpoint);
}
} // namespace skewer::windows
