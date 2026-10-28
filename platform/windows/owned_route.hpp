#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string>

namespace skewer::windows {
// Trusted worker input only, never raw IPC fields. Numeric canonical IPv4
// prefixes keep this first implementation separate from IPv6 routing policy.
MIB_IPFORWARD_ROW2 ipv4Route(NET_LUID luid, const std::string& network, unsigned prefix,
                             const std::string& next_hop, ULONG metric);

// Owns a newly created ActiveStore route, never adopts/replaces an existing one.
// Destruction is a best-effort backstop. The service must inspect remove() while
// its egress guard is still armed before announcing successful release.
class OwnedRoute final {
public:
    enum class Removal { Removed, Missing, Changed, Failed };
    explicit OwnedRoute(MIB_IPFORWARD_ROW2 route);
    ~OwnedRoute();
    OwnedRoute(const OwnedRoute&) = delete;
    OwnedRoute& operator=(const OwnedRoute&) = delete;
    Removal remove() noexcept;

private:
    MIB_IPFORWARD_ROW2 route_;
    bool owned_{};
    Removal result_{Removal::Missing};
};
} // namespace skewer::windows
