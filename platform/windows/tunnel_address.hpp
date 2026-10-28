#pragma once
#include "wintun_device.hpp"
#include "paired_tunnel.hpp"
#include <netioapi.h>

namespace skewer::windows {
// Only for a newly created, exclusively owned Wintun adapter. Its destruction
// is the final backstop for interface settings; no physical NIC is modified.
class TunnelAddress final {
public:
    TunnelAddress(WintunDevice& device, const Tuntom::Endpoint& endpoint, HANDLE cancel);
    ~TunnelAddress();
    TunnelAddress(const TunnelAddress&) = delete;
    TunnelAddress& operator=(const TunnelAddress&) = delete;
    bool remove() noexcept;

private:
    MIB_UNICASTIPADDRESS_ROW row_{};
    bool owned_{};
};

// Configures the authenticated address before the packet pump starts. Caller
// keeps device alive longer than this wrapper. Failed setup closes the lease.
class AddressedTunnelControl final : public TunnelControl {
public:
    AddressedTunnelControl(TunnelControl& control, WintunDevice& device, HANDLE cancel,
                           std::wstring dns = {});
    PairedTunnel open() override;
    void renew(const Tuntom::Endpoint& endpoint) override;
    void close(const Tuntom::Endpoint& endpoint) override;

private:
    TunnelControl& control_;
    WintunDevice& device_;
    HANDLE cancel_;
    std::wstring dns_;
    std::unique_ptr<TunnelAddress> address_;
};
} // namespace skewer::windows
