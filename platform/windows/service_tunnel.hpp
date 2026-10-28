#pragma once
#include "guarded_tunnel.hpp"
#include "tunnel_address.hpp"

namespace skewer::windows {
// Trusted service policy, not a filter/route expression supplied through IPC.
// Called after authenticated addressing and transport health are established.
using ServiceRoutePlan = std::function<std::vector<MIB_IPFORWARD_ROW2>(NET_LUID, const Tuntom::Endpoint&)>;
using ServiceGuardFactory = std::function<std::unique_ptr<traffic::PacketCapture>(NET_LUID)>;

// Create the fresh adapter first so a native guard can exclude exactly its
// interface. Arm the guard before assigning addresses or opening the tunnel.
GuardedTunnelResult runConfiguredServiceTunnel(std::shared_ptr<const WintunApi> api,
                                               const std::wstring& adapter_name, TunnelControl& control,
                                               const QString& peer, ServiceGuardFactory guard_factory,
                                               ServiceRoutePlan plan, HANDLE stop, std::atomic_bool& ready,
                                               std::atomic_bool& blocked, const std::wstring& dns = {},
                                               std::atomic<std::shared_ptr<const std::string>>* retry_error =
                                                   nullptr);

// One routing generation owns adapter, address and routes. The caller owns an
// already armed guard and keeps control/API alive until this function returns.
// Setup failure stays blocked until Stop, just like loss of an established tunnel.
GuardedTunnelResult runServiceTunnel(traffic::PacketCapture& guard, std::shared_ptr<const WintunApi> api,
                                     const std::wstring& adapter_name, TunnelControl& control,
                                     const QString& peer, ServiceRoutePlan plan, HANDLE stop,
                                     std::atomic_bool& ready, std::atomic_bool& blocked);
} // namespace skewer::windows
