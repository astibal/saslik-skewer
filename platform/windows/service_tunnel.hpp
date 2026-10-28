#pragma once
#include "guarded_tunnel.hpp"
#include "tunnel_address.hpp"

namespace skewer::windows {
// Trusted service policy, not a filter/route expression supplied through IPC.
// Called after authenticated addressing and transport health are established.
using ServiceRoutePlan = std::function<std::vector<MIB_IPFORWARD_ROW2>(NET_LUID, const Tuntom::Endpoint&)>;

// One routing generation owns adapter, address and routes. The caller owns an
// already armed guard and keeps control/API alive until this function returns.
// Setup failure stays blocked until Stop, just like loss of an established tunnel.
GuardedTunnelResult runServiceTunnel(traffic::PacketCapture& guard, std::shared_ptr<const WintunApi> api,
                                     const std::wstring& adapter_name, TunnelControl& control,
                                     const QString& peer, ServiceRoutePlan plan, HANDLE stop,
                                     std::atomic_bool& ready, std::atomic_bool& blocked);
} // namespace skewer::windows
