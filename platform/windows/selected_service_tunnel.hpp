#pragma once
#include "paired_tunnel.hpp"
#include "routing_control.hpp"

namespace skewer::windows {
// Experimental one-process IPv4 TCP/UDP backend. The target is already authorized
// by IPC. Existing sockets, ambiguous shared binds and descendants are not selected here.
// Capture survives transport generations; retry remains blocked until a fresh
// lease is healthy. No host routes or DNS mutations; explicit Stop releases guards.
void runSelectedServiceTunnel(const std::wstring& dll, std::unique_ptr<ProcessTarget> target,
                              TunnelControl& control, const QString& peer, std::uint16_t control_port,
                              HANDLE cancel, RoutingSignals& state);
} // namespace skewer::windows
