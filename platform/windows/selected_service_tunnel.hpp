#pragma once
#include "paired_tunnel.hpp"
#include "routing_control.hpp"

namespace skewer::windows {
// Experimental process-group IPv4 TCP/UDP backend. The root is already
// authorized by IPC; descendants created after Job Object attachment inherit
// selection. Existing sockets, pre-existing descendants and ambiguous shared
// binds remain held/not selected.
// Capture survives transport generations; retry remains blocked until a fresh
// lease is healthy. No host routes or DNS mutations; explicit Stop releases guards.
void runSelectedServiceTunnel(const std::wstring& dll, std::unique_ptr<ProcessTarget> target,
                              const ServiceOwner& owner, TunnelControl& control, const QString& peer,
                              std::uint16_t control_port,
                              HANDLE cancel, RoutingSignals& state);
} // namespace skewer::windows
