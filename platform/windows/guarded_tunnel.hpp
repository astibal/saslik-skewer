#pragma once
#include "guarded_worker.hpp"
#include "tunnel_routes.hpp"

namespace skewer::windows {
struct GuardedTunnelResult {
    GuardedWorkerResult worker;
    TunnelPump::Counters counters;
};

// Service-side composition. The caller supplies an already-armed physical
// egress guard, configured adapter and validated route plan. These objects must
// outlive this call. Neither tunnel failure nor GUI lifetime releases the guard.
GuardedTunnelResult runGuardedPairedTunnel(traffic::PacketCapture& guard, PacketDevice& device,
                                           TunnelControl& control, const QString& numeric_peer,
                                           TunnelRoutes& routes, HANDLE stop, std::atomic_bool& ready,
                                           std::atomic_bool* blocked = nullptr);
} // namespace skewer::windows
