#include "guarded_tunnel.hpp"

namespace skewer::windows {
GuardedTunnelResult runGuardedPairedTunnel(traffic::PacketCapture& guard, PacketDevice& device,
                                           TunnelControl& control, const QString& numeric_peer,
                                           TunnelRoutes& routes, HANDLE stop, std::atomic_bool& ready) {
    GuardedTunnelResult result{};
    ready.store(false);
    result.worker = runGuardedWorker(
        guard, stop,
        [&](HANDLE cancel) {
            result.counters = runPairedTunnel(device, control, numeric_peer, cancel, ready, &routes);
        },
        [&] {
            // The session has joined: ownership passes back to the supervisor.
            // A failed/changed route keeps the guard alive even after SCM STOP.
            ready.store(false);
            routes.withdraw();
            return routes.clean();
        });
    return result;
}
} // namespace skewer::windows
