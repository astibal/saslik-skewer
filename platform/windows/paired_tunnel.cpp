#include "paired_tunnel.hpp"
#include "../traffic/tunnel_lease.hpp"
#include <QHostAddress>
#include <future>
#include <algorithm>

namespace skewer::windows {
namespace {
bool cancelled(HANDLE stop) {
    const auto state = WaitForSingleObject(stop, 0);
    if (state == WAIT_OBJECT_0) {
        return true;
    }
    if (state != WAIT_TIMEOUT) {
        throw std::runtime_error("Cannot inspect tunnel cancellation");
    }
    return false;
}
void validatePeer(const QString& peer) {
    const QHostAddress address(peer);
    if (address.protocol() != QAbstractSocket::IPv4Protocol || address.isMulticast() || address.isNull() ||
        address.toIPv4Address() == 0 || address.toIPv4Address() == 0xffffffff) {
        throw std::invalid_argument("Tunnel peer must be a unicast numeric IPv4 address");
    }
}
} // namespace

PskTunnelControl::PskTunnelControl(QUrl endpoint, QString peer)
    : endpoint_(std::move(endpoint)), peer_(std::move(peer)) {
    validatePeer(peer_);
}
PairedTunnel PskTunnelControl::open() {
    return openPairedTunnel(endpoint_, peer_);
}
void PskTunnelControl::renew(const Tuntom::Endpoint& endpoint) {
    heartbeatPairedTunnel(endpoint_, endpoint, peer_);
}
void PskTunnelControl::close(const Tuntom::Endpoint& endpoint) {
    closePairedTunnel(endpoint_, endpoint, peer_);
}

TunnelPump::Counters runPairedTunnel(PacketDevice& device, TunnelControl& control,
                                     const QString& numeric_peer, HANDLE stop, std::atomic_bool& ready,
                                     TunnelRoutePolicy* routes) {
    ready.store(false);
    validatePeer(numeric_peer);
    if (cancelled(stop)) {
        return {};
    }
    const auto started = TunnelPump::Clock::now();
    auto paired = control.open();
    // Even initialization failures release the lease; remote expiry remains the
    // backstop when control connectivity is already lost.
    struct CloseLease {
        TunnelControl& control;
        PairedTunnel& paired;
        ~CloseLease() {
            std::fill(paired.key.begin(), paired.key.end(), '\0');
            try {
                control.close(paired.endpoint);
            } catch (...) {
            }
        }
    } close{control, paired};
    if (cancelled(stop)) {
        return {};
    }
    skewer::traffic::TunnelLease lease(started, TunnelPump::Clock::now(),
                                       std::chrono::seconds(paired.endpoint.leaseSeconds));
    if (paired.key.size() != 16 || paired.endpoint.id < 1 || paired.endpoint.id > 255) {
        throw std::runtime_error("Invalid paired transport key or ID");
    }
    tuntom::ascon::key_type key{};
    std::copy(paired.key.begin(), paired.key.end(), key.begin());
    struct WipeKey {
        tuntom::ascon::key_type& key;
        ~WipeKey() { tuntom::secure_zero(key.data(), key.size()); }
    } wipe{key};
    UdpEndpoint udp(UdpAddress::numeric("0.0.0.0", 0));
    const auto peer = UdpAddress::numeric(numeric_peer.toStdString(), 40000 + paired.endpoint.id);
    TunnelPump pump(device, udp, peer, paired.endpoint.id, key, false,
                    [&] { return !cancelled(stop) && lease.valid(TunnelPump::Clock::now()); });
    tuntom::secure_zero(key.data(), key.size());
    std::fill(paired.key.begin(), paired.key.end(), '\0');
    const auto interval = std::chrono::seconds(paired.endpoint.leaseSeconds / 3);
    auto renewal_started = started;
    auto next_renewal = started + interval;
    std::future<void> renewal;
    // Declare after the future: mark not-ready before waiting for a pending
    // bounded control request to finish during stack unwinding.
    struct StopReadiness {
        std::atomic_bool& ready;
        TunnelRoutePolicy* routes;
        ~StopReadiness() {
            ready.store(false);
            if (routes) {
                routes->withdraw();
            }
        }
    } reset{ready, routes};
    bool installed = false;
    while (!cancelled(stop)) {
        auto now = TunnelPump::Clock::now();
        if (!lease.valid(now)) {
            throw std::runtime_error("Tunnel lease expired; traffic remains blocked");
        }
        if (renewal.valid() && renewal.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            renewal.get(); // A rejection is terminal; never silently reopen.
            if (!lease.renew(renewal_started, TunnelPump::Clock::now())) {
                throw std::runtime_error("Tunnel renewal arrived after its deadline");
            }
            next_renewal = renewal_started + interval;
        }
        now = TunnelPump::Clock::now();
        if (!renewal.valid() && now >= next_renewal) {
            renewal_started = now;
            renewal = std::async(std::launch::async,
                                 [&control, endpoint = paired.endpoint] { control.renew(endpoint); });
        }
        pump.step(TunnelPump::Clock::now());
        now = TunnelPump::Clock::now();
        if (cancelled(stop)) {
            break;
        }
        const bool healthy = lease.valid(now) && pump.healthy(now);
        if (routes && installed && !healthy) {
            // No automatic reactivation: require a fresh explicit lifecycle.
            throw std::runtime_error("Routed tunnel lost readiness; traffic remains blocked");
        }
        if (routes && !installed && healthy) {
            routes->activate(paired.endpoint);
            installed = true;
        }
        // Route installation may take time. Never publish stale lease health.
        now = TunnelPump::Clock::now();
        ready.store(healthy && !cancelled(stop) && lease.valid(now) && pump.healthy(now));
        if (udp.wait(stop, 25, device.readEvent()) == UdpEndpoint::Wait::Cancelled) {
            break;
        }
    }
    return pump.counters();
}
} // namespace skewer::windows
