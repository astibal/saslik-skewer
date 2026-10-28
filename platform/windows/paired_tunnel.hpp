#pragma once
#include "tunnel_pump.hpp"
#include "pairing.hpp"
#include <atomic>

namespace skewer::windows {
// Control operations may block. Only renewal runs on a separate worker; open,
// renew and close never overlap. Implementations must impose network deadlines.
class TunnelControl {
public:
    virtual ~TunnelControl() = default;
    virtual PairedTunnel open() = 0;
    virtual void renew(const Tuntom::Endpoint&) = 0;
    virtual void close(const Tuntom::Endpoint&) = 0;
};

class PskTunnelControl final : public TunnelControl {
public:
    PskTunnelControl(QUrl endpoint, QString peer);
    PskTunnelControl(QUrl endpoint, QString peer, QByteArray identity, QByteArray key);
    PairedTunnel open() override;
    void renew(const Tuntom::Endpoint&) override;
    void close(const Tuntom::Endpoint&) override;
    const QString& peer() const { return peer_; }

private:
    QString peer_;
    std::unique_ptr<PairedControl> control_;
};

// Called only by the packet worker. The external egress guard must already be
// armed and must outlive this policy, including unsuccessful route cleanup.
class TunnelRoutePolicy {
public:
    virtual ~TunnelRoutePolicy() = default;
    virtual void activate(const Tuntom::Endpoint&) = 0;
    virtual void withdraw() noexcept = 0;
};

// Optional selected-packet integration, invoked only on the packet worker.
// prepare may configure the supplied PacketDevice from the assigned address.
// poll runs only after authenticated readiness, and must be bounded/nonblocking.
// block retires selected traffic on every exit, before waiting for renewal;
// it must be idempotent and must not release interception or unrelated traffic.
class TunnelPacketWorker {
public:
    virtual ~TunnelPacketWorker() = default;
    virtual void prepare(const Tuntom::Endpoint&) = 0;
    virtual void poll() = 0;
    // Optional borrowed capture event; used only once the transport is ready.
    // poll must consume/re-arm it so an idle worker cannot spin the loop.
    virtual HANDLE captureEvent() const { return nullptr; }
    virtual void block() noexcept = 0;
};

// Owns lease and packet lifetime, but not routing/filter policy. The caller must
// keep its external traffic guard armed before and after this function. A false
// ready flag never authorizes fallback to ordinary host routes. No GUI lifetime
// is involved. stop, device and ready must outlive this synchronous operation.
TunnelPump::Counters runPairedTunnel(PacketDevice& device, TunnelControl& control,
                                     const QString& numeric_peer, HANDLE stop, std::atomic_bool& ready,
                                     TunnelRoutePolicy* routes = nullptr,
                                     TunnelPacketWorker* packets = nullptr,
                                     std::atomic_bool* blocked = nullptr);
inline TunnelPump::Counters runPairedTunnel(PacketDevice& device, PskTunnelControl& control, HANDLE stop,
                                            std::atomic_bool& ready) {
    // Pin both control and transport to the same resolved peer for this lifetime.
    return runPairedTunnel(device, control, control.peer(), stop, ready);
}
} // namespace skewer::windows
