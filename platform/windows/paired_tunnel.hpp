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
    PairedTunnel open() override;
    void renew(const Tuntom::Endpoint&) override;
    void close(const Tuntom::Endpoint&) override;
    const QString& peer() const { return peer_; }

private:
    QUrl endpoint_;
    QString peer_;
};

// Owns lease and packet lifetime, but not routing/filter policy. The caller must
// keep its external traffic guard armed before and after this function. A false
// ready flag never authorizes fallback to ordinary host routes. No GUI lifetime
// is involved. stop, device and ready must outlive this synchronous operation.
TunnelPump::Counters runPairedTunnel(PacketDevice& device, TunnelControl& control,
                                     const QString& numeric_peer, HANDLE stop, std::atomic_bool& ready);
inline TunnelPump::Counters runPairedTunnel(PacketDevice& device, PskTunnelControl& control, HANDLE stop,
                                            std::atomic_bool& ready) {
    // Pin both control and transport to the same resolved peer for this lifetime.
    return runPairedTunnel(device, control, control.peer(), stop, ready);
}
} // namespace skewer::windows
