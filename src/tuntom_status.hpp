#pragma once
#include <QString>
#include <QJsonObject>

namespace Tuntom {
struct StatusView {
    QString mode, license, state;
    bool connected = false, paired = false, requested = false;
    bool directKnown = false, direct = false, selected = false;
    bool fresh = false, routingActive = false;
    int enabled = -1;
    QJsonObject stats;
};

inline QString humanBytes(const QString& text)
{
    bool ok = false;
    const auto bytes = text.toULongLong(&ok);
    if (!ok) return "?";
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024 && unit < 6) { value /= 1024; ++unit; }
    return QString::number(value, 'f', unit ? 1 : 0) + ' ' + units[unit];
}

inline QString compactStatus(const StatusView& s, bool missingBinary = false)
{
    const bool needed = s.requested && s.mode != "direct"
        && (s.selected || s.mode == "tunnel" || (s.connected && s.directKnown && !s.direct));
    if (needed && missingBinary) return "Tuntom missing — install or select executable in Settings";
    if (!s.requested) return "Tunnel off";
    if (s.state == "authorization-required") return "Tunnel · helper authorization required";
    if (s.mode == "direct" || (s.mode == "auto" && !s.selected && s.directKnown && s.direct)) return "Direct routing";
    if (!s.connected) return "Tunnel · waiting for Saslik";
    if (s.selected && s.state == "failed") return "Tunnel failed · see details";
    if (s.selected && s.state == "verified" && s.fresh && s.routingActive)
        return QString("Tuntom · TX %1 / RX %2")
            .arg(humanBytes(s.stats["tun_rx_bytes"].toString()), humanBytes(s.stats["tun_tx_bytes"].toString()));
    if (s.selected && s.state == "verified") return "Tunnel · routing unverified";
    return "Tunnel · connecting";
}

inline QString statusSummary(const StatusView& s)
{
    QString license = "license unknown";
    if (s.connected && s.paired) {
        if (s.license == "ok") license = "license ok";
        else if (s.license == "not-present") license = "license not present";
        else if (s.license == "development-override") license = "development override (license not verified)";
        else if (s.license == "expired") license = "license expired";
        else if (s.license == "error") license = "license check failed";
    }
    QString capability;
    if (!s.requested) capability = "not used - disabled";
    else if (s.mode == "direct") capability = s.directKnown && s.direct
        ? "not used - directly connected" : "not used - disabled (Direct mode)";
    else if (s.mode == "tunnel") capability = "required - enforced by user";
    else if (s.selected) capability = "auto-detected as needed (retained; no direct fallback)";
    else if (!s.connected || !s.directKnown) capability = "waiting for detection";
    else capability = s.direct ? "auto-detected as not necessary" : "auto-detected as needed";
    QString state = "down";
    if (s.selected) {
        if (s.state == "failed") state += " - failed (see details)";
        else if (s.state == "connecting" || s.state == "prepared") state += " - connecting";
        else if (!s.fresh) state += " - telemetry stale";
        else if (s.state != "verified") state += " - waiting for handshake / data path";
        else {
            state = "up";
            // TUN RX is traffic read from the local kernel: upload to Saslik.
            const auto tx = s.stats["tun_rx_bytes"].toString();
            const auto rx = s.stats["tun_tx_bytes"].toString();
            if (!tx.isEmpty() && !rx.isEmpty())
                state += QString(" (TX %1 B / RX %2 B; uptime %3 s)")
                    .arg(tx, rx, s.stats["uptime_seconds"].toString("?"));
            else state += " (stats unavailable)";
            if (!s.routingActive) state += " - process routing inactive";
        }
    } else if (s.requested && !s.connected && s.mode != "direct") state += " - Saslik unavailable";
    if (s.connected && s.enabled == 0) capability += " - unavailable on Saslik";
    return QString("Tunnel capability: %1 (%2)\nTunnel status: %3").arg(capability, license, state);
}
}
