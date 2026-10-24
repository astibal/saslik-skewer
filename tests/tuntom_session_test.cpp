#include "tuntom_session.hpp"
#include "tuntom_control.hpp"
#include "tuntom_status.hpp"
#include "tuntom_recovery.hpp"

int main()
{
    QByteArray key;
    for (int i = 0; i < 32; ++i) key.append(char(i));
    if (Tuntom::deriveKey(key, QByteArray(64, '0')).toHex() != "af07b757429bdce394a510a8635cf9da") return 1;
    try { Tuntom::deriveKey(key, QByteArray(64, 'x')); return 2; }
    catch (const std::invalid_argument&) {}
    using namespace Tuntom;
    if (selectRoute(Mode::Auto, true, false, false) != Route::Direct) return 3;
    if (selectRoute(Mode::Auto, false, false, false) != Route::WaitForTunnel) return 4;
    if (selectRoute(Mode::Auto, false, true, false) != Route::Tunnel) return 5;
    if (selectRoute(Mode::Auto, true, false, true) != Route::Blocked) return 6;
    if (selectRoute(Mode::DirectOnly, false, true, true) != Route::Blocked) return 7;
    if (selectRoute(Mode::TunnelOnly, true, false, false) != Route::WaitForTunnel) return 16;
    if (selectRoute(Mode::TunnelOnly, true, true, false) != Route::Tunnel) return 17;
    if (selectRoute(Mode::Auto, true, true, true) != Route::Tunnel) return 18;
    QJsonObject value{{"version", 1}, {"transport", "tuntom"}, {"id", 1}, {"port", 40001},
        {"context", QString(64, '0')}, {"client_interface", "skt1c"}, {"server_interface", "skt1s"},
        {"server_address", "10.253.0.5/30"}, {"client_address", "10.253.0.6/30"}};
    const auto parse = [](const QJsonObject& endpoint) {
        return endpointFromResponse({{"ok", true}, {"lease_seconds", 60}, {"tunnel", endpoint}});
    };
    if (parse(value).id != 1) return 8;
    for (const auto& field : {"id", "port", "context", "client_interface", "server_address", "client_address"}) {
        auto broken = value;
        broken[field] = "invalid";
        try { parse(broken); return 9; } catch (const std::invalid_argument&) {}
    }
    value["client_address"] = "10.253.0.10/30";
    try { parse(value); return 10; } catch (const std::invalid_argument&) {}
    const QByteArray stats = "format_version=1\nmode=client\ntunnel_id=1\nupdated_unix=100\nsession_ready=1\nsession_confirmed=1\n";
    if (!confirmedSnapshot(stats, 1, 103)) return 11;
    if (confirmedSnapshot(stats, 1, 106) || confirmedSnapshot(stats, 2, 103)) return 12;
    if (confirmedSnapshot(stats, 1, 99)) return 13;
    if (confirmedSnapshot(stats + "session_ready=0\n", 1, 103)) return 14;
    auto unconfirmed = stats;
    unconfirmed.replace("session_confirmed=1", "session_confirmed=0");
    if (confirmedSnapshot(unconfirmed, 1, 103)) return 15;
    const auto counters = stats + "tun_rx_bytes=18446744073709551615\ntun_tx_bytes=42\nuptime_seconds=9\nsecret=hidden\n";
    const auto traffic = trafficSnapshot(counters, 1, 103);
    if (traffic.size() != 3 || traffic["tun_rx_bytes"] != "18446744073709551615") return 19;
    if (!trafficSnapshot(counters, 1, 106).isEmpty()) return 20;
    if (trafficSnapshot(stats + "tun_rx_bytes=-1\n", 1, 103).contains("tun_rx_bytes")) return 21;
    if (trafficSnapshot(stats + "tun_rx_bytes=18446744073709551616\n", 1, 103).contains("tun_rx_bytes")) return 22;
    StatusView view;
    if (humanBytes("0") != "0 B" || humanBytes("1024") != "1.0 KiB"
        || humanBytes("1048576") != "1.0 MiB" || humanBytes("bad") != "?") return 40;
    StatusView compact;
    compact.requested = true; compact.mode = "tunnel";
    if (!compactStatus(compact, true).contains("Tuntom missing")) return 41;
    compact.mode = "auto"; compact.connected = true; compact.directKnown = true;
    if (!compactStatus(compact, true).contains("Tuntom missing")) return 42;
    compact.direct = true;
    if (compactStatus(compact, true) != "Direct routing") return 43;
    compact.selected = true; compact.state = "verified";
    compact.fresh = true; compact.routingActive = true;
    compact.stats = {{"tun_rx_bytes", "1024"}, {"tun_tx_bytes", "1048576"}};
    if (compactStatus(compact) != "Tuntom · TX 1.0 KiB / RX 1.0 MiB") return 44;
    view.mode = "auto";
    if (!statusSummary(view).contains("not used - disabled (license unknown)")) return 23;
    view.requested = true;
    if (!statusSummary(view).contains("waiting for detection")) return 24;
    view.connected = view.paired = view.directKnown = true;
    view.license = "not-present";
    if (!statusSummary(view).contains("auto-detected as needed (license not present)")) return 25;
    view.direct = true;
    if (!statusSummary(view).contains("auto-detected as not necessary")) return 26;
    view.mode = "direct";
    if (!statusSummary(view).contains("not used - directly connected")) return 27;
    view.direct = false;
    if (!statusSummary(view).contains("disabled (Direct mode)")) return 28;
    view.mode = "tunnel";
    view.direct = true;
    if (!statusSummary(view).contains("required - enforced by user")) return 29;
    view.selected = view.fresh = view.routingActive = true;
    view.state = "verified";
    view.stats = traffic;
    if (!statusSummary(view).contains("Tunnel status: up (TX 18446744073709551615 B / RX 42 B; uptime 9 s)")) return 30;
    view.fresh = false;
    if (statusSummary(view).contains("Tunnel status: up") || !statusSummary(view).contains("telemetry stale")) return 31;
    view.fresh = true;
    view.state = "failed";
    if (!statusSummary(view).contains("down - failed")) return 32;
    view.license = "development-override";
    if (statusSummary(view).contains("license ok") || !statusSummary(view).contains("development override")) return 33;
    view.mode = "auto";
    if (!statusSummary(view).contains("no direct fallback")) return 34;
    view.connected = false;
    if (!statusSummary(view).contains("license unknown")) return 35;
    Recovery recovery;
    const auto controller = controllerArguments("/test/skewer", "skewer://127.0.0.1:8766/pair");
    if (!controller.contains("--user") || !controller.contains("--slice=app.slice")
        || !controller.contains("--pipe") || !controller.contains("--collect")
        || controller.mid(controller.indexOf("--") + 1)
            != QStringList{"/test/skewer", "tunnel", "skewer://127.0.0.1:8766/pair", "--gui-route"}) return 40;
    for (int expected : {5000, 10000, 20000, 30000, 30000})
        if (recovery.nextDelayMs() != expected) return 36;
    recovery.reset();
    if (recovery.nextDelayMs() != 5000) return 37;
    if (!Recovery::allowed(true, true, true, false, false)) return 38;
    if (Recovery::allowed(false, true, true, false, false)
        || Recovery::allowed(true, false, true, false, false)
        || Recovery::allowed(true, true, false, false, false)
        || Recovery::allowed(true, true, true, true, false)
        || Recovery::allowed(true, true, true, false, true)) return 39;
}
