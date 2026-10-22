#include "tuntom_session.hpp"
#include "tuntom_control.hpp"

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
}
