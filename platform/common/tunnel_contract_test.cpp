#include "../../src/tuntom_control.hpp"
#include "../../src/tuntom_recovery.hpp"
#include <QCoreApplication>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void testRouteSelection() {
    using namespace Tuntom;
    for (const bool direct : {false, true}) {
        for (const bool ready : {false, true}) {
            for (const bool previously_active : {false, true}) {
                require(selectRoute(Mode::TunnelOnly, direct, ready, previously_active) ==
                            (ready ? Route::Tunnel : Route::WaitForTunnel),
                        "Tunnel-only mode selected a direct fallback");
                require(selectRoute(Mode::DirectOnly, direct, ready, previously_active) ==
                            (direct ? Route::Direct : Route::Blocked),
                        "Explicit direct mode changed semantics");
                const auto automatic = selectRoute(Mode::Auto, direct, ready, previously_active);
                if (previously_active) {
                    require(automatic == (ready ? Route::Tunnel : Route::Blocked),
                            "An established tunnel fell back to direct routing");
                } else {
                    const auto expected = direct ? Route::Direct
                                                 : (ready ? Route::Tunnel : Route::WaitForTunnel);
                    require(automatic == expected, "Initial automatic route selection changed");
                }
            }
        }
    }
}

QJsonObject endpoint() {
    return {{"ok", true}, {"lease_seconds", 60},
            {"tunnel", QJsonObject{{"version", 1}, {"transport", "tuntom"},
                {"id", 1}, {"port", 40001}, {"context", QString(64, 'a')},
                {"client_interface", "skt1c"}, {"server_interface", "skt1s"},
                {"server_address", "10.253.0.5/30"}, {"client_address", "10.253.0.6/30"}}}};
}

void expectInvalid(const QJsonObject& response) {
    try {
        Tuntom::endpointFromResponse(response);
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("Invalid endpoint metadata was accepted");
}

void testEndpointAndKeys() {
    using namespace Tuntom;
    require(endpointFromResponse(endpoint()).id == 1, "Valid endpoint rejected");
    for (const char* field : {"id", "port", "version", "transport", "context", "client_interface",
                              "server_interface", "server_address", "client_address"}) {
        auto response = endpoint();
        auto tunnel = response["tunnel"].toObject();
        tunnel[field] = "invalid";
        response["tunnel"] = tunnel;
        expectInvalid(response);
    }
    for (const int lease : {0, 9, 3601}) {
        auto response = endpoint();
        response["lease_seconds"] = lease;
        expectInvalid(response);
    }
    auto rejected = endpoint();
    rejected["ok"] = false;
    expectInvalid(rejected);

    QByteArray psk;
    for (int i = 0; i < 32; ++i) {
        psk.append(char(i));
    }
    require(deriveKey(psk, QByteArray(64, '0')).toHex() == "af07b757429bdce394a510a8635cf9da",
            "Paired-session key derivation differs from Linux/Saslik");
    require(deriveKey(psk, QByteArray(64, '0')) != deriveKey(psk, QByteArray(64, '1')),
            "Replacement context reused a session key");
}

void testTelemetry() {
    using namespace Tuntom;
    const QByteArray snapshot = "format_version=1\nmode=client\ntunnel_id=1\nupdated_unix=100\n"
                                "session_ready=1\nsession_confirmed=1\n";
    require(confirmedSnapshot(snapshot, 1, 100), "Fresh session was rejected");
    require(confirmedSnapshot(snapshot, 1, 105), "Five-second boundary changed");
    require(!confirmedSnapshot(snapshot, 1, 106), "Stale telemetry reopened the tunnel");
    require(!confirmedSnapshot(snapshot, 1, 99), "Future-dated telemetry was accepted");
    require(!confirmedSnapshot(snapshot, 2, 100), "Another tunnel's telemetry was accepted");
    require(!confirmedSnapshot(snapshot + "session_ready=0\n", 1, 100), "Duplicate field was accepted");
    require(!confirmedSnapshot(QByteArray(65537, 'x'), 1, 100), "Oversized telemetry was accepted");
    for (const auto& field : {QByteArray("session_ready"), QByteArray("session_confirmed")}) {
        auto waiting = snapshot;
        waiting.replace(field + "=1", field + "=0");
        require(!confirmedSnapshot(waiting, 1, 100), "Unconfirmed session was accepted");
    }
    const auto traffic = trafficSnapshot(snapshot + "tun_rx_bytes=18446744073709551615\nsecret=hidden\n", 1, 100);
    require(traffic.size() == 1 && traffic["tun_rx_bytes"] == "18446744073709551615",
            "Telemetry leaked an unknown field or lost counter precision");
}

void testRecovery() {
    using namespace Tuntom;
    require(Recovery::allowed(true, true, true, false, false), "Valid recovery rejected");
    require(!Recovery::allowed(false, true, true, false, false) &&
                !Recovery::allowed(true, false, true, false, false) &&
                !Recovery::allowed(true, true, false, false, false) &&
                !Recovery::allowed(true, true, true, true, false) &&
                !Recovery::allowed(true, true, true, false, true),
            "Recovery ignored cancellation, shutdown or an existing worker");
    Recovery recovery;
    for (const int expected : {5000, 10000, 20000, 30000, 30000}) {
        require(recovery.nextDelayMs() == expected, "Recovery backoff changed");
    }
    recovery.reset();
    require(recovery.nextDelayMs() == 5000, "Recovery backoff did not reset");
}
} // namespace

int main(int argc, char** argv) {
    QCoreApplication application(argc, argv);
    try {
        testRouteSelection();
        testEndpointAndKeys();
        testTelemetry();
        testRecovery();
        std::cout << "PASS: shared tunnel policy, endpoint validation, key derivation, telemetry and recovery\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
