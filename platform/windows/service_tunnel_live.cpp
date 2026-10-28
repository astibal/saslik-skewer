#include "service_tunnel.hpp"
#include "routing_control.hpp"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QTextStream>

using namespace skewer::windows;

namespace {
class RejectedControl final : public TunnelControl {
public:
    PairedTunnel open() override {
        ++opens;
        throw std::runtime_error("Injected control rejection");
    }
    void renew(const Tuntom::Endpoint&) override { throw std::logic_error("Unexpected renewal"); }
    void close(const Tuntom::Endpoint&) override { throw std::logic_error("Unexpected close"); }
    unsigned opens{}; // Read only after the session worker has joined.
};
} // namespace

// Explicit VM fixture, not an installed production service. The service runner
// owns a real adapter and one TEST-NET route, but the false capture filter blocks
// nothing. Never use this fixture as an application-egress security boundary.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    const auto args = app.arguments();
    const bool reject_open = args.size() == 7 && args[6] == "--reject-open";
    if ((args.size() != 6 && !reject_open) || args[1] != "--live") {
        QTextStream(stderr) << "Expected --live WINTUN_DLL ENDPOINT PEER WINDIVERT_DLL [--reject-open]\n";
        return 2;
    }
    try {
        PskTunnelControl control(QUrl(args[3]), args[4]);
        RejectedControl rejected_control;
        TunnelControl& session_control =
            reject_open ? static_cast<TunnelControl&>(rejected_control) : control;
        auto api = loadWintun(args[2].toStdWString());
        const auto name = L"SkewerPaired-" + std::to_wstring(GetCurrentProcessId());
        RoutingController controller([&](HANDLE stop, RoutingSignals& state_flags) {
            try {
                traffic::PacketCapture guard(args[5].toStdWString(), "false");
                const auto result = runServiceTunnel(
                    guard, api, name, session_control, control.peer(),
                    [](NET_LUID luid, const Tuntom::Endpoint& endpoint) {
                        const QJsonObject config{{"id", endpoint.id},
                                                 {"client_address", endpoint.clientAddress},
                                                 {"server_address", endpoint.serverAddress}};
                        QTextStream(stdout)
                            << "ENDPOINT " << QJsonDocument(config).toJson(QJsonDocument::Compact)
                            << Qt::endl;
                        return std::vector{ipv4Route(luid, "203.0.113.254", 32,
                                                     endpoint.serverAddress.chopped(3).toStdString(), 4999)};
                    },
                    stop, state_flags.ready, state_flags.blocked);
                if (reject_open) {
                    if (rejected_control.opens < 2 || result.worker.session_error ||
                        result.worker.unexpected_session_exit) {
                        throw std::runtime_error("Setup rejection did not retry safely until Stop");
                    }
                    return;
                }
                if (result.worker.session_error) {
                    std::rethrow_exception(result.worker.session_error);
                }
                if (result.worker.unexpected_session_exit) {
                    throw std::runtime_error("Service tunnel exited unexpectedly");
                }
                QTextStream(stdout) << "Service probe completed: tx=" << result.counters.tx
                                    << " rx=" << result.counters.rx << Qt::endl;
            } catch (const std::exception& error) {
                QTextStream(stderr) << "Service fixture worker: " << error.what() << Qt::endl;
                throw;
            }
        });
        auto state = controller.command(RoutingCommand::Status, 0);
        state = controller.command(RoutingCommand::Start, state.generation);
        const auto deadline = GetTickCount64() + 45000;
        bool active = false;
        bool blocked = false;
        while (GetTickCount64() < deadline) {
            state = controller.command(RoutingCommand::Status, 0);
            if (state.phase == RoutingPhase::Active && !active) {
                active = true;
                QTextStream(stdout) << "ACTIVE service worker" << Qt::endl;
            }
            if (reject_open && state.phase == RoutingPhase::Blocked) {
                Sleep(500);
                state = controller.command(RoutingCommand::Status, 0);
                if (state.phase != RoutingPhase::Blocked) {
                    throw std::runtime_error("Setup failure released the guarded worker before Stop");
                }
                blocked = true;
                break;
            }
            if (state.phase == RoutingPhase::Blocked || state.phase == RoutingPhase::Failed) {
                throw std::runtime_error("Service worker failed; stopping fixture");
            }
            Sleep(50);
        }
        state = controller.command(RoutingCommand::Stop, state.generation);
        const auto stop_deadline = GetTickCount64() + 15000;
        while (state.phase == RoutingPhase::Stopping && GetTickCount64() < stop_deadline) {
            Sleep(50);
            state = controller.command(RoutingCommand::Status, 0);
        }
        if ((reject_open ? !blocked || active : !active) || state.phase != RoutingPhase::Idle) {
            throw std::runtime_error("Service worker did not complete Active -> Stop -> Idle");
        }
        QTextStream(stdout) << (reject_open ? "PASS: setup failure retries while Blocked until Stop\n"
                                            : "PASS: service worker Active -> Stop -> Idle\n");
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
