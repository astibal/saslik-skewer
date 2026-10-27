#include "paired_tunnel.hpp"
#include "wintun_device.hpp"
#include "processes.hpp"
#include <QCoreApplication>
#include <QJsonDocument>
#include <QTextStream>
#include <thread>

using namespace skewer::windows;
namespace {
class ReportingControl final : public TunnelControl {
public:
    explicit ReportingControl(PskTunnelControl& control) : control_(control) {}
    PairedTunnel open() override {
        auto value = control_.open();
        // Authenticated public configuration only. Never print the derived key.
        const QJsonObject config{{"id", value.endpoint.id},
                                 {"client_address", value.endpoint.clientAddress},
                                 {"server_address", value.endpoint.serverAddress}};
        QTextStream(stdout) << "ENDPOINT " << QJsonDocument(config).toJson(QJsonDocument::Compact)
                            << Qt::endl;
        return value;
    }
    void renew(const Tuntom::Endpoint& endpoint) override { control_.renew(endpoint); }
    void close(const Tuntom::Endpoint& endpoint) override { control_.close(endpoint); }

private:
    PskTunnelControl& control_;
};
} // namespace

// Explicit developer probe: one ephemeral adapter and a 45-second paired
// session. IP configuration is external; default routes and filters are untouched.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    app.setOrganizationName("Saslik");
    app.setApplicationName("Skewer");
    const auto args = app.arguments();
    if (args.size() != 5 || args[1] != "--live") {
        QTextStream(stderr)
            << "Usage: paired_tunnel_live --live ABSOLUTE_WINTUN_DLL PAIRED_ENDPOINT IPV4_PEER\n";
        return 2;
    }
    try {
        PskTunnelControl psk(QUrl(args[3]), args[4]);
        ReportingControl control(psk);
        Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!stop) {
            throw std::runtime_error("Cannot create cancellation event");
        }
        const auto name = L"SkewerPaired-" + std::to_wstring(GetCurrentProcessId());
        WintunDevice device(loadWintun(args[2].toStdWString()), name);
        QTextStream(stdout) << "ADAPTER " << QString::fromStdWString(name) << Qt::endl;
        std::jthread timer([event = stop.get()](std::stop_token token) {
            const auto deadline = TunnelPump::Clock::now() + std::chrono::seconds(45);
            while (!token.stop_requested() && TunnelPump::Clock::now() < deadline) {
                if (WaitForSingleObject(event, 50) != WAIT_TIMEOUT) {
                    return;
                }
            }
            SetEvent(event);
        });
        std::atomic_bool ready{};
        const auto counters = runPairedTunnel(device, control, psk.peer(), stop.get(), ready);
        QTextStream(stdout) << "Paired probe completed: tx=" << counters.tx << " rx=" << counters.rx
                            << " (not an application-routing readiness claim)\n";
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
