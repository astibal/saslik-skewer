#include "routing_service.hpp"
#include "service_host.hpp"
#include "whole_host_policy.hpp"
#include "selected_service_tunnel.hpp"
#include "direct_host_policy.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <optional>

using namespace skewer::windows;

// Arguments are administrator-owned SCM configuration, not commands supplied
// by the unprivileged pipe client. Credentials arrive only through the handoff.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if ((args.size() != 4 && args.size() != 7 && args.size() != 8) || args[1] != "--service") {
        QTextStream(stderr)
            << "Expected --service NAME OWNER_SID [ENDPOINT IPV4_PEER DNS_SERVER [SSH_MANAGEMENT_IP]]\n";
        return 2;
    }
    try {
        const auto name = args[2].toStdWString();
        const ServiceOwner owner(args[3].toStdWString());
        struct TunnelConfiguration {
            QUrl endpoint;
            QString peer;
            std::wstring dns;
            std::string management;
        };
        std::optional<TunnelConfiguration> tunnel;
        if (args.size() >= 7) {
            const QUrl endpoint(args[4]);
            if (endpoint.scheme() != "skewer" || endpoint.path() != "/pair" || endpoint.host().isEmpty() ||
                endpoint.port() < 1 || endpoint.port() > 65535 || endpoint.hasQuery() ||
                endpoint.hasFragment() || !endpoint.userInfo().isEmpty()) {
                throw std::invalid_argument("Invalid configured pairing endpoint");
            }
            tunnel.emplace(TunnelConfiguration{endpoint, args[5], args[6].toStdWString(),
                                               args.size() == 8 ? args[7].toStdString()
                                                                : std::string{}});
        }
        const auto directory = QCoreApplication::applicationDirPath();
        const auto wintun = QDir::toNativeSeparators(directory + "/wintun.dll").toStdWString();
        const auto divert = QDir::toNativeSeparators(directory + "/WinDivert.dll").toStdWString();
        return runService(name, [&](HANDLE stop) -> DWORD {
            // The service remains LocalSystem. Expose only the process identity
            // rights needed by its configured unelevated owner to authenticate IPC.
            allowSelectionServiceInspection(owner);
            PairedRoutingRunner whole_host;
            SelectedRoutingRunner selected;
            if (tunnel) {
                whole_host = [&](const PairingHandoff& pairing, HANDLE cancel, RoutingSignals& state) {
                    if (QUrl(QString::fromStdString(pairing.endpoint)) != tunnel->endpoint) {
                        throw std::invalid_argument("Pairing does not match the configured service endpoint");
                    }
                    PskTunnelControl control(
                        tunnel->endpoint, tunnel->peer, QByteArray::fromStdString(pairing.identity),
                        QByteArray(reinterpret_cast<const char*>(pairing.key.data()), pairing.key.size()));
                    WholeHostPolicy policy(tunnel->peer.toStdString(), tunnel->endpoint.port(),
                                           tunnel->management);
                    const auto result = runConfiguredServiceTunnel(
                        loadWintun(wintun), L"Skewer-" + name, control, tunnel->peer,
                        [&](NET_LUID luid) {
                            return std::make_unique<traffic::PacketCapture>(divert, policy.filter(luid));
                        },
                        [&](NET_LUID luid, const Tuntom::Endpoint& endpoint) {
                            return policy.routes(luid, endpoint);
                        },
                        cancel, state.ready, state.blocked, tunnel->dns, &state.retry_error, &state);
                    if (result.worker.session_error) {
                        std::rethrow_exception(result.worker.session_error);
                    }
                    if (result.worker.unexpected_session_exit) {
                        throw std::runtime_error("Tunnel exited without Stop");
                    }
                };
                selected = [&](const PairingHandoff& pairing, std::unique_ptr<ProcessTarget> target,
                               HANDLE cancel, RoutingSignals& state) {
                    if (QUrl(QString::fromStdString(pairing.endpoint)) != tunnel->endpoint) {
                        throw std::invalid_argument("Pairing does not match the configured service endpoint");
                    }
                    PskTunnelControl control(
                        tunnel->endpoint, tunnel->peer, QByteArray::fromStdString(pairing.identity),
                        QByteArray(reinterpret_cast<const char*>(pairing.key.data()), pairing.key.size()));
                    runSelectedServiceTunnel(divert, std::move(target), owner, control, tunnel->peer,
                                             tunnel->endpoint.port(), cancel, state);
                };
            }
            serveRoutingService(name, owner, stop, std::move(whole_host), std::move(selected),
                [&](std::array<std::uint8_t, 4> gateway, HANDLE cancel, RoutingSignals& state) {
                    runDirectHostRouting(divert, gateway, {}, cancel, state);
                });
            return 0;
        });
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
