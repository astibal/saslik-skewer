#include "pairing.hpp"
#include "diagnostic_log.hpp"
#include "preferences_values.hpp"
#include "tuntom_binary.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHostInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QTextStream>
#include <csignal>
#include <optional>
#include <QSettings>
#include <QJsonArray>
#include <poll.h>
#include <unistd.h>

namespace {
volatile std::sig_atomic_t stopped = 0;
void stop(int) { stopped = 1; }

// The GUI owns the one authorized helper session. Requests and replies stay
// on private pipes; never log this stream because tunnel-start carries a key.
QString guiHelper(const QStringList& args)
{
    QTextStream(stdout) << QJsonDocument(QJsonObject{{"helper_request", QJsonArray::fromStringList(args)}})
        .toJson(QJsonDocument::Compact) << '\n' << Qt::flush;
    QByteArray response;
    QElapsedTimer deadline; deadline.start();
    while (!response.endsWith('\n') && deadline.elapsed() < 65000) {
        pollfd input{STDIN_FILENO, POLLIN, 0};
        if (::poll(&input, 1, 250) <= 0) continue;
        char byte;
        if (::read(STDIN_FILENO, &byte, 1) != 1) throw std::runtime_error("GUI helper channel closed");
        response += byte;
        if (response.size() > 65536) throw std::runtime_error("Invalid GUI helper response");
    }
    const auto reply = QJsonDocument::fromJson(response).object();
    if (!reply["ok"].toBool()) throw std::runtime_error(reply["detail"].toString("GUI helper unavailable").toStdString());
    return reply["detail"].toString();
}
}

int tuntomClientCommand(const QStringList& arguments)
{
    const bool gui = arguments.size() == 4 && arguments[3] == "--gui-route";
    if (arguments.size() != 3 && !gui) {
        QTextStream(stderr) << "Usage: skewer tunnel skewer://HOST:PORT/pair [--gui-route]\n";
        return 2;
    }
    const QUrl address(arguments[2]);
    if (address.scheme() != "skewer" || address.host().isEmpty() || address.port() <= 0 || address.path() != "/pair" || address.hasFragment()
        || address.hasQuery() || !address.userInfo().isEmpty()) return 2;
    QString current_phase;
    auto phase = [gui, &current_phase](const QString& message) {
        current_phase = message;
        DiagnosticLog::write("phase", message);
        if (gui) QTextStream(stdout) << QJsonDocument(QJsonObject{{"phase", message}}).toJson(QJsonDocument::Compact) << '\n' << Qt::flush;
    };
    const auto preflight = Preferences::tunnelPreflightError();
    if (!preflight.isEmpty()) {
        DiagnosticLog::write("preflight", preflight, "error");
        if (gui) QTextStream(stdout) << QJsonDocument(QJsonObject{{"state", "failed"}, {"error", preflight}, {"retryable", false}}).toJson(QJsonDocument::Compact) << '\n' << Qt::flush;
        else QTextStream(stderr) << preflight << '\n';
        return 2;
    }
    std::optional<PairedTunnel> tunnel;
    QString host;
    QProcess helper;
    DiagnosticLog::Lines transport_diagnostics;
    bool gui_helper_started = false;
    auto cleanup = [&] {
        if (gui_helper_started) {
            try { guiHelper({"tunnel-stop"}); } catch (const std::exception&) {}
            gui_helper_started = false;
        }
        if (helper.state() != QProcess::NotRunning) {
            helper.write("stop\n"); helper.closeWriteChannel();
            helper.waitForFinished(8000);
        }
        transport_diagnostics.append(helper.readAllStandardError(), "transport");
        transport_diagnostics.finish("transport");
        if (tunnel) {
            try { closePairedTunnel(address, tunnel->endpoint, host); }
            catch (const std::exception&) {
                DiagnosticLog::write("cleanup", "Server cleanup pending lease expiry", "warning");
            }
        }
    };
    try {
        phase("Checking local transport binary");
        QString binary_error;
        const bool development = Preferences::developmentBinaryAcknowledged();
        const QString binary = Tuntom::checkedBinary(Preferences::tuntomBinary(), binary_error, development);
        if (binary.isEmpty()) throw std::runtime_error(binary_error.toStdString());
        if (gui) {
            phase("Preparing routed slice");
            QProcess slice;
            slice.start("systemctl", {"--user", "start", "skewer-routed.slice"});
            if (!slice.waitForFinished(10000) || slice.exitStatus() != QProcess::NormalExit || slice.exitCode())
                throw std::runtime_error("Cannot create routed cgroup");
        }
        phase("Resolving server address");
        const bool whole_host = gui && QSettings().value("routing/scope", "applications") == "host";
        // Recovery must not need external DNS while the host guard is closed.
        // Keep the authenticated endpoint identity for PSK lookup; pin only
        // the transport address, shared by UDP and control renewals.
        if (whole_host && QFile::exists("/run/skewer-host.json")
            && QSettings().value("routing/peerEndpoint") == address.toString()) {
            QHostAddress cached(QSettings().value("routing/peerAddress").toString());
            if (cached.protocol() == QAbstractSocket::IPv4Protocol) host = cached.toString();
        }
        if (host.isEmpty())
            for (const auto& ip : QHostInfo::fromName(address.host()).addresses())
                if (ip.protocol() == QAbstractSocket::IPv4Protocol) { host = ip.toString(); break; }
        if (host.isEmpty()) throw std::runtime_error("No IPv4 address for tunnel server");
        phase("Opening authenticated control session");
        tunnel = openPairedTunnel(address, host);
        if (whole_host) {
            QSettings settings;
            settings.setValue("routing/peerEndpoint", address.toString());
            settings.setValue("routing/peerAddress", host);
            settings.sync();
        }
        phase("Server endpoint accepted");
        const auto& ep = tunnel->endpoint;
        const QJsonObject metadata{{"version", 1}, {"transport", "tuntom"}, {"id", ep.id},
            {"port", 40000 + ep.id}, {"context", ep.context}, {"client_interface", ep.clientInterface},
            {"server_interface", QString("skt%1s").arg(ep.id)},
            {"server_address", ep.serverAddress}, {"client_address", ep.clientAddress}};
        const QJsonObject request{{"ok", true}, {"lease_seconds", ep.leaseSeconds}, {"tunnel", metadata},
            {"host", host}, {"key", QString::fromLatin1(tunnel->key.toHex())}, {"binary", binary},
            {"acknowledge_development_binary", development},
            {"scope", QSettings().value("routing/scope", "applications").toString()},
            {"control_port", address.port()},
            {"route", gui}, {"exemptions", QJsonArray::fromStringList(QSettings().value("routing/exemptions").toStringList())}};
        QString executable = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
        if (!QFileInfo(executable).isExecutable()) executable = SKEWER_INSTALLED_HELPER_PATH;
        helper.setProcessChannelMode(QProcess::SeparateChannels);
        phase("Starting privileged local helper");
        if (gui) {
            guiHelper({"tunnel-start", QString::fromUtf8(QJsonDocument(request).toJson(QJsonDocument::Compact))});
            gui_helper_started = true;
        } else {
            helper.start("/usr/bin/sudo", {executable, "tunnel-session"});
            if (!helper.waitForStarted(5000)) throw std::runtime_error("Cannot launch tunnel helper");
            helper.write(QJsonDocument(request).toJson(QJsonDocument::Compact) + '\n');
        }
        stopped = 0;
        std::signal(SIGINT, stop); std::signal(SIGTERM, stop);
        std::signal(SIGPIPE, SIG_IGN);
        QElapsedTimer heartbeat; heartbeat.start();
        QElapsedTimer startup; startup.start();
        bool prepared = false;
        QString last_reported_state;
        QByteArray pending;
        if (!gui) QTextStream(stdout) << "Starting tuntom; routing is not changed by this diagnostic command.\n" << Qt::flush;
        while (!stopped) {
            if (gui) {
                pollfd input{STDIN_FILENO, POLLIN, 0};
                if (::poll(&input, 1, 0) > 0 && (input.revents & (POLLIN | POLLHUP | POLLERR))) {
                    // The owning GUI's EOF or stop request ends this lease.
                    stopped = 1;
                    break;
                }
            }
            bool helper_running;
            QByteArray helper_error;
            if (gui) {
                const auto reply = QJsonDocument::fromJson(guiHelper({"tunnel-poll"}).toUtf8()).object();
                pending += reply["stdout"].toString().toUtf8();
                helper_error = reply["stderr"].toString().toUtf8();
                helper_running = reply["running"].toBool();
                ::poll(nullptr, 0, 100);
            } else {
                helper.waitForReadyRead(100);
                pending += helper.readAllStandardOutput();
                helper_error = helper.readAllStandardError();
                helper_running = helper.state() != QProcess::NotRunning;
            }
            while (pending.contains('\n')) {
                const auto line = pending.first(pending.indexOf('\n'));
                pending.remove(0, pending.indexOf('\n') + 1);
                const auto status = QJsonDocument::fromJson(line).object();
                const auto state = status["state"].toString();
                if (!state.isEmpty()) {
                    prepared = true;
                    if (gui) {
                        const QJsonObject progress{{"state", state}, {"gateway", ep.serverAddress.chopped(3)},
                            {"interface", ep.clientInterface}, {"stats", status["stats"].toObject()}};
                        QTextStream(stdout) << QJsonDocument(progress).toJson(QJsonDocument::Compact) << '\n' << Qt::flush;
                    } else if (state != last_reported_state) {
                        QTextStream(stdout) << "tuntom: " << state << '\n' << Qt::flush;
                    }
                    if (state != last_reported_state) DiagnosticLog::write("state", state);
                    last_reported_state = state;
                }
            }
            if (pending.size() > 65536) throw std::runtime_error("Invalid helper response");
            const auto error = helper_error;
            if (!error.isEmpty()) transport_diagnostics.append(error, "transport");
            if (!helper_running)
                throw std::runtime_error("Tunnel helper stopped");
            if (!prepared && startup.elapsed() > 120000)
                throw std::runtime_error("Tunnel startup timed out");
            if (heartbeat.elapsed() >= 10000) {
                heartbeatPairedTunnel(address, ep, host);
                if (prepared) {
                    if (gui) guiHelper({"tunnel-renew"});
                    else helper.write("keepalive\n");
                }
                heartbeat.restart();
            }
        }
        cleanup();
        return 0;
    } catch (const std::exception& error) {
        cleanup();
        const auto reason = QString::fromUtf8(error.what());
        const bool retryable = reason != "No pairing for this endpoint" && reason != "Invalid pairing credentials";
        const auto detail = DiagnosticLog::redact(current_phase + ": " + reason)
            + (retryable ? QString{} : QString(". Pair this endpoint again before retrying."));
        DiagnosticLog::write("failure", detail, "error");
        if (gui) QTextStream(stdout) << QJsonDocument(QJsonObject{{"state", "failed"}, {"error", detail}, {"retryable", retryable}}).toJson(QJsonDocument::Compact) << '\n' << Qt::flush;
        else QTextStream(stderr) << "Tunnel failed: " << detail << '\n';
        return retryable ? 1 : 2;
    }
}
