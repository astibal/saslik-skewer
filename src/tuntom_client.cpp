#include "pairing.hpp"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHostInfo>
#include <QJsonDocument>
#include <QProcess>
#include <QTextStream>
#include <csignal>
#include <optional>

namespace {
volatile std::sig_atomic_t stopped = 0;
void stop(int) { stopped = 1; }
}

int tuntomClientCommand(const QStringList& arguments)
{
    if (arguments.size() != 3) {
        QTextStream(stderr) << "Usage: skewer tunnel skewer://HOST:PORT/pair\n";
        return 2;
    }
    const QUrl address(arguments[2]);
    std::optional<PairedTunnel> tunnel;
    QProcess helper;
    auto cleanup = [&] {
        if (helper.state() != QProcess::NotRunning) {
            helper.write("stop\n"); helper.closeWriteChannel();
            helper.waitForFinished(8000);
        }
        if (tunnel) {
            try { closePairedTunnel(address, tunnel->endpoint); }
            catch (const std::exception&) {
                QTextStream(stderr) << "Server cleanup pending lease expiry.\n";
            }
        }
    };
    try {
        QString host;
        for (const auto& ip : QHostInfo::fromName(address.host()).addresses())
            if (ip.protocol() == QAbstractSocket::IPv4Protocol) { host = ip.toString(); break; }
        if (host.isEmpty()) throw std::runtime_error("No IPv4 address for tunnel server");
        tunnel = openPairedTunnel(address);
        const auto& ep = tunnel->endpoint;
        const QJsonObject metadata{{"version", 1}, {"transport", "tuntom"}, {"id", ep.id},
            {"port", 40000 + ep.id}, {"context", ep.context}, {"client_interface", ep.clientInterface},
            {"server_interface", QString("skt%1s").arg(ep.id)},
            {"server_address", ep.serverAddress}, {"client_address", ep.clientAddress}};
        const QJsonObject request{{"ok", true}, {"lease_seconds", ep.leaseSeconds}, {"tunnel", metadata},
            {"host", host}, {"key", QString::fromLatin1(tunnel->key.toHex())}};
        QString executable = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
        if (!QFileInfo(executable).isExecutable()) executable = SKEWER_INSTALLED_HELPER_PATH;
        helper.setProcessChannelMode(QProcess::SeparateChannels);
        helper.start("/usr/bin/sudo", {executable, "tunnel-session"});
        if (!helper.waitForStarted(5000)) throw std::runtime_error("Cannot launch tunnel helper");
        helper.write(QJsonDocument(request).toJson(QJsonDocument::Compact) + '\n');
        stopped = 0;
        std::signal(SIGINT, stop); std::signal(SIGTERM, stop);
        QElapsedTimer heartbeat; heartbeat.start();
        QElapsedTimer startup; startup.start();
        bool prepared = false;
        QByteArray pending;
        QTextStream(stdout) << "Starting tuntom; routing is not changed by this diagnostic command.\n" << Qt::flush;
        while (!stopped) {
            helper.waitForReadyRead(100);
            pending += helper.readAllStandardOutput();
            while (pending.contains('\n')) {
                const auto line = pending.first(pending.indexOf('\n'));
                pending.remove(0, pending.indexOf('\n') + 1);
                const auto status = QJsonDocument::fromJson(line).object();
                const auto state = status["state"].toString();
                if (!state.isEmpty()) {
                    prepared = true;
                    QTextStream(stdout) << "tuntom: " << state << '\n' << Qt::flush;
                }
            }
            if (pending.size() > 65536) throw std::runtime_error("Invalid helper response");
            const auto error = helper.readAllStandardError();
            if (!error.isEmpty()) QTextStream(stderr) << error << Qt::flush;
            if (helper.state() == QProcess::NotRunning)
                throw std::runtime_error("Tunnel helper stopped");
            if (!prepared && startup.elapsed() > 120000)
                throw std::runtime_error("Tunnel startup timed out");
            if (heartbeat.elapsed() >= 10000) {
                heartbeatPairedTunnel(address, ep);
                if (prepared) helper.write("keepalive\n");
                heartbeat.restart();
            }
        }
        cleanup();
        return 0;
    } catch (const std::exception& error) {
        cleanup();
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
