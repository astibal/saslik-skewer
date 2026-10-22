#include "tuntom_process.hpp"
#include "tuntom_control.hpp"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QLockFile>
#include <QProcess>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QTextStream>
#include <csignal>
#include <poll.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
volatile std::sig_atomic_t interrupted = 0;
void interrupt(int) { interrupted = 1; }

QByteArray command(const QStringList& args)
{
    QProcess p;
    p.start("/usr/sbin/ip", args);
    if (!p.waitForStarted(3000) || !p.waitForFinished(5000)) {
        p.kill(); p.waitForFinished();
        throw std::runtime_error("Tunnel network setup timed out");
    }
    if (p.exitStatus() != QProcess::NormalExit || p.exitCode())
        throw std::runtime_error("Tunnel network setup failed");
    return p.readAllStandardOutput();
}

// No shell, environment expansion or user-selected executable is involved.
void validateSubnet(const Tuntom::Endpoint& endpoint)
{
    const auto local = QHostAddress(endpoint.clientAddress.chopped(3)).toIPv4Address();
    const auto routes = QJsonDocument::fromJson(command({"-j", "-4", "route", "show", "table", "all"}));
    if (!routes.isArray()) throw std::runtime_error("Cannot inspect existing routes");
    for (const auto row : routes.array()) {
        auto dst = row.toObject()["dst"].toString();
        if (dst.isEmpty() || dst == "default") continue;
        if (!dst.contains('/')) dst += "/32";
        const auto subnet = QHostAddress::parseSubnet(dst);
        if (subnet.second < 0) throw std::runtime_error("Cannot inspect route prefix");
        const auto network = QHostAddress(local & ~quint32(3));
        if (network.isInSubnet(subnet) || subnet.first.isInSubnet(network, 30))
            throw std::runtime_error("Tunnel subnet overlaps an existing route");
    }
}
}

int tuntomProcess(uid_t owner)
{
    QProcess transport;
    try {
        QFile cgroup("/proc/self/cgroup");
        if (!cgroup.open(QIODevice::ReadOnly)
            || !cgroup.readAll().contains(QString("/skewer-tuntom-%1.service\n").arg(owner).toUtf8()))
            throw std::runtime_error("Tunnel worker must be owned by its systemd service");
        QLockFile lock(QString("/run/skewer-tuntom-%1.lock").arg(owner));
        if (!lock.tryLock(0)) throw std::runtime_error("A tunnel session is already running");
        QByteArray input;
        QElapsedTimer timer; timer.start();
        while (!input.contains('\n') && input.size() < 16384 && timer.elapsed() < 10000) {
            pollfd fd{STDIN_FILENO, POLLIN, 0};
            if (::poll(&fd, 1, 100) <= 0) continue;
            char bytes[1024]; const auto n = ::read(STDIN_FILENO, bytes, sizeof(bytes));
            if (n <= 0) throw std::runtime_error("Tunnel request pipe closed");
            input.append(bytes, n);
        }
        if (!input.endsWith('\n') || input.size() >= 16384)
            throw std::runtime_error("Invalid tunnel request framing");
        auto request = QJsonDocument::fromJson(input).object();
        const auto endpoint = Tuntom::endpointFromResponse(request);
        const auto keyHex = request["key"].toString().toLatin1();
        const auto key = QByteArray::fromHex(keyHex);
        if (key.size() != 16 || key.toHex() != keyHex)
            throw std::runtime_error("Invalid tunnel key");
        QHostAddress remote(request["host"].toString());
        if (remote.protocol() != QAbstractSocket::IPv4Protocol || remote.isNull() || remote.isMulticast())
            throw std::runtime_error("Tunnel server must be a resolved IPv4 address");
        if (remote.isInSubnet(QHostAddress::parseSubnet(endpoint.clientAddress)))
            throw std::runtime_error("Tunnel address pool contains its own transport destination");
        const QString binary = "/usr/libexec/saslik/tuntom";
        struct stat metadata{};
        if (::stat(binary.toLocal8Bit().constData(), &metadata) || !S_ISREG(metadata.st_mode)
            || metadata.st_uid != 0 || (metadata.st_mode & 0022) || !(metadata.st_mode & 0111))
            throw std::runtime_error("Install the root-owned tuntom transport in /usr/libexec/saslik/tuntom");
        const auto* account = ::getpwnam("tuntom");
        if (!account || account->pw_uid == 0) throw std::runtime_error("The tuntom runtime account is missing");
        if (QFile::exists("/sys/class/net/" + endpoint.clientInterface))
            throw std::runtime_error("Tunnel interface already exists");
        validateSubnet(endpoint);
        QTemporaryDir runtime("/run/skewer-tuntom-XXXXXX");
        if (!runtime.isValid() || ::chown(runtime.path().toLocal8Bit().constData(), account->pw_uid, account->pw_gid))
            throw std::runtime_error("Cannot prepare tunnel runtime directory");
        const auto statsPath = runtime.path() + "/stats";
        QProcessEnvironment environment;
        environment.insert("PATH", "/usr/sbin:/usr/bin");
        environment.insert("TUNTOM_SECRET", QString::fromLatin1(keyHex));
        transport.setProcessEnvironment(environment);
        // The service's KillMode=control-group owns the child even after its
        // privilege drop (which would clear PR_SET_PDEATHSIG).
        transport.start(binary, {"client", QString::number(endpoint.id), endpoint.clientInterface,
            remote.toString(), "--stats-file", statsPath});
        if (!transport.waitForStarted(5000)) throw std::runtime_error("Cannot start tuntom");
        timer.restart();
        while (!QFile::exists("/sys/class/net/" + endpoint.clientInterface)) {
            if (transport.waitForFinished(50) || timer.elapsed() > 5000)
                throw std::runtime_error("tuntom did not create its interface");
        }
        command({"address", "add", endpoint.clientAddress, "dev", endpoint.clientInterface});
        command({"link", "set", "dev", endpoint.clientInterface, "up"});
        std::signal(SIGTERM, interrupt); std::signal(SIGINT, interrupt);
        // The parent renews this local lease only after the server accepted its
        // heartbeat. EOF, timeout or explicit stop tears down the transport.
        timer.restart();
        QByteArray pending;
        QElapsedTimer probe; probe.start();
        QString previousState = "prepared";
        QTextStream(stdout) << "{\"state\":\"prepared\"}\n" << Qt::flush;
        while (!interrupted && timer.elapsed() < 30000) {
            if (transport.waitForFinished(100)) throw std::runtime_error("tuntom exited");
            transport.readAllStandardOutput(); transport.readAllStandardError();
            if (probe.elapsed() >= 3000) {
                QFile stats(statsPath);
                bool ready = stats.open(QIODevice::ReadOnly)
                    && Tuntom::confirmedSnapshot(stats.read(65537), endpoint.id, QDateTime::currentSecsSinceEpoch());
                if (ready) {
                    // Confirmation alone can outlive the peer. Check the data
                    // path too; readiness never follows mere interface creation.
                    QProcess ping;
                    ping.start("/usr/bin/ping", {"-n", "-I", endpoint.clientInterface,
                        "-c", "1", "-W", "1", endpoint.serverAddress.chopped(3)});
                    ready = ping.waitForStarted(1000) && ping.waitForFinished(1500)
                        && ping.exitStatus() == QProcess::NormalExit && ping.exitCode() == 0;
                    if (ping.state() != QProcess::NotRunning) { ping.kill(); ping.waitForFinished(); }
                }
                const QString state = ready ? "verified" : "waiting";
                if (state != previousState) {
                    QTextStream(stdout) << "{\"state\":\"" << state << "\"}\n" << Qt::flush;
                    previousState = state;
                }
                probe.restart();
            }
            pollfd fd{STDIN_FILENO, POLLIN, 0};
            if (::poll(&fd, 1, 0) > 0) {
                char bytes[128]; const auto n = ::read(STDIN_FILENO, bytes, sizeof(bytes));
                if (n <= 0) break;
                pending.append(bytes, n);
                while (pending.contains('\n')) {
                    const auto line = pending.first(pending.indexOf('\n'));
                    pending.remove(0, pending.indexOf('\n') + 1);
                    if (line == "keepalive") timer.restart();
                    else if (line == "stop") interrupted = 1;
                    else throw std::runtime_error("Invalid tunnel lease command");
                }
                if (pending.size() > 128) throw std::runtime_error("Invalid tunnel lease framing");
            }
        }
        transport.terminate();
        if (!transport.waitForFinished(2000)) { transport.kill(); transport.waitForFinished(); }
        return 0;
    } catch (const std::exception& error) {
        transport.kill(); transport.waitForFinished(2000);
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}

int tuntomService(uid_t owner)
{
    QProcess service;
    service.setInputChannelMode(QProcess::ForwardedInputChannel);
    service.setProcessChannelMode(QProcess::ForwardedChannels);
    service.start("/usr/bin/systemd-run", {"--quiet", "--pipe", "--collect",
        "--service-type=exec", QString("--unit=skewer-tuntom-%1").arg(owner),
        "--property=KillMode=control-group", "--property=TimeoutStopSec=5",
        "--property=Restart=no", QString("--setenv=PKEXEC_UID=%1").arg(owner),
        "--", QCoreApplication::applicationFilePath(), "tunnel-worker"});
    if (!service.waitForStarted(5000)) return 1;
    service.waitForFinished(-1);
    return service.exitStatus() == QProcess::NormalExit ? service.exitCode() : 1;
}
