#include "session_guard.hpp"
#include "routing_guard.hpp"
#include "session_status.hpp"
#include <QTemporaryDir>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QSettings>
#include <QStandardPaths>
#include <QThread>
#include <QTextStream>
#include <systemd/sd-bus.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <optional>
#include <vector>
#include <cerrno>

namespace {
QByteArray read(const QString& path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray{};
}

struct Process {
    GuardIdentity identity;
    QString group;
};

std::optional<Process> inspect(pid_t pid)
{
    const QString base = QString("/proc/%1").arg(pid);
    struct stat metadata{};
    if (pid <= 1 || ::stat(base.toLocal8Bit().constData(), &metadata) != 0
        || metadata.st_uid != getuid()) return {};
    const QByteArray stat = read(base + "/stat");
    // comm may contain spaces and parentheses; fields after the final ')' are stable.
    const int end = stat.lastIndexOf(')');
    if (end < 0) return {};
    const auto fields = stat.mid(end + 2).split(' ');
    if (fields.size() <= 19 || fields[0] == "Z") return {};
    bool valid = false;
    const auto start = fields[19].toULongLong(&valid);
    const auto group = read(base + "/cgroup").trimmed();
    if (!valid || !group.startsWith("0::")) return {};
    return Process{{pid, metadata.st_uid, start}, QString::fromUtf8(group.mid(3))};
}

void report(const QString& message, bool terminal = true)
{
    const QString line = "skewer session: " + message + '\n';
    if (terminal) {
        const QByteArray output = line.toLocal8Bit();
        ::write(STDERR_FILENO, output.constData(), output.size());
    }
    const QString directory = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/skewer";
    QDir().mkpath(directory);
    QFile log(directory + "/session.log");
    if (log.open(QIODevice::WriteOnly | QIODevice::Append)) log.write(line.toUtf8());
}

bool repair(sd_bus* bus, const QString& unit, const GuardIdentity& identity, bool log_failure)
{
    // Recheck ownership and birth time immediately before the PID-based systemd API.
    const auto current = inspect(identity.pid);
    if (!current || !sameProcess(identity, current->identity)) return false;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    const int result = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "AttachProcessesToUnit", &error, nullptr,
        "ssau", unit.toUtf8().constData(), "", 1, static_cast<uint32_t>(identity.pid));
    if (result < 0 && log_failure) report(QString("cannot restore PID %1: %2 (further retries are silent)").arg(identity.pid)
        .arg(error.message ? QString::fromUtf8(error.message) : QString("systemd error %1").arg(result)));
    const auto after = result >= 0 ? inspect(identity.pid) : std::nullopt;
    const bool restored = after && sameProcess(identity, after->identity) && routedGroup(after->group);
    if (restored) report(QString("restored PID %1 to %2").arg(identity.pid).arg(unit), false);
    else if (result >= 0 && log_failure) report(QString("PID %1 is not back in the routed cgroup yet; retrying silently").arg(identity.pid));
    sd_bus_error_free(&error);
    return restored;
}

void watch(Process root, pid_t guard_pid, const QString& status_directory)
{
    std::unique_ptr<QThread> status;
    if (!status_directory.isEmpty()) {
        status.reset(QThread::create([=] { watchSessionStatus(root.identity.pid, status_directory); }));
        status->start();
    }
    struct Tracked { GuardIdentity identity; qint64 discovered; qint64 retry_after{}; bool warned{}; };
    QElapsedTimer clock; clock.start();
    QHash<pid_t, Tracked> tracked;
    tracked.insert(root.identity.pid, {root.identity, 0});
    const QString unit = root.group.section('/', -1);
    sd_bus* bus = nullptr;
    if (sd_bus_open_user(&bus) < 0) { report("cannot connect guard to user systemd; monitoring only"); }
    if (bus) sd_bus_set_method_call_timeout(bus, 100000); // Do not block forever on a stalled manager.
    bool root_alive = true;
    while (!tracked.isEmpty()) {
        const qint64 tick = clock.elapsed();
        const auto pids = tracked.keys();
        for (pid_t pid : pids) {
            auto entry = tracked.value(pid);
            const auto process = inspect(pid);
            if (!process || !sameProcess(entry.identity, process->identity)) {
                tracked.remove(pid);
                if (pid == root.identity.pid) root_alive = false;
                continue;
            }
            // Read only this known subtree, including children created by non-leader threads.
            if (root_alive) {
                const QString tasks = QString("/proc/%1/task").arg(pid);
                for (const auto& tid : QDir(tasks).entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
                    for (const auto& word : read(tasks + '/' + tid + "/children").simplified().split(' ')) {
                        bool valid = false; const pid_t child = word.toInt(&valid);
                        if (!valid || child == guard_pid || tracked.contains(child)) continue;
                        if (const auto observed = inspect(child)) tracked.insert(child, {observed->identity, clock.elapsed()});
                    }
                }
            }
            // The session root must remain protected for its entire lifetime.
            if ((pid == root.identity.pid || guardWindowOpen(entry.discovered, clock.elapsed())) && !routedGroup(process->group)
                && clock.elapsed() >= entry.retry_after && bus) {
                // Keep inspecting at 10 ms, but back off failed D-Bus repairs to avoid flooding the manager.
                if (!repair(bus, unit, entry.identity, !entry.warned)) {
                    tracked[pid].retry_after = clock.elapsed() + 100;
                    tracked[pid].warned = true;
                }
            }
            // Once the shell exits, finish outstanding windows without retaining background jobs forever.
            if (!root_alive && !guardWindowOpen(entry.discovered, clock.elapsed())) tracked.remove(pid);
        }
        const auto remaining = 10 - (clock.elapsed() - tick);
        if (remaining > 0) QThread::msleep(static_cast<unsigned long>(remaining));
    }
    sd_bus_unref(bus);
    if (status) {
        status->requestInterruption();
        status->wait();
        QFile::remove(status_directory + "/status");
        QDir().rmdir(status_directory);
    }
}

bool startGuard(const Process& root, const QString& status_directory)
{
    // Double fork: the shell keeps its PID/terminal and does not acquire a waitable watchdog job.
    int ready[2];
    if (::pipe2(ready, O_CLOEXEC) != 0) return false;
    const pid_t intermediate = fork();
    if (intermediate == 0) {
        ::close(ready[0]);
        if (setsid() < 0) _exit(1);
        const pid_t child = fork();
        if (child < 0) _exit(1);
        if (child > 0) _exit(0);
        const char ok = 1;
        ::write(ready[1], &ok, 1); ::close(ready[1]);
        watch(root, getpid(), status_directory);
        _exit(0);
    }
    ::close(ready[1]);
    char ok = 0;
    const bool started = intermediate > 0 && ::read(ready[0], &ok, 1) == 1 && ok == 1;
    ::close(ready[0]);
    if (intermediate > 0) while (waitpid(intermediate, nullptr, 0) < 0 && errno == EINTR) {}
    return started;
}
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    QCoreApplication::setOrganizationName("Saslik");
    QCoreApplication::setApplicationName("Skewer");
    QStringList command = application.arguments().sliced(1);
    const bool shell = command == QStringList{"--shell"};
    if (shell) {
        QString program = qEnvironmentVariable("SHELL", "/bin/bash");
        if (!QFileInfo(program).isAbsolute() || !QFileInfo(program).isExecutable()) program = "/bin/bash";
        command = {program, "-i"};
        if (QFileInfo(program).fileName() == "bash") {
            const QString startup = QCoreApplication::applicationDirPath() + "/skewer.bashrc";
            if (!QFileInfo(startup).isReadable()) {
                report("missing Skewer Bash startup file: " + startup); return 1;
            }
            command = {program, "--rcfile", startup, "-i"};
        }
    } else if (!command.isEmpty() && command.first() == "--") command.removeFirst();
    if (command.isEmpty()) { report("no command provided"); return 2; }
    const auto root = inspect(getpid());
    if (!root || !routedGroup(root->group)) { report("refusing to launch outside skewer-routed.slice"); return 1; }
    QString protection_error;
    if (!RoutingGuard::ensure(protection_error)) { report(protection_error); return 1; }
    const QString bundle = QSettings().value("runtimeTrust/activeBundle").toString();
    const QString ca = QSettings().value("runtimeTrust/activeCa").toString();
    if (!bundle.isEmpty()) {
        if (!QFileInfo(bundle).isReadable() || !QFileInfo(ca).isReadable()) {
            report("prepared CA files are missing; prepare the bundle again before launching"); return 1;
        }
        for (const auto* variable : {"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT"})
            qputenv(variable, bundle.toLocal8Bit());
        qputenv("NODE_EXTRA_CA_CERTS", ca.toLocal8Bit());
        report("using prepared runtime CA bundle: " + bundle, false);
    }
    qputenv("SKEWER_SESSION", "1");
    qputenv("SKEWER_CGROUP", root->group.toUtf8());
    qputenv("SKEWER_GATEWAY", QSettings().value("routing/nextHop").toString().toUtf8());
    qputenv("SKEWER_API_URL", QSettings().value("routing/saslikUrl").toString().toUtf8());
    qputenv("SKEWER_CA_FILE", ca.toUtf8());
    QString status_directory;
    if (shell) {
        QTemporaryDir directory(QDir::tempPath() + "/skewer-status-XXXXXX");
        if (!directory.isValid()) { report("cannot create session status cache"); return 1; }
        directory.setAutoRemove(false);
        status_directory = directory.path();
        qputenv("SKEWER_STATUS_FILE", (status_directory + "/status").toLocal8Bit());
    }
    if (!startGuard(*root, status_directory)) {
        if (!status_directory.isEmpty()) QDir().rmdir(status_directory);
        report("cannot start cgroup guard; command was not launched"); return 1;
    }
    report("cgroup guard active: lifetime protection for session root, 5 seconds per discovered child, 10 ms target interval; existing sockets cannot be repaired", false);
    QList<QByteArray> encoded;
    for (const auto& argument : command) encoded << argument.toLocal8Bit();
    std::vector<char*> pointers;
    for (auto& argument : encoded) pointers.push_back(argument.data());
    pointers.push_back(nullptr);
    execvp(pointers[0], pointers.data());
    const int failure = errno;
    perror("skewer session exec");
    return failure == ENOENT ? 127 : 126;
}
