#include "routing_plan.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QTextStream>

#include <optional>
#include <unistd.h>

namespace {
constexpr auto ip_binary = "/usr/sbin/ip";
constexpr auto nft_binary = "/usr/sbin/nft";
constexpr auto update_ca_binary = "/usr/sbin/update-ca-certificates";

struct Result {
    int exit_code{-1};
    QByteArray output;
};

Result run(const QString& program, const QStringList& arguments,
           const QByteArray& input = {})
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted()) return {-1, process.errorString().toUtf8()};
    if (!input.isEmpty()) process.write(input);
    process.closeWriteChannel();
    if (!process.waitForFinished(15000)) {
        process.kill();
        process.waitForFinished();
        return {-1, QByteArray("command timed out")};
    }
    return {process.exitCode(), process.readAll()};
}

std::optional<uid_t> invokingUid()
{
    for (const char* name : {"PKEXEC_UID", "SUDO_UID"}) {
        const QByteArray value = qgetenv(name);
        bool ok = false;
        const qulonglong parsed = value.toULongLong(&ok);
        if (ok && parsed > 0 && parsed <= std::numeric_limits<uid_t>::max())
            return static_cast<uid_t>(parsed);
    }
    if (geteuid() != 0 && getuid() > 0) return getuid();
    return std::nullopt;
}

QString interfaceFor(const QString& next_hop, QString& error)
{
    const Result route = run(QString::fromLatin1(ip_binary),
                             {QStringLiteral("-4"), QStringLiteral("route"),
                              QStringLiteral("get"), next_hop});
    if (route.exit_code != 0) {
        error = QStringLiteral("Next hop is not reachable: %1")
                    .arg(QString::fromLocal8Bit(route.output).trimmed());
        return {};
    }
    const QString text = QString::fromLocal8Bit(route.output).simplified();
    if (text.split(QLatin1Char(' ')).contains(QStringLiteral("via"))) {
        error = QStringLiteral("Next hop must be directly reachable, not behind another gateway");
        return {};
    }
    const QRegularExpression match_dev(QStringLiteral("(?:^|\\s)dev\\s+(\\S+)"));
    const auto match = match_dev.match(text);
    if (!match.hasMatch()) {
        error = QStringLiteral("Cannot determine the next-hop interface");
        return {};
    }
    return match.captured(1);
}

int cgroupLevel(uid_t uid, QString& error)
{
    const QString relative = QStringLiteral("user.slice/user-%1.slice/user@%1.service/"
                                            "skewer.slice/skewer-routed.slice").arg(uid);
    if (!QDir(QStringLiteral("/sys/fs/cgroup/") + relative).exists()) {
        error = QStringLiteral("Skewer cgroup does not exist yet; attach or launch an application first");
        return 0;
    }
    return relative.count(QLatin1Char('/')) + 1;
}

bool execute(const RoutingCommand& command, QString& error)
{
    const QString program = command.program == QStringLiteral("ip")
        ? QString::fromLatin1(ip_binary) : QString::fromLatin1(nft_binary);
    const Result result = run(program, command.arguments);
    if (result.exit_code == 0 || command.allow_failure) return true;
    error = QStringLiteral("%1 failed: %2")
                .arg(command.program, QString::fromLocal8Bit(result.output).trimmed());
    return false;
}

void cleanup(const RoutingPlan& plan)
{
    QString ignored;
    for (const auto& command : plan.cleanup) execute(command, ignored);
}

int up(uid_t uid, const QString& next_hop)
{
    QString error;
    const QString interface_name = interfaceFor(next_hop, error);
    if (interface_name.isEmpty()) {
        QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
        return 2;
    }
    const int level = cgroupLevel(uid, error);
    if (!level) {
        QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
        return 2;
    }
    const RoutingPlan plan = RoutingPlanner::create(uid, next_hop, interface_name, level);
    if (!plan.valid) {
        QTextStream(stderr) << "skewer-net-helper: " << plan.error << '\n';
        return 2;
    }
    cleanup(plan);
    for (const auto& command : plan.prepare) {
        if (!execute(command, error)) {
            cleanup(plan);
            QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
            return 1;
        }
    }
    const Result nft = run(QString::fromLatin1(nft_binary), {QStringLiteral("-f"),
                                                              QStringLiteral("-")},
                           plan.nft_rules.toUtf8());
    if (nft.exit_code != 0) {
        cleanup(plan);
        QTextStream(stderr) << "skewer-net-helper: nft failed: "
                            << QString::fromLocal8Bit(nft.output).trimmed() << '\n';
        return 1;
    }
    QTextStream(stdout) << "active: cgroup traffic -> " << next_hop
                        << " via " << interface_name << '\n';
    return 0;
}

int down(uid_t uid)
{
    // The cleanup identifiers depend only on UID. Placeholder values are never
    // installed and merely let the shared planner produce the cleanup commands.
    const RoutingPlan plan = RoutingPlanner::create(uid, QStringLiteral("192.0.2.1"),
                                                     QStringLiteral("lo"));
    cleanup(plan);
    QTextStream(stdout) << "inactive\n";
    return 0;
}

int status(uid_t uid)
{
    const Result nft = run(QString::fromLatin1(nft_binary),
        {QStringLiteral("list"), QStringLiteral("table"), QStringLiteral("inet"),
         RoutingPlanner::tableName(uid)});
    const Result rule = run(QString::fromLatin1(ip_binary),
        {QStringLiteral("-4"), QStringLiteral("rule"), QStringLiteral("show"),
         QStringLiteral("pref"), QString::number(RoutingPlanner::rulePriority(uid))});
    const bool active = nft.exit_code == 0 && rule.exit_code == 0 && !rule.output.trimmed().isEmpty();
    QTextStream(stdout) << (active ? "active" : "inactive") << '\n';
    return active ? 0 : 3;
}

QString caTarget(const QString& identity)
{
    if (!QRegularExpression(QStringLiteral("^[A-Za-z0-9_.-]+$")).match(identity).hasMatch())
        return {};
    return QStringLiteral("/usr/local/share/ca-certificates/skewer-saslik-%1.crt").arg(identity);
}

int caInstall(uid_t uid, const QString& identity, const QString& source)
{
    const QString target = caTarget(identity);
    const QFileInfo info(source);
    QFile input(source);
    if (target.isEmpty() || !info.isFile() || info.isSymLink() || info.ownerId() != uid
        || info.size() <= 0 || info.size() > 1024 * 1024 || !input.open(QIODevice::ReadOnly)) {
        QTextStream(stderr) << "skewer-net-helper: invalid CA certificate source\n";
        return 2;
    }
    const QByteArray value = input.readAll();
    if (!value.contains("-----BEGIN CERTIFICATE-----")
        || !value.contains("-----END CERTIFICATE-----")) {
        QTextStream(stderr) << "skewer-net-helper: source is not a PEM certificate\n";
        return 2;
    }
    QFile::remove(target);
    if (!QFile::copy(source, target)) {
        QTextStream(stderr) << "skewer-net-helper: cannot install system certificate\n";
        return 1;
    }
    QFile::setPermissions(target, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    const Result update = run(QString::fromLatin1(update_ca_binary), {});
    if (update.exit_code != 0) {
        QFile::remove(target);
        QTextStream(stderr) << "skewer-net-helper: update-ca-certificates failed: "
                            << update.output << '\n';
        return 1;
    }
    return 0;
}

int caRemove(const QString& identity)
{
    const QString target = caTarget(identity);
    if (target.isEmpty()) return 2;
    QFile::remove(target);
    const Result update = run(QString::fromLatin1(update_ca_binary), {QStringLiteral("--fresh")});
    return update.exit_code == 0 ? 0 : 1;
}
}

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    if (geteuid() != 0) {
        QTextStream(stderr) << "skewer-net-helper: must run as root through pkexec or sudo\n";
        return 2;
    }
    const auto uid = invokingUid();
    if (!uid) {
        QTextStream(stderr) << "skewer-net-helper: cannot identify the invoking desktop user\n";
        return 2;
    }
    const QStringList arguments = application.arguments().sliced(1);
    if (arguments.size() == 3 && arguments.first() == QStringLiteral("ca-install"))
        return caInstall(*uid, arguments.at(1), arguments.at(2));
    if (arguments.size() == 2 && arguments.first() == QStringLiteral("ca-remove"))
        return caRemove(arguments.at(1));
    if (arguments == QStringList{QStringLiteral("down")}) return down(*uid);
    if (arguments == QStringList{QStringLiteral("status")}) return status(*uid);
    if (arguments.size() == 2 && arguments.first() == QStringLiteral("up"))
        return up(*uid, arguments.at(1));
    QTextStream(stderr) << "usage: skewer-net-helper up NEXT_HOP | down | status | "
                           "ca-install IDENTITY PEM | ca-remove IDENTITY\n";
    return 2;
}
