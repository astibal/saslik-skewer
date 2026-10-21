#include "routing_controller.hpp"

#include "routing_plan.hpp"

#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QSettings>
#include <QFile>

#include <unistd.h>

#ifndef SKEWER_INSTALLED_HELPER_PATH
#define SKEWER_INSTALLED_HELPER_PATH "/usr/libexec/skewer-net-helper"
#endif

namespace {
RoutingResult run(const QString& program, const QStringList& arguments, int timeout_ms)
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted()) return {false, process.errorString()};
    if (!process.waitForFinished(timeout_ms)) {
        process.kill();
        process.waitForFinished();
        return {false, QStringLiteral("Command timed out")};
    }
    const QString detail = QString::fromLocal8Bit(process.readAll()).trimmed();
    return {process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0,
            detail.isEmpty() ? QStringLiteral("Command failed") : detail};
}
}

RoutingResult RoutingController::activate(const QString& next_hop,
                                           Authorization authorization) const
{
    const RoutingResult slice = run(QStringLiteral("systemctl"),
        {QStringLiteral("--user"), QStringLiteral("start"),
         QStringLiteral("skewer-routed.slice")}, 10000);
    if (!slice.ok) return {false, QStringLiteral("Cannot create Skewer cgroup: %1").arg(slice.detail)};
    QStringList arguments{QStringLiteral("up"), next_hop};
    arguments.append(QSettings().value("routing/exemptions").toStringList());
    return invoke(arguments, authorization);
}

RoutingResult RoutingController::updateExemptions(const QStringList& destinations, Authorization authorization) const
{
    QStringList arguments{QStringLiteral("exemptions")};
    arguments.append(destinations);
    return invoke(arguments, authorization);
}

RoutingResult RoutingController::deactivate(Authorization authorization) const
{
    return invoke({QStringLiteral("down")}, authorization);
}

RoutingResult RoutingController::cleanupTcp(const QVector<pid_t>& pids, Authorization authorization, bool preview) const
{
    QStringList arguments{preview ? "preview-tcp" : "cleanup-tcp"};
    for (pid_t pid : pids) {
        QFile file(QString("/proc/%1/stat").arg(pid));
        if (!file.open(QIODevice::ReadOnly)) return {false, "Process disappeared; refresh and retry."};
        const auto data = file.readAll();
        const auto fields = data.mid(data.lastIndexOf(')')+2).simplified().split(' ');
        if (fields.size() <= 19) return {false, "Cannot verify process identity."};
        arguments << QString::number(pid) + ':' + QString::fromLatin1(fields[19]);
    }
    return invoke(arguments,authorization);
}

bool RoutingController::active(const QString& next_hop) const
{
    const RoutingResult rule = run(QStringLiteral("/usr/sbin/ip"),
        {QStringLiteral("-4"), QStringLiteral("rule"), QStringLiteral("show"),
         QStringLiteral("pref"),
         QString::number(RoutingPlanner::rulePriority(getuid()))}, 3000);
    if (!rule.ok || rule.detail.isEmpty() || rule.detail == QStringLiteral("Command failed"))
        return false;

    const RoutingResult route = run(QStringLiteral("/usr/sbin/ip"),
        {QStringLiteral("-4"), QStringLiteral("route"), QStringLiteral("show"),
         QStringLiteral("table"), QString::number(RoutingPlanner::routeTable(getuid())),
         QStringLiteral("default")}, 3000);
    return route.ok && route.detail.contains(QStringLiteral("default via %1 ").arg(next_hop));
}

bool RoutingController::nextHopReachable(const QString& next_hop) const
{
    return !directInterface(next_hop).isEmpty();
}

QString RoutingController::directInterface(const QString& next_hop) const
{
    if (next_hop.isEmpty()) return {};
    const RoutingResult route = run(QStringLiteral("/usr/sbin/ip"),
        {QStringLiteral("-4"), QStringLiteral("route"), QStringLiteral("get"), next_hop}, 3000);
    if (!route.ok || route.detail.contains(QStringLiteral(" via "))
        || !route.detail.startsWith(next_hop + QLatin1Char(' '))) return {};
    const QRegularExpression device(QStringLiteral("(?:^|\\s)dev\\s+(\\S+)"));
    const auto match = device.match(route.detail);
    return match.hasMatch() ? match.captured(1) : QString{};
}

QString RoutingController::helperPath()
{
    const QString adjacent = QCoreApplication::applicationDirPath()
        + QStringLiteral("/skewer-net-helper");
    if (QFileInfo(adjacent).isExecutable()) return adjacent;
    return QString::fromLatin1(SKEWER_INSTALLED_HELPER_PATH);
}

RoutingResult RoutingController::invoke(const QStringList& helper_arguments,
                                        Authorization authorization)
{
    QStringList arguments;
    if (authorization == Authorization::Desktop) {
        arguments << helperPath() << helper_arguments;
        return run(QStringLiteral("/usr/bin/pkexec"), arguments, 120000);
    }
    arguments << helperPath() << helper_arguments;
    return run(QStringLiteral("/usr/bin/sudo"), arguments, 120000);
}
