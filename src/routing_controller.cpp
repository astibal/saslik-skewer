#include "routing_controller.hpp"

#include "routing_plan.hpp"

#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>

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
    return invoke({QStringLiteral("up"), next_hop}, authorization);
}

RoutingResult RoutingController::deactivate(Authorization authorization) const
{
    return invoke({QStringLiteral("down")}, authorization);
}

bool RoutingController::active() const
{
    const RoutingResult result = run(QStringLiteral("/usr/sbin/ip"),
        {QStringLiteral("-4"), QStringLiteral("rule"), QStringLiteral("show"),
         QStringLiteral("pref"),
         QString::number(RoutingPlanner::rulePriority(getuid()))}, 3000);
    return result.ok && !result.detail.isEmpty() && result.detail != QStringLiteral("Command failed");
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
