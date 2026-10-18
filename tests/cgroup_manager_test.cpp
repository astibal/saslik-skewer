#include "cgroup_manager.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QThread>

#include <iostream>

namespace {
QString cgroupFor(qint64 pid)
{
    QFile file(QStringLiteral("/proc/%1/cgroup").arg(pid));
    if (!file.open(QIODevice::ReadOnly)) return {};
    return QString::fromUtf8(file.readAll());
}

bool waitForCgroup(qint64 pid, const QString& needle)
{
    for (int attempt = 0; attempt < 30; ++attempt) {
        if (cgroupFor(pid).contains(needle)) return true;
        QThread::msleep(20);
    }
    return false;
}
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    QProcess child;
    child.start(QStringLiteral("/usr/bin/sleep"), {QStringLiteral("20")});
    if (!child.waitForStarted()) {
        std::cerr << "cannot start test process\n";
        return 1;
    }

    CgroupManager manager;
    const QVector<pid_t> pids{static_cast<pid_t>(child.processId())};
    const CgroupResult routed = manager.route(pids, QStringLiteral("integration-test"));
    if (!routed.ok || !waitForCgroup(child.processId(), QStringLiteral("skewer-routed.slice"))) {
        std::cerr << "route failed: " << routed.detail.toStdString() << '\n';
        child.kill();
        child.waitForFinished();
        return 2;
    }

    const CgroupResult released = manager.release(pids, QStringLiteral("integration-test"));
    if (!released.ok || !waitForCgroup(child.processId(), QStringLiteral("skewer-direct-"))) {
        std::cerr << "release failed: " << released.detail.toStdString() << '\n';
        child.kill();
        child.waitForFinished();
        return 3;
    }
    child.terminate();
    child.waitForFinished();
    return 0;
}
