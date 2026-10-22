#pragma once
#include "privileged_session.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <sys/stat.h>
#include <unistd.h>

namespace RoutingGuard {
inline QString path(uid_t uid) { return QString("/run/skewer-guard-%1").arg(uid); }
inline QString cgroup(uid_t uid) {
    return QString("/sys/fs/cgroup/user.slice/user-%1.slice/user@%1.service/skewer.slice/skewer-routed.slice").arg(uid);
}
inline QByteArray identity(uid_t uid) {
    struct stat info{};
    if (::stat(cgroup(uid).toLocal8Bit().constData(), &info)) return {};
    return QByteArray::number(qulonglong(info.st_ino));
}
// Root-owned receipt for the lifetime of this exact cgroup. Skewer never
// removes its guard on Disable. External privileged firewall changes are not
// covered by this receipt and require reinstalling the guard.
inline bool installed(uid_t uid) {
    QFile file(path(uid));
    struct stat info{};
    if (::lstat(path(uid).toLocal8Bit().constData(), &info) || !S_ISREG(info.st_mode)
        || info.st_uid != 0 || (info.st_mode & 0022) || info.st_size > 64) return false;
    const auto current = identity(uid);
    return !current.isEmpty() && file.open(QIODevice::ReadOnly) && file.readAll().trimmed() == current;
}
inline bool ensure(QString& error) {
    if (installed(getuid())) return true;
    QProcess slice;
    slice.start("systemctl", {"--user", "start", "skewer-routed.slice"});
    if (!slice.waitForFinished(10000) || slice.exitCode()) {
        slice.kill(); slice.waitForFinished(); error = "Cannot prepare guarded slice"; return false;
    }
    QString helper = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
    if (!QFileInfo(helper).isExecutable()) {
#ifdef SKEWER_INSTALLED_HELPER_PATH
        helper = QString::fromUtf8(SKEWER_INSTALLED_HELPER_PATH);
#else
        helper = "/usr/libexec/skewer-net-helper";
#endif
    }
    const bool terminal = isatty(STDIN_FILENO) || (qEnvironmentVariableIsEmpty("DISPLAY") && qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"));
    const auto result = PrivilegedSession::request(helper, {"guard"}, !terminal);
    if (!result.ok || !installed(getuid())) {
        error = "Fail-closed protection could not be installed; refusing Attach/launch: " + result.detail;
        return false;
    }
    return true;
}
}
