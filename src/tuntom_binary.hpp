#pragma once
#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <sys/stat.h>

namespace Tuntom {
#ifndef SKEWER_DEVELOPMENT_BINARY
#define SKEWER_DEVELOPMENT_BINARY 0
#endif
inline constexpr bool developmentBinaryAllowed = SKEWER_DEVELOPMENT_BINARY == 1;
// Execute the canonical path we validated, never a user-controlled symlink.
// Writable ancestors would let a user replace an otherwise root-owned file.
inline QString checkedBinary(const QString& path, QString& error, bool acknowledgeDevelopment = false)
{
    if (!QDir::isAbsolutePath(path) || path.contains(QChar::Null)) { error = "Use an absolute path to tuntom"; return {}; }
    const QString canonical = QFileInfo(path).canonicalFilePath();
    if (canonical.isEmpty()) { error = "Transport not found: " + path; return {}; }
    if constexpr (developmentBinaryAllowed) {
        if (acknowledgeDevelopment) {
            struct stat info{};
            if (::stat(canonical.toLocal8Bit().constData(), &info) || !S_ISREG(info.st_mode)
                || !(info.st_mode & 0111)) {
                error = "Development transport must be a regular executable file"; return {};
            }
            error.clear();
            return canonical;
        }
    }
    if (QFileInfo(canonical).fileName() != "tuntom") {
        error = "The transport executable must be named tuntom"; return {};
    }
    struct stat info{};
    if (::stat(canonical.toLocal8Bit().constData(), &info) || !S_ISREG(info.st_mode)
        || info.st_uid != 0 || (info.st_mode & 0022) || !(info.st_mode & 0111)) {
        error = "Transport must be executable, root-owned and not group/world-writable"; return {};
    }
    QString directory = QFileInfo(canonical).absolutePath();
    for (;;) {
        if (::stat(directory.toLocal8Bit().constData(), &info) || !S_ISDIR(info.st_mode)
            || info.st_uid != 0 || (info.st_mode & 0022)) {
            error = "Transport directories must be root-owned and not group/world-writable"; return {};
        }
        if (directory == "/") break;
        directory = QFileInfo(directory).absolutePath();
    }
    error.clear();
    return canonical;
}
inline QStringList installedBinaryPaths()
{
    return {"/usr/bin/tuntom", "/usr/libexec/saslik/tuntom", "/usr/libexec/tuntom"};
}
inline QString detectBinary(QString& error, const QStringList& candidates = installedBinaryPaths())
{
    QStringList failures;
    for (const auto& candidate : candidates) {
        QString reason;
        // Autodetection never grants a development exception or searches PATH.
        const auto binary = checkedBinary(candidate, reason);
        if (!binary.isEmpty()) { error.clear(); return binary; }
        failures << candidate + ": " + reason;
    }
    error = "No trusted Tuntom executable found. Checked: " + failures.join("; ");
    return {};
}

}
