#pragma once

#include <QDir>
#include <QFile>
#include <QStandardPaths>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace DiagnosticLog::detail {
inline QString _directory_linux()
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + "/skewer/logs";
}

inline bool _prepareDirectory_linux(const QString& path)
{
    if (::geteuid() != ::getuid() || !QDir().mkpath(path)) return false;
    struct stat info{};
    const auto encoded = QFile::encodeName(path);
    if (::lstat(encoded.constData(), &info)
        || !S_ISDIR(info.st_mode)
        || info.st_uid != ::getuid()) return false;
    return ::chmod(encoded.constData(), 0700) == 0;
}

inline bool _appendRecord_linux(const QString& path, const QByteArray& record)
{
    const int fd = ::open(QFile::encodeName(path).constData(),
        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0600);
    if (fd < 0) return false;

    struct stat info{};
    if (::fstat(fd, &info)
        || !S_ISREG(info.st_mode)
        || info.st_uid != ::getuid()
        || info.st_nlink != 1) {
        ::close(fd);
        return false;
    }
    ::fchmod(fd, 0600);

    QFile file;
    if (!file.open(fd, QIODevice::WriteOnly, QFileDevice::AutoCloseHandle)) {
        ::close(fd);
        return false;
    }
    return file.write(record) == record.size() && file.flush();
}
} // namespace DiagnosticLog::detail
