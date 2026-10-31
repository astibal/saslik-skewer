#pragma once

#include <QDir>
#include <QStandardPaths>

#include <windows.h>

namespace DiagnosticLog::detail {
inline QString _directory_win()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
        + "/logs";
}

inline bool _prepareDirectory_win(const QString& path)
{
    if (!QDir().mkpath(path)) return false;
    const DWORD attributes = GetFileAttributesW(
        reinterpret_cast<LPCWSTR>(path.utf16()));
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_DIRECTORY)
        && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

inline bool _appendRecord_win(const QString& path, const QByteArray& record)
{
    // Keep reparse points out of the write path. The directory is per-user;
    // Windows applies its inherited user ACL to a newly created log file.
    const HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;

    BY_HANDLE_FILE_INFORMATION info{};
    const bool regular = GetFileInformationByHandle(handle, &info)
        && !(info.dwFileAttributes
            & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        && info.nNumberOfLinks == 1;
    DWORD written = 0;
    const bool complete = regular
        && WriteFile(handle, record.constData(), DWORD(record.size()),
            &written, nullptr)
        && written == DWORD(record.size())
        && FlushFileBuffers(handle);
    CloseHandle(handle);
    return complete;
}
} // namespace DiagnosticLog::detail
