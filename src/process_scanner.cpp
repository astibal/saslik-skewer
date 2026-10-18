#include "process_scanner.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>

#include <optional>

namespace {
QString readTextFile(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    return QString::fromLocal8Bit(file.readAll());
}

QString readCommandLine(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    QByteArray data = file.readAll();
    data.replace('\0', ' ');
    return QString::fromLocal8Bit(data).trimmed();
}

std::optional<ProcessInfo> readProcess(pid_t pid, uid_t wanted_uid)
{
    const QString root = QStringLiteral("/proc/%1").arg(pid);
    const QString status = readTextFile(root + QStringLiteral("/status"));
    if (status.isEmpty()) {
        return std::nullopt;
    }

    static const QRegularExpression uid_pattern(QStringLiteral("^Uid:\\s+(\\d+)"),
                                                QRegularExpression::MultilineOption);
    static const QRegularExpression parent_pattern(QStringLiteral("^PPid:\\s+(\\d+)"),
                                                   QRegularExpression::MultilineOption);
    static const QRegularExpression name_pattern(QStringLiteral("^Name:\\s+(.+)$"),
                                                 QRegularExpression::MultilineOption);

    const auto uid_match = uid_pattern.match(status);
    if (!uid_match.hasMatch() || uid_match.captured(1).toUInt() != wanted_uid) {
        return std::nullopt;
    }

    ProcessInfo process;
    process.pid = pid;
    process.uid = wanted_uid;
    const auto parent_match = parent_pattern.match(status);
    process.parent_pid = parent_match.hasMatch() ? parent_match.captured(1).toInt() : 0;
    const auto name_match = name_pattern.match(status);
    process.name = name_match.hasMatch() ? name_match.captured(1).trimmed()
                                         : QString::number(pid);
    process.executable = QFileInfo(root + QStringLiteral("/exe")).symLinkTarget();
    process.command_line = readCommandLine(root + QStringLiteral("/cmdline"));
    return process;
}
} // namespace

QVector<ProcessInfo> ProcessScanner::scan(uid_t uid) const
{
    QVector<ProcessInfo> result;
    const QDir proc(QStringLiteral("/proc"));
    const auto entries = proc.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString& entry : entries) {
        bool numeric = false;
        const int pid = entry.toInt(&numeric);
        if (!numeric || pid <= 0) {
            continue;
        }
        if (auto process = readProcess(pid, uid)) {
            result.push_back(std::move(*process));
        }
    }
    return result;
}
