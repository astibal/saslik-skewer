#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

#include <sys/types.h>

struct ProcessInfo {
    pid_t pid{};
    pid_t parent_pid{};
    uid_t uid{};
    QString name;
    QString executable;
    QString command_line;
    QString cgroup;
    QStringList arguments;
};

class ProcessScanner {
public:
    [[nodiscard]] QVector<ProcessInfo> scan(uid_t uid) const;
};
