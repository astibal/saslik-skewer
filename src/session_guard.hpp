#pragma once
#include <QString>
#include <QStringList>
#include <sys/types.h>

struct GuardIdentity {
    pid_t pid{};
    uid_t uid{};
    quint64 start_ticks{};
};

inline bool sameProcess(const GuardIdentity& expected, const GuardIdentity& observed)
{
    return expected.pid > 1 && expected.pid == observed.pid
        && expected.uid == observed.uid && expected.start_ticks != 0
        && expected.start_ticks == observed.start_ticks;
}

inline bool guardWindowOpen(qint64 discovered_ms, qint64 now_ms)
{
    return now_ms >= discovered_ms && now_ms - discovered_ms < 5000;
}

inline bool routedGroup(const QString& group)
{
    return group.split('/').contains(QStringLiteral("skewer-routed.slice"));
}
