#pragma once
#include <QStringList>
#include <sys/types.h>

inline bool cleanupCandidate(uid_t caller, uid_t owner, unsigned state,
                             quint64 group, bool routed, bool selected)
{
    return caller == owner && selected && group != 0 && !routed
        && state != 10 && state != 7; // Never destroy TCP listeners or closed sockets.
}

// Privileged entry point. Targets are PID:starttime, never arbitrary addresses.
int cleanupSockets(uid_t uid, const QStringList& targets, bool dry_run, int* count_out = nullptr);
