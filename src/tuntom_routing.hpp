#pragma once
#include "tuntom_control.hpp"
#include <QStringList>
#include <sys/types.h>

// Only the privileged tunnel worker calls these hooks. The session context
// fences stale workers: Disable or a replacement session always wins.
namespace Tuntom {
void beginRouting(uid_t uid, const Endpoint& endpoint, const QStringList& exemptions, const QJsonObject& host = {});
void updateRouting(uid_t uid, const Endpoint& endpoint, bool verified);
void suspendRouting(uid_t uid, const Endpoint& endpoint);
}
