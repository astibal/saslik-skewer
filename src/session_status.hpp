#pragma once
#include <QString>
#include <QStringList>
#include <sys/types.h>
#include <QJsonObject>

// A fresh control-plane observation, not proof of end-to-end interception.
QJsonObject sessionStatus(pid_t pid);
int sessionCommand(const QStringList& arguments);

// Poll on a separate worker, never on the 10 ms process-guard loop.
void watchSessionStatus(pid_t shell_pid, const QString& directory);
