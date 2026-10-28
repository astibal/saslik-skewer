#pragma once
#include <QString>

namespace skewer::windows {
struct InstallerResult {
    unsigned exit_code{};
    QString error;
};

bool routingServiceInstalled(const QString& name);
InstallerResult runRoutingServiceInstaller(const QString& script, const QString& package,
                                           const QString& service, const QString& endpoint,
                                           bool upgrade);
} // namespace skewer::windows
