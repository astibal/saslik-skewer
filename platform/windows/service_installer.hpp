#pragma once
#include <QHostAddress>
#include <QList>
#include <QString>

namespace skewer::windows {
struct InstallerResult {
    unsigned exit_code{};
    QString error;
};

bool routingServiceInstalled(const QString& name);
// Select one stable numeric transport peer from a DNS bootstrap result.
// The endpoint hostname remains the pairing identity; this address is only the
// pinned control/data underlay for the installed service generation.
QString selectBootstrapIpv4(const QString& host, const QList<QHostAddress>& addresses);
InstallerResult runRoutingServiceInstaller(const QString& script, const QString& package,
                                           const QString& service, const QString& endpoint,
                                           bool upgrade);
InstallerResult runRoutingServiceRemover(const QString& script, const QString& service);
} // namespace skewer::windows
