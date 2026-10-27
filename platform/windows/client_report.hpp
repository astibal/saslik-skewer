#pragma once
#include <QJsonObject>
#include <QUrl>

namespace skewer::windows {
QJsonObject clientReport(const QString& hostname, const QString& version);
// Return an error for presentation, never credentials or a request dump.
QString sendClientReport(const QUrl& endpoint, const QString& version);
} // namespace skewer::windows
