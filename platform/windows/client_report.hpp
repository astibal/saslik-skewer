#pragma once
#include <QJsonObject>
#include <QUrl>
#include "ca_observation.hpp"

namespace skewer::windows {
QJsonObject clientReport(const QString& hostname, const QString& version);
QJsonObject clientReport(const QString& hostname, const QString& version,
                         const CaObservation& observation);
// Return an error for presentation, never credentials or a request dump.
QString sendClientReport(const QUrl& endpoint, const QString& version);
} // namespace skewer::windows
