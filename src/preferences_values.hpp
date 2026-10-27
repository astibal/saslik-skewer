#pragma once
#include <QSettings>
#include <algorithm>
#include "tuntom_binary.hpp"

namespace Preferences {
inline int number(const char* key, int fallback, int minimum, int maximum)
{
    bool ok = false;
    const int value = QSettings().value(key, fallback).toInt(&ok);
    return ok ? std::clamp(value, minimum, maximum) : fallback;
}
inline QString tuntomBinary()
{
    const auto configured = QSettings().value("tunnel/binary").toString().trimmed();
    if (!configured.isEmpty()) return configured;
    QString error;
    return Tuntom::detectBinary(error);
}
inline bool developmentBinaryAcknowledged()
{
    const auto configured = QSettings().value("tunnel/binary").toString().trimmed();
    return Tuntom::developmentBinaryAllowed && !configured.isEmpty()
        && QSettings().value("tunnel/developmentAcknowledgedPath").toString() == configured;
}
inline QString tunnelPreflightError()
{
    QString error;
    const auto configured = QSettings().value("tunnel/binary").toString().trimmed();
    const auto binary = configured.isEmpty() ? Tuntom::detectBinary(error)
        : Tuntom::checkedBinary(configured, error, developmentBinaryAcknowledged());
    if (!binary.isEmpty()) return {};
    return error + (Tuntom::developmentBinaryAllowed
        ? QString(". Open Preferences > Tunnel to select an installed transport or explicitly acknowledge your development executable.")
        : QString(". Install a protected root-owned tuntom executable, then select it in Preferences > Tunnel. This build does not permit development exceptions."));
}

}
