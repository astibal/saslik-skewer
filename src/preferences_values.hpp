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
    return QSettings().value("tunnel/binary", "/usr/libexec/saslik/tuntom").toString();
}
inline bool developmentBinaryAcknowledged()
{
    return Tuntom::developmentBinaryAllowed && !tuntomBinary().isEmpty()
        && QSettings().value("tunnel/developmentAcknowledgedPath").toString() == tuntomBinary();
}
inline QString tunnelPreflightError()
{
    QString error;
    if (!Tuntom::checkedBinary(tuntomBinary(), error, developmentBinaryAcknowledged()).isEmpty()) return {};
    return error + (Tuntom::developmentBinaryAllowed
        ? QString(". Open Preferences > Tunnel to select an installed transport or explicitly acknowledge your development executable.")
        : QString(". Install a protected root-owned tuntom executable, then select it in Preferences > Tunnel. This build does not permit development exceptions."));
}

}
