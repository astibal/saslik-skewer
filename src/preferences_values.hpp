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
}
