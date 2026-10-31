#pragma once

#include "../traffic/ipv4_prefix.hpp"
#include <QRegularExpression>
#include <QSettings>
#include <QStringList>
#include <algorithm>
#include <stdexcept>

namespace skewer::windows {

inline QStringList storedDestinationExemptions() {
    return QSettings().value("routing/exemptions").toStringList();
}

inline std::vector<skewer::traffic::Ipv4Prefix> parseDestinationExemptions(
    const QStringList& values) {
    std::vector<skewer::traffic::Ipv4Prefix> result;
    result.reserve(values.size());
    for (const auto& value : values) {
        skewer::traffic::Ipv4Prefix prefix;
        if (!skewer::traffic::parseIpv4Prefix(value.trimmed().toStdString(), prefix)) {
            throw std::invalid_argument("Invalid IPv4 destination exemption: " + value.toStdString());
        }
        if (std::ranges::find(result, prefix) == result.end()) result.push_back(prefix);
    }
    if (result.size() > skewer::traffic::max_ipv4_exemptions) {
        throw std::invalid_argument("Too many IPv4 destination exemptions");
    }
    return result;
}

inline QStringList normalizeDestinationExemptions(const QString& text) {
    std::vector<std::string> input;
    const auto entries = text.split(QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts);
    input.reserve(entries.size());
    for (const auto& entry : entries) input.push_back(entry.toStdString());
    std::vector<std::string> normalized;
    std::string error;
    if (!skewer::traffic::normalizeIpv4Prefixes(input, normalized, error)) {
        throw std::invalid_argument(error);
    }
    QStringList result;
    for (const auto& prefix : normalized) result.push_back(QString::fromStdString(prefix));
    return result;
}

} // namespace skewer::windows
