#pragma once

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>

namespace HelperProtocol {
inline constexpr int maxRequest = 32768;

inline bool decode(const QByteArray& frame, QStringList& arguments)
{
    arguments.clear();
    if (frame.size() > maxRequest) return false;
    const auto object = QJsonDocument::fromJson(frame).object();
    if (object.size() != 1 || !object["args"].isArray()) return false;
    const auto values = object["args"].toArray();
    if (values.isEmpty() || values.size() > 257) return false;
    for (const auto& value : values) {
        if (!value.isString() || value.toString().size() > 2048
            || value.toString().contains(QChar::Null)) return false;
        arguments << value.toString();
    }
    // No UID override, shell or CA command. Tunnel operations are session-owned;
    // their payload is validated again by the privileged tunnel worker.
    // Each allowed operation still uses the regular helper's argument validation.
    static const QStringList allowed{"up", "down", "status", "host-status", "resume", "guard", "exemptions", "exemptions-reset-tcp",
        "interface-attach", "interface-release", "cleanup-tcp", "preview-tcp",
        "tunnel-start", "tunnel-poll", "tunnel-renew", "tunnel-stop"};
    return allowed.contains(arguments.first());
}
}
