#pragma once
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonObject>
#include <QRegularExpression>

namespace SessionRoute {
// Observe installed kernel routing, not a GUI preference or a lingering TUN
// device. The privileged worker removes this route when verification is lost.
// This is a control-plane observation, not an end-to-end traffic guarantee.
inline bool matches(const QJsonObject& route, const QHostAddress& directGateway,
                    const QJsonArray& links)
{
    const auto type = route["type"].toString();
    if (!type.isEmpty() && type != "unicast") return false;
    if (route["flags"].toArray().contains("linkdown")) return false;
    const QHostAddress gateway(route["gateway"].toString());
    if (gateway.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const auto device = route["dev"].toString();
    static const QRegularExpression tunnelName("^skt[0-9]+c$");
    if (!tunnelName.match(device).hasMatch()) return gateway == directGateway;
    for (const auto& entry : links) {
        const auto link = entry.toObject();
        const auto info = link["linkinfo"].toObject();
        if (link["ifname"].toString() == device && link["flags"].toArray().contains("UP")
            && info["info_kind"] == "tun" && info["info_data"].toObject()["type"] == "tun")
            return true;
    }
    return false;
}
}
