#pragma once

#include "tuntom_session.hpp"
#include <QJsonObject>
#include <QHostAddress>
#include <QMap>

namespace Tuntom {
inline bool confirmedSnapshot(const QByteArray& snapshot, int id, qint64 now)
{
    if (snapshot.size() > 65536) return false;
    QMap<QByteArray, QByteArray> fields;
    for (const auto& line : snapshot.split('\n')) {
        if (line.isEmpty()) continue;
        const auto separator = line.indexOf('=');
        if (separator <= 0 || fields.contains(line.first(separator))) return false;
        fields.insert(line.first(separator), line.mid(separator + 1));
    }
    bool ok = false;
    const auto updated = fields.value("updated_unix").toLongLong(&ok);
    return ok && now >= updated && now - updated <= 5
        && fields.value("format_version") == "1" && fields.value("mode") == "client"
        && fields.value("tunnel_id") == QByteArray::number(id)
        && fields.value("session_ready") == "1" && fields.value("session_confirmed") == "1";
}

inline QJsonObject trafficSnapshot(const QByteArray& snapshot, int id, qint64 now)
{
    if (!confirmedSnapshot(snapshot, id, now)) return {};
    QJsonObject result;
    // Export only public counters, never session keys or arbitrary stats fields.
    // Decimal strings preserve uint64 precision across JSON consumers.
    for (const auto& line : snapshot.split('\n')) {
        const auto separator = line.indexOf('=');
        if (separator <= 0) continue;
        const auto key = line.first(separator);
        if (key != "tun_rx_bytes" && key != "tun_tx_bytes"
            && key != "tun_rx_packets" && key != "tun_tx_packets" && key != "uptime_seconds") continue;
        const auto value = line.mid(separator + 1);
        bool valid = !value.isEmpty();
        for (const char c : value) valid = valid && c >= '0' && c <= '9';
        bool converted = false;
        const auto number = value.toULongLong(&converted);
        if (valid && converted) result[QString::fromLatin1(key)] = QString::number(number);
    }
    return result;
}

struct Endpoint {
    int id = 0;
    int leaseSeconds = 0;
    QString context, clientInterface, serverAddress, clientAddress;
};

// Validate authenticated metadata too: it eventually reaches a privileged
// helper. Accept only the pairwise address/interface contract we implement.
inline Endpoint endpointFromResponse(const QJsonObject& response)
{
    const auto value = response.value("tunnel").toObject();
    Endpoint result;
    result.id = value.value("id").toInt();
    result.leaseSeconds = response.value("lease_seconds").toInt();
    result.context = value.value("context").toString();
    result.clientInterface = value.value("client_interface").toString();
    result.serverAddress = value.value("server_address").toString();
    result.clientAddress = value.value("client_address").toString();
    if (!response.value("ok").toBool() || value.value("version").toInt() != 1
        || value.value("transport").toString() != "tuntom"
        || result.id < 1 || result.id > 255
        || value.value("port").toInt() != 40000 + result.id
        || result.leaseSeconds < 10 || result.leaseSeconds > 3600
        || result.clientInterface != QString("skt%1c").arg(result.id)
        || value.value("server_interface").toString() != QString("skt%1s").arg(result.id))
        throw std::invalid_argument("Invalid tunnel endpoint metadata");
    // Reuse the strict context validator without retaining any real secret.
    deriveKey(QByteArray(32, '\0'), result.context.toLatin1());
    auto address = [](const QString& text) {
        if (!text.endsWith("/30")) throw std::invalid_argument("Invalid tunnel prefix");
        bool ok = false;
        const auto ip = QHostAddress(text.chopped(3)).toIPv4Address(&ok);
        if (!ok || (ip >> 24) != 10) throw std::invalid_argument("Invalid tunnel address");
        return ip;
    };
    const auto server = address(result.serverAddress);
    const auto client = address(result.clientAddress);
    if ((server & 3) != 1 || client != server + 1)
        throw std::invalid_argument("Invalid tunnel address pair");
    return result;
}
} // namespace Tuntom
