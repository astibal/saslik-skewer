#include "client_report.hpp"
#include "pairing.hpp"
#include <QHostInfo>
#include <QJsonArray>
#include <exception>

namespace skewer::windows {
QJsonObject clientReport(const QString& hostname, const QString& version) {
    // Presence is not routing health. Do not invent trust-store observations
    // until the native certificate-store integration can actually collect them.
    return {
        {"version", 1},
        {"hostname", hostname},
        {"skewer_version", version},
        {"ca", QJsonObject{{"fingerprint", ""}, {"applications", QJsonArray{}}, {"stores", QJsonArray{}}}}};
}

QString sendClientReport(const QUrl& endpoint, const QString& version) {
    try {
        const auto result = pairedRequest(
            endpoint, {{"action", "report"}, {"report", clientReport(QHostInfo::localHostName(), version)}});
        if (!result.value("ok").toBool()) {
            return QStringLiteral("Saslik rejected the client report.");
        }
        return {};
    } catch (const std::exception&) {
        // The endpoint is user input: never echo an accidentally pasted invite.
        return QStringLiteral("Client report failed. Check the endpoint, pairing and connectivity.");
    }
}
} // namespace skewer::windows
