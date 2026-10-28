#include "client_report.hpp"
#include "pairing.hpp"
#include <QHostInfo>
#include <QJsonArray>
#include <exception>

namespace skewer::windows {
QJsonObject clientReport(const QString& hostname, const QString& version,
                         const CaObservation& observation) {
    QJsonArray applications;
    QJsonArray stores;
    if (!observation.fingerprint.isEmpty()) {
        applications.append(QJsonObject{{"id", "system"}, {"alias", "Windows"},
                                        {"recognized", true}, {"icon", ""}});
        stores.append(QJsonObject{{"key", "windows-current-user-root"},
                                  {"label", "Current User Root"},
                                  {"path", "Current User\\ROOT"},
                                  {"system", true}, {"available", true},
                                  {"installed", observation.current_user_root},
                                  {"detail", "Windows CryptoAPI exact certificate match"},
                                  {"matches", observation.current_user_root ? 1 : 0},
                                  {"application_id", "system"}});
    }
    return {
        {"version", 1},
        {"hostname", hostname},
        {"skewer_version", version},
        {"ca", QJsonObject{{"fingerprint", observation.fingerprint},
                           {"applications", applications}, {"stores", stores}}}};
}

QJsonObject clientReport(const QString& hostname, const QString& version) {
    return clientReport(hostname, version, advertisedCaObservation());
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
