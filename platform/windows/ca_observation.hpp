#pragma once

#include <QByteArray>
#include <QString>

namespace skewer::windows {
struct CaObservation {
    QString fingerprint;
    bool current_user_root{};
    bool managed_runtime{};
};

// The advertised CA is public material. Persist only a validated certificate;
// pairing credentials remain exclusively in the DPAPI-protected store.
void rememberAdvertisedCa(const QByteArray& pem);
QByteArray advertisedCaCertificate();
CaObservation advertisedCaObservation();
} // namespace skewer::windows
