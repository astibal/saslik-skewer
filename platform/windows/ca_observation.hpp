#pragma once

#include <QByteArray>
#include <QString>

namespace skewer::windows {
struct CaObservation {
    QString fingerprint;
    bool current_user_root{};
};

// The advertised CA is public material. Persist only a validated certificate;
// pairing credentials remain exclusively in the DPAPI-protected store.
void rememberAdvertisedCa(const QByteArray& pem);
CaObservation advertisedCaObservation();
} // namespace skewer::windows
