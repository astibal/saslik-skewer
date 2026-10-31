#include "stored_pairing_handoff.hpp"
#include "pairing.hpp"
#include <algorithm>

namespace skewer::windows {
void sendStoredPairing(HANDLE pipe, const std::wstring& service_name, const QUrl& endpoint, HANDLE cancel,
                       DWORD timeout_ms) {
    // Fail before decrypting user storage when the pipe is not our SCM server.
    // sendPairingHandoff pins/rechecks it again for the actual wire exchange.
    auto server = verifySelectionService(pipe, service_name);
    auto snapshot = PairedControl::load(endpoint);
    snapshot->withCredentials([&](const QUrl& address, const QByteArray& identity, const QByteArray& key) {
        PairingHandoff envelope;
        envelope.endpoint = address.toEncoded().toStdString();
        envelope.identity = identity.toStdString();
        if (key.size() != static_cast<qsizetype>(envelope.key.size())) {
            throw std::runtime_error("Invalid stored pairing key length");
        }
        std::copy(key.begin(), key.end(), envelope.key.begin());
        sendPairingHandoff(pipe, service_name, envelope, cancel, timeout_ms);
    });
}
} // namespace skewer::windows
