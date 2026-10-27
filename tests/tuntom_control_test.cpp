#include "pairing.hpp"
#include <QCoreApplication>
#include <QTextStream>
#include <QStandardPaths>
#include <QCryptographicHash>
#include <QFile>

// Invoked by Saslik's integration test against a real TLS-PSK listener and a
// mocked endpoint backend. No privileged networking or tunnel process is used.
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().size() != 2) return 2;
    // Do not read or replace the developer's real endpoint credentials.
    QStandardPaths::setTestModeEnabled(true);
    const auto endpointBytes = QUrl(app.arguments()[1]).toEncoded();
    const auto path = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + "/skewer/pairings/"
        + QString::fromLatin1(QCryptographicHash::hash(endpointBytes, QCryptographicHash::Sha256).toHex())
        + ".json";
    if (QFile::exists(path)) {
        QTextStream(stderr) << "Test pairing already exists; use an isolated test endpoint\n";
        return 8;
    }
    struct Cleanup {
        QString path;
        ~Cleanup() { QFile::remove(path); }
    } cleanup{path};
    if (pairingCommand({"skewer", "pair", "-"}) != 0) return 3;
    try {
        const QUrl address(app.arguments()[1]);
        const auto first = openPairedTunnel(address);
        if (first.key.size() != 16) return 4;
        heartbeatPairedTunnel(address, first.endpoint);
        const auto repeated = openPairedTunnel(address);
        if (repeated.key != first.key || repeated.endpoint.context != first.endpoint.context) return 5;
        closePairedTunnel(address, first.endpoint);
        const auto replacement = openPairedTunnel(address);
        if (replacement.key == first.key || replacement.endpoint.context == first.endpoint.context) return 6;
        bool staleRejected = false;
        try { heartbeatPairedTunnel(address, first.endpoint); }
        catch (const std::exception&) { staleRejected = true; }
        closePairedTunnel(address, replacement.endpoint);
        return staleRejected ? 0 : 7;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
