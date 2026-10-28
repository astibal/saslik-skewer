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
        for (int size : {0, 31, 33}) {
            bool rejected = false;
            try { PairedControl invalid(address, "fixture-client", QByteArray(size, 'p')); }
            catch (const std::exception&) { rejected = true; }
            if (!rejected) return 11;
        }
        for (const auto& identity : {QByteArray(), QByteArray(257, 'i'), QByteArray("i\0d", 3)}) {
            bool rejected = false;
            try { PairedControl invalid(address, identity, QByteArray(32, 'p')); }
            catch (const std::exception&) { rejected = true; }
            if (!rejected) return 12;
        }
        const QByteArray callerKey(32, 'p');
        {
            PairedControl owned(address, "fixture-client", callerKey);
        }
        if (callerKey != QByteArray(32, 'p')) return 13;
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
        if (!staleRejected) return 7;
        auto snapshot = PairedControl::load(address);
        // Once handed off, the worker must not depend on the GUI user's file.
        if (!QFile::remove(path)) return 9;
        bool storageRequired = false;
        try { (void)PairedControl::load(address); }
        catch (const std::exception&) { storageRequired = true; }
        if (!storageRequired) return 10;
        const auto independent = snapshot->open();
        snapshot->renew(independent.endpoint);
        snapshot->close(independent.endpoint);
        QTextStream(stdout) << "PASS: credential snapshot survives removal of user pairing storage\n";
        return 0;
    } catch (const std::exception& error) {
        QTextStream(stderr) << error.what() << '\n';
        return 1;
    }
}
