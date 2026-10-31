#include "pairing.hpp"
#include <QCoreApplication>
#include <iostream>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        const QUrl endpoint("skewer://127.0.0.1:18767/pair");
        QByteArray key(32, 'p');
        PairedControl snapshot(endpoint, "fixture-client", key);
        key.fill('x');
        unsigned calls{};
        auto verify = [&](const QUrl& address, const QByteArray& identity, const QByteArray& secret) {
            if (address != endpoint || identity != "fixture-client" || secret != QByteArray(32, 'p')) {
                throw std::runtime_error("Snapshot changed during handoff");
            }
            ++calls;
        };
        snapshot.withCredentials(verify);
        bool rejected{};
        try {
            snapshot.withCredentials({});
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        if (!rejected) {
            return 1;
        }
        bool propagated{};
        try {
            snapshot.withCredentials([](const auto&, const auto&, const auto&) {
                throw std::runtime_error("Injected transport failure");
            });
        } catch (const std::runtime_error&) {
            propagated = true;
        }
        snapshot.withCredentials(verify);
        if (!propagated || calls != 2 || key != QByteArray(32, 'x')) {
            return 2;
        }
        std::cout << "PASS: borrowed handoff, detached snapshot and failed consumer recovery\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 3;
    }
}
