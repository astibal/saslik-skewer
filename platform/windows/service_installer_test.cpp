#include "service_installer.hpp"
#include <QCoreApplication>
#include <QHostAddress>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        const QList<QHostAddress> bootstrap{QHostAddress(QStringLiteral("203.0.113.9")),
                                            QHostAddress(QStringLiteral("192.0.2.20")),
                                            QHostAddress(QStringLiteral("::1")),
                                            QHostAddress(QStringLiteral("127.0.0.1")),
                                            QHostAddress(QStringLiteral("192.0.2.20"))};
        if (skewer::windows::selectBootstrapIpv4(QStringLiteral("lab.example"), bootstrap) !=
            QStringLiteral("192.0.2.20")) {
            throw std::runtime_error("DNS bootstrap selection is not deterministic");
        }
        if (skewer::windows::selectBootstrapIpv4(QStringLiteral("198.51.100.7"), {}) !=
            QStringLiteral("198.51.100.7")) {
            throw std::runtime_error("Numeric endpoint changed during bootstrap");
        }
        bool unusable_rejected{};
        try {
            (void)skewer::windows::selectBootstrapIpv4(
                QStringLiteral("local.example"), {QHostAddress(QStringLiteral("127.0.0.1")),
                                                   QHostAddress(QStringLiteral("::1"))});
        } catch (const std::runtime_error&) {
            unusable_rejected = true;
        }
        if (!unusable_rejected) {
            throw std::runtime_error("Unusable DNS bootstrap result was accepted");
        }
        const auto missing = QStringLiteral("SkewerRouting-Test-Missing-Installer-Test");
        if (skewer::windows::routingServiceInstalled(missing))
            throw std::runtime_error("Unexpected test service exists");
        const auto rejected = skewer::windows::runRoutingServiceInstaller(
            QStringLiteral("missing.ps1"), QStringLiteral("missing"), missing,
            QStringLiteral("skewer://127.0.0.1:8766/pair"), false);
        if (rejected.error.isEmpty())
            throw std::runtime_error("Non-production service reached UAC execution");
        const auto endpoint = skewer::windows::runRoutingServiceInstaller(
            QStringLiteral("missing.ps1"), QStringLiteral("missing"), QStringLiteral("SkewerRouting"),
            QStringLiteral("skewer://example.invalid:8766/pair"), false);
        if (endpoint.error.isEmpty())
            throw std::runtime_error("Non-numeric installer endpoint reached UAC execution");
        const auto direct = skewer::windows::runRoutingServiceInstaller(
            QStringLiteral("missing.ps1"), QStringLiteral("missing"), QStringLiteral("SkewerRouting"),
            QString{}, false);
        if (!direct.error.contains("incomplete"))
            throw std::runtime_error("Direct-only installation was rejected as invalid configuration");
        const auto remover = skewer::windows::runRoutingServiceRemover(
            QStringLiteral("missing.ps1"), missing);
        if (remover.error.isEmpty())
            throw std::runtime_error("Non-production service reached remover UAC execution");
        std::cout << "PASS: service detection, deterministic DNS bootstrap and pre-UAC validation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
