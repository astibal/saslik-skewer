#include "service_installer.hpp"
#include <QCoreApplication>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
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
        std::cout << "PASS: service detection and pre-UAC installer validation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
