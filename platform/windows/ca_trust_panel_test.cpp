#include "ca_trust_panel.hpp"
#include "ca_observation.hpp"
#include "test_certificate.hpp"
#include <QApplication>
#include <QLineEdit>
#include <QSettings>
#include <QStandardPaths>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) try {
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("SkewerTests");
    QCoreApplication::setApplicationName("CaTrustPanel");
    QStandardPaths::setTestModeEnabled(true);
    QSettings().clear();
    QSettings().setValue("windows/advertisedCa", skewer::windows::test::nonCaCertificate());

    skewer::windows::CaTrustPanel panel;
    if (!skewer::windows::advertisedCaCertificate().isEmpty()) {
        throw std::runtime_error("CA Trust restored an invalid saved certificate");
    }
    auto* endpoint = panel.findChild<QLineEdit*>("caTrustEndpoint");
    if (!endpoint) {
        throw std::runtime_error("CA Trust endpoint control is missing");
    }
    panel.setPairedEndpoint("  skewer://192.0.2.10:8766/pair  ");
    if (endpoint->text() != "skewer://192.0.2.10:8766/pair") {
        throw std::runtime_error("CA Trust did not adopt the paired endpoint");
    }
    panel.setPairedEndpoint("   ");
    if (endpoint->text() != "skewer://192.0.2.10:8766/pair") {
        throw std::runtime_error("Empty propagation erased the paired endpoint");
    }

    QSettings().clear();
    std::cout << "PASS: CA Trust adopts the shared paired endpoint\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
