#include "pairing.hpp"
#include <QCoreApplication>

// Keep invitations on stdin, not in process listings. This client deliberately
// performs no privileged adapter setup or routing changes.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("Saslik");
    QCoreApplication::setApplicationName("Skewer");
    return pairingCommand(app.arguments());
}
