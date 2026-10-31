#include "pairing.hpp"
#include <QCoreApplication>
#include "client_report.hpp"
#include <QSettings>
#include <cstdio>

// Keep invitations on stdin, not in process listings. This client deliberately
// performs no privileged adapter setup or routing changes.
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("Saslik");
    QCoreApplication::setApplicationName("Skewer");
    const auto arguments = app.arguments();
    if (arguments.size() == 3 && arguments[1] == "report") {
        const QUrl endpoint(arguments[2]);
        const auto error = skewer::windows::sendClientReport(endpoint, SKEWER_VERSION);
        if (!error.isEmpty()) {
            std::fprintf(stderr, "%s\n", qPrintable(error));
            return 1;
        }
        // Only persist the validated, credential-free endpoint after success.
        QSettings().setValue("windows/saslikEndpoint", endpoint.toString());
        std::puts("Client report accepted. Endpoint saved for the Windows GUI.");
        return 0;
    }
    return pairingCommand(app.arguments());
}
