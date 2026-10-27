#include "client_report.hpp"
#include <QCoreApplication>
#include <QJsonArray>
#include <cstdio>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const auto report = skewer::windows::clientReport("SKEWER-WIN11", "test-version");
    const auto ca = report.value("ca").toObject();
    if (report.size() != 4 || report.value("version").toInt() != 1 ||
        report.value("hostname").toString() != "SKEWER-WIN11" ||
        report.value("skewer_version").toString() != "test-version" || ca.size() != 3 ||
        !ca.value("stores").isArray() || !ca.value("stores").toArray().isEmpty() ||
        !ca.value("applications").isArray() || !ca.value("applications").toArray().isEmpty() ||
        ca.value("fingerprint").toString() != "") {
        std::fputs("Unexpected presence report or invented trust state\n", stderr);
        return 1;
    }
    const auto error = skewer::windows::sendClientReport(
        QUrl("skewer://localhost:8766/pair#psk=not-a-real-secret"), "test-version");
    if (error.isEmpty() || error.contains("not-a-real-secret")) {
        std::fputs("Invalid endpoint accepted or credentials exposed\n", stderr);
        return 1;
    }
    std::puts("Client report tests passed");
}
