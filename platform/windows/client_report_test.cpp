#include "client_report.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <QCoreApplication>
#include <QJsonArray>
#include <QSettings>
#include <cstdio>
#include <memory>

namespace {
struct StoreCloser {
    void operator()(void* value) const {
        if (value) CertCloseStore(static_cast<HCERTSTORE>(value), 0);
    }
};

QByteArray firstCurrentUserRoot() {
    std::unique_ptr<void, StoreCloser> store(CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        L"ROOT"));
    if (!store) return {};
    const auto certificate = CertEnumCertificatesInStore(static_cast<HCERTSTORE>(store.get()), nullptr);
    if (!certificate) return {};
    DWORD size{};
    if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER, nullptr, &size)) return {};
    QByteArray pem(static_cast<int>(size), '\0');
    if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER, pem.data(), &size)) return {};
    if (!pem.isEmpty() && pem.back() == '\0') pem.chop(1);
    return pem;
}
} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("SaslikTests");
    QCoreApplication::setApplicationName("ClientReport");
    QSettings().clear();
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
    const auto trusted = skewer::windows::clientReport(
        "SKEWER-WIN11", "test-version", {"0123456789abcdef", true});
    const auto trusted_ca = trusted.value("ca").toObject();
    const auto stores = trusted_ca.value("stores").toArray();
    const auto applications = trusted_ca.value("applications").toArray();
    if (trusted_ca.value("fingerprint").toString() != "0123456789abcdef" ||
        stores.size() != 1 || !stores.first().toObject().value("installed").toBool() ||
        stores.first().toObject().value("key").toString() != "windows-current-user-root" ||
        applications.size() != 1 || applications.first().toObject().value("id").toString() != "system") {
        std::fputs("Windows trust observation was not reported exactly\n", stderr);
        return 1;
    }
    const auto root = firstCurrentUserRoot();
    if (root.isEmpty()) {
        std::fputs("Current User Root fixture unavailable\n", stderr);
        return 1;
    }
    skewer::windows::rememberAdvertisedCa(root);
    if (skewer::windows::advertisedCaCertificate() != root) {
        std::fputs("Validated advertised CA was not restored\n", stderr);
        return 1;
    }
    const auto observed_ca = skewer::windows::clientReport("SKEWER-WIN11", "test-version")
                                 .value("ca").toObject();
    const auto observed_stores = observed_ca.value("stores").toArray();
    if (observed_ca.value("fingerprint").toString().size() != 64 ||
        observed_stores.size() != 1 ||
        !observed_stores.first().toObject().value("installed").toBool()) {
        std::fputs("Persisted Windows Root observation was not reported\n", stderr);
        return 1;
    }
    const auto error = skewer::windows::sendClientReport(
        QUrl("skewer://localhost:8766/pair#psk=not-a-real-secret"), "test-version");
    if (error.isEmpty() || error.contains("not-a-real-secret")) {
        std::fputs("Invalid endpoint accepted or credentials exposed\n", stderr);
        return 1;
    }
    QSettings().clear();
    std::puts("Client report tests passed");
}
