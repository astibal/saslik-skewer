#include "client_report.hpp"
#include "test_certificate.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <QCoreApplication>
#include <QJsonArray>
#include <QSettings>
#include <QTemporaryFile>
#include <cstdio>
#include <memory>

namespace {
struct StoreCloser {
    void operator()(void* value) const {
        if (value) CertCloseStore(static_cast<HCERTSTORE>(value), 0);
    }
};

bool currentCa(const CERT_CONTEXT& certificate) {
    const auto* extension = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
                                               certificate.pCertInfo->cExtension,
                                               certificate.pCertInfo->rgExtension);
    if (!extension || CertVerifyTimeValidity(nullptr, certificate.pCertInfo) != 0) return false;
    CERT_BASIC_CONSTRAINTS2_INFO* decoded{};
    DWORD size{};
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                             extension->Value.pbData, extension->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &size)) return false;
    std::unique_ptr<void, decltype(&LocalFree)> owner(decoded, LocalFree);
    return decoded->fCA;
}

QByteArray firstCurrentUserCa() {
    std::unique_ptr<void, StoreCloser> store(CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        L"ROOT"));
    if (!store) return {};
    PCCERT_CONTEXT certificate{};
    while ((certificate = CertEnumCertificatesInStore(
                static_cast<HCERTSTORE>(store.get()), certificate))) {
        if (!currentCa(*certificate)) continue;
        DWORD size{};
        if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                                  CRYPT_STRING_BASE64HEADER, nullptr, &size)) return {};
        QByteArray pem(static_cast<int>(size), '\0');
        if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                                  CRYPT_STRING_BASE64HEADER, pem.data(), &size)) return {};
        if (!pem.isEmpty() && pem.back() == '\0') pem.chop(1);
        CertFreeCertificateContext(certificate);
        return pem;
    }
    return {};
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
    const auto managed = skewer::windows::clientReport(
        "SKEWER-WIN11", "test-version", {"0123456789abcdef", true, true});
    const auto managed_ca = managed.value("ca").toObject();
    const auto managed_stores = managed_ca.value("stores").toArray();
    const auto managed_applications = managed_ca.value("applications").toArray();
    if (managed_stores.size() != 2 || managed_applications.size() != 2 ||
        managed_stores.last().toObject().value("key").toString() !=
            "windows-managed-runtime" ||
        !managed_stores.last().toObject().value("installed").toBool() ||
        managed_applications.last().toObject().value("id").toString() !=
            "managed-runtime") {
        std::fputs("Managed runtime trust observation was not reported exactly\n", stderr);
        return 1;
    }
    const auto root = firstCurrentUserCa();
    if (root.isEmpty()) {
        std::fputs("Current User Root fixture unavailable\n", stderr);
        return 1;
    }
    bool non_ca_rejected = false;
    try {
        skewer::windows::rememberAdvertisedCa(skewer::windows::test::nonCaCertificate());
    } catch (const std::exception&) {
        non_ca_rejected = true;
    }
    if (!non_ca_rejected) {
        std::fputs("Structurally valid non-CA certificate was remembered as a CA\n", stderr);
        return 1;
    }
    QSettings().setValue("windows/advertisedCa", skewer::windows::test::nonCaCertificate());
    if (!skewer::windows::advertisedCaCertificate().isEmpty() ||
        !skewer::windows::advertisedCaObservation().fingerprint.isEmpty()) {
        std::fputs("Invalid saved CA was restored or advertised\n", stderr);
        return 1;
    }
    QSettings().remove("windows/advertisedCa");
    skewer::windows::rememberAdvertisedCa(root);
    if (skewer::windows::advertisedCaCertificate() != root) {
        std::fputs("Validated advertised CA was not restored\n", stderr);
        return 1;
    }
    QTemporaryFile managed_ca_file;
    if (!managed_ca_file.open() || managed_ca_file.write(root) != root.size() ||
        !managed_ca_file.flush()) {
        std::fputs("Cannot create managed runtime CA fixture\n", stderr);
        return 1;
    }
    QSettings().setValue("windows/runtimeTrustCa", managed_ca_file.fileName());
    const auto observed_ca = skewer::windows::clientReport("SKEWER-WIN11", "test-version")
                                 .value("ca").toObject();
    const auto observed_stores = observed_ca.value("stores").toArray();
    if (observed_ca.value("fingerprint").toString().size() != 64 ||
        observed_stores.size() != 2 ||
        !observed_stores.first().toObject().value("installed").toBool() ||
        observed_stores.last().toObject().value("key").toString() !=
            "windows-managed-runtime") {
        std::fputs("Persisted Windows trust observations were not reported\n", stderr);
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
