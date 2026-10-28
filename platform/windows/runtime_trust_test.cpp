#include "runtime_trust_panel.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSettings>
#include <QStandardPaths>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {
using skewer::windows::EnvironmentOverrides;

struct StoreCloser {
    void operator()(void* value) const {
        if (value) CertCloseStore(value, 0);
    }
};
using Store = std::unique_ptr<void, StoreCloser>;

QByteArray firstRootPem() {
    Store store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG |
                                  CERT_STORE_READONLY_FLAG,
                              L"ROOT"));
    if (!store) throw std::runtime_error("Cannot open the current-user Root store");
    const auto certificate = CertEnumCertificatesInStore(store.get(), nullptr);
    if (!certificate) throw std::runtime_error("The current-user Root store is empty");
    DWORD size{};
    if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER, nullptr, &size))
        throw std::runtime_error("Cannot size the fixture PEM");
    QByteArray pem(static_cast<int>(size), '\0');
    if (!CryptBinaryToStringA(certificate->pbCertEncoded, certificate->cbCertEncoded,
                              CRYPT_STRING_BASE64HEADER, pem.data(), &size))
        throw std::runtime_error("Cannot encode the fixture PEM");
    if (!pem.isEmpty() && pem.back() == '\0') pem.chop(1);
    return pem;
}

std::wstring value(const EnvironmentOverrides& environment, const wchar_t* name) {
    for (const auto& [key, item] : environment) if (key == name) return item;
    return {};
}
} // namespace

int main(int argc, char** argv) try {
    QCoreApplication app(argc, argv);
    QCoreApplication::setOrganizationName("SaslikTests");
    QCoreApplication::setApplicationName("RuntimeTrust");
    QStandardPaths::setTestModeEnabled(true);
    QSettings().clear();

    const auto result = skewer::windows::prepareManagedRuntimeTrust(firstRootPem());
    if (!QFile::exists(result.ca_path) || !QFile::exists(result.bundle_path) ||
        QFile(result.bundle_path).size() <= QFile(result.ca_path).size())
        throw std::runtime_error("Managed trust files were not generated");

    QSettings settings;
    settings.setValue("windows/runtimeTrustCa", result.ca_path);
    settings.setValue("windows/runtimeTrustBundle", result.bundle_path);
    const auto environment = skewer::windows::managedRuntimeEnvironment();
    const auto ca = QDir::toNativeSeparators(result.ca_path).toStdWString();
    const auto bundle = QDir::toNativeSeparators(result.bundle_path).toStdWString();
    if (environment.size() != 5 || value(environment, L"SSL_CERT_FILE") != bundle ||
        value(environment, L"REQUESTS_CA_BUNDLE") != bundle ||
        value(environment, L"CURL_CA_BUNDLE") != bundle || value(environment, L"PIP_CERT") != bundle ||
        value(environment, L"NODE_EXTRA_CA_CERTS") != ca)
        throw std::runtime_error("Managed runtime environment is incomplete");

    QFile::remove(result.ca_path);
    QFile::remove(result.bundle_path);
    QSettings().clear();
    std::cout << "PASS: Windows roots bundle and scoped runtime environment\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
