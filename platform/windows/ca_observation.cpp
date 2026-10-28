#include "ca_observation.hpp"

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <QSettings>
#include <QFile>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace skewer::windows {
namespace {
struct StoreCloser {
    void operator()(void* value) const {
        if (value) CertCloseStore(static_cast<HCERTSTORE>(value), 0);
    }
};
struct ContextCloser {
    void operator()(const CERT_CONTEXT* value) const {
        if (value) CertFreeCertificateContext(value);
    }
};
using Store = std::unique_ptr<void, StoreCloser>;
using Context = std::unique_ptr<const CERT_CONTEXT, ContextCloser>;

Context decode(const QByteArray& pem) {
    auto encoded = pem;
    encoded.replace("-----BEGIN CERTIFICATE-----", "");
    encoded.replace("-----END CERTIFICATE-----", "");
    encoded = encoded.simplified();
    encoded.replace(" ", "");
    const auto der = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
    Context certificate(der.isEmpty() ? nullptr : CertCreateCertificateContext(
        X509_ASN_ENCODING, reinterpret_cast<const BYTE*>(der.constData()),
        static_cast<DWORD>(der.size())));
    if (!certificate) throw std::runtime_error("Cannot decode the advertised CA certificate");
    return certificate;
}

bool currentCa(const CERT_CONTEXT& certificate) {
    const auto* extension = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
                                               certificate.pCertInfo->cExtension,
                                               certificate.pCertInfo->rgExtension);
    if (!extension || CertVerifyTimeValidity(nullptr, certificate.pCertInfo) != 0) {
        return false;
    }
    CERT_BASIC_CONSTRAINTS2_INFO* decoded{};
    DWORD size{};
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                             extension->Value.pbData, extension->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &decoded, &size)) {
        return false;
    }
    std::unique_ptr<void, decltype(&LocalFree)> owner(decoded, LocalFree);
    return decoded->fCA;
}

CaObservation inspect(const QByteArray& pem) {
    auto certificate = decode(pem);
    if (!currentCa(*certificate)) {
        throw std::runtime_error("The advertised certificate is not a currently valid CA");
    }
    BYTE digest[32]{};
    DWORD digest_size = sizeof(digest);
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                               certificate->pbCertEncoded, certificate->cbCertEncoded,
                               digest, &digest_size) || digest_size != sizeof(digest))
        throw std::runtime_error("Cannot fingerprint the advertised CA certificate");

    Store store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER |
                                  CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                              L"ROOT"));
    if (!store) throw std::runtime_error("Cannot inspect Current User Root certificate store");
    bool present = false;
    PCCERT_CONTEXT item{};
    while ((item = CertEnumCertificatesInStore(static_cast<HCERTSTORE>(store.get()), item))) {
        if (item->cbCertEncoded == certificate->cbCertEncoded &&
            std::memcmp(item->pbCertEncoded, certificate->pbCertEncoded,
                        certificate->cbCertEncoded) == 0) {
            present = true;
            CertFreeCertificateContext(item);
            break;
        }
    }
    return {QByteArray(reinterpret_cast<const char*>(digest), sizeof(digest)).toHex(), present, false};
}

bool managedRuntimeMatches(const QByteArray& advertised) {
    const auto path = QSettings().value("windows/runtimeTrustCa").toString();
    QFile input(path);
    if (path.isEmpty() || !input.open(QIODevice::ReadOnly) || input.size() > 1024 * 1024) {
        return false;
    }
    try {
        const auto expected = decode(advertised);
        const auto managed = decode(input.readAll());
        return expected->cbCertEncoded == managed->cbCertEncoded &&
               std::memcmp(expected->pbCertEncoded, managed->pbCertEncoded,
                           expected->cbCertEncoded) == 0;
    } catch (const std::exception&) {
        return false;
    }
}
} // namespace

void rememberAdvertisedCa(const QByteArray& pem) {
    if (pem.isEmpty() || pem.size() > 1024 * 1024)
        throw std::runtime_error("Advertised CA certificate exceeds bounds");
    (void)inspect(pem);
    QSettings().setValue("windows/advertisedCa", pem);
}

QByteArray advertisedCaCertificate() {
    const auto pem = QSettings().value("windows/advertisedCa").toByteArray();
    if (pem.isEmpty() || pem.size() > 1024 * 1024) return {};
    try {
        (void)inspect(pem);
        return pem;
    } catch (const std::exception&) {
        return {};
    }
}

CaObservation advertisedCaObservation() {
    const auto pem = advertisedCaCertificate();
    if (pem.isEmpty()) {
        return {};
    }
    auto observation = inspect(pem);
    observation.managed_runtime = managedRuntimeMatches(pem);
    return observation;
}
} // namespace skewer::windows
