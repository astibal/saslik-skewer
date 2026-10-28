#include "ca_trust_panel.hpp"
#include "ca_observation.hpp"
#include "pairing.hpp"
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

namespace skewer::windows {
namespace {
struct StoreCloser {
    void operator()(void* store) const { CertCloseStore(static_cast<HCERTSTORE>(store), 0); }
};
struct ContextCloser {
    void operator()(const CERT_CONTEXT* context) const { CertFreeCertificateContext(context); }
};
using Store = std::unique_ptr<void, StoreCloser>;
using Context = std::unique_ptr<const CERT_CONTEXT, ContextCloser>;

Store openStore() {
    Store store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                              L"ROOT"));
    if (!store) {
        throw std::runtime_error("Cannot open the current-user Root certificate store");
    }
    return store;
}

QByteArray pemDer(const QByteArray& pem) {
    auto encoded = pem;
    encoded.replace("-----BEGIN CERTIFICATE-----", "");
    encoded.replace("-----END CERTIFICATE-----", "");
    encoded = encoded.simplified();
    encoded.replace(" ", "");
    return QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
}

Context context(const QByteArray& pem) {
    const auto der = pemDer(pem);
    if (der.isEmpty()) {
        throw std::runtime_error("Cannot decode the PEM CA certificate");
    }
    Context value(CertCreateCertificateContext(X509_ASN_ENCODING,
                                                reinterpret_cast<const BYTE*>(der.constData()),
                                                static_cast<DWORD>(der.size())),
                  ContextCloser{});
    if (!value) {
        throw std::runtime_error("Cannot decode the CA certificate");
    }
    return value;
}

bool isCa(const CERT_CONTEXT& certificate) {
    const auto* extension = CertFindExtension(szOID_BASIC_CONSTRAINTS2,
                                               certificate.pCertInfo->cExtension,
                                               certificate.pCertInfo->rgExtension);
    if (!extension) {
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

PCCERT_CONTEXT findExact(HCERTSTORE store, const CERT_CONTEXT& wanted) {
    PCCERT_CONTEXT found{};
    while ((found = CertEnumCertificatesInStore(store, found))) {
        if (found->cbCertEncoded == wanted.cbCertEncoded &&
            std::memcmp(found->pbCertEncoded, wanted.pbCertEncoded, wanted.cbCertEncoded) == 0) {
            auto* duplicate = CertDuplicateCertificateContext(found);
            CertFreeCertificateContext(found);
            return duplicate;
        }
    }
    return nullptr;
}

CaTrustPanel::Result inspect(const QByteArray& pem) {
    if (pem.isEmpty()) {
        throw std::runtime_error("Paired Saslik status did not include a CA certificate");
    }
    auto native = context(pem);
    if (!isCa(*native) || CertVerifyTimeValidity(nullptr, native->pCertInfo) != 0) {
        throw std::runtime_error("The supplied certificate is not a currently valid CA");
    }
    auto store = openStore();
    Context found(findExact(static_cast<HCERTSTORE>(store.get()), *native));
    return {pem, {}, bool(found)};
}

CaTrustPanel::Result changeStore(const QByteArray& pem, bool remove) {
    auto result = inspect(pem);
    auto native = context(result.pem);
    auto store = openStore();
    Context found(findExact(static_cast<HCERTSTORE>(store.get()), *native));
    if (remove) {
        if (found) {
            auto* deleting = found.release();
            if (!CertDeleteCertificateFromStore(deleting)) {
                throw std::runtime_error("Cannot remove the selected CA certificate");
            }
        }
        result.present = false;
        result.message = QObject::tr("The selected CA was removed from Current User\\ROOT.");
    } else {
        if (!found && !CertAddCertificateContextToStore(static_cast<HCERTSTORE>(store.get()), native.get(),
                                                         CERT_STORE_ADD_NEW, nullptr)) {
            throw std::runtime_error("Cannot install the selected CA certificate");
        }
        result.present = true;
        result.message = found ? QObject::tr("The selected CA is already trusted by this user.")
                               : QObject::tr("The selected CA was installed in Current User\\ROOT.");
    }
    return result;
}
} // namespace

CaTrustPanel::CaTrustPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    auto* note = new QLabel(tr("Manage only the CA advertised by the paired Saslik. This first Windows "
                               "backend targets the current user's Root store; system and application-specific "
                               "stores remain unchanged."), this);
    note->setWordWrap(true);
    layout->addWidget(note);
    const QSettings settings;
    endpoint_ = new QLineEdit(settings.value("windows/saslikEndpoint",
                                             settings.value("windows/routingEndpoint")).toString(), this);
    endpoint_->setAccessibleName(tr("Paired Saslik endpoint"));
    endpoint_->setPlaceholderText("skewer://HOST:8766/pair");
    layout->addWidget(endpoint_);
    details_ = new QLabel(tr("No CA downloaded."), this);
    details_->setWordWrap(true);
    details_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(details_);
    auto* buttons = new QHBoxLayout;
    download_ = new QPushButton(tr("Download from paired Saslik"), this);
    install_ = new QPushButton(tr("Trust for current user"), this);
    remove_ = new QPushButton(tr("Remove this CA"), this);
    buttons->addWidget(download_);
    buttons->addWidget(install_);
    buttons->addWidget(remove_);
    buttons->addStretch();
    layout->addLayout(buttons);
    status_ = new QLabel(this);
    status_->setWordWrap(true);
    layout->addWidget(status_);
    layout->addStretch();
    connect(download_, &QPushButton::clicked, this, &CaTrustPanel::download);
    connect(install_, &QPushButton::clicked, this, [this] { store(false); });
    connect(remove_, &QPushButton::clicked, this, [this] { store(true); });
    connect(&watcher_, &QFutureWatcher<Result>::finished, this, [this] {
        try {
            const auto result = watcher_.result();
            if (!result.pem.isEmpty()) {
                applyCertificate(result.pem);
                rememberAdvertisedCa(result.pem);
                QSettings().setValue("windows/saslikEndpoint", endpoint_->text().trimmed());
            }
            status_->setText(result.message.isEmpty()
                                 ? (result.present ? tr("Trusted by the current user.")
                                                   : tr("Not present in Current User\\ROOT."))
                                 : result.message);
            install_->setEnabled(!certificate_.isEmpty() && !result.present);
            remove_->setEnabled(!certificate_.isEmpty() && result.present);
        } catch (const std::exception& error) {
            status_->setText(QString::fromUtf8(error.what()));
        }
        download_->setEnabled(true);
        endpoint_->setEnabled(true);
        if (certificate_.isEmpty()) {
            updateControls();
        }
    });
    updateControls();
}

void CaTrustPanel::setCertificateCallback(CertificateCallback callback) {
    certificate_callback_ = std::move(callback);
    if (certificate_callback_ && !certificate_.isEmpty()) certificate_callback_(certificate_);
}

void CaTrustPanel::download() {
    const QUrl endpoint(endpoint_->text().trimmed());
    download_->setEnabled(false);
    endpoint_->setEnabled(false);
    install_->setEnabled(false);
    remove_->setEnabled(false);
    status_->setText(tr("Downloading CA over the paired channel…"));
    watcher_.setFuture(QtConcurrent::run([endpoint] {
        try {
            const auto response = pairedStatus(endpoint);
            return inspect(response.value("ca_pem").toString().toUtf8());
        } catch (const std::exception& error) {
            return Result{{}, QString::fromUtf8(error.what()), false};
        }
    }));
}

void CaTrustPanel::store(bool remove) {
    if (certificate_.isEmpty() || watcher_.isRunning()) {
        return;
    }
    download_->setEnabled(false);
    endpoint_->setEnabled(false);
    install_->setEnabled(false);
    remove_->setEnabled(false);
    status_->setText(remove ? tr("Removing the exact selected CA…")
                            : tr("Installing the exact selected CA…"));
    watcher_.setFuture(QtConcurrent::run([pem = certificate_, remove] {
        try {
            return changeStore(pem, remove);
        } catch (const std::exception& error) {
            return Result{{}, QString::fromUtf8(error.what()), false};
        }
    }));
}

void CaTrustPanel::applyCertificate(const QByteArray& pem) {
    certificate_ = pem;
    auto native = context(pem);
    wchar_t name[512]{};
    CertGetNameStringW(native.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512);
    BYTE digest[32]{};
    DWORD digest_size = sizeof(digest);
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, native->pbCertEncoded,
                               native->cbCertEncoded, digest, &digest_size) || digest_size != sizeof(digest)) {
        throw std::runtime_error("Cannot fingerprint the CA certificate");
    }
    const auto fingerprint = QByteArray(reinterpret_cast<const char*>(digest), sizeof(digest)).toHex();
    details_->setText(tr("CA: %1\nSHA-256: %2\nValidated by Windows CryptoAPI")
                          .arg(QString::fromWCharArray(name), QString::fromLatin1(fingerprint)));
    if (certificate_callback_) certificate_callback_(certificate_);
}

void CaTrustPanel::updateControls() {
    install_->setEnabled(false);
    remove_->setEnabled(false);
}
} // namespace skewer::windows
