#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include "runtime_trust_panel.hpp"
#include <QApplication>
#include <QClipboard>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QtConcurrent>
#include <memory>
#include <set>
#include <stdexcept>

namespace skewer::windows {
namespace {
struct ContextCloser { void operator()(const CERT_CONTEXT* value) const { CertFreeCertificateContext(value); } };
using Context = std::unique_ptr<const CERT_CONTEXT, ContextCloser>;

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
    Context result(der.isEmpty() ? nullptr : CertCreateCertificateContext(
        X509_ASN_ENCODING, reinterpret_cast<const BYTE*>(der.constData()), static_cast<DWORD>(der.size())));
    if (!result) throw std::runtime_error("Cannot decode the selected CA certificate");
    return result;
}

QByteArray fingerprint(const CERT_CONTEXT& certificate) {
    BYTE digest[32]{};
    DWORD size = sizeof(digest);
    if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, certificate.pbCertEncoded,
                               certificate.cbCertEncoded, digest, &size) || size != sizeof(digest))
        throw std::runtime_error("Cannot fingerprint the selected CA certificate");
    return QByteArray(reinterpret_cast<const char*>(digest), sizeof(digest)).toHex();
}

QByteArray toPem(const BYTE* der, DWORD size) {
    DWORD output_size{};
    if (!CryptBinaryToStringA(der, size, CRYPT_STRING_BASE64HEADER,
                              nullptr, &output_size))
        throw std::runtime_error("Cannot encode a Windows root certificate");
    QByteArray output(static_cast<int>(output_size), '\0');
    if (!CryptBinaryToStringA(der, size, CRYPT_STRING_BASE64HEADER,
                              output.data(), &output_size))
        throw std::runtime_error("Cannot encode a Windows root certificate");
    if (!output.isEmpty() && output.back() == '\0') output.chop(1);
    if (!output.endsWith("\r\n")) output += "\r\n";
    return output;
}

void collectRoots(DWORD location, std::set<QByteArray>& certificates) {
    const auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
                                     L"ROOT");
    if (!store) throw std::runtime_error("Cannot read a Windows Root certificate store");
    PCCERT_CONTEXT item{};
    while ((item = CertEnumCertificatesInStore(store, item))) {
        certificates.emplace(reinterpret_cast<const char*>(item->pbCertEncoded), item->cbCertEncoded);
        if (certificates.size() > 4096) {
            CertCloseStore(store, 0);
            throw std::runtime_error("Windows Root stores exceed the managed bundle limit");
        }
    }
    CertCloseStore(store, 0);
}

QString directoryFor(const QByteArray& pem) {
    auto certificate = context(pem);
    return QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) +
           QStringLiteral("/runtime-trust/") + QString::fromLatin1(fingerprint(*certificate));
}

bool writePrivate(const QString& path, const QByteArray& data) {
    QSaveFile output(path);
    return output.open(QIODevice::WriteOnly) && output.write(data) == data.size() && output.commit();
}

RuntimeTrustResult prepareBundleInternal(const QByteArray& pem) {
    auto selected = context(pem);
    std::set<QByteArray> roots;
    collectRoots(CERT_SYSTEM_STORE_LOCAL_MACHINE, roots);
    collectRoots(CERT_SYSTEM_STORE_CURRENT_USER, roots);
    roots.emplace(reinterpret_cast<const char*>(selected->pbCertEncoded), selected->cbCertEncoded);
    QByteArray bundle;
    for (const auto& root : roots) {
        bundle += toPem(reinterpret_cast<const BYTE*>(root.data()), static_cast<DWORD>(root.size()));
        if (bundle.size() > 32 * 1024 * 1024) throw std::runtime_error("Managed CA bundle exceeds 32 MiB");
    }
    const auto directory = directoryFor(pem);
    if (!QDir().mkpath(directory)) throw std::runtime_error("Cannot create the managed runtime-trust directory");
    const auto ca_path = directory + QStringLiteral("/saslik-ca.pem");
    const auto bundle_path = directory + QStringLiteral("/ca-bundle.pem");
    if (!writePrivate(ca_path, toPem(selected->pbCertEncoded, selected->cbCertEncoded)) ||
        !writePrivate(bundle_path, bundle))
        throw std::runtime_error("Cannot write the managed runtime-trust bundle");
    return {QObject::tr("Ready. New applications launched by Skewer inherit the managed CA settings."),
            ca_path, bundle_path};
}

QString powerShellSetup() {
    const QSettings settings;
    const auto ca = QDir::toNativeSeparators(settings.value("windows/runtimeTrustCa").toString());
    const auto bundle = QDir::toNativeSeparators(settings.value("windows/runtimeTrustBundle").toString());
    if (!QFileInfo::exists(ca) || !QFileInfo::exists(bundle)) return {};
    const auto quote = [](QString value) { value.replace("'", "''"); return QStringLiteral("'") + value + "'"; };
    return QStringLiteral("$env:SSL_CERT_FILE = %1\r\n$env:REQUESTS_CA_BUNDLE = %1\r\n"
                          "$env:CURL_CA_BUNDLE = %1\r\n$env:PIP_CERT = %1\r\n"
                          "$env:NODE_EXTRA_CA_CERTS = %2\r\n").arg(quote(bundle), quote(ca));
}
} // namespace

RuntimeTrustResult prepareManagedRuntimeTrust(const QByteArray& pem) {
    return prepareBundleInternal(pem);
}

QByteArray managedRuntimeCertificate() {
    const auto path = QSettings().value("windows/runtimeTrustCa").toString();
    QFile input(path);
    if (path.isEmpty() || !input.open(QIODevice::ReadOnly) || input.size() > 1024 * 1024) return {};
    const auto pem = input.readAll();
    try {
        (void)context(pem);
        return pem;
    } catch (const std::exception&) {
        return {};
    }
}

EnvironmentOverrides managedRuntimeEnvironment() {
    const QSettings settings;
    const auto ca = QDir::toNativeSeparators(settings.value("windows/runtimeTrustCa").toString());
    const auto bundle = QDir::toNativeSeparators(settings.value("windows/runtimeTrustBundle").toString());
    if (!QFileInfo::exists(ca) || !QFileInfo::exists(bundle)) return {};
    const auto native_bundle = bundle.toStdWString();
    return {{L"SSL_CERT_FILE", native_bundle}, {L"REQUESTS_CA_BUNDLE", native_bundle},
            {L"CURL_CA_BUNDLE", native_bundle}, {L"PIP_CERT", native_bundle},
            {L"NODE_EXTRA_CA_CERTS", ca.toStdWString()}};
}

RuntimeTrustPanel::RuntimeTrustPanel(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    auto* note = new QLabel(tr("Some Python, Node, curl and pip builds use OpenSSL bundles instead of the "
                               "Windows certificate store. Prepare creates a private bundle from the Windows "
                               "machine/user Root stores plus the selected Saslik CA. Only new programs launched "
                               "by Skewer receive these variables; existing processes are unchanged. Java and "
                               "application-private stores are not modified."), this);
    note->setWordWrap(true);
    layout->addWidget(note);
    certificate_status_ = new QLabel(tr("Download a CA on the CA Trust tab first."), this);
    certificate_status_->setWordWrap(true);
    layout->addWidget(certificate_status_);
    auto* actions = new QHBoxLayout;
    prepare_ = new QPushButton(tr("Prepare managed bundle"), this);
    remove_ = new QPushButton(tr("Remove managed bundle"), this);
    copy_ = new QPushButton(tr("Copy PowerShell setup"), this);
    for (auto* button : {prepare_, remove_, copy_}) actions->addWidget(button);
    actions->addStretch();
    layout->addLayout(actions);
    status_ = new QLabel(this);
    status_->setWordWrap(true);
    layout->addWidget(status_);
    auto* table = new QTableWidget(3, 3, this);
    table->setObjectName("runtimeTrustTable");
    table->setHorizontalHeaderLabels({tr("Runtime"), tr("Environment"), tr("Managed file")});
    const QStringList runtimes{tr("Python / OpenSSL"), tr("Requests / curl / pip"), tr("Node.js")};
    const QStringList variables{QStringLiteral("SSL_CERT_FILE"),
                                QStringLiteral("REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE / PIP_CERT"),
                                QStringLiteral("NODE_EXTRA_CA_CERTS")};
    for (int row = 0; row < 3; ++row) {
        const QStringList values{runtimes[row], variables[row],
                                 row == 2 ? tr("Selected CA") : tr("Windows roots + selected CA")};
        for (int column = 0; column < values.size(); ++column) {
            auto* item = new QTableWidgetItem(values[column]);
            item->setToolTip(values[column]);
            table->setItem(row, column, item);
        }
    }
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table->horizontalHeader()->setStretchLastSection(false);
    table->setColumnWidth(0, 170);
    table->setColumnWidth(1, 390);
    table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(table);
    layout->addStretch();
    connect(prepare_, &QPushButton::clicked, this, &RuntimeTrustPanel::prepare);
    connect(remove_, &QPushButton::clicked, this, &RuntimeTrustPanel::remove);
    connect(copy_, &QPushButton::clicked, this, [this] {
        QApplication::clipboard()->setText(powerShellSetup());
        status_->setText(tr("PowerShell setup copied. It affects only subsequently launched programs."));
    });
    connect(&watcher_, &QFutureWatcher<RuntimeTrustResult>::finished, this, [this] {
        const auto result = watcher_.result();
        if (!result.ca_path.isEmpty() && !result.bundle_path.isEmpty()) {
            QSettings settings;
            settings.setValue("windows/runtimeTrustCa", result.ca_path);
            settings.setValue("windows/runtimeTrustBundle", result.bundle_path);
        }
        status_->setText(result.message);
        updateControls();
    });
    const auto managed = managedRuntimeCertificate();
    if (!managed.isEmpty()) {
        setCertificate(managed);
        status_->setText(tr("Managed runtime trust is active. The saved Saslik CA can be rebuilt without downloading it again."));
    }
    updateControls();
}

RuntimeTrustPanel::~RuntimeTrustPanel() {
    // Bundle generation is bounded and owns no UI objects. Do not destroy its
    // watcher while the worker may still be publishing a result.
    watcher_.waitForFinished();
}

void RuntimeTrustPanel::setCertificate(const QByteArray& pem) {
    certificate_ = pem;
    try {
        auto selected = context(pem);
        certificate_status_->setText(tr("Selected CA SHA-256: %1").arg(QString::fromLatin1(fingerprint(*selected))));
    } catch (const std::exception& error) {
        certificate_.clear();
        certificate_status_->setText(QString::fromUtf8(error.what()));
    }
    updateControls();
}

void RuntimeTrustPanel::prepare() {
    if (certificate_.isEmpty() || watcher_.isRunning()) return;
    status_->setText(tr("Building a managed bundle from Windows Root stores…"));
    updateControls();
    watcher_.setFuture(QtConcurrent::run([pem = certificate_] {
        try { return prepareManagedRuntimeTrust(pem); }
        catch (const std::exception& error) { return RuntimeTrustResult{QString::fromUtf8(error.what()), {}, {}}; }
    }));
}

void RuntimeTrustPanel::remove() {
    QSettings settings;
    const auto ca = settings.value("windows/runtimeTrustCa").toString();
    const auto bundle = settings.value("windows/runtimeTrustBundle").toString();
    bool ok = true;
    for (const auto& path : {ca, bundle}) if (!path.isEmpty() && QFileInfo::exists(path) && !QFile::remove(path)) ok = false;
    if (ok) {
        settings.remove("windows/runtimeTrustCa");
        settings.remove("windows/runtimeTrustBundle");
        if (!ca.isEmpty()) {
            const auto directory = QFileInfo(ca).dir();
            if (directory.exists()) QDir().rmdir(directory.path());
        }
    }
    status_->setText(ok ? tr("Managed runtime-trust files removed. Existing processes are unchanged.")
                        : tr("Some managed runtime-trust files could not be removed."));
    updateControls();
}

void RuntimeTrustPanel::updateControls() {
    const auto environment = managedRuntimeEnvironment();
    const bool busy = watcher_.isRunning();
    prepare_->setEnabled(!certificate_.isEmpty() && !busy);
    remove_->setEnabled(!environment.empty() && !busy);
    copy_->setEnabled(!environment.empty() && !busy);
}
} // namespace skewer::windows
