#include "runtime_trust.hpp"
#include "runtime_trust_service.hpp"
#include <QCryptographicHash>
#include <QClipboard>
#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRegularExpression>
#include <QSslCertificate>
#include <QStandardPaths>
#include <QSaveFile>
#include <QSettings>
#include <QTableWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QtConcurrentRun>

namespace {
struct CommandResult { QByteArray out, err; bool ok{}; };
CommandResult run(const QString& program, const QStringList& arguments,
                  const QProcessEnvironment& environment = QProcessEnvironment::systemEnvironment())
{
    QProcess process; process.setProcessEnvironment(environment); process.setWorkingDirectory("/");
    process.start(program, arguments); process.closeWriteChannel();
    const bool finished = process.waitForStarted(3000) && process.waitForFinished(10000);
    return {process.readAllStandardOutput(), process.readAllStandardError(),
        finished && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0};
}
QString digest(const QSslCertificate& certificate)
{
    return certificate.isNull() ? QString{} : QString::fromLatin1(
        certificate.digest(QCryptographicHash::Sha256).toHex());
}
bool bundleContains(const QString& path, const QString& wanted)
{
    QFile file(path);
    if (wanted.isEmpty() || !file.open(QIODevice::ReadOnly) || file.size() > 32 * 1024 * 1024) return false;
    for (const auto& certificate : QSslCertificate::fromData(file.readAll()))
        if (digest(certificate) == wanted) return true;
    return false;
}
QVector<RuntimeResult> python(const QString& wanted)
{
    RuntimeResult result{"Python / ssl", {}, "OpenSSL defaults", {}, "not found", {}};
    const QString executable = QStandardPaths::findExecutable("python3");
    if (executable.isEmpty()) return {result};
    const QString script = "import importlib.util,json,os,ssl,sys\n"
        "p=ssl.get_default_verify_paths()\n"
        "c=''\n"
        "if importlib.util.find_spec('certifi'):\n import certifi; c=certifi.where()\n"
        "print(json.dumps({'version':sys.version.split()[0],'cafile':p.cafile or '',"
        "'capath':p.capath or '','certifi':c,'ssl_env':os.getenv('SSL_CERT_FILE',''),"
        "'requests_env':os.getenv('REQUESTS_CA_BUNDLE','') or os.getenv('CURL_CA_BUNDLE',''),"
        "'pip_env':os.getenv('PIP_CERT','')}))\n";
    const auto command = run(executable, {"-I", "-c", script});
    const auto value = QJsonDocument::fromJson(command.out).object();
    if (!command.ok || value.isEmpty()) { result.state = "probe failed"; result.detail = QString::fromLocal8Bit(command.err).trimmed(); return {result}; }
    result.version = value["version"].toString();
    const QString certifi = value["certifi"].toString(), cafile = value["cafile"].toString();
    const QString ssl_override = value["ssl_env"].toString();
    result.location = ssl_override.isEmpty() ? cafile : ssl_override;
    if (!ssl_override.isEmpty()) result.source = "SSL_CERT_FILE override";
    if (result.location.isEmpty()) result.location = value["capath"].toString();
    result.state = wanted.isEmpty() ? "select CA" : bundleContains(result.location, wanted) ? "trusted" : "CA absent";
    QVector<RuntimeResult> results{result};
    const QString requests_override = value["requests_env"].toString();
    if (!certifi.isEmpty() || !requests_override.isEmpty()) {
        const QString override = requests_override;
        const QString effective = override.isEmpty() ? certifi : override;
        RuntimeResult requests{"Python / requests", result.version,
            override.isEmpty() ? "certifi bundle" : "REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE override", effective,
            wanted.isEmpty() ? "select CA" : bundleContains(effective, wanted) ? "trusted" : "CA absent",
            "REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE may override this"};
        results << requests;
    }
    const QString pip = value["pip_env"].toString();
    if (!pip.isEmpty()) results << RuntimeResult{"pip", result.version, "PIP_CERT override", pip,
        wanted.isEmpty() ? "select CA" : bundleContains(pip, wanted) ? "trusted" : "CA absent", {}};
    return results;
}
RuntimeResult node(const QString& wanted)
{
    RuntimeResult result{"Node.js", {}, "bundled Mozilla roots", {}, "not found", {}};
    const QString executable = QStandardPaths::findExecutable("node");
    if (executable.isEmpty()) return result;
    const QString script = "const tls=require('node:tls'),crypto=require('node:crypto');"
        "const roots=tls.getCACertificates?tls.getCACertificates('default'):tls.rootCertificates;"
        "const fp=x=>new crypto.X509Certificate(x).fingerprint256.replaceAll(':','').toLowerCase();"
        "console.log(JSON.stringify({version:process.versions.node,extra:process.env.NODE_EXTRA_CA_CERTS||'',"
        "present:!!process.env.SKEWER_WANTED_CA&&roots.some(x=>fp(x)===process.env.SKEWER_WANTED_CA)}));";
    auto environment = QProcessEnvironment::systemEnvironment(); environment.insert("SKEWER_WANTED_CA", wanted);
    const auto command = run(executable, {"-e", script}, environment);
    const auto value = QJsonDocument::fromJson(command.out).object();
    if (!command.ok || value.isEmpty()) { result.state = "probe failed"; result.detail = QString::fromLocal8Bit(command.err).trimmed(); return result; }
    result.version = value["version"].toString(); result.location = value["extra"].toString();
    if (!result.location.isEmpty()) result.source += " + NODE_EXTRA_CA_CERTS";
    result.state = wanted.isEmpty() ? "select CA" : value["present"].toBool() ? "trusted" : "CA absent";
    result.detail = "Fresh Node process in Skewer's environment"; return result;
}
RuntimeResult java(const QString& wanted)
{
    RuntimeResult result{"Java", {}, "JVM cacerts", {}, "not found", {}};
    const QString executable = QStandardPaths::findExecutable("java");
    if (executable.isEmpty()) return result;
    const auto settings = run(executable, {"-XshowSettings:properties", "-version"});
    const QString text = QString::fromLocal8Bit(settings.err + settings.out);
    result.version = QRegularExpression("java\\.version = ([^\\r\\n]+)").match(text).captured(1).trimmed();
    const QString home = QRegularExpression("java\\.home = ([^\\r\\n]+)").match(text).captured(1).trimmed();
    result.location = home.isEmpty() ? QString{} : home + "/lib/security/cacerts";
    const auto environment = QProcessEnvironment::systemEnvironment();
    const QString java_options = environment.value("JAVA_TOOL_OPTIONS") + ' '
        + environment.value("_JAVA_OPTIONS") + ' ' + environment.value("JDK_JAVA_OPTIONS");
    const auto override = QRegularExpression("(?:^|\\s)-Djavax\\.net\\.ssl\\.trustStore=(?:\"([^\"]+)\"|'([^']+)'|([^\\s]+))")
        .match(java_options);
    const QString overridden = !override.captured(1).isEmpty() ? override.captured(1)
        : !override.captured(2).isEmpty() ? override.captured(2) : override.captured(3);
    if (!overridden.isEmpty()) { result.source = "javax.net.ssl.trustStore override"; result.location = overridden; }
    if (!settings.ok || result.location.isEmpty()) { result.state = "probe failed"; result.detail = text.trimmed(); return result; }
    if (wanted.isEmpty()) result.state = "select CA";
    else {
        const QString keytool = QFileInfo(executable).dir().filePath("keytool");
        const QStringList arguments = overridden.isEmpty()
            ? QStringList{"-list", "-cacerts", "-storepass", "changeit", "-rfc"}
            : QStringList{"-list", "-keystore", overridden, "-storepass", "changeit", "-rfc"};
        const auto listing = run(keytool, arguments);
        bool present = false;
        for (const auto& certificate : QSslCertificate::fromData(listing.out))
            if (digest(certificate) == wanted) { present = true; break; }
        result.state = !listing.ok ? "unverified" : present ? "trusted" : "CA absent";
        if (!listing.ok) result.detail = overridden.isEmpty()
            ? QString::fromLocal8Bit(listing.err).trimmed()
            : "Custom Java truststore found; it could not be inspected with the default password";
    }
    return result;
}
QVector<RuntimeResult> discover(const QByteArray& pem)
{
    const auto certificates = QSslCertificate::fromData(pem);
    const QString wanted = certificates.size() == 1 ? digest(certificates.first()) : QString{};
    auto results = python(wanted);
    results << node(wanted) << java(wanted);
    return results;
}
}

QVector<RuntimeResult> discoverRuntimeTrust(const QByteArray& pem) { return discover(pem); }

RuntimeTrustPanel::RuntimeTrustPanel(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    auto* explanation = new QLabel(tr(
        "Why this exists: Python, Node and Java may use their own CA sources instead of the system or browser store. "
        "A trusted browser therefore does not guarantee that your scripts trust the lab CA.\n\n"
        "Refresh inspects fresh runtime processes in Skewer's environment; it does not change trust. "
        "Applications, virtual environments and custom launchers may use different settings.\n\n"
        "Prepare managed bundle creates Skewer-owned certificate files for the selected lab CA and selects them for new Skewer shell/run and launcher sessions. "
        "New Skewer Shell sessions receive the exports automatically; no copying is needed. "
        "Copy shell setup is only for ordinary terminals outside Skewer. "
        "The variables apply to that shell and its new children, not already running applications. "
        "The provided setup covers Python/Requests/pip, curl and Node; it does not configure Java.\n\n"
        "Trusting the lab CA permits TLS interception by whoever controls its private key. "
        "Nothing is installed into system or browser stores by this panel. "
        "Remove managed bundle deletes the managed files, but does not unset existing environment variables "
        "or revoke open TLS sessions; unset the exports or close that shell afterward."), this);
    explanation->setWordWrap(true); layout->addWidget(explanation);
    auto* actions = new QHBoxLayout;
    auto* select_ca = new QPushButton(tr("Select CA…"), this);
    select_ca->setObjectName("runtimeTrustSelectCa");
    select_ca->setToolTip(tr("View the CA downloaded from Saslik, or select a local CA in CA Trust."));
    connect(select_ca, &QPushButton::clicked, this, &RuntimeTrustPanel::selectCertificateRequested);
    actions->addWidget(select_ca);
    refresh_ = new QPushButton(tr("Refresh runtime trust"), this);
    prepare_ = new QPushButton(tr("Prepare managed bundle"), this);
    remove_ = new QPushButton(tr("Remove managed bundle"), this);
    copy_ = new QPushButton(tr("Copy shell setup"), this);
    refresh_->setObjectName("runtimeTrustRefresh");
    prepare_->setObjectName("runtimeTrustPrepare");
    remove_->setObjectName("runtimeTrustRemove");
    copy_->setObjectName("runtimeTrustCopyEnvironment");
    connect(refresh_, &QPushButton::clicked, this, &RuntimeTrustPanel::refresh);
    connect(prepare_, &QPushButton::clicked, this, &RuntimeTrustPanel::prepareBundle);
    connect(remove_, &QPushButton::clicked, this, &RuntimeTrustPanel::removeBundle);
    connect(copy_, &QPushButton::clicked, this, &RuntimeTrustPanel::copyEnvironment);
    for (auto* button : {refresh_, prepare_, remove_, copy_}) actions->addWidget(button);
    actions->addStretch(); layout->addLayout(actions);
    summary_ = new QLabel(this); summary_->setWordWrap(true); layout->addWidget(summary_);
    table_ = new QTableWidget(0, 6, this); table_->setObjectName("runtimeTrustTable");
    table_->setHorizontalHeaderLabels({tr("Runtime"), tr("Version"), tr("Effective source"), tr("Location / override"), tr("Selected CA"), tr("Details")});
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(false);
    const int widths[] = {130, 120, 170, 300, 140, 350};
    for (int col = 0; col < 6; ++col) table_->setColumnWidth(col, widths[col]);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers); table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(table_, 1);
    // Restore only a previously prepared CA, never silently trust a new one.
    QFile saved_ca(QSettings().value("runtimeTrust/activeCa").toString());
    if (saved_ca.open(QIODevice::ReadOnly) && saved_ca.size() <= 65536) {
        const auto pem = saved_ca.readAll();
        if (QSslCertificate::fromData(pem).size() == 1) certificate_ = pem;
    }
    updateActions(); refresh();
}
void RuntimeTrustPanel::setCertificate(const QByteArray& pem)
{
    certificate_ = pem; updateActions(); refresh();
}

QString RuntimeTrustPanel::managedDirectory() const
{
    return runtimeTrustDirectory(certificate_);
}

QString runtimeTrustDirectory(const QByteArray& pem)
{
    const auto certificates = QSslCertificate::fromData(pem);
    if (certificates.size() != 1) return {};
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)
        + "/skewer/runtime-trust/" + digest(certificates.first());
}
QString RuntimeTrustPanel::managedCaPath() const { return managedDirectory() + "/saslik-ca.pem"; }
QString RuntimeTrustPanel::managedBundlePath() const { return managedDirectory() + "/ca-bundle.pem"; }

void RuntimeTrustPanel::updateActions()
{
    const bool selected = QSslCertificate::fromData(certificate_).size() == 1;
    const bool prepared = selected && QFileInfo::exists(managedCaPath()) && QFileInfo::exists(managedBundlePath());
    if (prepare_) prepare_->setEnabled(selected && !working_);
    if (remove_) remove_->setEnabled(prepared && !working_);
    if (copy_) copy_->setEnabled(prepared && !working_);
}

void RuntimeTrustPanel::prepareBundle()
{
    summary_->setText(prepareRuntimeTrust(certificate_)); updateActions();
}

QString prepareRuntimeTrust(const QByteArray& pem)
{
    const auto certificates = QSslCertificate::fromData(pem);
    if (certificates.size() != 1) return "Select exactly one CA first.";
    const QString directory = runtimeTrustDirectory(pem);
    if (!QDir().mkpath(directory)) return "Cannot create the managed runtime-trust directory.";
    QFile::setPermissions(directory, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
    const QByteArray ca = certificates.first().toPem();
    QFile system(QStringLiteral("/etc/ssl/certs/ca-certificates.crt"));
    QByteArray bundle;
    if (system.open(QIODevice::ReadOnly) && system.size() <= 32 * 1024 * 1024) bundle = system.readAll();
    if (!bundle.endsWith('\n')) bundle += '\n';
    if (!bundleContains(QStringLiteral("/etc/ssl/certs/ca-certificates.crt"), digest(certificates.first()))) bundle += ca;
    const auto write = [](const QString& path, const QByteArray& value) {
        QSaveFile file(path);
        file.setDirectWriteFallback(false);
        if (!file.open(QIODevice::WriteOnly) || file.write(value) != value.size()
            || !file.commit()) return false;
        return QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    };
    if (!write(directory + "/saslik-ca.pem", ca) || !write(directory + "/ca-bundle.pem", bundle))
        return "Cannot write the managed CA bundle.";
    QSettings().setValue("runtimeTrust/activeBundle", directory + "/ca-bundle.pem");
    QSettings().setValue("runtimeTrust/activeCa", directory + "/saslik-ca.pem");
    return "Ready. New Skewer Shell sessions automatically use this CA bundle. Existing shells are unchanged.";
}

void RuntimeTrustPanel::removeBundle()
{
    summary_->setText(removeRuntimeTrust(certificate_)); updateActions();
}

QString removeRuntimeTrust(const QByteArray& pem)
{
    const auto directory = runtimeTrustDirectory(pem);
    if (directory.isEmpty()) return "Select exactly one CA first.";
    bool ok = true;
    for (const auto& path : {directory + "/saslik-ca.pem", directory + "/ca-bundle.pem"})
        if (QFileInfo::exists(path) && !QFile::remove(path)) ok = false;
    if (QFileInfo::exists(directory) && !QDir().rmdir(directory)) ok = false;
    if (ok && QSettings().value("runtimeTrust/activeBundle").toString() == directory + "/ca-bundle.pem") {
        QSettings().remove("runtimeTrust/activeBundle");
        QSettings().remove("runtimeTrust/activeCa");
    }
    return ok ? "Managed runtime CA files removed." : "Some managed runtime CA files could not be removed.";
}

void RuntimeTrustPanel::copyEnvironment() const
{
    QApplication::clipboard()->setText(runtimeTrustEnvironment(certificate_));
    summary_->setText(tr("Shell setup copied. It affects only programs started from that environment."));
}

QString runtimeTrustEnvironment(const QByteArray& pem)
{
    const auto directory = runtimeTrustDirectory(pem);
    if (directory.isEmpty()) return {};
    const auto quote = [](QString value) {
        value.replace(QLatin1Char('\''), QStringLiteral("'\\''"));
        return QLatin1Char('\'') + value + QLatin1Char('\'');
    };
    const QString bundle = quote(directory + "/ca-bundle.pem"), ca = quote(directory + "/saslik-ca.pem");
    const QString commands = "export SSL_CERT_FILE=" + bundle + "\n"
        + "export REQUESTS_CA_BUNDLE=" + bundle + "\n"
        + "export CURL_CA_BUNDLE=" + bundle + "\n"
        + "export PIP_CERT=" + bundle + "\n"
        + "export NODE_EXTRA_CA_CERTS=" + ca + "\n";
    return commands;
}
void RuntimeTrustPanel::refresh()
{
    if (working_) return;
    working_ = true; refresh_->setEnabled(false); updateActions(); summary_->setText(tr("Inspecting runtimes…"));
    auto* watcher = new QFutureWatcher<QVector<RuntimeResult>>(this);
    connect(watcher, &QFutureWatcher<QVector<RuntimeResult>>::finished, this, [this, watcher] {
        const auto results = watcher->result(); watcher->deleteLater(); table_->setRowCount(results.size());
        for (int row = 0; row < results.size(); ++row) {
            const auto& result = results.at(row);
            const QStringList cells{result.runtime, result.version, result.source, result.location, result.state, result.detail};
            for (int column = 0; column < cells.size(); ++column) {
                auto* item = new QTableWidgetItem(cells.at(column));
                if (column == 4 && result.state == "trusted") item->setForeground(QColor("#41b879"));
                table_->setItem(row, column, item);
            }
        }
        summary_->setText(certificate_.isEmpty() ? tr("Runtime sources found. Select a CA in CA Trust to verify its presence.") : tr("Runtime sources checked against the selected CA."));
        working_ = false; refresh_->setEnabled(true); updateActions();
    });
    watcher->setFuture(QtConcurrent::run([pem = certificate_] { return discoverRuntimeTrust(pem); }));
}
