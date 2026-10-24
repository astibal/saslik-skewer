#include "ca_store.hpp"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDirIterator>
#include <QFile>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QSslCertificateExtension>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <algorithm>
namespace {
bool run(const QString& program, const QStringList& args, QByteArray& output, QString& error)
{
    QProcess process;
    process.start(program, args);
    process.closeWriteChannel();
    if (!process.waitForStarted(5000) || !process.waitForFinished(60000)
        || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        error = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (error.isEmpty()) error = process.errorString();
        return false;
    }
    output = process.readAllStandardOutput(); return true;
}
QString digest(const QSslCertificate& cert)
{
    return cert.isNull() ? QString{} : QString::fromLatin1(cert.digest(QCryptographicHash::Sha256).toHex());
}
QSslCertificate readCertificate(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) return QSslCertificate();
    const auto certs = QSslCertificate::fromData(file.readAll());
    return certs.size() == 1 ? certs.first() : QSslCertificate{};
}
QString helper()
{
    const QString adjacent = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
    return QFileInfo(adjacent).isExecutable() ? adjacent : QStringLiteral(SKEWER_INSTALLED_HELPER_PATH);
}
QString nssHelper()
{
    const QString adjacent = QCoreApplication::applicationDirPath() + "/skewer-nss-helper";
    return QFileInfo(adjacent).isExecutable() ? adjacent
        : QFileInfo(QStringLiteral(SKEWER_INSTALLED_HELPER_PATH)).dir().filePath("skewer-nss-helper");
}
bool enumerate(CaStore& store, const QSslCertificate& selected)
{
    QByteArray output;
    if (!run(nssHelper(), {"inspect", store.path, QString::fromLatin1(selected.toDer().toBase64())}, output, store.detail)) return false;
    QJsonParseError error;
    const auto value = QJsonDocument::fromJson(output, &error).object();
    if (error.error != QJsonParseError::NoError || !value.contains("present")) {
        store.detail = "Invalid NSS helper response"; return false;
    }
    if (value["present"].toBool()) {
        const auto name = value["nickname"].toString();
        store.matches << (name.isEmpty() ? "SHA-256 " + digest(selected) : name);
    }
    store.installed = value["trusted"].toBool();
    return true;
}
void describeSnap(CaStore& store, const QString& home)
{
    const QString root = home + "/snap/";
    if (!store.path.startsWith(root)) return;
    const auto parts = store.path.mid(root.size()).split('/');
    if (parts.size() < 3) return;
    store.snap_name = parts.at(0);
    store.snap_revision = parts.at(1);
    const QString app_root = root + store.snap_name;
    const QFileInfo current(app_root + "/current");
    const QString target = current.isSymLink() ? current.canonicalFilePath() : QString{};
    const QString revision = QFileInfo(target).fileName();
    const QRegularExpression revision_name("^(?:[0-9]+|x[0-9]+)$");
    const bool valid_current = !target.isEmpty() && QFileInfo(target).isDir()
        && QFileInfo(target).absolutePath() == app_root && revision_name.match(revision).hasMatch();
    if (store.snap_revision == "common") store.snap_state = "common (shared)";
    else if (!revision_name.match(store.snap_revision).hasMatch()) store.snap_state = "unknown layout";
    else if (!valid_current) store.snap_state = "current unknown";
    else store.snap_state = store.snap_revision == revision ? "current" : "retained (not current)";
    store.label = "Snap · " + store.snap_name + " · " + parts.mid(2).join('/');
    // current is used only as metadata, never as a mutation path. The scanner
    // visits real revision directories once, including retained revisions.
}
}
CaStoreManager::CaStoreManager(QSslCertificate certificate) : certificate_(std::move(certificate)) {}
QSslCertificate CaStoreManager::parse(const QByteArray& pem)
{
    if (pem.size() > 65536) return QSslCertificate();
    const auto certificates = QSslCertificate::fromData(pem);
    if (certificates.size() != 1) return QSslCertificate();
    const auto& cert = certificates.first();
    for (const auto& extension : cert.extensions())
        if (extension.oid() == "2.5.29.19" && extension.value().toMap().value("ca").toBool()) return cert;
    return QSslCertificate();
}
QString CaStoreManager::fingerprint() const { return digest(certificate_); }
QVector<CaStore> CaStoreManager::stores() const
{
    QVector<CaStore> result;
    const QString home = QDir::homePath();
    const QStringList roots{home + "/.mozilla", home + "/.thunderbird", home + "/.librewolf",
        home + "/.waterfox", home + "/.floorp", home + "/.zen",
        home + "/.pki", home + "/snap", home + "/.var/app", home + "/.config",
        QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/pki"};
    QSet<QString> seen;
    for (const auto& root : roots) {
        if (!QFileInfo::exists(root)) continue;
        QStringList pending{root}; int visited = 0;
        while (!pending.isEmpty() && visited++ < 15000) {
            const QString dir = pending.takeLast();
            const QString canonical = QFileInfo(dir).canonicalFilePath();
            if (!canonical.startsWith(home + '/') || seen.contains(canonical)) continue;
            seen.insert(canonical);
            if (!QFileInfo(dir).isReadable() || !QFileInfo(dir).isExecutable()) {
                result << CaStore{canonical, "Unreadable directory", canonical, {}, false, false, false,
                                  "Not inspected; permissions denied", {}, {}, {}}; continue;
            }
            if (QFileInfo::exists(dir + "/cert9.db")) {
                CaStore store; store.key = store.path = canonical;
                store.label = canonical.mid(home.size() + 1);
                describeSnap(store, home);
                if (QFileInfo(dir + "/cert9.db").isSymLink())
                    store.detail = "Symlinked NSS database: not inspected";
                else store.available = enumerate(store, certificate_);
                if (store.detail.isEmpty()) store.detail = store.installed ? "Trusted"
                    : store.matches.isEmpty() ? "CA absent" : "Present, not explicitly trusted";
                result << store;
            }
            // Bounded discovery only; no symlink traversal or cache inspection.
            for (const auto& child : QDir(dir).entryInfoList(QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot)) {
                if (child.isSymLink() || child.fileName().contains("cache", Qt::CaseInsensitive)
                    || child.fileName() == "node_modules") continue;
                pending << child.absoluteFilePath();
            }
        }
        if (!pending.isEmpty()) result << CaStore{root, "Scan limit reached", root, {}, false, false, false,
                                                  "Not all directories were inspected", {}, {}, {}};
    }
    CaStore system;
    system.key = "system"; system.label = "System trust (shared)";
    system.path = "/usr/local/share/ca-certificates"; system.system = true;
    system.available = QFileInfo::exists("/usr/sbin/update-ca-certificates");
    QDirIterator files(system.path, {"*.crt"}, QDir::Files | QDir::NoSymLinks, QDirIterator::Subdirectories);
    bool unreadable = false;
    while (files.hasNext()) {
        const QString path = files.next();
        if (!QFileInfo(path).isReadable()) { unreadable = true; continue; }
        if (digest(readCertificate(path)) == fingerprint() && !fingerprint().isEmpty()) system.matches << path;
    }
    QFile bundle("/etc/ssl/certs/ca-certificates.crt");
    if (bundle.open(QIODevice::ReadOnly)) {
        for (const auto& cert : QSslCertificate::fromData(bundle.readAll()))
            if (!fingerprint().isEmpty() && digest(cert) == fingerprint()) system.installed = true;
    } else unreadable = true;
    system.detail = system.installed ? "Present in system CA bundle" : "Not present in system CA bundle";
    if (system.installed && system.matches.isEmpty()) {
        system.available = false;
        system.detail = "Present in system bundle; source is outside supported local anchors (cannot remove)";
    }
    if (unreadable) { system.available = false; system.detail += "; some system files are unreadable"; }
    result << system;
    return result;
}
bool CaStoreManager::install(const CaStore& store, QString& error, bool desktop) const
{
    if (parse(certificate_.toPem()).isNull() || certificate_.expiryDate() < QDateTime::currentDateTimeUtc()
        || certificate_.effectiveDate() > QDateTime::currentDateTimeUtc()) {
        error = "CA is missing or outside its validity period"; return false;
    }
    QTemporaryFile file;
    if (!file.open() || file.write(certificate_.toPem()) != certificate_.toPem().size() || !file.flush()) {
        error = "Cannot stage CA certificate"; return false;
    }
    QByteArray output;
    if (store.system) {
        QStringList args{helper(), "ca-install", fingerprint(), file.fileName()};
        if (!desktop) args.prepend("-n");
        return run(desktop ? "pkexec" : "sudo", args, output, error);
    }
    return run(nssHelper(), {"install", store.path, QString::fromLatin1(certificate_.toDer().toBase64())}, output, error);
}
bool CaStoreManager::remove(const CaStore& store, QString& error, bool desktop) const
{
    if (fingerprint().isEmpty()) { error = "No CA selected"; return false; }
    QByteArray output;
    if (store.system) {
        for (const auto& path : store.matches) {
            QStringList args{helper(), "ca-remove", fingerprint(), path};
            if (!desktop) args.prepend("-n");
            if (!run(desktop ? "pkexec" : "sudo", args, output, error)) return false;
        }
        return true;
    }
    return run(nssHelper(), {"remove", store.path, QString::fromLatin1(certificate_.toDer().toBase64())}, output, error);
}
