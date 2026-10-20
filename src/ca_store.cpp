#include "ca_store.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>

namespace {
QStringList profileDatabases(const QString& root)
{
    QStringList result;
    const QDir directory(root);
    if (!directory.exists()) return result;
    for (const QFileInfo& entry : directory.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        const QString database = entry.absoluteFilePath();
        if (QFileInfo::exists(database + QStringLiteral("/cert9.db"))) result << database;
    }
    return result;
}

QStringList revisionDatabases(const QString& root)
{
    QStringList result;
    const QDir directory(root);
    if (!directory.exists()) return result;
    for (const QFileInfo& revision : directory.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        const QString database = revision.absoluteFilePath() + QStringLiteral("/.pki/nssdb");
        if (QFileInfo::exists(database + QStringLiteral("/cert9.db"))) result << database;
    }
    result.removeDuplicates();
    return result;
}

bool run(const QString& program, const QStringList& arguments, QString& error)
{
    QProcess process;
    process.start(program, arguments);
    if (!process.waitForStarted(5000) || !process.waitForFinished(30000)
        || process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        error = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (error.isEmpty()) error = process.errorString();
        return false;
    }
    return true;
}

QString helperPath()
{
    const QString adjacent = QCoreApplication::applicationDirPath()
        + QStringLiteral("/skewer-net-helper");
    if (QFileInfo(adjacent).isExecutable()) return adjacent;
    return QString::fromLatin1(SKEWER_INSTALLED_HELPER_PATH);
}
}

CaStoreManager::CaStoreManager(QString identity) : identity_(std::move(identity)) {}

QString CaStoreManager::nickname() const
{
    return QStringLiteral("Saslik %1 CA").arg(identity_);
}

QVector<CaStore> CaStoreManager::discovered() const
{
    const QString home = QDir::homePath();
    QVector<CaStore> values{
        {QStringLiteral("firefox"), QStringLiteral("Firefox"),
         profileDatabases(home + QStringLiteral("/.mozilla/firefox"))},
        {QStringLiteral("firefox-snap"), QStringLiteral("Firefox Snap"),
         profileDatabases(home + QStringLiteral("/snap/firefox/common/.mozilla/firefox"))},
        {QStringLiteral("firefox-flatpak"), QStringLiteral("Firefox Flatpak"),
         profileDatabases(home + QStringLiteral("/.var/app/org.mozilla.firefox/.mozilla/firefox"))},
        {QStringLiteral("librewolf"), QStringLiteral("LibreWolf"),
         profileDatabases(home + QStringLiteral("/.librewolf"))},
        {QStringLiteral("librewolf-flatpak"), QStringLiteral("LibreWolf Flatpak"),
         profileDatabases(home + QStringLiteral("/.var/app/io.gitlab.librewolf-community/.librewolf"))},
        {QStringLiteral("thunderbird"), QStringLiteral("Thunderbird"),
         profileDatabases(home + QStringLiteral("/.thunderbird"))},
        {QStringLiteral("thunderbird-snap"), QStringLiteral("Thunderbird Snap"),
         profileDatabases(home + QStringLiteral("/snap/thunderbird/common/.thunderbird"))},
        {QStringLiteral("brave-snap"), QStringLiteral("Brave Snap"),
         revisionDatabases(home + QStringLiteral("/snap/brave"))},
        {QStringLiteral("chromium-snap"), QStringLiteral("Chromium Snap"),
         revisionDatabases(home + QStringLiteral("/snap/chromium"))},
    };
    QString chromium = home + QStringLiteral("/.pki/nssdb");
    if (!QDir(chromium).exists()) {
        const QString data = qEnvironmentVariable("XDG_DATA_HOME",
                                                   home + QStringLiteral("/.local/share"));
        chromium = data + QStringLiteral("/pki/nssdb");
    }
    values.insert(5, {QStringLiteral("chromium"), QStringLiteral("Chromium family"),
                      QDir(chromium).exists() ? QStringList{chromium} : QStringList{}});
    const QString certutil = QStandardPaths::findExecutable(QStringLiteral("certutil"));
    for (CaStore& store : values) {
        store.available = !certutil.isEmpty() && !store.databases.isEmpty();
        store.installed = store.available;
        for (const QString& database : store.databases) {
            QProcess process;
            process.start(certutil, {QStringLiteral("-L"), QStringLiteral("-d"),
                                     QStringLiteral("sql:") + database,
                                     QStringLiteral("-n"), nickname()});
            process.waitForFinished(5000);
            store.installed = store.installed && process.exitCode() == 0;
        }
    }
    QString safe = identity_;
    safe.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9_.-]")), QStringLiteral("_"));
    const QString system_path = QStringLiteral("/usr/local/share/ca-certificates/skewer-saslik-%1.crt").arg(safe);
    values << CaStore{QStringLiteral("system"), QStringLiteral("Ubuntu system"), {}, true,
                      QFileInfo::exists(QStringLiteral("/usr/sbin/update-ca-certificates")),
                      QFileInfo::exists(system_path)};
    return values;
}

QVector<CaStore> CaStoreManager::stores() const { return discovered(); }

bool CaStoreManager::modifyNss(const CaStore& store, const QString& certificate,
                               bool remove, QString& error) const
{
    const QString certutil = QStandardPaths::findExecutable(QStringLiteral("certutil"));
    if (certutil.isEmpty()) { error = QStringLiteral("certutil is not installed"); return false; }
    for (const QString& database : store.databases) {
        QString ignored;
        run(certutil, {QStringLiteral("-D"), QStringLiteral("-d"), QStringLiteral("sql:") + database,
                       QStringLiteral("-n"), nickname()}, ignored);
        if (!remove && !run(certutil, {QStringLiteral("-A"), QStringLiteral("-d"),
                                      QStringLiteral("sql:") + database, QStringLiteral("-n"), nickname(),
                                      QStringLiteral("-t"), QStringLiteral("CT,,"),
                                      QStringLiteral("-i"), certificate}, error)) return false;
    }
    return true;
}

bool CaStoreManager::modifySystem(const QString& certificate, bool remove, QString& error) const
{
    const QString helper = helperPath();
    if (!QFileInfo(helper).isExecutable()) {
        error = QStringLiteral("Skewer privileged helper is missing: %1. "
                               "Build the skewer-net-helper target or install the Skewer package.")
                    .arg(helper);
        return false;
    }
    const QString pkexec = QStandardPaths::findExecutable(QStringLiteral("pkexec"));
    if (pkexec.isEmpty()) {
        error = QStringLiteral("pkexec is not installed");
        return false;
    }
    QStringList arguments{helper,
                          remove ? QStringLiteral("ca-remove") : QStringLiteral("ca-install"), identity_};
    if (!remove) arguments << certificate;
    return run(pkexec, arguments, error);
}

bool CaStoreManager::install(const QString& key, const QString& certificate, QString& error) const
{
    for (const CaStore& store : discovered()) if (store.key == key)
        return store.system ? modifySystem(certificate, false, error)
                            : modifyNss(store, certificate, false, error);
    error = QStringLiteral("Unknown certificate store");
    return false;
}

bool CaStoreManager::remove(const QString& key, QString& error) const
{
    for (const CaStore& store : discovered()) if (store.key == key)
        return store.system ? modifySystem({}, true, error) : modifyNss(store, {}, true, error);
    error = QStringLiteral("Unknown certificate store");
    return false;
}
