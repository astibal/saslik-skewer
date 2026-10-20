#include "ca_store.hpp"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QTextStream>

static bool command(const QString& program, const QStringList& args)
{
    QProcess process; process.start(program, args); process.closeWriteChannel();
    return process.waitForFinished(20000) && process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
}
static QByteArray read(const QString& path)
{
    QFile file(path); if (!file.open(QIODevice::ReadOnly)) return {}; return file.readAll();
}
int main(int argc, char** argv)
{
    QTemporaryDir home;
    if (!home.isValid()) return 1;
    qputenv("HOME", home.path().toUtf8());
    qputenv("XDG_DATA_HOME", (home.path() + "/.local/share").toUtf8());
    QCoreApplication app(argc, argv);
    for (const auto& name : {QString("first"), QString("other"), QString("same-subject")})
        if (!command("openssl", {"req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", name == "other" ? "/CN=Other CA" : "/CN=Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", home.path() + '/' + name + ".key", "-out", home.path() + '/' + name + ".pem"})) return 2;
    const auto pem = read(home.path() + "/first.pem");
    const auto cert = CaStoreManager::parse(pem);
    if (cert.isNull() || !CaStoreManager::parse("not a certificate").isNull()
        || !CaStoreManager::parse(pem + pem).isNull()) return 3;
    CaStoreManager manager(cert);
    const QString profile = home.path() + "/.mozilla/firefox/test.default";
    if (!QDir().mkpath(profile) || !command("certutil", {"-N", "--empty-password", "-d", "sql:" + profile})) return 4;
    const auto import = [&](const QString& name, const QString& file) {
        return command("certutil", {"-A", "-d", "sql:" + profile, "-n", name, "-t", "CT,,", "-i", file});
    };
    // A matching nickname or subject must not be mistaken for the same CA.
    if (!import("Saslik lab1 CA", home.path() + "/other.pem")) return 5;
    CaStore store;
    for (const auto& value : manager.stores()) if (value.path == profile) store = value;
    if (!store.available || store.installed || !store.matches.isEmpty()) return 6;
    QString error;
    if (!manager.install(store, error)) { QTextStream(stderr) << error; return 7; }
    for (const auto& value : manager.stores()) if (value.path == profile) store = value;
    if (!store.installed || store.matches.size() != 1) {
        QTextStream(stderr) << "After install: " << store.detail << " matches=" << store.matches.join(',') << '\n';
        QProcess listing; listing.start("certutil", {"-L", "-d", "sql:" + profile}); listing.waitForFinished();
        QTextStream(stderr) << listing.readAllStandardOutput();
        return 8;
    }
    if (!manager.remove(store, error)) return 9;
    if (!command("certutil", {"-L", "-d", "sql:" + profile, "-n", "Saslik lab1 CA"})) return 10;
    // Removal must refuse a stale preview if that nickname now holds another CA.
    if (!import("external alias", home.path() + "/first.pem")) return 11;
    for (const auto& value : manager.stores()) if (value.path == profile) store = value;
    if (!command("certutil", {"-D", "-d", "sql:" + profile, "-n", "external alias"})
        || !import("external alias", home.path() + "/other.pem")) return 12;
    if (manager.remove(store, error)) return 13;
    if (!command("certutil", {"-L", "-d", "sql:" + profile, "-n", "Saslik lab1 CA"})) return 14;
    // Same-subject rotation must not be ambiguous when selected by exact DER.
    if (!import("rotated CA", home.path() + "/same-subject.pem")) return 15;
    if (!manager.install(store, error)) { QTextStream(stderr) << error; return 16; }
    for (const auto& value : manager.stores()) if (value.path == profile) store = value;
    if (!store.available || !store.installed || store.matches.isEmpty()) return 18;
    if (!manager.remove(store, error)) return 19;
    CaStoreManager rotated(CaStoreManager::parse(read(home.path() + "/same-subject.pem")));
    bool rotated_present = false;
    for (const auto& value : rotated.stores()) if (value.path == profile)
        rotated_present = value.available && value.installed && !value.matches.isEmpty();
    if (!rotated_present) return 26;
    const QString snap = home.path() + "/snap/test-browser";
    for (const auto& revision : {QString("100"), QString("99"), QString("x1"), QString("common")}) {
        const QString db = snap + '/' + revision + "/.pki/nssdb";
        if (!QDir().mkpath(db) || !command("certutil", {"-N", "--empty-password", "-d", "sql:" + db})) return 20;
    }
    if (!QFile::link(snap + "/100", snap + "/current")) return 21;
    const auto check_snap = [&](const QString& current, bool known) {
        int count = 0;
        for (const auto& value : manager.stores()) {
            if (value.snap_name != "test-browser") continue;
            ++count;
            const QString expected = value.snap_revision == "common" ? "common (shared)"
                : !known ? "current unknown" : value.snap_revision == current ? "current" : "retained (not current)";
            if (value.snap_state != expected || value.path.contains("/current/")) return false;
        }
        return count == 4; // current must not duplicate its real database.
    };
    if (!check_snap("100", true)) return 22;
    // Reverting to a lower revision is still current. Refresh metadata each scan.
    if (!QFile::remove(snap + "/current") || !QFile::link(snap + "/99", snap + "/current")
        || !check_snap("99", true)) return 23;
    if (!QFile::remove(snap + "/current") || !check_snap({}, false)) return 24;
    if (!QFile::link(home.path(), snap + "/current") || !check_snap({}, false)) return 25;
    return 0;
}
