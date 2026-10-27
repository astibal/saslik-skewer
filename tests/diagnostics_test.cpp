#include "support_package.hpp"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <cstdio>

#define CHECK(condition) do { if (!(condition)) { std::fprintf(stderr, "Check failed at line %d: %s\n", __LINE__, #condition); return 1; } } while (0)
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QTemporaryDir temporary;
    CHECK(temporary.isValid());
    qputenv("XDG_DATA_HOME", temporary.path().toUtf8());
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, temporary.path());
    app.setOrganizationName("SkewerTest"); app.setApplicationName("Diagnostics");
    DiagnosticLog::initialize("app");
    const QString secret = "DO_NOT_EXPORT_THIS_VALUE";
    const auto input = "token=" + secret + " psk=\"" + secret + "\" https://host/path#" + secret
        + " Bearer " + secret + "\n-----BEGIN PRIVATE KEY-----\n" + secret + "\n-----END PRIVATE KEY-----";
    CHECK(!DiagnosticLog::redact(input).contains(secret));
    CHECK(DiagnosticLog::write("test", input));
    DiagnosticLog::Lines fragmented;
    fragmented.append("token=DO_NOT_", "fragment");
    fragmented.append("EXPORT_THIS_VALUE\n", "fragment");
    fragmented.append("-----BEGIN PRIVATE KEY-----\nDO_NOT_", "fragment");
    fragmented.append("EXPORT_THIS_VALUE\n-----END PRIVATE KEY-----\n", "fragment");
    fragmented.finish("fragment");
    qWarning("Qt warning also reaches the file");
    auto files = SupportPackage::logs();
    CHECK(files.contains("logs/app.log"));
    CHECK(!files["logs/app.log"].contains(secret.toUtf8()));
    CHECK(files["logs/app.log"].contains("Qt warning"));
    for (const auto& line : files["logs/app.log"].split('\n')) {
        if (!line.isEmpty()) CHECK(QJsonDocument::fromJson(line).isObject());
    }
    // Rotation bounds retention, preserving the newest records and owner-only access.
    for (int i = 0; i < 230; ++i) CHECK(DiagnosticLog::write("rotation", QString(16000, 'x')));
    CHECK(DiagnosticLog::write("rotation", "newest marker"));
    const QString path = DiagnosticLog::directory() + "/app.log";
    CHECK(QFileInfo(path).size() <= DiagnosticLog::maxBytes);
    CHECK(QFile::exists(path + ".1") && QFile::exists(path + ".2") && !QFile::exists(path + ".3"));
    struct stat metadata{};
    CHECK(::stat(QFile::encodeName(path).constData(), &metadata) == 0 && (metadata.st_mode & 0777) == 0600);
    CHECK(::stat(QFile::encodeName(DiagnosticLog::directory()).constData(), &metadata) == 0 && (metadata.st_mode & 0777) == 0700);
    CHECK(SupportPackage::readBounded(path).contains("newest marker"));
    // Symlinked log files must not disclose an unrelated file or overwrite it.
    QFile outside(temporary.filePath("secret.txt"));
    CHECK(outside.open(QIODevice::WriteOnly)); outside.write(secret.toUtf8()); outside.close();
    QFile::remove(path);
    CHECK(QFile::link(outside.fileName(), path));
    CHECK(!DiagnosticLog::write("test", "must not write"));
    CHECK(SupportPackage::readBounded(path).isEmpty());
    QFile::remove(path);
    QSettings settings;
    settings.setValue("pairing/psk", secret);
    settings.setValue("routing/saslikUrl", "skewer://server/pair#psk=" + secret);
    settings.setValue("routing/scope", "host");
    settings.setValue("tunnel/binary", temporary.filePath("missing/tuntom"));
    CHECK(Preferences::tunnelPreflightError().contains("Preferences > Tunnel"));
    QFile legacy(temporary.filePath("skewer/session.log"));
    CHECK(legacy.open(QIODevice::WriteOnly));
    legacy.write(("-----BEGIN PRIVATE KEY-----\n" + secret + "\n-----END PRIVATE KEY-----\n").toUtf8());
    legacy.close();
    const auto package = SupportPackage::collect(true, "test-version");
    CHECK(package.contains("configuration.json"));
    CHECK(QJsonDocument::fromJson(package["configuration.json"]).object()["routing/scope"] == "host");
    for (const auto& content : package) CHECK(!content.contains(secret.toUtf8()));
    CHECK(!SupportPackage::collect(false, "test-version").contains("configuration.json"));
    CHECK(!SupportPackage::save(temporary.filePath("bad.zip"), {{"../escape", "no"}}).isEmpty());
    CHECK(!SupportPackage::save(temporary.filePath("absent/file.zip"), package).isEmpty());
    const auto archive = argc > 1 ? QString::fromLocal8Bit(argv[1]) : temporary.filePath("support.zip");
    CHECK(SupportPackage::save(archive, package).isEmpty());
    CHECK(::stat(QFile::encodeName(archive).constData(), &metadata) == 0 && (metadata.st_mode & 0777) == 0600);
    return 0;
}
