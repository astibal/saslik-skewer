#pragma once
#include "diagnostic_log.hpp"
#include "preferences_values.hpp"
#include <QElapsedTimer>
#include <QProcess>
#include <QSaveFile>
#include <QSysInfo>
#include <QUrl>
#include <QtEndian>

namespace SupportPackage {
using Files = QMap<QString, QByteArray>;
inline QByteArray readBounded(const QString& path, qint64 limit = DiagnosticLog::maxBytes) {
    // Do not follow log symlinks or read devices/FIFOs.
    const int fd = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return {};
    struct stat info{};
    if (::fstat(fd, &info) || !S_ISREG(info.st_mode)) { ::close(fd); return {}; }
    QFile file;
    if (!file.open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) { ::close(fd); return {}; }
    if (file.size() > limit) file.seek(file.size() - limit);
    QByteArray result;
    auto data = file.read(limit);
    // Legacy multiline PEM blocks must be removed before processing JSON lines.
    QString text = QString::fromUtf8(data);
    text.replace(QRegularExpression("-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(-----END [^-]*PRIVATE KEY-----|$)"), "[private key removed]");
    data = text.toUtf8();
    for (const auto& line : data.split('\n')) {
        const auto json = QJsonDocument::fromJson(line);
        // Redact values before serialization, preserving JSON quoting and escapes.
        if (json.isObject()) result += QJsonDocument(DiagnosticLog::redactJson(json.object()).toObject()).toJson(QJsonDocument::Compact);
        else result += DiagnosticLog::redact(QString::fromUtf8(line)).toUtf8();
        result += '\n';
    }
    return data.isEmpty() ? QByteArray{} : result;
}
inline Files logs() {
    Files files;
    DiagnosticLog::prepareDirectory();
    for (const auto& component : DiagnosticLog::components) {
        QLockFile lock(DiagnosticLog::directory() + "/" + component + ".lock");
        if (!lock.tryLock(500)) {
            files.insert("logs/" + component + "-unavailable.txt", "Log is busy or unavailable; retry export.\n");
            continue;
        }
        for (const QString& suffix : {QString{}, QString(".1"), QString(".2")}) {
            const QString name = component + ".log" + suffix;
            const auto data = readBounded(DiagnosticLog::directory() + "/" + name);
            if (!data.isEmpty()) files.insert("logs/" + name, data);
        }
    }
    // Include the tail of logs from older versions, without changing them.
    const auto legacy = readBounded(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/skewer/session.log");
    if (!legacy.isEmpty()) files.insert("logs/legacy-session.log", legacy);
    return files;
}
inline QByteArray command(const QString& program, const QStringList& args) {
    const QString executable = QStandardPaths::findExecutable(program, {"/usr/bin", "/usr/sbin", "/bin", "/sbin"});
    if (executable.isEmpty()) return "Unavailable: command not installed\n";
    QProcess process;
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.setProgram(executable); process.setArguments(args);
    process.start();
    if (!process.waitForStarted(1000)) return "Unavailable: cannot start command\n";
    QByteArray output;
    QElapsedTimer timer; timer.start();
    while (process.state() != QProcess::NotRunning && timer.elapsed() < 2000 && output.size() < 128 * 1024) {
        process.waitForReadyRead(50);
        output += process.readAll();
    }
    bool truncated = process.state() != QProcess::NotRunning;
    if (truncated) { process.kill(); process.waitForFinished(1000); }
    output += process.readAll();
    output = output.left(128 * 1024);
    output += QString("\n[exit=%1, incomplete=%2]\n").arg(process.exitCode()).arg(truncated).toUtf8();
    return DiagnosticLog::redact(QString::fromUtf8(output)).toUtf8();
}
inline Files collect(bool full, const QString& version) {
    Files files = logs();
    files.insert("README.txt", QByteArray("Skewer support export. Generated locally; nothing was uploaded.\n"
        "Logs are bounded and rotated; older records may be absent. Missing diagnostics are reported.\n"
        "Credentials, raw settings, environment, pairing files and private keys are excluded.\n"
        "Review before sharing: messages may contain local paths; full packages also contain IP addresses, interface names and DNS domains.\n"));
    QJsonObject manifest{{"schema", 1}, {"created", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"version", version}, {"qt", qVersion()}, {"platform", QSysInfo::prettyProductName()},
        {"kernel", QSysInfo::kernelVersion()}, {"architecture", QSysInfo::currentCpuArchitecture()},
        {"debug_transport_allowed", Tuntom::developmentBinaryAllowed}, {"full", full}};
    files.insert("manifest.json", QJsonDocument(manifest).toJson());
    if (!full) return files;
    // Explicit allowlist: never export QSettings wholesale or copy /run state.
    QSettings settings;
    QJsonObject configuration;
    for (const auto* key : {"routing/scope", "routing/transport", "routing/mode", "routing/requested", "routing/resumeOnStartup",
                            "routing/nextHop", "routing/peerAddress", "routing/exemptions", "tunnel/binary"})
        if (settings.contains(key)) configuration.insert(key, QJsonValue::fromVariant(settings.value(key)));
    QString binaryError;
    const auto binary = Tuntom::checkedBinary(Preferences::tuntomBinary(), binaryError, Preferences::developmentBinaryAcknowledged());
    configuration.insert("transport_detected_path", Preferences::tuntomBinary());
    configuration.insert("transport_ready", !binary.isEmpty());
    configuration.insert("transport_error", binaryError);
    configuration.insert("host_guard_present", QFile::exists("/run/skewer-host.json"));
    configuration.insert("application_guard_present", QFile::exists(QString("/run/skewer-guard-%1").arg(::getuid())));
    files.insert("configuration.json", QJsonDocument(DiagnosticLog::redactJson(configuration).toObject()).toJson());
#ifdef Q_OS_LINUX
    files.insert("network/addresses.txt", command("ip", {"-brief", "address", "show"}));
    files.insert("network/routes-ipv4.txt", command("ip", {"-4", "route", "show", "table", "all"}));
    files.insert("network/routes-ipv6.txt", command("ip", {"-6", "route", "show", "table", "all"}));
    files.insert("network/rules-ipv4.txt", command("ip", {"-4", "rule", "show"}));
    files.insert("network/rules-ipv6.txt", command("ip", {"-6", "rule", "show"}));
    files.insert("network/dns.txt", command("resolvectl", {"status", "--no-pager"}));
    // resolv.conf is commonly a symlink managed by the resolver; follow ONLY this fixed system path.
    QFile resolver("/etc/resolv.conf");
    if (resolver.open(QIODevice::ReadOnly))
        files.insert("network/resolv.conf.txt", DiagnosticLog::redact(QString::fromUtf8(resolver.read(16384))).toUtf8());
    files.insert("network/routed-slice.txt", command("systemctl", {"--user", "show", "skewer-routed.slice",
        "--property=ActiveState,SubState,ControlGroup,Result", "--no-pager"}));
#endif
    return files;
}
// Small, uncompressed ZIP writer: no external archiver, shell, or temporary copies.
// Entries are internally generated, bounded, and always relative paths.
inline quint32 crc32(const QByteArray& data) {
    quint32 crc = 0xffffffff;
    for (unsigned char byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
inline void u16(QByteArray& out, quint16 v) { v = qToLittleEndian(v); out.append(reinterpret_cast<const char*>(&v), 2); }
inline void u32(QByteArray& out, quint32 v) { v = qToLittleEndian(v); out.append(reinterpret_cast<const char*>(&v), 4); }
inline QString save(const QString& path, const Files& files) {
    QByteArray archive, directory;
    if (files.size() > 100) return "Too many support files";
    for (auto it = files.begin(); it != files.end(); ++it) {
        const auto name = it.key().toUtf8();
        if (name.startsWith('/') || name.contains("..") || name.contains('\\') || name.size() > 512)
            return "Invalid support entry";
        const auto& data = it.value();
        if (data.size() > 2 * DiagnosticLog::maxBytes || archive.size() + data.size() > 20 * DiagnosticLog::maxBytes)
            return "Support package exceeds size limit";
        const auto offset = archive.size(); const auto crc = crc32(data);
        u32(archive, 0x04034b50); u16(archive, 20); u16(archive, 0x800); u16(archive, 0);
        u16(archive, 0); u16(archive, 33); u32(archive, crc); u32(archive, data.size()); u32(archive, data.size());
        u16(archive, name.size()); u16(archive, 0); archive += name; archive += data;
        u32(directory, 0x02014b50); u16(directory, 20); u16(directory, 20); u16(directory, 0x800); u16(directory, 0);
        u16(directory, 0); u16(directory, 33); u32(directory, crc); u32(directory, data.size()); u32(directory, data.size());
        u16(directory, name.size()); u16(directory, 0); u16(directory, 0); u16(directory, 0); u16(directory, 0);
        u32(directory, 0); u32(directory, offset); directory += name;
    }
    const auto offset = archive.size(); archive += directory;
    u32(archive, 0x06054b50); u16(archive, 0); u16(archive, 0); u16(archive, files.size()); u16(archive, files.size());
    u32(archive, directory.size()); u32(archive, offset); u16(archive, 0);
    QSaveFile output(path);
    if (!output.open(QIODevice::WriteOnly)) return output.errorString();
    if (!output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)) return "Cannot protect support archive permissions";
    if (output.write(archive) != archive.size() || !output.commit()) return output.errorString();
    return {};
}
}
