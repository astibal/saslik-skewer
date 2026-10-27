#pragma once
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLockFile>
#include <QRegularExpression>
#include <QStandardPaths>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace DiagnosticLog {
inline constexpr qint64 maxBytes = 1024 * 1024;
inline const QStringList components{"app", "tunnel", "session"};
inline QString component = "app";
inline QString directory() {
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/skewer/logs";
}
// Defense in depth: callers must never submit protocol frames, credentials,
// environment dumps or command lines. Redaction is repeated during export.
inline QString redact(QString text) {
    text.replace(QRegularExpression("-----BEGIN [^-]*PRIVATE KEY-----[\\s\\S]*?(-----END [^-]*PRIVATE KEY-----|$)"), "[private key removed]");
    text.replace(QRegularExpression(R"((?:skewer|https?)://[^\s<>"']+)"), "[endpoint removed]");
    text.replace(QRegularExpression(R"(\bBearer\s+\S+)", QRegularExpression::CaseInsensitiveOption), "Bearer [redacted]");
    text.replace(QRegularExpression(R"re(("?(?:key|psk|token|secret|password|authorization|invitation|access_token|refresh_token)"?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}"']+))re",
        QRegularExpression::CaseInsensitiveOption), "\\1[redacted]");
    text.replace(QRegularExpression("\\b[0-9a-fA-F]{32,}\\b"), "[hex redacted]");
    return text;
}
inline QJsonValue redactJson(const QJsonValue& value) {
    if (value.isString()) return redact(value.toString());
    if (value.isArray()) {
        QJsonArray result;
        for (const auto& item : value.toArray()) result.append(redactJson(item));
        return result;
    }
    if (value.isObject()) {
        QJsonObject result;
        const auto object = value.toObject();
        const QRegularExpression sensitive("^(key|psk|token|secret|password|authorization|invitation|access_token|refresh_token)$",
            QRegularExpression::CaseInsensitiveOption);
        for (auto it = object.begin(); it != object.end(); ++it)
            result.insert(it.key(), sensitive.match(it.key()).hasMatch() ? QJsonValue("[redacted]") : redactJson(it.value()));
        return result;
    }
    return value;
}
inline bool prepareDirectory() {
    if (::geteuid() != ::getuid()) return false;
    const auto path = directory();
    if (!QDir().mkpath(path)) return false;
    struct stat info{};
    const auto encoded = QFile::encodeName(path);
    if (::lstat(encoded.constData(), &info) || !S_ISDIR(info.st_mode) || info.st_uid != ::getuid()) return false;
    return ::chmod(encoded.constData(), 0700) == 0;
}
inline bool write(const QString& category, const QString& message, const QString& level = "info") {
    if (message.trimmed().isEmpty() || !prepareDirectory()) return false;
    // One lock per process family protects appends AND rotation across processes.
    QLockFile lock(directory() + "/" + component + ".lock");
    if (!lock.tryLock(100)) return false;
    const QString path = directory() + "/" + component + ".log";
    const QByteArray record = QJsonDocument(QJsonObject{
        {"time", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"pid", double(::getpid())}, {"component", component}, {"level", level},
        {"category", category}, {"message", redact(message).left(16384)}}).toJson(QJsonDocument::Compact) + '\n';
    if (QFileInfo(path).size() + record.size() > maxBytes) {
        QFile::remove(path + ".2");
        QFile::rename(path + ".1", path + ".2");
        if (!QFile::rename(path, path + ".1")) return false;
    }
    const int fd = ::open(QFile::encodeName(path).constData(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return false;
    struct stat info{};
    if (::fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != ::getuid() || info.st_nlink != 1) {
        ::close(fd); return false;
    }
    ::fchmod(fd, 0600);
    QFile file;
    if (!file.open(fd, QIODevice::WriteOnly, QFileDevice::AutoCloseHandle)) { ::close(fd); return false; }
    return file.write(record) == record.size() && file.flush();
}
// Reassemble stderr lines before redacting; keys can straddle pipe reads.
class Lines {
public:
    void append(const QByteArray& data, const QString& category) {
        if (dropping_) {
            const auto newline = data.indexOf('\n');
            if (newline < 0) return;
            dropping_ = false;
            pending_ += data.mid(newline + 1);
        } else pending_ += data;
        while (pending_.contains('\n')) {
            const auto end = pending_.indexOf('\n');
            const auto line = pending_.first(end);
            pending_.remove(0, end + 1);
            if (private_key_) {
                if (line.contains("-----END ") && line.contains("PRIVATE KEY-----")) private_key_ = false;
                continue;
            }
            if (line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----")) {
                write(category, "[private key removed]", "warning");
                private_key_ = !line.contains("-----END ");
                continue;
            }
            write(category, end > 65536 ? QString("Oversized diagnostic line omitted") : QString::fromUtf8(line), "warning");
        }
        if (pending_.size() > 65536) {
            pending_.clear(); dropping_ = true;
            write(category, "Oversized diagnostic line omitted", "warning");
        }
    }
    void finish(const QString& category) {
        if (!dropping_ && !private_key_) write(category, QString::fromUtf8(pending_), "warning");
        pending_.clear(); dropping_ = false; private_key_ = false;
    }
private:
    QByteArray pending_;
    bool dropping_{};
    bool private_key_{};
};
inline void qtMessage(QtMsgType type, const QMessageLogContext& context, const QString& message) {
    write(QString::fromLatin1(context.category ? context.category : "qt"), message,
        type == QtDebugMsg ? "debug" : type == QtInfoMsg ? "info" : type == QtWarningMsg ? "warning" : "error");
}
inline void initialize(const QString& name) {
    component = components.contains(name) ? name : "app";
    qInstallMessageHandler(qtMessage);
    // Polling CLI commands deliberately do not produce startup records.
}
}
