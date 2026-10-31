#pragma once
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QLockFile>
#include <QRegularExpression>
#ifdef Q_OS_WIN
#include "diagnostic_log_win.hpp"
#else
#include "diagnostic_log_linux.hpp"
#endif

namespace DiagnosticLog {
inline constexpr qint64 maxBytes = 1024 * 1024;
inline const QStringList components{"app", "tunnel", "session"};
inline QString component = "app";

namespace detail {
inline QString directoryPath() {
#ifdef Q_OS_WIN
    return _directory_win();
#else
    return _directory_linux();
#endif
}

inline bool prepareDirectory(const QString& path) {
#ifdef Q_OS_WIN
    return _prepareDirectory_win(path);
#else
    return _prepareDirectory_linux(path);
#endif
}

inline bool appendRecord(const QString& path, const QByteArray& record) {
#ifdef Q_OS_WIN
    return _appendRecord_win(path, record);
#else
    return _appendRecord_linux(path, record);
#endif
}
} // namespace detail

inline QString directory() { return detail::directoryPath(); }
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
    return detail::prepareDirectory(directory());
}
inline bool write(const QString& category, const QString& message, const QString& level = "info") {
    if (message.trimmed().isEmpty() || !prepareDirectory()) return false;
    // One lock per process family protects appends AND rotation across processes.
    QLockFile lock(directory() + "/" + component + ".lock");
    if (!lock.tryLock(100)) return false;
    const QString path = directory() + "/" + component + ".log";
    const QByteArray record = QJsonDocument(QJsonObject{
        {"time", QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {"pid", double(QCoreApplication::applicationPid())}, {"component", component}, {"level", level},
        {"category", category}, {"message", redact(message).left(16384)}}).toJson(QJsonDocument::Compact) + '\n';
    if (QFileInfo(path).size() + record.size() > maxBytes) {
        QFile::remove(path + ".2");
        QFile::rename(path + ".1", path + ".2");
        if (!QFile::rename(path, path + ".1")) return false;
    }
    return detail::appendRecord(path, record);
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
