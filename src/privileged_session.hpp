#pragma once

#include <QElapsedTimer>
#include <QCoreApplication>
#include <QThread>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>

namespace PrivilegedSession {
struct Reply { bool ok{}; QString detail; };

class Client {
public:
    ~Client() {
        // EOF ends the privileged session, without dismantling live routing.
        if (process_.state() != QProcess::NotRunning) {
            process_.closeWriteChannel();
            process_.waitForFinished(3000);
        }
    }

    bool running() const { return usable_ && process_.state() == QProcess::Running; }

    Reply request(const QString& helper, const QStringList& arguments, bool desktop) {
        if (process_.state() == QProcess::NotRunning) {
            process_.setProcessChannelMode(QProcess::ForwardedErrorChannel);
            process_.start(desktop ? "/usr/bin/pkexec" : "/usr/bin/sudo", {helper, "serve"});
            if (!process_.waitForStarted(3000)) return {false, process_.errorString()};
            usable_ = true;
        }
        if (!usable_) return {false, "Helper request still pending; restart Skewer before retrying"};
        const auto payload = QJsonDocument(QJsonObject{{"args", QJsonArray::fromStringList(arguments)}})
            .toJson(QJsonDocument::Compact) + '\n';
        if (payload.size() > 32768) return {false, "Helper request too large"};
        if (process_.write(payload) != payload.size()) return {false, "Cannot send helper request"};
        QElapsedTimer elapsed;
        elapsed.start();
        while (!process_.canReadLine() && elapsed.elapsed() < 60000) {
            process_.waitForReadyRead(250);
            if (process_.state() == QProcess::NotRunning || process_.bytesAvailable() > 65536) break;
        }
        if (!process_.canReadLine()) {
            // Never associate a late response with a subsequent command.
            usable_ = false;
            process_.closeWriteChannel();
            return {false, "Privileged helper unavailable; routing remains guarded. Retry explicitly."};
        }
        const auto reply = QJsonDocument::fromJson(process_.readLine(65537)).object();
        if (!reply["ok"].isBool() || !reply["detail"].isString()) {
            usable_ = false;
            process_.closeWriteChannel();
            return {false, "Invalid helper response"};
        }
        return {reply["ok"].toBool(), reply["detail"].toString()};
    }
private:
    QProcess process_;
    bool usable_{};
};

inline Client& client() {
    static thread_local Client instance;
    return instance;
}

// QProcess stays on the application thread. Explicit background actions (such
// as cleanup-on-attach) reuse the same authorized session instead of prompting
// again. Read-only status polling never enters this path.
inline Reply request(const QString& helper, const QStringList& arguments, bool desktop) {
    auto* application = QCoreApplication::instance();
    if (application && application->thread() != QThread::currentThread()) {
        Reply reply;
        QMetaObject::invokeMethod(application, [&] {
            reply = request(helper, arguments, desktop);
        }, Qt::BlockingQueuedConnection);
        return reply;
    }
    return client().request(helper, arguments, desktop);
}
}
