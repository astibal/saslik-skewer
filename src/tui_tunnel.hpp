#pragma once
#include "privileged_session.hpp"
#include "preferences_values.hpp"
#include "tuntom_recovery.hpp"
#include "tuntom_status.hpp"
#include <QElapsedTimer>
#include <QFileInfo>
#include <QJsonArray>
#include <QUrl>

// Terminal adapter for the same controller and authorized helper protocol as
// the GUI. It never implements transport, key derivation or routing itself.
class TuiTunnel {
public:
    static QStringList authorizationProbe() { return {"tunnel-poll"}; }
    static PrivilegedSession::Reply authorize() {
        // `status` returns failure when routes are inactive. That is not an
        // authorization failure and must never prevent enabling those routes.
        return PrivilegedSession::request(helperPath(), authorizationProbe(), false);
    }
    static QString helperPath() {
        const auto adjacent = QCoreApplication::applicationDirPath() + "/skewer-net-helper";
        return QFileInfo(adjacent).isExecutable() ? adjacent : QString::fromLatin1(SKEWER_INSTALLED_HELPER_PATH);
    }
    ~TuiTunnel() { stop(); }
    bool running() const { return process_.state() != QProcess::NotRunning; }
    bool start(const QString& address) {
        if (running()) return true;
        retryable = true;
        const QUrl url(address);
        if (!url.isValid() || url.host().isEmpty() || url.scheme() != "skewer" || url.path() != "/pair" || url.hasFragment()
            || url.hasQuery() || !url.userInfo().isEmpty()) {
            error = "Use an already paired skewer://HOST:PORT/pair address"; retryable = false; return false;
        }
        error = Preferences::tunnelPreflightError();
        if (!error.isEmpty()) { retryable = false; DiagnosticLog::write("preflight", error, "error"); return false; }
        pending_.clear(); error.clear(); age_.invalidate(); view.selected = true; view.state = "connecting";
        view.fresh = false; view.stats = {};
        process_.start("/usr/bin/systemd-run", Tuntom::controllerArguments(
            QCoreApplication::applicationFilePath(), address));
        if (!process_.waitForStarted(3000)) { error = process_.errorString(); view.state = "failed"; return false; }
        return true;
    }
    void poll() {
        if (!view.selected) return;
        // Drain final output even if the child exited between UI iterations.
        if (running()) process_.waitForReadyRead(1);
        pending_ += process_.readAllStandardOutput();
        error = (error + QString::fromUtf8(process_.readAllStandardError())).right(4096);
        if (pending_.size() > 65536) { error = "Invalid tunnel status stream"; stop(); view.state = "failed"; return; }
        while (pending_.contains('\n')) {
            const auto end = pending_.indexOf('\n');
            const auto status = QJsonDocument::fromJson(pending_.left(end)).object();
            pending_.remove(0, end + 1);
            if (status["helper_request"].isArray()) {
                QStringList args;
                for (const auto& arg : status["helper_request"].toArray()) args << arg.toString();
                const auto reply = PrivilegedSession::request(helperPath(), args, false, false);
                process_.write(QJsonDocument(QJsonObject{{"ok", reply.ok}, {"detail", reply.detail}})
                    .toJson(QJsonDocument::Compact) + '\n');
            } else if (status["phase"].isString()) {
                phase = status["phase"].toString();
            } else if (status["state"] == "failed") {
                error = DiagnosticLog::redact(status["error"].toString());
                retryable = status["retryable"].toBool(true);
            } else if (QStringList{"prepared", "waiting", "verified"}.contains(status["state"].toString())) {
                view.state = status["state"].toString(); view.stats = status["stats"].toObject();
                gateway = status["gateway"].toString(); age_.restart();
            }
        }
        view.fresh = age_.isValid() && age_.elapsed() <= 10000;
        if (!running()) {
            view.state = "failed"; view.fresh = false;
            if (process_.exitStatus() == QProcess::NormalExit && process_.exitCode() == 2) retryable = false;
        }
    }
    void stop() {
        if (running()) {
            PrivilegedSession::request(helperPath(), {"tunnel-stop"}, false, false);
            process_.closeWriteChannel();
            if (!process_.waitForFinished(10000)) {
                process_.terminate();
                if (!process_.waitForFinished(2000)) { process_.kill(); process_.waitForFinished(1000); }
            }
        }
        view.selected = false; view.fresh = false; view.state.clear(); gateway.clear();
    }
    Tuntom::StatusView view;
    QString gateway, error, phase;
    bool retryable = true;
private:
    QProcess process_;
    QByteArray pending_;
    QElapsedTimer age_;
};
