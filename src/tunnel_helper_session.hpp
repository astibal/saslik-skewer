#pragma once

#include <QCoreApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <sys/types.h>

// One authorized serve session owns one tunnel controller. The worker still
// validates endpoint metadata and runs in its own systemd cgroup.
class TunnelHelperSession {
public:
    struct Result { int exit_code; QByteArray output; };
    explicit TunnelHelperSession(uid_t owner) : owner_(owner) {}
    ~TunnelHelperSession() { stop(); }

    Result request(const QStringList& args) {
        if (args.isEmpty()) return {2, "Missing tunnel operation"};
        const auto op = args.first();
        if (op == "tunnel-start") {
            if (args.size() != 2 || !QJsonDocument::fromJson(args[1].toUtf8()).isObject())
                return {2, "Invalid tunnel start payload"};
            if (process_.state() != QProcess::NotRunning) return {1, "Tunnel already running in this session"};
            auto environment = QProcessEnvironment::systemEnvironment();
            environment.insert("PKEXEC_UID", QString::number(owner_));
            process_.setProcessEnvironment(environment);
            process_.start(QCoreApplication::applicationFilePath(), {"tunnel-session"});
            if (!process_.waitForStarted(3000)) return {1, "Cannot start tunnel service controller"};
            process_.write(args[1].toUtf8() + '\n');
            return {0, "Tunnel service controller started"};
        }
        if (args.size() != 1) return {2, "Invalid tunnel command"};
        if (op == "tunnel-stop") { stop(); return {0, "Tunnel stopped"}; }
        if (op == "tunnel-renew") {
            if (process_.state() == QProcess::NotRunning) return {1, "Tunnel service controller stopped"};
            process_.write("keepalive\n");
            return {0, "Tunnel lease renewed"};
        }
        if (op != "tunnel-poll") return {2, "Unknown tunnel operation"};
        if (process_.state() != QProcess::NotRunning) process_.waitForReadyRead(1);
        // Leave room for JSON escaping inside the outer 8192-character reply.
        process_.setReadChannel(QProcess::StandardOutput);
        const auto out = process_.read(512);
        process_.setReadChannel(QProcess::StandardError);
        const auto err = process_.read(512);
        return {0, QJsonDocument(QJsonObject{{"running", process_.state() != QProcess::NotRunning},
            {"stdout", QString::fromUtf8(out)}, {"stderr", QString::fromUtf8(err)}}).toJson(QJsonDocument::Compact)};
    }

private:
    void stop() {
        if (process_.state() == QProcess::NotRunning) return;
        process_.write("stop\n");
        process_.closeWriteChannel();
        if (!process_.waitForFinished(8000)) {
            process_.terminate();
            if (!process_.waitForFinished(2000)) { process_.kill(); process_.waitForFinished(1000); }
        }
    }
    uid_t owner_;
    QProcess process_;
};
