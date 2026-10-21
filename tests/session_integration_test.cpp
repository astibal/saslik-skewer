#include "cgroup_manager.hpp"
#include "session_guard.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QTextStream>
#include <QStandardPaths>
#include <QSettings>
#include <unistd.h>

static bool routed()
{
    QFile file("/proc/self/cgroup");
    return file.open(QIODevice::ReadOnly) && routedGroup(QString::fromUtf8(file.readAll()).trimmed());
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.contains("--escape")) {
        if (!routed() || qEnvironmentVariable("SKEWER_SESSION") != "1") return 2;
        const auto result = CgroupManager().release({getpid()}, "session-guard-test");
        if (!result.ok) { QTextStream(stderr) << result.detail; return 3; }
        for (int attempt = 0; attempt < 150; ++attempt) {
            // StartTransientUnit is asynchronous. Seeing the original cgroup
            // immediately after release is NOT evidence that repair happened.
            QFile log(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/skewer/session.log");
            if (log.open(QIODevice::ReadOnly)
                && log.readAll().contains(QString("restored PID %1 to ").arg(getpid()).toUtf8())
                && routed()) return 0;
            QThread::msleep(10);
        }
        return 4;
    }
    if (args.contains("--parent")) {
        const QString root = qEnvironmentVariable("XDG_CONFIG_HOME");
        for (const auto* variable : {"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT"})
            if (qEnvironmentVariable(variable) != root + "/test-bundle.pem") return 11;
        if (qEnvironmentVariable("NODE_EXTRA_CA_CERTS") != root + "/test-ca.pem"
            || qEnvironmentVariable("SKEWER_CA_FILE") != root + "/test-ca.pem") return 12;
        // A new command must receive its own window even after shell startup's window ended.
        QThread::msleep(5500);
        // Reuse the escape check in this root process after its initial window.
        const auto released = CgroupManager().release({getpid()}, "session-root-test");
        if (!released.ok) return 9;
        bool restored = false;
        for (int attempt = 0; attempt < 150; ++attempt) {
            QFile log(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/skewer/session.log");
            if (log.open(QIODevice::ReadOnly)
                && log.readAll().contains(QString("restored PID %1 to ").arg(getpid()).toUtf8())
                && routed()) { restored = true; break; }
            QThread::msleep(10);
        }
        if (!restored) return 10;
        QProcess child;
        child.setProcessChannelMode(QProcess::ForwardedChannels);
        child.start(app.applicationFilePath(), {"--escape"});
        if (!child.waitForFinished(4000)) return 5;
        return child.exitStatus() == QProcess::NormalExit ? child.exitCode() : 6;
    }
    QTemporaryDir settings;
    // Test session environment propagation, not certificate verification. These
    // fixtures are never installed into any trust store or used for networking.
    for (const auto* name : {"test-ca.pem", "test-bundle.pem"}) {
        QFile file(settings.path() + '/' + name);
        if (!file.open(QIODevice::WriteOnly)) return 13;
        file.write("environment fixture\n");
    }
    QSettings configuration(settings.path() + "/Saslik/Skewer.conf", QSettings::IniFormat);
    configuration.setValue("runtimeTrust/activeCa", settings.path() + "/test-ca.pem");
    configuration.setValue("runtimeTrust/activeBundle", settings.path() + "/test-bundle.pem");
    configuration.sync();
    QProcess process;
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert("XDG_CONFIG_HOME", settings.path());
    environment.insert("XDG_DATA_HOME", settings.path());
    process.setProcessEnvironment(environment);
    process.setProcessChannelMode(QProcess::ForwardedChannels);
    process.start(SKEWER_TEST_BINARY, {"run", "--", app.applicationFilePath(), "--parent"});
    if (!process.waitForFinished(15000)) { process.kill(); process.waitForFinished(); return 7; }
    return process.exitStatus() == QProcess::NormalExit ? process.exitCode() : 8;
}
