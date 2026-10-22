#include "session_status.hpp"
#include "session_guard.hpp"
#include "routing_guard.hpp"
#include "routing_plan.hpp"
#include "pairing.hpp"
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <optional>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QProcess>
#include <QSaveFile>
#include <QSettings>
#include <QThread>
#include <QTimer>
#include <unistd.h>
#include <QTextStream>

namespace {
struct Snapshot { QString state; QString reason; };

std::optional<QString> ip(const QStringList& arguments)
{
    QProcess process;
    process.start("/usr/sbin/ip", arguments);
    if (!process.waitForStarted(300) || !process.waitForFinished(500)) {
        process.kill(); process.waitForFinished(300); return {};
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) return {};
    return QString::fromUtf8(process.readAllStandardOutput());
}

Snapshot sample(pid_t shell_pid)
{
    QFile cgroup(QString("/proc/%1/cgroup").arg(shell_pid));
    if (!cgroup.open(QIODevice::ReadOnly) || !routedGroup(QString::fromUtf8(cgroup.readAll()).trimmed()))
        return {"offline", "shell-outside-routed-cgroup"};
    QSettings settings;
    if (!RoutingGuard::installed(getuid())) return {"offline", "routing-guard-missing"};
    const bool api = settings.value("routing/mode").toString() == "saslik";
    QString gateway = settings.value("routing/nextHop").toString();
    if (api) {
        const QUrl url(settings.value("routing/saslikUrl").toString());
        QJsonObject value;
        if (url.scheme()=="skewer") {
            try { value=pairedStatus(url); }
            catch (const std::exception&) { return {"offline","psk-control-unavailable"}; }
        } else {
        if ((url.scheme() != "http" && url.scheme() != "https") || url.host().isEmpty())
            return {"unknown", "invalid-saslik-url"};
        QNetworkAccessManager manager;
        QNetworkRequest request(url);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        request.setTransferTimeout(1200);
        auto* reply = manager.get(request);
        QEventLoop loop;
        QTimer timeout; timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, reply, &QNetworkReply::abort);
        QObject::connect(reply, &QNetworkReply::readyRead, reply, [reply] {
            if (reply->bytesAvailable() > 65536) reply->abort();
        });
        QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
        timeout.start(1500); loop.exec();
        if (reply->error() != QNetworkReply::NoError
            || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200)
            return {"offline", "saslik-unavailable"};
        value = QJsonDocument::fromJson(reply->readAll()).object();
        }
        if (value["version"].toInt() != 1) return {"unknown", "unsupported-api-response"};
        if (!value["available"].toBool()) return {"offline", "lab-unavailable"};
        gateway = value["gateway"].toString();
    }
    QHostAddress address;
    if (!address.setAddress(gateway) || address.protocol() != QAbstractSocket::IPv4Protocol)
        return {"unknown", "no-ipv4-gateway"};
    const auto rules = ip({"-4", "-j", "rule", "show", "pref", QString::number(RoutingPlanner::rulePriority(getuid()))});
    const auto routes = ip({"-4", "-j", "route", "show", "table", QString::number(RoutingPlanner::routeTable(getuid())), "default"});
    if (!rules) return {"unknown", "cannot-read-policy-routing"};
    bool matching_rule = false;
    for (const auto& item : QJsonDocument::fromJson(rules->toUtf8()).array()) {
        const auto rule = item.toObject();
        bool valid = false;
        const auto mark = rule["fwmark"].toString().toUInt(&valid, 0);
        if (valid && mark == RoutingPlanner::mark(getuid())
            && rule["table"].toVariant().toUInt() == RoutingPlanner::routeTable(getuid())) matching_rule = true;
    }
    if (!matching_rule) return {"offline", "routing-inactive"};
    if (!routes) return {"unknown", "cannot-read-route-table"};
    bool matching_route = false;
    for (const auto& item : QJsonDocument::fromJson(routes->toUtf8()).array())
        if (QHostAddress(item.toObject()["gateway"].toString()) == address) matching_route = true;
    if (!matching_route) return {"offline", "gateway-route-missing"};
    // A route alone says nothing about the remote lab's health.
    return api ? Snapshot{"online", "routing-and-saslik-api-available"}
               : Snapshot{"route", "routing-only-no-api-health-check"};
}
}

QJsonObject sessionStatus(pid_t pid)
{
    const auto result = sample(pid);
    QFile file(QString("/proc/%1/cgroup").arg(pid));
    QString group;
    if (file.open(QIODevice::ReadOnly)) group = QString::fromUtf8(file.readAll()).trimmed();
    return {{"state", result.state}, {"reason", result.reason},
            {"cgroup", group}, {"pid", static_cast<int>(pid)},
            {"end_to_end_verified", false}};
}

int sessionCommand(const QStringList& arguments)
{
    const QString command = arguments.value(1);
    const auto options = arguments.sliced(2);
    for (const auto& option : options) {
        if (option != "--json" && !(command == "check" && option == "--require-routed")) {
            QTextStream(stderr) << "Unknown option: " << option << '\n';
            return 2;
        }
    }
    QJsonObject value;
    if (command == "env") {
        // An explicit allowlist prevents accidental disclosure of unrelated credentials.
        for (const auto* key : {"SKEWER_SESSION", "SKEWER_CGROUP", "SKEWER_GATEWAY",
                               "SKEWER_API_URL", "SKEWER_CA_FILE"})
            value[key] = qEnvironmentVariable(key);
    } else value = sessionStatus(getpid());
    if (options.contains("--json"))
        QTextStream(stdout) << QJsonDocument(value).toJson(QJsonDocument::Compact) << '\n';
    else {
        for (auto it = value.begin(); it != value.end(); ++it)
            QTextStream(stdout) << it.key() << ": " << it.value().toVariant().toString() << '\n';
        if (command != "env") QTextStream(stdout)
            << "Control-plane check only; packet interception is not verified.\n";
    }
    if (command == "check") {
        const auto state = value["state"].toString();
        return state == "online" || state == "route" ? 0 : 1;
    }
    return 0;
}

void watchSessionStatus(pid_t shell_pid, const QString& directory)
{
    while (!QThread::currentThread()->isInterruptionRequested()) {
        QElapsedTimer elapsed; elapsed.start();
        const auto snapshot = sample(shell_pid);
        QSaveFile file(directory + "/status");
        if (file.open(QIODevice::WriteOnly)) {
            file.write((QString::number(QDateTime::currentSecsSinceEpoch()) + ' ' + snapshot.state
                + ' ' + snapshot.reason + '\n').toUtf8());
            file.commit();
        }
        while (elapsed.elapsed() < 2000 && !QThread::currentThread()->isInterruptionRequested()) QThread::msleep(50);
    }
}
