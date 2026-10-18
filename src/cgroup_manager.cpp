#include "cgroup_manager.hpp"

#include <QDateTime>
#include <QFileInfo>
#include <QRegularExpression>

#include <systemd/sd-bus.h>

#include <memory>
#include <cstdint>
#include <unistd.h>

namespace {
using BusPointer = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>;
using MessagePointer = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;
using ErrorPointer = std::unique_ptr<sd_bus_error, decltype(&sd_bus_error_free)>;

bool appendStringProperty(sd_bus_message* message, const char* name, const QByteArray& value)
{
    return sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv") >= 0
        && sd_bus_message_append(message, "s", name) >= 0
        && sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "s") >= 0
        && sd_bus_message_append(message, "s", value.constData()) >= 0
        && sd_bus_message_close_container(message) >= 0
        && sd_bus_message_close_container(message) >= 0;
}

bool appendPidProperty(sd_bus_message* message, const QVector<pid_t>& pids)
{
    if (sd_bus_message_open_container(message, SD_BUS_TYPE_STRUCT, "sv") < 0
        || sd_bus_message_append(message, "s", "PIDs") < 0
        || sd_bus_message_open_container(message, SD_BUS_TYPE_VARIANT, "au") < 0
        || sd_bus_message_open_container(message, SD_BUS_TYPE_ARRAY, "u") < 0) return false;
    for (pid_t pid : pids) {
        const std::uint32_t value = static_cast<std::uint32_t>(pid);
        if (sd_bus_message_append(message, "u", value) < 0) return false;
    }
    return sd_bus_message_close_container(message) >= 0
        && sd_bus_message_close_container(message) >= 0
        && sd_bus_message_close_container(message) >= 0;
}
}

CgroupResult CgroupManager::route(const QVector<pid_t>& pids,
                                  const QString& application_name) const
{
    return moveToScope(pids, application_name, true);
}

CgroupResult CgroupManager::release(const QVector<pid_t>& pids,
                                    const QString& application_name) const
{
    return moveToScope(pids, application_name, false);
}

QStringList CgroupManager::routedLaunchPrefix(const QString& application_name)
{
    const QString unit = QStringLiteral("skewer-routed-%1-%2")
        .arg(safeName(application_name))
        .arg(QDateTime::currentMSecsSinceEpoch());
    return {QStringLiteral("systemd-run"), QStringLiteral("--user"), QStringLiteral("--scope"),
            QStringLiteral("--quiet"), QStringLiteral("--slice=skewer-routed.slice"),
            QStringLiteral("--unit=") + unit, QStringLiteral("--")};
}

CgroupResult CgroupManager::moveToScope(const QVector<pid_t>& pids,
                                        const QString& application_name, bool routed) const
{
    if (pids.isEmpty()) return {false, QStringLiteral("No processes selected"), {}};
    QVector<pid_t> validated;
    validated.reserve(pids.size());
    const uid_t caller = getuid();
    for (pid_t pid : pids) {
        const QFileInfo process(QStringLiteral("/proc/%1").arg(pid));
        if (pid <= 1 || !process.exists()) continue;
        if (process.ownerId() != caller) {
            return {false, QStringLiteral("Refusing a process owned by another user"), {}};
        }
        validated.push_back(pid);
    }
    if (validated.isEmpty())
        return {false, QStringLiteral("No live processes owned by the current user"), {}};
    sd_bus* raw_bus = nullptr;
    int result = sd_bus_open_user(&raw_bus);
    BusPointer bus(raw_bus, &sd_bus_unref);
    if (result < 0) return {false, QStringLiteral("Cannot connect to the user systemd bus"), {}};

    const QString stem = QStringLiteral("skewer-%1-%2-%3.scope")
        .arg(routed ? QStringLiteral("routed") : QStringLiteral("direct"))
        .arg(safeName(application_name))
        .arg(QDateTime::currentMSecsSinceEpoch());
    sd_bus_message* raw_message = nullptr;
    result = sd_bus_message_new_method_call(bus.get(), &raw_message,
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartTransientUnit");
    MessagePointer message(raw_message, &sd_bus_message_unref);
    if (result < 0) return {false, QStringLiteral("Cannot create a systemd request"), {}};

    const QByteArray unit = stem.toUtf8();
    if (sd_bus_message_append(message.get(), "ss", unit.constData(), "fail") < 0
        || sd_bus_message_open_container(message.get(), SD_BUS_TYPE_ARRAY, "(sv)") < 0
        || !appendStringProperty(message.get(), "Description",
             QStringLiteral("Skewer: %1").arg(application_name).toUtf8())
        || !appendStringProperty(message.get(), "Slice",
             routed ? QByteArray("skewer-routed.slice") : QByteArray("app.slice"))
        || !appendStringProperty(message.get(), "CollectMode", QByteArray("inactive-or-failed"))
        || !appendPidProperty(message.get(), validated)
        || sd_bus_message_close_container(message.get()) < 0
        || sd_bus_message_open_container(message.get(), SD_BUS_TYPE_ARRAY, "(sa(sv))") < 0
        || sd_bus_message_close_container(message.get()) < 0) {
        return {false, QStringLiteral("Cannot encode a systemd request"), {}};
    }

    sd_bus_error raw_error = SD_BUS_ERROR_NULL;
    ErrorPointer error(&raw_error, &sd_bus_error_free);
    sd_bus_message* raw_reply = nullptr;
    result = sd_bus_call(bus.get(), message.get(), 0, error.get(), &raw_reply);
    MessagePointer reply(raw_reply, &sd_bus_message_unref);
    if (result < 0) {
        const QString detail = raw_error.message
            ? QString::fromUtf8(raw_error.message) : QStringLiteral("systemd rejected the request");
        return {false, detail, {}};
    }
    return {true, routed ? QStringLiteral("Application is attached to Skewer")
                         : QStringLiteral("Application was released from Skewer"), stem};
}

QString CgroupManager::safeName(QString value)
{
    value = value.toLower();
    value.replace(QRegularExpression(QStringLiteral("[^a-z0-9]+")), QStringLiteral("-"));
    value = value.left(32).trimmed();
    while (value.startsWith(QLatin1Char('-'))) value.removeFirst();
    while (value.endsWith(QLatin1Char('-'))) value.chop(1);
    return value.isEmpty() ? QStringLiteral("application") : value;
}
