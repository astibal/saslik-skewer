#pragma once

#include <QElapsedTimer>
#include <QFileInfo>
#include <QMap>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QXmlStreamReader>
#include <unistd.h>

namespace VmDiscovery {
inline QMap<QString, QString> parse(const QByteArray& data)
{
    QXmlStreamReader xml(data);
    QString domain;
    QStringList targets;
    bool interface = false;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isStartElement()) {
            if (xml.name() == u"name" && domain.isEmpty()) domain = xml.readElementText();
            else if (xml.name() == u"interface") interface = true;
            else if (interface && xml.name() == u"target") targets << xml.attributes().value("dev").toString();
        } else if (xml.isEndElement() && xml.name() == u"interface") interface = false;
    }
    QMap<QString, QString> result;
    if (!xml.hasError() && !domain.isEmpty())
        for (const auto& target : targets) if (!target.isEmpty()) result.insert(target, domain);
    return result;
}

// Worker-thread only. Explicit read-only sockets prevent authentication prompts,
// daemon autostart and accidental fallback to a privileged read/write connection.
inline QMap<QString, QString> query()
{
    QMap<QString, QString> result;
    const QString virsh = QStandardPaths::findExecutable("virsh");
    if (virsh.isEmpty()) return result;
    QElapsedTimer budget;
    budget.start();
    const auto command = [&](const QString& uri, const QStringList& args) {
        QByteArray data;
        const int remaining = 3000 - int(budget.elapsed());
        if (remaining <= 0) return data;
        QProcess process;
        process.start(virsh, QStringList{"--readonly", "--connect", uri} + args);
        process.closeWriteChannel();
        if (!process.waitForFinished(qMin(750, remaining))) {
            process.kill(); process.waitForFinished(1000);
            return data;
        }
        if (process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0)
            data = process.readAllStandardOutput();
        return data;
    };
    const QStringList sockets{"/run/libvirt/libvirt-sock-ro", "/run/libvirt/virtqemud-sock-ro",
        QString("/run/user/%1/libvirt/virtqemud-sock-ro").arg(getuid())};
    for (const auto& socket : sockets) {
        if (!QFileInfo::exists(socket) || budget.elapsed() >= 3000) continue;
        const QString uri = "qemu+unix:///" + QString(socket.startsWith("/run/user/") ? "session" : "system")
            + "?socket=" + socket;
        const auto ids = command(uri, {"list", "--uuid"}).split('\n');
        int count = 0;
        for (const auto& line : ids) {
            const QString id = QString::fromLatin1(line.trimmed());
            if (!QRegularExpression("^[a-fA-F0-9-]{36}$").match(id).hasMatch()) continue;
            if (++count > 64 || budget.elapsed() >= 3000) break;
            const auto found = parse(command(uri, {"dumpxml", id}));
            for (auto it = found.begin(); it != found.end(); ++it) result.insert(it.key(), it.value());
        }
    }
    return result;
}
}
