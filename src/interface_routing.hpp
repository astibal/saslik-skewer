#pragma once
#include "vm_discovery.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QXmlStreamReader>
#include <QMap>
#include <unistd.h>

namespace InterfaceRouting {
// Optional, read-only hints. Never prompt for libvirt authorization or run a
// hypervisor command from the UI refresh path. Unreadable metadata is fine.
inline QMap<QString, QString> virtualMachines()
{
    QMap<QString, QString> result;
    const QDir runtime("/run/libvirt/qemu");
    for (const auto& path : runtime.entryList({"*.xml"}, QDir::Files)) {
        QFile file(runtime.filePath(path));
        if (file.size() > 1024 * 1024 || !file.open(QIODevice::ReadOnly)) continue;
        const auto found = VmDiscovery::parse(file.readAll());
        for (auto it = found.begin(); it != found.end(); ++it) result.insert(it.key(), it.value());
    }
    return result;
}
struct Link {
    QString name, master;
    int index{};
    bool bridge{};
};
inline QVector<Link> links()
{
    QVector<Link> result;
    const QDir root("/sys/class/net");
    for (const auto& name : root.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        QFile index(root.filePath(name + "/ifindex"));
        if (!index.open(QIODevice::ReadOnly)) continue;
        result.push_back({name, QFileInfo(QFileInfo(root.filePath(name + "/master")).symLinkTarget()).fileName(),
            index.readAll().trimmed().toInt(), QDir(root.filePath(name + "/bridge")).exists()});
    }
    return result;
}
inline QString statePath(uid_t uid) { return QString("/run/skewer-interfaces-%1.json").arg(uid); }
inline QJsonObject state(uid_t uid)
{
    QFile file(statePath(uid));
    const QFileInfo metadata(file);
    if (metadata.isSymLink() || metadata.ownerId() != 0 || file.size() > 65536
        || !file.open(QIODevice::ReadOnly)) return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}
inline QString table(uid_t uid) { return QString("skewer_if_%1").arg(uid); }
inline QString bridgeAddress(const QString& name)
{
    if (!QRegularExpression("^[A-Za-z0-9_.:-]{1,15}$").match(name).hasMatch()) return {};
    QFile file("/sys/class/net/" + name + "/address");
    if (!file.open(QIODevice::ReadOnly)) return {};
    const QString address = QString::fromLatin1(file.readAll().trimmed());
    return QRegularExpression("^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$").match(address).hasMatch() ? address : QString{};
}
inline quint32 mark(uid_t uid) { return 0x54000000U | (quint32(uid) & 0x00ffffffU); }
inline quint32 routingTable(uid_t uid) { return mark(uid); }
inline quint32 priority(uid_t uid) { return 25000 + 2 * (uid % 1000); }

// Resolve a bridge to its current ports. Never automatically adopt future ports.
inline QVector<Link> resolve(const QVector<Link>& all, const QString& name, int index,
                             const QString& uplink, QString& error)
{
    Link selected;
    for (const auto& link : all) if (link.name == name && link.index == index) selected = link;
    if (!selected.index || selected.name == "lo") { error = "Interface disappeared or is loopback"; return {}; }
    QVector<Link> result;
    if (selected.bridge) {
        for (const auto& link : all) if (link.master == name) result.push_back(link);
    } else result.push_back(selected);
    if (result.isEmpty()) { error = "Bridge has no ports"; return {}; }
    for (const auto& port : result) {
        if (!port.master.isEmpty()) {
            bool bridge = false;
            for (const auto& link : all) if (link.name == port.master) bridge = link.bridge;
            if (!bridge) { error = "Only standalone interfaces and bridge ports are supported"; return {}; }
        }
        // Shared uplink bridges require gateway FDB resolution, not guessing.
        if (port.name == uplink || port.master == uplink) {
            error = "Selected interface shares Saslik's uplink; cannot safely determine the return-facing port";
            return {};
        }
        if (port.index <= 0 || !QRegularExpression("^[A-Za-z0-9_.:-]{1,15}$").match(port.name).hasMatch()) {
            error = "Unsupported interface name"; return {};
        }
    }
    return result;
}
inline QString rules(uid_t uid, const QJsonArray& ports, const QString& gateway,
                     const QStringList& local, const QStringList& bypass, bool replace)
{
    const QString name = table(uid), tag = QString("0x%1").arg(mark(uid), 0, 16);
    QString script;
    if (replace) script += "delete table inet " + name + "\ndelete table bridge " + name + '\n';
    QStringList direct, bridged, gateways;
    for (const auto& value : ports) {
        const auto port = value.toObject();
        // Both identifiers must match: do not adopt a renamed/reused interface.
        const QString match = QString("meta iif %1 meta iifname \"%2\" jump selected\n")
            .arg(port["index"].toInt()).arg(port["name"].toString());
        (port["master"].toString().isEmpty() ? direct : bridged) << match;
        if (!port["master"].toString().isEmpty()
            && QRegularExpression("^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$").match(port["bridge_mac"].toString()).hasMatch())
            gateways << QString("meta iif %1 ether daddr %2 counter meta mark set %3 return\n")
                .arg(port["index"].toInt()).arg(port["bridge_mac"].toString(), tag);
    }
    const auto exclusions = [&] {
        QString value = "ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } return\n";
        value += "ip daddr " + gateway + " return\n";
        for (const auto& address : local) value += "ip daddr " + address + " return\n";
        for (const auto& address : bypass) value += "ip daddr " + address + " return\n";
        return value + "udp dport { 67, 68 } return\n";
    };
    script += "table inet " + name + " {\nchain selected {\nmeta nfproto ipv6 counter drop\n"
        + exclusions() + "meta nfproto ipv4 counter meta mark set " + tag + "\n}\n"
        "chain ingress { type filter hook prerouting priority -150; policy accept;\n";
    script += direct.join("");
    script += "}\n}\ntable bridge " + name + " {\nchain selected {\n"
        "ether type arp return\nether type != ip counter drop\n" + exclusions()
        // Keep host-gateway frames on the normal bridge-local delivery path.
        // Forcing broute delivers on the unnumbered slave and can fail RPF.
        + gateways.join("") + "counter drop\n}\n"
        "chain ingress { type filter hook prerouting priority -300; policy accept;\n";
    script += bridged.join("");
    return script + "}\n}\n";
}
}
