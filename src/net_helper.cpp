#include "routing_plan.hpp"
#include "routing_guard.hpp"
#include "helper_protocol.hpp"
#include "tunnel_helper_session.hpp"
#include "ca_store.hpp"
#include "socket_cleanup.hpp"
#include "tuntom_process.hpp"
#include "tuntom_routing.hpp"
#include "interface_routing.hpp"
#include <QLockFile>
#include <QNetworkInterface>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QCryptographicHash>
#include <QDateTime>
#include <QTextStream>
#include <QTemporaryFile>
#include <QElapsedTimer>
#include <poll.h>
#include <signal.h>
#include <functional>

#include <optional>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace {
constexpr auto ip_binary = "/usr/sbin/ip";
constexpr auto nft_binary = "/usr/sbin/nft";
constexpr auto update_ca_binary = "/usr/sbin/update-ca-certificates";

struct Result {
    int exit_code{-1};
    QByteArray output;
};

Result run(const QString& program, const QStringList& arguments,
           const QByteArray& input = {})
{
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.setProcessChannelMode(QProcess::MergedChannels);
    process.start();
    if (!process.waitForStarted()) return {-1, process.errorString().toUtf8()};
    if (!input.isEmpty()) process.write(input);
    process.closeWriteChannel();
    if (!process.waitForFinished(15000)) {
        process.kill();
        process.waitForFinished();
        return {-1, QByteArray("command timed out")};
    }
    return {process.exitCode(), process.readAll()};
}

std::optional<uid_t> invokingUid()
{
    for (const char* name : {"PKEXEC_UID", "SUDO_UID"}) {
        const QByteArray value = qgetenv(name);
        bool ok = false;
        const qulonglong parsed = value.toULongLong(&ok);
        if (ok && parsed > 0 && parsed <= std::numeric_limits<uid_t>::max())
            return static_cast<uid_t>(parsed);
    }
    if (geteuid() != 0 && getuid() > 0) return getuid();
    return std::nullopt;
}

QString interfaceFor(const QString& next_hop, QString& error)
{
    const Result route = run(QString::fromLatin1(ip_binary),
                             {QStringLiteral("-4"), QStringLiteral("route"),
                              QStringLiteral("get"), next_hop});
    if (route.exit_code != 0) {
        error = QStringLiteral("Next hop is not reachable: %1")
                    .arg(QString::fromLocal8Bit(route.output).trimmed());
        return {};
    }
    const QString text = QString::fromLocal8Bit(route.output).simplified();
    if (text.split(QLatin1Char(' ')).contains(QStringLiteral("via"))) {
        error = QStringLiteral("Next hop must be directly reachable, not behind another gateway");
        return {};
    }
    const QRegularExpression match_dev(QStringLiteral("(?:^|\\s)dev\\s+(\\S+)"));
    const auto match = match_dev.match(text);
    if (!match.hasMatch()) {
        error = QStringLiteral("Cannot determine the next-hop interface");
        return {};
    }
    return match.captured(1);
}

int cgroupLevel(uid_t uid, QString& error)
{
    const QString relative = QStringLiteral("user.slice/user-%1.slice/user@%1.service/"
                                            "skewer.slice/skewer-routed.slice").arg(uid);
    if (!QDir(QStringLiteral("/sys/fs/cgroup/") + relative).exists()) {
        error = QStringLiteral("Skewer cgroup does not exist yet; attach or launch an application first");
        return 0;
    }
    return relative.count(QLatin1Char('/')) + 1;
}

bool execute(const RoutingCommand& command, QString& error)
{
    const QString program = command.program == QStringLiteral("ip")
        ? QString::fromLatin1(ip_binary) : QString::fromLatin1(nft_binary);
    const Result result = run(program, command.arguments);
    if (result.exit_code == 0 || command.allow_failure) return true;
    error = QStringLiteral("%1 failed: %2")
                .arg(command.program, QString::fromLocal8Bit(result.output).trimmed());
    return false;
}

void cleanup(const RoutingPlan& plan)
{
    QString ignored;
    for (const auto& command : plan.cleanup) execute(command, ignored);
}

bool setGuard(uid_t uid, int level, QString& error, const QString& gateway = {},
              const QString& interface = {}, const QStringList& exemptions = {},
              const QString& local_control = {}, quint16 local_control_port = 0)
{
    QStringList normalized;
    if (!RoutingPlanner::normalizeExemptions(exemptions, normalized, error)) return false;
    const QString table = QString("skewer_guard_%1").arg(uid);
    QString rules;
    if (run(nft_binary, {"list", "table", "inet", table}).exit_code == 0)
        rules = "delete table inet " + table + '\n';
    rules += RoutingPlanner::guardRules(uid, level, gateway, interface, normalized,
                                       local_control, local_control_port);
    const auto applied = run(nft_binary, {"-f", "-"}, rules.toUtf8());
    if (applied.exit_code) { error = QString::fromLocal8Bit(applied.output); return false; }
    QSaveFile receipt(RoutingGuard::path(uid));
    const auto identity = RoutingGuard::identity(uid);
    if (identity.isEmpty() || !receipt.open(QIODevice::WriteOnly)) { error = "Cannot save protection receipt"; return false; }
    receipt.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    if (receipt.write(identity) != identity.size() || !receipt.commit()) { error = "Cannot save protection receipt"; return false; }
    return true;
}

int ensureGuard(uid_t uid)
{
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(0)) return 1;
    if (RoutingGuard::installed(uid)
        && run(nft_binary, {"list", "table", "inet", QString("skewer_guard_%1").arg(uid)}).exit_code == 0) return 0;
    QString error;
    const int level = cgroupLevel(uid, error);
    if (!level || !setGuard(uid, level, error)) { QTextStream(stderr) << error << '\n'; return 1; }
    return 0;
}

QString intentPath(uid_t uid) { return QString("/run/skewer-route-intent-%1.json").arg(uid); }

QByteArray readIntent(uid_t uid)
{
    const int fd = ::open(intentPath(uid).toLocal8Bit().constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return {};
    struct stat metadata{};
    QFile file;
    if (::fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0
        || (metadata.st_mode & 0022) || metadata.st_size > 32768
        || !file.open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(fd);
        return {};
    }
    return file.readAll();
}

bool writeIntent(uid_t uid, const QString& gateway, const QStringList& exemptions,
                 const QString& tunnel_context = {})
{
    QSaveFile file(intentPath(uid));
    if (!file.open(QIODevice::WriteOnly)) return false;
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    const auto data = QJsonDocument(QJsonObject{{"gateway", gateway},
        {"exemptions", QJsonArray::fromStringList(exemptions)},
        {"tunnel_context", tunnel_context}}).toJson(QJsonDocument::Compact);
    return file.write(data) == data.size() && file.commit();
}

int up(uid_t uid, const QString& next_hop, const QStringList& exemptions,
       const QByteArray& expected_intent = {}, const QString& tunnel_context = {})
{
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(0)) return 1;
    // A concurrent Disable or another client changing the gateway wins over a
    // stale watchdog snapshot. Compare under the same lock as kernel updates.
    if (!expected_intent.isEmpty() && readIntent(uid) != expected_intent) return 0;
    const auto desired_context = QJsonDocument::fromJson(readIntent(uid)).object()["tunnel_context"].toString();
    if (desired_context != tunnel_context) {
        QTextStream(stderr) << "Disable the current tunnel before changing routing\n";
        return 1;
    }
    QString error, local_control;
    quint16 local_control_port = 0;
    QStringList destinations;
    for (const auto& value : exemptions) {
        if (!value.startsWith("--local-control=")) { destinations << value; continue; }
        const auto endpoint = value.sliced(16);
        const int separator = endpoint.lastIndexOf(':');
        QHostAddress address(endpoint.first(separator));
        bool port_ok = false;
        const int port = endpoint.sliced(separator + 1).toInt(&port_ok);
        if (separator < 1 || !address.isLoopback() || !port_ok || port < 1 || port > 65535) {
            QTextStream(stderr) << "skewer-net-helper: invalid local control endpoint\n";
            return 2;
        }
        local_control = address.toString(); local_control_port = quint16(port);
    }
    const auto interface_state = InterfaceRouting::state(uid);
    QStringList active_exemptions;
    for (const auto& value : interface_state["exemptions"].toArray()) active_exemptions << value.toString();
    if (!interface_state.isEmpty() && (interface_state["gateway"].toString() != next_hop || active_exemptions != destinations)) {
        QTextStream(stderr) << "Release interfaces before changing the gateway or exemptions\n";
        return 2;
    }
    const QString interface_name = interfaceFor(next_hop, error);
    if (interface_name.isEmpty()) {
        QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
        return 2;
    }
    const int level = cgroupLevel(uid, error);
    if (!level) {
        QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
        return 2;
    }
    const RoutingPlan plan = RoutingPlanner::create(uid, next_hop, interface_name, level, destinations,
                                                     local_control, local_control_port);
    if (!plan.valid) {
        QTextStream(stderr) << "skewer-net-helper: " << plan.error << '\n';
        return 2;
    }
    // Block first, then rebuild routing. Failure leaves the guard closed.
    if (!setGuard(uid, level, error)) { QTextStream(stderr) << error << '\n'; return 1; }
    cleanup(plan);
    for (const auto& command : plan.prepare) {
        if (!execute(command, error)) {
            cleanup(plan);
            QTextStream(stderr) << "skewer-net-helper: " << error << '\n';
            return 1;
        }
    }
    QString nft_rules = plan.nft_rules;
    if (!tunnel_context.isEmpty()) {
        // OUTPUT policy rerouting can retain the source chosen by the main
        // table. Give the remote lab a return path through this /30 only.
        const QString client_address = QHostAddress(QHostAddress(next_hop).toIPv4Address() + 1).toString();
        nft_rules += QString("add chain inet %1 tunnel_snat { type nat hook postrouting priority srcnat; policy accept; }\n"
            "add rule inet %1 tunnel_snat meta mark 0x%2 oifname \"%3\" snat ip to %4\n")
            .arg(plan.nft_table).arg(RoutingPlanner::mark(uid), 0, 16).arg(interface_name, client_address);
    }
    const Result nft = run(QString::fromLatin1(nft_binary), {QStringLiteral("-f"),
                                                              QStringLiteral("-")},
                           nft_rules.toUtf8());
    if (nft.exit_code != 0) {
        cleanup(plan);
        QTextStream(stderr) << "skewer-net-helper: nft failed: "
                            << QString::fromLocal8Bit(nft.output).trimmed() << '\n';
        return 1;
    }
    if (!setGuard(uid, level, error, next_hop, interface_name, destinations,
                  local_control, local_control_port)) {
        QString ignored;
        setGuard(uid, level, ignored);
        cleanup(plan);
        QTextStream(stderr) << error << '\n'; return 1;
    }
    if (!writeIntent(uid, next_hop, exemptions, tunnel_context)) {
        QString ignored;
        setGuard(uid, level, ignored);
        cleanup(plan);
        QFile::remove(intentPath(uid));
        QTextStream(stderr) << "Cannot save desired routing; traffic remains blocked\n";
        return 1;
    }
    QTextStream(stdout) << "active: cgroup traffic -> " << next_hop
                        << " via " << interface_name << '\n';
    return 0;
}

int interfacesDown(uid_t uid, bool prepared = false)
{
    const QString table = InterfaceRouting::table(uid);
    QString removal;
    for (const auto& family : {"inet", "bridge"}) {
        const auto exists = run(nft_binary, {"list", "table", family, table});
        if (exists.exit_code == 0) removal += QString("delete table %1 %2\n").arg(family, table);
    }
    if (!prepared && removal.isEmpty() && InterfaceRouting::state(uid).isEmpty()) return 0;
    // Remove both hooks atomically before dismantling their policy routes.
    if (!removal.isEmpty() && run(nft_binary, {"-f", "-"}, removal.toUtf8()).exit_code) return 1;
    const QString tag = QString("0x%1").arg(InterfaceRouting::mark(uid), 0, 16);
    run(ip_binary, {"-4", "rule", "del", "pref", QString::number(InterfaceRouting::priority(uid)),
        "fwmark", tag, "lookup", QString::number(InterfaceRouting::routingTable(uid))});
    run(ip_binary, {"-4", "rule", "del", "pref", QString::number(InterfaceRouting::priority(uid)+1),
        "fwmark", tag, "unreachable"});
    run(ip_binary, {"-4", "route", "flush", "table", QString::number(InterfaceRouting::routingTable(uid))});
    QFile::remove(InterfaceRouting::statePath(uid));
    return 0;
}

int interfaceChange(uid_t uid, const QStringList& args)
{
    // /run is root-owned: neither the state file nor this lock is client input.
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(0)) { QTextStream(stderr) << "Interface operation already in progress\n"; return 1; }
    const bool attach = args[0] == "interface-attach";
    if (attach && !QJsonDocument::fromJson(readIntent(uid)).object()["tunnel_context"].toString().isEmpty()) {
        QTextStream(stderr) << "Interface ingress through tunnels is not supported yet\n";
        return 2;
    }
    const auto previous = InterfaceRouting::state(uid);
    auto selections = previous["selections"].toObject();
    const QString name = args[1];
    bool valid_index = false;
    const int index = args[2].toInt(&valid_index);
    if (!valid_index || index <= 0 || !QRegularExpression("^[A-Za-z0-9_.:-]{1,15}$").match(name).hasMatch()) return 2;
    const QString key = name + ':' + QString::number(index);
    QString gateway = previous["gateway"].toString(), uplink, error;
    if (attach) {
        QHostAddress address(args[3]);
        if (address.protocol() != QAbstractSocket::IPv4Protocol || address.isLoopback()
            || address.isMulticast() || address.isNull()) return 2;
        if (!selections.isEmpty() && gateway != address.toString()) {
            QTextStream(stderr) << "Release interfaces before changing Saslik gateway\n"; return 2;
        }
        gateway = address.toString();
        uplink = interfaceFor(gateway, error);
        const auto ports = InterfaceRouting::resolve(InterfaceRouting::links(), name, index, uplink, error);
        if (uplink.isEmpty() || ports.isEmpty()) { QTextStream(stderr) << error << '\n'; return 2; }
        QFile forwarding("/proc/sys/net/ipv4/ip_forward");
        if (!forwarding.open(QIODevice::ReadOnly) || forwarding.readAll().trimmed() != "1") {
            QTextStream(stderr) << "IPv4 forwarding is disabled. Enable it explicitly before attaching an interface.\n"; return 2;
        }
        QJsonArray chosen;
        for (const auto& port : ports) {
            // A lower device of a VLAN/bond uplink is also a potential loop.
            if (QFileInfo::exists("/sys/class/net/" + uplink + "/lower_" + port.name)) {
                QTextStream(stderr) << "Interface is a lower device of Saslik's uplink\n"; return 2;
            }
            for (auto it = selections.begin(); it != selections.end(); ++it)
                if (it.key() != key) for (const auto& value : it.value().toArray())
                    if (value.toObject()["index"].toInt() == port.index) {
                        QTextStream(stderr) << "Port is already selected by another interface/bridge\n"; return 2;
                    }
            chosen.append(QJsonObject{{"name", port.name}, {"index", port.index}, {"master", port.master}});
        }
        selections[key] = chosen;
    } else {
        selections.remove(key);
        if (selections.isEmpty()) return interfacesDown(uid);
        uplink = previous["uplink"].toString();
    }
    QStringList exemptions;
    if (attach) {
        if (!RoutingPlanner::normalizeExemptions(args.sliced(4), exemptions, error)) {
            QTextStream(stderr) << error << '\n'; return 2;
        }
    } else for (const auto& value : previous["exemptions"].toArray()) exemptions << value.toString();
    QStringList local;
    for (const auto& address : QNetworkInterface::allAddresses())
        if (address.protocol() == QAbstractSocket::IPv4Protocol) local << address.toString();
    QJsonArray ports;
    for (auto it = selections.begin(); it != selections.end(); ++it)
        for (const auto& value : it.value().toArray()) {
            auto port = value.toObject();
            if (!port["master"].toString().isEmpty()) {
                const QString address = InterfaceRouting::bridgeAddress(port["master"].toString());
                if (address.isEmpty()) {
                    QTextStream(stderr) << "Cannot determine bridge gateway MAC; release disappeared selections first\n";
                    return 2;
                }
                port["bridge_mac"] = address;
            }
            ports.append(port);
        }
    const QString rules = InterfaceRouting::rules(uid, ports, gateway, local, exemptions, !previous.isEmpty());
    auto result = run(nft_binary, {"-c", "-f", "-"}, rules.toUtf8());
    if (result.exit_code) { QTextStream(stderr) << "Rules unsupported; nothing changed: " << result.output; return 1; }
    const QString route_table = QString::number(InterfaceRouting::routingTable(uid));
    const QString priority = QString::number(InterfaceRouting::priority(uid));
    const QString tag = QString("0x%1").arg(InterfaceRouting::mark(uid), 0, 16);
    if (previous.isEmpty()) {
        // Never flush or reuse somebody else's policy-routing slot.
        const auto routes = run(ip_binary, {"-4", "route", "show", "table", route_table});
        if (!routes.output.trimmed().isEmpty() && !routes.output.contains("FIB table does not exist")) {
            QTextStream(stderr) << "Interface routing table is already occupied\n"; return 1;
        }
        for (int offset : {0, 1}) {
            const auto existing = run(ip_binary, {"-4", "rule", "show", "pref", QString::number(InterfaceRouting::priority(uid)+offset)});
            if (existing.exit_code || !existing.output.trimmed().isEmpty()) {
                QTextStream(stderr) << "Interface routing priority is already occupied\n"; return 1;
            }
        }
        const QVector<QStringList> commands{
            {"-4", "route", "add", gateway + "/32", "dev", uplink, "scope", "link", "table", route_table},
            {"-4", "route", "add", "default", "via", gateway, "dev", uplink, "table", route_table},
            // A missing route must not silently fall back to the main table.
            {"-4", "rule", "add", "pref", QString::number(InterfaceRouting::priority(uid)+1), "fwmark", tag, "unreachable"},
            {"-4", "rule", "add", "pref", priority, "fwmark", tag, "lookup", route_table}};
        for (const auto& command : commands) if (run(ip_binary, command).exit_code) {
            interfacesDown(uid, true); QTextStream(stderr) << "Cannot prepare interface routing\n"; return 1;
        }
    } else {
        // Routes tied to Saslik's veth disappear when the lab recreates that
        // interface.  The selected VM ports and nftables hooks remain valid,
        // so restore only the recorded policy table here.  `replace` is also
        // what makes a manual Attach/Restore repair this state idempotently.
        const QVector<QStringList> commands{
            {"-4", "route", "replace", gateway + "/32", "dev", uplink,
             "scope", "link", "table", route_table},
            {"-4", "route", "replace", "default", "via", gateway,
             "dev", uplink, "table", route_table}};
        for (const auto& command : commands) if (run(ip_binary, command).exit_code) {
            QTextStream(stderr) << "Cannot restore interface routing\n"; return 1;
        }
    }
    result = run(nft_binary, {"-f", "-"}, rules.toUtf8());
    if (result.exit_code) {
        if (previous.isEmpty()) interfacesDown(uid, true);
        QTextStream(stderr) << result.output; return 1;
    }
    QJsonArray bypass; for (const auto& value : exemptions) bypass.append(value);
    QSaveFile file(InterfaceRouting::statePath(uid));
    if (!file.open(QIODevice::WriteOnly)) { interfacesDown(uid); return 1; }
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    const auto data = QJsonDocument(QJsonObject{{"selections", selections}, {"gateway", gateway},
        {"uplink", uplink}, {"exemptions", bypass}}).toJson();
    if (file.write(data) != data.size() || !file.commit()) { interfacesDown(uid); return 1; }
    QTextStream(stdout) << (attach ? "Interface ingress attached" : "Interface ingress released") << '\n';
    return 0;
}

int down(uid_t uid)
{
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(0)) return 1;
    // Explicit Disable cancels reconciliation, including in other GUI instances.
    if (QFile::exists(intentPath(uid)) && !QFile::remove(intentPath(uid))) return 1;
    QString error;
    const int level = cgroupLevel(uid, error);
    if (level && !setGuard(uid, level, error)) { QTextStream(stderr) << error << '\n'; return 1; }
    if (interfacesDown(uid)) return 1;
    // The cleanup identifiers depend only on UID. Placeholder values are never
    // installed and merely let the shared planner produce the cleanup commands.
    const RoutingPlan plan = RoutingPlanner::create(uid, QStringLiteral("192.0.2.1"),
                                                     QStringLiteral("lo"));
    cleanup(plan);
    QTextStream(stdout) << "inactive\n";
    return 0;
}

int status(uid_t uid)
{
    const Result nft = run(QString::fromLatin1(nft_binary),
        {QStringLiteral("list"), QStringLiteral("table"), QStringLiteral("inet"),
         RoutingPlanner::tableName(uid)});
    const Result rule = run(QString::fromLatin1(ip_binary),
        {QStringLiteral("-4"), QStringLiteral("rule"), QStringLiteral("show"),
         QStringLiteral("pref"), QString::number(RoutingPlanner::rulePriority(uid))});
    const bool active = nft.exit_code == 0 && rule.exit_code == 0 && !rule.output.trimmed().isEmpty();
    QTextStream(stdout) << (active ? "active" : "inactive") << '\n';
    return active ? 0 : 3;
}

QString caTarget(const QString& identity)
{
    if (!QRegularExpression(QStringLiteral("^[a-f0-9]{64}$")).match(identity).hasMatch())
        return {};
    return QStringLiteral("/usr/local/share/ca-certificates/skewer-saslik-%1.crt").arg(identity);
}

int caInstall(uid_t uid, const QString& identity, const QString& source)
{
    const QString target = caTarget(identity);
    if (target.isEmpty()) return 2;
    const int descriptor = ::open(source.toLocal8Bit().constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return 2;
    struct stat metadata{};
    QFile input;
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_uid != uid
        || metadata.st_size <= 0 || metadata.st_size > 65536
        || !input.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(descriptor);
        QTextStream(stderr) << "skewer-net-helper: invalid CA certificate source\n";
        return 2;
    }
    const QByteArray value = input.readAll();
    const auto certificate = CaStoreManager::parse(value);
    if (certificate.isNull() || CaStoreManager(certificate).fingerprint() != identity
        || certificate.expiryDate() < QDateTime::currentDateTimeUtc()
        || certificate.effectiveDate() > QDateTime::currentDateTimeUtc()) {
        QTextStream(stderr) << "skewer-net-helper: invalid CA, fingerprint or validity\n";
        return 2;
    }
    // Do not reopen the user-controlled source after validation, or overwrite a
    // pre-existing unrelated anchor. QSaveFile replaces the directory entry.
    const bool existed = QFileInfo::exists(target);
    if (existed) {
        if (QFileInfo(target).isSymLink()) return 2;
        QFile old(target);
        if (!old.open(QIODevice::ReadOnly)
            || CaStoreManager(CaStoreManager::parse(old.readAll())).fingerprint() != identity) return 2;
    }
    QSaveFile output(target);
    if (!output.open(QIODevice::WriteOnly) || output.write(certificate.toPem()) != certificate.toPem().size()
        || !output.commit()) {
        QTextStream(stderr) << "skewer-net-helper: cannot install system certificate\n";
        return 1;
    }
    QFile::setPermissions(target, QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    const Result update = run(QString::fromLatin1(update_ca_binary), {});
    if (update.exit_code != 0) {
        if (!existed) QFile::remove(target);
        QTextStream(stderr) << "skewer-net-helper: update-ca-certificates failed: "
                            << update.output << '\n';
        return 1;
    }
    return 0;
}

int caRemove(const QString& identity, const QString& path)
{
    const QFileInfo target(path);
    if (caTarget(identity).isEmpty() || target.isSymLink() || !target.isFile()
        || target.canonicalFilePath() != target.absoluteFilePath()
        || !target.canonicalFilePath().startsWith("/usr/local/share/ca-certificates/")
        || !path.endsWith(".crt")) return 2;
    // Walk directory descriptors without following symlinks. User-writable
    // anchor directories are excluded to avoid a check/unlink race as root.
    int directory = ::open("/usr/local/share/ca-certificates", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) return 2;
    const auto parts = path.mid(QString("/usr/local/share/ca-certificates/").size()).split('/');
    for (int i = 0; i < parts.size(); ++i) {
        struct stat metadata{};
        if (::fstat(directory, &metadata) != 0 || metadata.st_uid != 0 || (metadata.st_mode & 0022)) {
            ::close(directory); return 2;
        }
        if (i + 1 == parts.size()) break;
        const int next = ::openat(directory, parts.at(i).toLocal8Bit().constData(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        ::close(directory); directory = next;
        if (directory < 0) return 2;
    }
    const QByteArray leaf = parts.last().toLocal8Bit();
    const int descriptor = ::openat(directory, leaf.constData(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    QFile file;
    struct stat metadata{};
    if (descriptor < 0) { ::close(directory); return 2; }
    if (::fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)
        || metadata.st_uid != 0 || (metadata.st_mode & 0022)
        || !file.open(descriptor, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        ::close(descriptor); ::close(directory); return 2;
    }
    if (file.size() > 65536) { ::close(directory); return 2; }
    const auto certs = QSslCertificate::fromData(file.readAll());
    if (certs.size() != 1 || CaStoreManager(certs.first()).fingerprint() != identity) {
        QTextStream(stderr) << "Certificate changed or fingerprint differs; refusing removal\n";
        ::close(directory);
        return 2;
    }
    file.close();
    const bool removed = ::unlinkat(directory, leaf.constData(), 0) == 0;
    ::close(directory);
    if (!removed) return 1;
    const Result update = run(QString::fromLatin1(update_ca_binary), {QStringLiteral("--fresh")});
    return update.exit_code == 0 ? 0 : 1;
}
}

int dispatch(const std::optional<uid_t>& uid, const QStringList& arguments)
{
    if (arguments == QStringList{"resume"}) {
        if (!QJsonDocument::fromJson(readIntent(*uid)).object()["tunnel_context"].toString().isEmpty()) {
            QTextStream(stderr) << "Resume the tunnel session before restoring routing\n";
            return 1;
        }
        if (readIntent(*uid).isEmpty()) {
            QTextStream(stderr) << "No saved routing intent. Use Enable/Restore routing explicitly.\n";
            return 1;
        }
        QTextStream(stdout) << "Routing maintenance resumed; missing routes will be restored when the gateway is available.\n";
        return 0;
    }
    if (arguments == QStringList{"guard"}) return ensureGuard(*uid);
    if (arguments == QStringList{"tunnel-session"}) return tuntomService(*uid);
    if (arguments == QStringList{"tunnel-worker"}) return tuntomProcess(*uid);
    if ((arguments.size() >= 4 && arguments[0] == "interface-attach")
        || (arguments.size() == 3 && arguments[0] == "interface-release")) return interfaceChange(*uid, arguments);
    if (!arguments.isEmpty() && (arguments[0] == "cleanup-tcp" || arguments[0] == "preview-tcp"))
        return cleanupSockets(*uid, arguments.sliced(1), arguments[0] == "preview-tcp");
    if (arguments.size() == 3 && arguments.first() == QStringLiteral("ca-install"))
        return caInstall(*uid, arguments.at(1), arguments.at(2));
    if (arguments.size() == 3 && arguments.first() == QStringLiteral("ca-remove"))
        return caRemove(arguments.at(1), arguments.at(2));
    if (arguments == QStringList{QStringLiteral("down")}) return down(*uid);
    if (arguments == QStringList{QStringLiteral("status")}) return status(*uid);
    if (!arguments.isEmpty() && arguments.first() == "exemptions") {
        QLockFile lock("/run/skewer-interface-routing.lock");
        if (!lock.tryLock(0)) return 1;
        if (!QJsonDocument::fromJson(readIntent(*uid)).object()["tunnel_context"].toString().isEmpty()) {
            QTextStream(stderr) << "Disable the tunnel before changing destination exemptions\n";
            return 2;
        }
        if (!InterfaceRouting::state(*uid).isEmpty()) {
            QTextStream(stderr) << "Release interfaces before changing destination exemptions\n";
            return 2;
        }
        QStringList normalized; QString error;
        if (!RoutingPlanner::normalizeExemptions(arguments.sliced(1), normalized, error)) {
            QTextStream(stderr) << error << '\n'; return 2;
        }
        QString rules = RoutingPlanner::exemptionUpdate(*uid, normalized);
        const QString guard_table = QString("skewer_guard_%1").arg(*uid);
        if (run(nft_binary, {"list", "table", "inet", guard_table}).exit_code == 0) {
            rules += "flush set inet " + guard_table + " bypass_v4\n";
            if (!normalized.isEmpty()) rules += "add element inet " + guard_table + " bypass_v4 { " + normalized.join(", ") + " }\n";
        }
        const Result result = run(QString::fromLatin1(nft_binary), {"-f", "-"}, rules.toUtf8());
        QTextStream(result.exit_code == 0 ? stdout : stderr) << result.output;
        if (result.exit_code == 0) {
            const auto desired = QJsonDocument::fromJson(readIntent(*uid)).object();
            QStringList saved = normalized;
            for (const auto& value : desired["exemptions"].toArray())
                if (value.toString().startsWith("--local-control=")) saved << value.toString();
            if (!desired.isEmpty() && !writeIntent(*uid, desired["gateway"].toString(), saved)) {
                QFile::remove(intentPath(*uid));
                QTextStream(stderr) << "Cannot save updated routing intent; automatic restoration stopped\n";
                return 1;
            }
        }
        if (result.exit_code != 0)
            QTextStream(stderr) << "No exceptions were changed. If routing was started by an older Skewer, disable and enable routing once.\n";
        return result.exit_code == 0 ? 0 : 1;
    }
    if (arguments.size() >= 2 && arguments.first() == QStringLiteral("up"))
        return up(*uid, arguments.at(1), arguments.sliced(2));
    QTextStream(stderr) << "usage: skewer-net-helper up NEXT_HOP | down | status | "
                           "ca-install SHA256 PEM | ca-remove SHA256 LOCAL_ANCHOR\n";
    return 2;
}

namespace {
Result captured(const std::function<int()>& operation)
{
    // Keep protocol stdout separate from existing operations' diagnostics.
    QTemporaryFile output;
    if (!output.open()) return {1, "Cannot capture helper output"};
    const int saved_out = ::dup(STDOUT_FILENO);
    const int saved_err = ::dup(STDERR_FILENO);
    if (saved_out < 0 || saved_err < 0) {
        if (saved_out >= 0) ::close(saved_out);
        if (saved_err >= 0) ::close(saved_err);
        return {1, "Cannot capture helper descriptors"};
    }
    ::fflush(stdout); ::fflush(stderr);
    const bool redirected = ::dup2(output.handle(), STDOUT_FILENO) >= 0
        && ::dup2(output.handle(), STDERR_FILENO) >= 0;
    const int code = redirected ? operation() : 1;
    ::fflush(stdout); ::fflush(stderr);
    ::dup2(saved_out, STDOUT_FILENO); ::dup2(saved_err, STDERR_FILENO);
    ::close(saved_out); ::close(saved_err);
    output.seek(0);
    return {code, output.read(16384)};
}

int reconcile(uid_t uid, const QString& tunnel_context = {})
{
    const auto snapshot = readIntent(uid);
    if (snapshot.isEmpty()) return 0;
    const auto desired = QJsonDocument::fromJson(snapshot).object();
    // Only the worker that verified this tunnel may reopen its route.
    if (desired["tunnel_context"].toString() != tunnel_context) return 0;
    const auto gateway = desired["gateway"].toString();
    if (gateway.isEmpty()) return 1;
    QStringList exemptions;
    for (const auto& item : desired["exemptions"].toArray()) exemptions << item.toString();
    const auto routes = run(ip_binary, {"-4", "route", "show", "table",
        QString::number(RoutingPlanner::routeTable(uid)), "default"});
    const auto rules = run(ip_binary, {"-4", "-j", "rule", "show"});
    bool matching_rule = false, fallback = false;
    for (const auto& value : QJsonDocument::fromJson(rules.output).array()) {
        const auto rule = value.toObject();
        bool valid = false;
        const auto mark = rule["fwmark"].toString().toUInt(&valid, 0);
        if (valid && mark == RoutingPlanner::mark(uid)
            && rule["table"].toVariant().toUInt() == RoutingPlanner::routeTable(uid)
            && rule["priority"].toInt() == int(RoutingPlanner::rulePriority(uid))) matching_rule = true;
        if (valid && mark == RoutingPlanner::mark(uid) && rule["action"].toString() == "unreachable"
            && rule["priority"].toInt() == int(RoutingPlanner::rulePriority(uid) + 1)) fallback = true;
    }
    const auto guard = run(nft_binary, {"-j", "list", "table", "inet", QString("skewer_guard_%1").arg(uid)});
    bool allows_marked_ipv4 = false;
    for (const auto& item : QJsonDocument::fromJson(guard.output).object()["nftables"].toArray()) {
        const auto rule = item.toObject()["rule"].toObject();
        if (rule["chain"].toString() != "guarded") continue;
        bool ipv4 = false, marked = false, returns = false;
        for (const auto& expression : rule["expr"].toArray()) {
            const auto statement = expression.toObject();
            returns |= statement.contains("return");
            const auto match = statement["match"].toObject();
            if (match["op"].toString() != "==") continue;
            const auto key = match["left"].toObject()["meta"].toObject()["key"].toString();
            ipv4 |= key == "nfproto" && match["right"].toString() == "ipv4";
            marked |= key == "mark" && match["right"].toDouble(-1) == RoutingPlanner::mark(uid);
        }
        allows_marked_ipv4 |= ipv4 && marked && returns;
    }
    const bool process_routing_ok = RoutingGuard::installed(uid) && matching_rule && fallback
        && routes.exit_code == 0
        && routes.output.contains(QString("default via %1 ").arg(gateway).toUtf8())
        && run(nft_binary, {"list", "table", "inet", RoutingPlanner::tableName(uid)}).exit_code == 0
        && (tunnel_context.isEmpty() || run(nft_binary,
            {"list", "chain", "inet", RoutingPlanner::tableName(uid), "tunnel_snat"}).exit_code == 0)
        // A freshly reinstalled drop-only guard is safe but not operational.
        // Restore the allow path too, rather than merely noticing table existence.
        && guard.exit_code == 0 && allows_marked_ipv4;
    if (!process_routing_ok && up(uid, gateway, exemptions, snapshot, tunnel_context)) return 1;

    const auto interface_state = InterfaceRouting::state(uid);
    if (interface_state.isEmpty()) return 0;
    const QString interface_gateway = interface_state["gateway"].toString();
    const QString uplink = interface_state["uplink"].toString();
    const QString interface_table = QString::number(InterfaceRouting::routingTable(uid));
    const auto interface_routes = run(ip_binary, {"-4", "route", "show", "table", interface_table});
    if (interface_gateway == gateway && interface_routes.exit_code == 0
        && interface_routes.output.contains(
            QString("default via %1 dev %2").arg(gateway, uplink).toUtf8())) return 0;

    // Replay one recorded top-level selection. interfaceChange validates its
    // current ifindex, reconstructs every bridge port, restores the policy
    // routes, and atomically rebuilds the nftables hooks for all selections.
    const auto selections = interface_state["selections"].toObject();
    if (selections.isEmpty()) return 1;
    const QString selection = selections.begin().key();
    const int separator = selection.lastIndexOf(':');
    if (separator < 1) return 1;
    QStringList restore{"interface-attach", selection.first(separator),
                        selection.sliced(separator + 1), gateway};
    for (const auto& value : interface_state["exemptions"].toArray())
        restore << value.toString();
    return interfaceChange(uid, restore);
}

bool sendReply(const Result& result)
{
    const auto data = QJsonDocument(QJsonObject{{"ok", result.exit_code == 0},
        {"detail", QString::fromLocal8Bit(result.output).trimmed().left(8192)}})
        .toJson(QJsonDocument::Compact) + '\n';
    qsizetype offset = 0;
    while (offset < data.size()) {
        const auto written = ::write(STDOUT_FILENO, data.constData() + offset, data.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        offset += written;
    }
    return true;
}

int serve(uid_t uid)
{
    ::signal(SIGPIPE, SIG_IGN);
    TunnelHelperSession tunnel(uid);
    QByteArray pending;
    QByteArray last_error;
    QElapsedTimer maintenance;
    maintenance.start();
    while (true) {
        pollfd input{STDIN_FILENO, POLLIN, 0};
        const int ready = ::poll(&input, 1, 500);
        if (ready < 0) { if (errno == EINTR) continue; return 1; }
        if (input.revents & (POLLIN | POLLHUP)) {
            char buffer[4096];
            const auto size = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (size < 0 && errno == EINTR) continue;
            if (size <= 0) return 0; // Session end never tears down routing.
            pending.append(buffer, size);
            while (pending.contains('\n')) {
                const auto end = pending.indexOf('\n');
                const auto frame = pending.left(end);
                pending.remove(0, end + 1);
                QStringList arguments;
                const auto result = HelperProtocol::decode(frame, arguments)
                    ? (arguments.first().startsWith("tunnel-") ? [&] {
                        const auto reply = tunnel.request(arguments);
                        return Result{reply.exit_code, reply.output};
                    }()
                       : captured([&] { return dispatch(uid, arguments); }))
                    : Result{2, "Invalid or unsupported helper request"};
                if (!sendReply(result)) return 0;
            }
            if (pending.size() > HelperProtocol::maxRequest) return 2;
        }
        if (input.revents & (POLLERR | POLLNVAL)) return 1;
        if (maintenance.elapsed() >= 2000) {
            const auto result = captured([&] { return reconcile(uid); });
            if (result.exit_code && !result.output.isEmpty() && result.output != last_error)
                QTextStream(stderr) << "skewer routing recovery: " << result.output;
            last_error = result.exit_code ? result.output : QByteArray{};
            maintenance.restart();
        }
    }
}
}

void Tuntom::beginRouting(uid_t uid, const Endpoint& endpoint, const QStringList& exemptions)
{
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(2000)) throw std::runtime_error("Routing operation already in progress");
    if (!InterfaceRouting::state(uid).isEmpty())
        throw std::runtime_error("Release interfaces before enabling tunnel routing");
    QString error;
    QStringList normalized;
    if (!RoutingPlanner::normalizeExemptions(exemptions, normalized, error))
        throw std::runtime_error(error.toStdString());
    const int level = cgroupLevel(uid, error);
    if (!level || !setGuard(uid, level, error)) throw std::runtime_error(error.toStdString());
    if (QFile::exists(intentPath(uid)) && !QFile::remove(intentPath(uid)))
        throw std::runtime_error("Cannot cancel previous routing intent");
    cleanup(RoutingPlanner::create(uid, "192.0.2.1", "lo"));
    // Persist the fence before readiness is checked. A generic route watchdog
    // must never mistake a still-existing TUN device for a live transport.
    if (!writeIntent(uid, endpoint.serverAddress.chopped(3), normalized, endpoint.context))
        throw std::runtime_error("Cannot save tunnel routing intent");
}

void Tuntom::suspendRouting(uid_t uid, const Endpoint& endpoint)
{
    QLockFile lock("/run/skewer-interface-routing.lock");
    if (!lock.tryLock(2000)) throw std::runtime_error("Cannot lock tunnel routing");
    if (QJsonDocument::fromJson(readIntent(uid)).object()["tunnel_context"].toString() != endpoint.context)
        return; // A newer session or explicit Disable owns the routing now.
    QString error;
    const int level = cgroupLevel(uid, error);
    if (!level || !setGuard(uid, level, error)) throw std::runtime_error(error.toStdString());
    cleanup(RoutingPlanner::create(uid, "192.0.2.1", "lo"));
}

void Tuntom::updateRouting(uid_t uid, const Endpoint& endpoint, bool verified)
{
    if (QJsonDocument::fromJson(readIntent(uid)).object()["tunnel_context"].toString() != endpoint.context)
        throw std::runtime_error("Tunnel routing canceled or replaced");
    if (!verified) { suspendRouting(uid, endpoint); return; }
    const auto result = captured([&] { return reconcile(uid, endpoint.context); });
    if (result.exit_code) throw std::runtime_error(result.output.toStdString());
}

int main(int argc, char* argv[])
{
    QCoreApplication application(argc, argv);
    if (geteuid() != 0) {
        QTextStream(stderr) << "skewer-net-helper: must run as root through pkexec or sudo\n";
        return 2;
    }
    const auto uid = invokingUid();
    if (!uid) {
        QTextStream(stderr) << "skewer-net-helper: cannot identify the invoking user\n";
        return 2;
    }
    const auto arguments = application.arguments().sliced(1);
    if (arguments == QStringList{"serve"}) return serve(*uid);
    return dispatch(uid, arguments);
}
