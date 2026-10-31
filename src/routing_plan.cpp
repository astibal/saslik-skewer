#include "routing_plan.hpp"
#include "ipv4_prefix.hpp"

#include <QHostAddress>
#include <QRegularExpression>

namespace {
QString number(quint32 value)
{
    return QString::number(value);
}
}

RoutingPlan RoutingPlanner::create(uid_t uid, const QString& next_hop,
                                   const QString& interface_name, int cgroup_level,
                                   const QStringList& exemptions,
                                   const QString& local_control, quint16 local_control_port)
{
    RoutingPlan plan;
    QStringList normalized;
    if (!normalizeExemptions(exemptions, normalized, plan.error)) return plan;
    QHostAddress address;
    if (!address.setAddress(next_hop) || address.protocol() != QAbstractSocket::IPv4Protocol) {
        plan.error = QStringLiteral("Next hop must be an IPv4 address");
        return plan;
    }
    static const QRegularExpression interface_pattern(QStringLiteral("^[A-Za-z0-9_.:-]{1,15}$"));
    if (!interface_pattern.match(interface_name).hasMatch()) {
        plan.error = QStringLiteral("Invalid network interface name");
        return plan;
    }
    if (cgroup_level < 1 || cgroup_level > 32) {
        plan.error = QStringLiteral("Invalid cgroup hierarchy level");
        return plan;
    }

    const QString gateway = address.toString();
    const quint32 packet_mark = mark(uid);
    const quint32 route_table = routeTable(uid);
    const quint32 priority = rulePriority(uid);
    const QString mark_hex = QStringLiteral("0x%1").arg(packet_mark, 0, 16);
    plan.nft_table = tableName(uid);
    plan.nft_rules = QStringLiteral(
        "table inet %1 {\n"
        "  set bypass_v4 { type ipv4_addr; flags interval; auto-merge; }\n"
        "  chain output {\n"
        "    type route hook output priority mangle; policy accept;\n"
        "    meta skuid %2 ip daddr @bypass_v4 return\n"
        "    meta skuid %2 ip daddr %3 return\n"
        // nft resolves this path relative to /sys/fs/cgroup, not the chosen
        // ancestor level. The level selects which socket ancestor to compare.
        "    meta skuid %2 socket cgroupv2 level %4 \"user.slice/user-%2.slice/user@%2.service/skewer.slice/skewer-routed.slice\" "
        "counter meta mark set %5\n"
        "  }\n"
        "}\n")
        .arg(plan.nft_table)
        .arg(uid)
        .arg(gateway)
        .arg(cgroup_level)
        .arg(mark_hex);
    const QString uid_match = "    meta skuid " + QString::number(uid);
    plan.nft_rules.replace(uid_match + " ip daddr " + gateway + " return\n",
        uid_match + " ip daddr 127.0.0.53 udp dport 53 return\n"
        + uid_match + " ip daddr 127.0.0.53 tcp dport 53 return\n"
        + uid_match + " ip daddr " + gateway + " return\n");
    if (!local_control.isEmpty() && local_control_port)
        plan.nft_rules.replace(uid_match + " ip daddr " + gateway + " return\n",
            uid_match + " ip daddr " + local_control
            + " tcp dport " + QString::number(local_control_port) + " return\n"
            + uid_match + " ip daddr " + gateway + " return\n");
    plan.nft_rules += exemptionUpdate(uid, normalized);

    plan.cleanup = {
        {QStringLiteral("nft"), {QStringLiteral("delete"), QStringLiteral("table"),
                                 QStringLiteral("inet"), plan.nft_table}, true},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("rule"),
                                QStringLiteral("del"), QStringLiteral("pref"), number(priority)}, true},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("rule"),
                                QStringLiteral("del"), QStringLiteral("pref"), number(priority + 1)}, true},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("route"),
                                QStringLiteral("flush"), QStringLiteral("table"), number(route_table)}, true},
    };
    plan.prepare = {
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("route"),
                                QStringLiteral("replace"), gateway + QStringLiteral("/32"),
                                QStringLiteral("dev"), interface_name, QStringLiteral("scope"),
                                QStringLiteral("link"), QStringLiteral("table"), number(route_table)}, false},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("route"),
                                QStringLiteral("replace"), QStringLiteral("default"),
                                QStringLiteral("via"), gateway, QStringLiteral("dev"), interface_name,
                                QStringLiteral("table"), number(route_table)}, false},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("rule"),
                                QStringLiteral("add"), QStringLiteral("pref"), number(priority),
                                QStringLiteral("fwmark"), mark_hex + QStringLiteral("/0xffffffff"),
                                QStringLiteral("lookup"), number(route_table)}, false},
        // Never let a marked socket fall through to the host's main table if
        // the dedicated route disappears between health checks.
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("rule"),
                                QStringLiteral("add"), QStringLiteral("pref"), number(priority + 1),
                                QStringLiteral("fwmark"), mark_hex + QStringLiteral("/0xffffffff"),
                                QStringLiteral("unreachable")}, false},
    };
    plan.valid = true;
    return plan;
}

QString RoutingPlanner::guardRules(uid_t uid, int level, const QString& gateway,
                                  const QString&, const QStringList& exemptions,
                                  const QString& local_control, quint16 local_control_port)
{
    const QString table = QString("skewer_guard_%1").arg(uid);
    QString rules = "table inet " + table + " {\n"
        "set bypass_v4 { type ipv4_addr; flags interval; auto-merge; }\n"
        "chain guarded {\n";
    if (!gateway.isEmpty()) {
        rules += "ip daddr @bypass_v4 return\nip daddr " + gateway + " return\n";
        // Desktop applications normally resolve through systemd-resolved's
        // loopback stub. Permit only DNS to that exact local endpoint.
        rules += "ip daddr 127.0.0.53 udp dport 53 return\n";
        rules += "ip daddr 127.0.0.53 tcp dport 53 return\n";
        if (!local_control.isEmpty() && local_control_port)
            rules += "ip daddr " + local_control + " tcp dport " + QString::number(local_control_port) + " return\n";
        // Policy rerouting happens after the output filter hooks. The old
        // oif/next-hop is therefore not meaningful here. The immediately
        // following unreachable policy rule provides the fail-closed check.
        rules += QString("meta nfproto ipv4 meta mark 0x%1 return\n").arg(mark(uid), 0, 16);
    }
    rules += "counter drop\n}\nchain output { type filter hook output priority 100; policy accept;\n";
    rules += QString("socket cgroupv2 level %1 \"user.slice/user-%2.slice/user@%2.service/skewer.slice/skewer-routed.slice\" jump guarded\n}\n}\n")
        .arg(level).arg(uid);
    if (!exemptions.isEmpty() && !gateway.isEmpty())
        rules += "add element inet " + table + " bypass_v4 { " + exemptions.join(", ") + " }\n";
    return rules;
}

bool RoutingPlanner::normalizeExemptions(const QStringList& input, QStringList& output, QString& error)
{
    std::vector<std::string> values;
    values.reserve(input.size());
    for (const auto& value : input) values.push_back(value.toStdString());
    std::vector<std::string> normalized;
    std::string failure;
    if (!skewer::traffic::normalizeIpv4Prefixes(values, normalized, failure)) {
        output.clear();
        error = QString::fromStdString(failure);
        return false;
    }
    output.clear();
    for (const auto& value : normalized) output.push_back(QString::fromStdString(value));
    error.clear();
    return true;
}

QString RoutingPlanner::exemptionUpdate(uid_t uid, const QStringList& normalized)
{
    // Both commands are submitted in one nft transaction; never flush live
    // exceptions separately from adding their replacements.
    const QString target = "inet " + tableName(uid) + " bypass_v4";
    QString script = "flush set " + target + '\n';
    if (!normalized.isEmpty()) script += "add element " + target + " { " + normalized.join(", ") + " }\n";
    return script;
}

QString RoutingPlanner::tableName(uid_t uid)
{
    return QStringLiteral("skewer_%1").arg(uid);
}

quint32 RoutingPlanner::mark(uid_t uid)
{
    return 0x53000000U | (static_cast<quint32>(uid) & 0x00ffffffU);
}

quint32 RoutingPlanner::routeTable(uid_t uid)
{
    return 45000U + (static_cast<quint32>(uid) % 1000U);
}

quint32 RoutingPlanner::rulePriority(uid_t uid)
{
    return 15000U + (static_cast<quint32>(uid) % 1000U);
}
