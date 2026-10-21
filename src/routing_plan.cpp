#include "routing_plan.hpp"

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
                                   const QStringList& exemptions)
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
    plan.nft_rules += exemptionUpdate(uid, normalized);

    plan.cleanup = {
        {QStringLiteral("nft"), {QStringLiteral("delete"), QStringLiteral("table"),
                                 QStringLiteral("inet"), plan.nft_table}, true},
        {QStringLiteral("ip"), {QStringLiteral("-4"), QStringLiteral("rule"),
                                QStringLiteral("del"), QStringLiteral("pref"), number(priority)}, true},
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
    };
    plan.valid = true;
    return plan;
}

bool RoutingPlanner::normalizeExemptions(const QStringList& input, QStringList& output, QString& error)
{
    output.clear();
    if (input.size() > 256) { error = "At most 256 destination exemptions are supported"; return false; }
    static const QRegularExpression syntax("^[0-9.]+(?:/[0-9]{1,2})?$");
    for (const auto& raw : input) {
        const QString value = raw.trimmed();
        QHostAddress address;
        const auto parts = value.split('/');
        const int bits = parts.size() == 2 ? parts[1].toInt() : 32;
        if (!syntax.match(value).hasMatch() || bits > 32
            || !address.setAddress(parts[0]) || address.protocol() != QAbstractSocket::IPv4Protocol) {
            error = QString("Invalid IPv4 address or CIDR: %1").arg(value); return false;
        }
        const quint32 mask = bits == 0 ? 0 : (0xffffffffU << (32 - bits));
        output << QHostAddress(address.toIPv4Address() & mask).toString() + '/' + QString::number(bits);
    }
    output.removeDuplicates();
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
