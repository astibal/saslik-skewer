#include "routing_plan.hpp"

#include <iostream>

int main(int argc, char** argv)
{
    if (argc == 2) {
        const bool active = QString::fromLocal8Bit(argv[1]) == "--active";
        std::cout << RoutingPlanner::guardRules(1000, 5, active ? "192.0.2.2" : "",
            active ? "uplink" : "", active ? QStringList{"198.51.100.7/32"} : QStringList{}).toStdString();
        return 0;
    }
    const auto closed = RoutingPlanner::guardRules(1000, 5);
    const auto open = RoutingPlanner::guardRules(1000, 5, "192.0.2.2", "uplink");
    if (!closed.contains("counter drop") || closed.contains(" return")
        || !closed.contains("socket cgroupv2 level 5")
        || open.contains("rt nexthop")
        || open.contains("oifname \"uplink\"")
        || !open.contains("meta mark 0x530003e8 return")) return 20;
    const RoutingPlan plan = RoutingPlanner::create(1000, QStringLiteral("192.0.2.10"),
                                                     QStringLiteral("eth0"));
    if (!plan.valid || plan.nft_table != QStringLiteral("skewer_1000")) return 1;
    if (!plan.nft_rules.contains(QStringLiteral("meta skuid 1000"))
        || !plan.nft_rules.contains(QStringLiteral("cgroupv2 level 5"))
        || !plan.nft_rules.contains(QStringLiteral("ip daddr 192.0.2.10 return"))
        || !plan.nft_rules.contains(QStringLiteral("ip daddr 127.0.0.53 udp dport 53 return"))
        || !plan.nft_rules.contains(QStringLiteral("ip daddr 127.0.0.53 tcp dport 53 return"))) return 2;
    if (plan.prepare.size() != 4 || plan.cleanup.size() != 4) return 3;
    if (!plan.prepare.last().arguments.contains("unreachable")
        || !plan.cleanup.at(2).arguments.contains("15001")) return 14;
    if (!plan.nft_rules.contains(QStringLiteral(
            "cgroupv2 level 5 \"user.slice/user-1000.slice/user@1000.service/"
            "skewer.slice/skewer-routed.slice\""))) return 7;
    const RoutingPlan other_user = RoutingPlanner::create(1001, QStringLiteral("192.0.2.10"),
                                                         QStringLiteral("eth0"));
    if (!other_user.nft_rules.contains(QStringLiteral("user-1001.slice/user@1001.service/"))
        || other_user.nft_rules.contains(QStringLiteral("user-1000.slice"))) return 8;
    if (RoutingPlanner::create(1000, QStringLiteral("not-an-address"),
                               QStringLiteral("eth0")).valid) return 4;
    if (RoutingPlanner::create(1000, QStringLiteral("2001:db8::1"),
                               QStringLiteral("eth0")).valid) return 5;
    if (RoutingPlanner::create(1000, QStringLiteral("192.0.2.10"),
                               QStringLiteral("bad interface")).valid) return 6;
    std::cout << "routing plan tests passed\n";
    QStringList normalized; QString error;
    if (!RoutingPlanner::normalizeExemptions({"203.0.113.7", "192.168.1.9/24", "203.0.113.7/32"}, normalized, error)
        || normalized != QStringList{"203.0.113.7/32", "192.168.1.0/24"}) return 9;
    for (const auto& invalid : {"example.com", "::1", "1.2.3.4/33", "1.2.3.4; flush ruleset", "1.2.3.4/-1"})
        if (RoutingPlanner::normalizeExemptions({invalid}, normalized, error)) return 10;
    const auto bypass = RoutingPlanner::create(1000, "192.0.2.10", "eth0", 5, {"0.0.0.0/0"});
    if (!bypass.valid || !bypass.nft_rules.contains("0.0.0.0/0")
        || bypass.nft_rules.indexOf("ip daddr @bypass_v4 return") > bypass.nft_rules.indexOf("meta mark set")) return 11;
    if (!RoutingPlanner::exemptionUpdate(1000, {}).startsWith("flush set inet skewer_1000 bypass_v4\n")) return 12;
    const auto control = RoutingPlanner::create(1000, "192.0.2.10", "eth0", 5, {}, "127.0.0.1", 8766);
    const auto control_guard = RoutingPlanner::guardRules(1000, 5, "192.0.2.10", "eth0", {}, "127.0.0.1", 8766);
    if (!control.nft_rules.contains("ip daddr 127.0.0.1 tcp dport 8766 return")
        || !control_guard.contains("ip daddr 127.0.0.1 tcp dport 8766 return")) return 13;
    return 0;
}
