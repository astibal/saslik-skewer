#include "routing_plan.hpp"

#include <iostream>

int main()
{
    const RoutingPlan plan = RoutingPlanner::create(1000, QStringLiteral("192.0.2.10"),
                                                     QStringLiteral("eth0"));
    if (!plan.valid || plan.nft_table != QStringLiteral("skewer_1000")) return 1;
    if (!plan.nft_rules.contains(QStringLiteral("meta skuid 1000"))
        || !plan.nft_rules.contains(QStringLiteral("cgroupv2 level 5"))
        || !plan.nft_rules.contains(QStringLiteral("ip daddr 192.0.2.10 return"))) return 2;
    if (plan.prepare.size() != 3 || plan.cleanup.size() != 3) return 3;
    if (RoutingPlanner::create(1000, QStringLiteral("not-an-address"),
                               QStringLiteral("eth0")).valid) return 4;
    if (RoutingPlanner::create(1000, QStringLiteral("2001:db8::1"),
                               QStringLiteral("eth0")).valid) return 5;
    if (RoutingPlanner::create(1000, QStringLiteral("192.0.2.10"),
                               QStringLiteral("bad interface")).valid) return 6;
    std::cout << "routing plan tests passed\n";
    return 0;
}
