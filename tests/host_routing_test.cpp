#include "host_routing.hpp"
#include <iostream>

int main(int argc, char** argv)
{
    QJsonObject direct{{"uid", 1000}, {"interface", "skout"}, {"exemptions", "198.51.100.7/32"}};
    if (argc == 2) {
        std::cout << HostRouting::rules(direct, 0x530003e8, QString(argv[1]) == "ready", false).toStdString();
        return 0;
    }
    const auto ready = HostRouting::rules(direct, 0x530003e8, true, false);
    const auto closed = HostRouting::rules(direct, 0x530003e8, false, true);
    if (ready.contains("meta skuid") || ready.contains("socket cgroupv2")
        || !ready.contains("masquerade") || !ready.contains("oifname != \"skout\"")
        || !closed.startsWith("delete table inet skewer_host") || closed.contains("chain egress")
        || closed.contains("meta nfproto ipv4 meta mark") || !closed.contains("counter drop")) return 1;
    QJsonObject tunnel{{"uid", 1000}, {"interface", "skt1c"}, {"peer", "192.0.2.2"},
        {"transport_port", 40001}, {"control_port", 8766}, {"probe", "10.253.0.5"}};
    const auto rules = HostRouting::rules(tunnel, 0x530003e8, true, false);
    if (rules.contains("ip daddr 192.0.2.2 return") || rules.contains("masquerade")
        || !rules.contains("system.slice/skewer-tuntom-1000.service")
        || !rules.contains("udp dport 40001 return")
        || !rules.contains("meta skuid 1000 ip daddr 192.0.2.2 tcp dport 8766 return")
        || !rules.contains("icmp type echo-request return")) return 2;
    return 0;
}
