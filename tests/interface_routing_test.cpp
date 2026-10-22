#include "interface_routing.hpp"
#include "vm_discovery.hpp"
#include <QCoreApplication>
#include <iostream>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const auto vm = VmDiscovery::parse("<domain><name>lilly</name><devices><interface><target dev='vnet9'/></interface></devices></domain>");
    if (vm.value("vnet9") != "lilly" || vm.size() != 1) return 20;
    if (!VmDiscovery::parse("<domain><name>broken").isEmpty()) return 21;
    if (!VmDiscovery::parse("<domain><name>vm</name><devices><disk><target dev='vda'/></disk></devices></domain>").isEmpty()) return 22;
    if (app.arguments().contains("--query-vms")) {
        const auto found = VmDiscovery::query();
        for (auto it = found.begin(); it != found.end(); ++it)
            std::cout << it.key().toStdString() << " -> " << it.value().toStdString() << '\n';
        return 0;
    }
    using namespace InterfaceRouting;
    const QVector<Link> topology{{"lo", {}, 1, false}, {"uplink", {}, 2, false},
        {"br0", {}, 3, true}, {"vnet0", "br0", 4, false}, {"vnet1", "br0", 5, false},
        {"bond0", {}, 6, false}, {"slave", "bond0", 7, false}};
    QString error;
    if (resolve(topology, "br0", 3, "uplink", error).size() != 2) return 1;
    if (resolve(topology, "vnet0", 4, "uplink", error).size() != 1) return 2;
    for (const auto& choice : QVector<QPair<QString, int>>{{"lo", 1}, {"uplink", 2}, {"vnet0", 99}, {"slave", 7}})
        if (!resolve(topology, choice.first, choice.second, "uplink", error).isEmpty()) return 3;
    if (!resolve(topology, "vnet0", 4, "br0", error).isEmpty()) return 4;
    const QJsonArray ports{QJsonObject{{"name", "vnet0"}, {"index", 4}, {"master", "br0"}, {"bridge_mac", "52:54:00:11:22:33"}}, QJsonObject{{"name", "direct0"}, {"index", 8}, {"master", ""}}};
    const auto script = rules(1000, ports, "192.0.2.2", {"192.0.2.1"}, {"198.51.100.0/24"}, false);
    if (!script.contains("meta iif 4 meta iifname \"vnet0\"") || !script.contains("meta iif 8 meta iifname \"direct0\"")
        || script.contains("broute") || !script.contains("ether daddr 52:54:00:11:22:33 counter meta mark set") || !script.contains("meta nfproto ipv6 counter drop")
        || !script.contains("ether type arp return") || !script.contains("udp dport { 67, 68 } return")
        || !script.contains("ip daddr 198.51.100.0/24 return") || script.contains("flush ruleset")) return 5;
    if (routingTable(1000) == routingTable(2000) || mark(1000) == mark(1001)) return 6;
    if (!rules(1000, ports, "192.0.2.2", {}, {}, true).startsWith("delete table inet skewer_if_1000\ndelete table bridge skewer_if_1000\n")) return 7;
    if (app.arguments().contains("--live-rules")) {
        QJsonArray live;
        for (const auto& link : links()) if (link.name == "vnet0" || link.name == "direct0")
            live.append(QJsonObject{{"name", link.name}, {"index", link.index}, {"master", link.master}, {"bridge_mac", bridgeAddress(link.master)}});
        if (live.size() != 2) return 8;
        std::cout << rules(1000, live, "192.0.2.2", {"192.0.2.1"}, {"198.51.100.0/24"}, false).toStdString();
    } else if (app.arguments().contains("--rules")) std::cout << script.toStdString();
    return 0;
}
