#pragma once
#include <QHostAddress>
#include <QJsonObject>
#include <QStringList>

// The host table touches OUTPUT only: forwarded VM/interface traffic remains
// owned by InterfaceRouting. The main routing table is never rewritten.
namespace HostRouting {
inline constexpr auto table = "skewer_host";
inline constexpr auto statePath = "/run/skewer-host.json";
inline constexpr auto option = "--whole-host";

inline QString bypass(const QJsonObject& state)
{
    QString rules = "ip daddr 127.0.0.0/8 return\nip6 daddr ::1 return\n"
        "meta nfproto ipv4 udp sport 68 udp dport 67 return\n";
    const auto peer = state["peer"].toString();
    if (!peer.isEmpty()) {
        // Transport sockets stay in the worker service cgroup even after its privilege drop. Control is limited to
        // the initiating user and one TCP service; peer-wide bypass is forbidden.
        rules += QString("socket cgroupv2 level 2 \"system.slice/skewer-tuntom-%1.service\" ip daddr %2 udp dport %3 return\n")
            .arg(state["uid"].toInt()).arg(peer).arg(state["transport_port"].toInt());
        rules += QString("meta skuid %1 ip daddr %2 tcp dport %3 return\n")
            .arg(state["uid"].toInt()).arg(peer).arg(state["control_port"].toInt());
    }
    if (!state["probe"].toString().isEmpty())
        rules += QString("socket cgroupv2 level 2 \"system.slice/skewer-tuntom-%1.service\" ip daddr %2 icmp type echo-request return\n")
            .arg(state["uid"].toInt()).arg(state["probe"].toString());
    return rules;
}

inline QString rules(const QJsonObject& state, quint32 mark, bool ready, bool replace)
{
    QString text = replace ? "delete table inet skewer_host\n" : QString{};
    text += "table inet skewer_host {\nset bypass_v4 { type ipv4_addr; flags interval; auto-merge; }\n";
    text += "chain output { type route hook output priority -149; policy accept;\n";
    // Reset only the Skewer mark, leaving unrelated firewall/VPN marks intact.
    text += QString("meta mark 0x%1 meta mark set 0\n").arg(mark, 0, 16);
    text += bypass(state);
    text += "ip daddr @bypass_v4 return\n";
    if (ready) text += QString("meta nfproto ipv4 counter meta mark set 0x%1\n").arg(mark, 0, 16);
    text += "}\nchain guard { type filter hook output priority 101; policy accept;\n";
    text += bypass(state);
    // Exemptions remain available during loss; they are explicit user policy.
    text += "ip daddr @bypass_v4 return\n";
    if (ready) text += QString("meta nfproto ipv4 meta mark 0x%1 return\n").arg(mark, 0, 16);
    text += "counter drop\n}\n";
    const auto interface = state["interface"].toString();
    if (ready && !interface.isEmpty()) {
        text += "chain egress { type filter hook postrouting priority 99; policy accept;\n";
        text += QString("meta mark 0x%1 oifname != \"%2\" counter drop\n}\n").arg(mark, 0, 16).arg(interface);
        if (state["peer"].toString().isEmpty())
            text += QString("chain source { type nat hook postrouting priority srcnat; policy accept;\n"
                "meta mark 0x%1 oifname \"%2\" masquerade\n}\n").arg(mark, 0, 16).arg(interface);
    }
    text += "}\n";
    const auto exemptions = state["exemptions"].toString().split(',', Qt::SkipEmptyParts);
    if (!exemptions.isEmpty()) text += "add element inet skewer_host bypass_v4 { " + exemptions.join(", ") + " }\n";
    return text;
}
}
