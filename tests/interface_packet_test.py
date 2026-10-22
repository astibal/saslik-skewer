#!/usr/bin/env python3
"""Run ONLY inside a disposable user/network namespace (see CTest)."""
import json
import socket
import struct
import subprocess
import sys
import fcntl
import select
import time


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, **kwargs)
    if result.returncode:
        sys.stderr.buffer.write(result.stdout + result.stderr)
        result.check_returncode()
    return result.stdout


def checksum(data):
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    value = sum(words)
    value = (value & 65535) + (value >> 16)
    value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def mac(name):
    value = json.loads(run("ip", "-j", "link", "show", name))[0]["address"]
    return bytes.fromhex(value.replace(":", ""))


def main():
    # The runner must create both namespaces; never accept the host netns.
    import os
    if len(sys.argv) != 4 or sys.argv[1] != "--inside":
        raise RuntimeError("Use the namespace runner")
    host_net, host_mount = sys.argv[2].split(",")
    if os.readlink("/proc/self/ns/net") == host_net or os.readlink("/proc/self/ns/mnt") == host_mount:
        raise RuntimeError("Refusing to change the host network")
    run("mount", "-t", "sysfs", "-o", "ro", "sysfs", "/sys")
    tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH', b'vnet0', 0x0002 | 0x1000))
    run('ip', 'link', 'add', 'guest0', 'type', 'dummy')
    class TapSender:
        def bind(self, address): pass
        def send(self, data): return os.write(tap, data)
        def close(self): pass
    for left, right in (("uplink", "gateway"), ("direct0", "client0"), ("fallback", "bridgepeer")):
        run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
    run("ip", "link", "add", "br0", "type", "bridge")
    run("ip", "link", "set", "vnet0", "master", "br0")
    run("ip", "link", "set", "fallback", "master", "br0")
    for name in ("lo", "br0", "vnet0", "guest0", "direct0", "client0", "uplink", "gateway", "fallback", "bridgepeer"):
        run("ip", "link", "set", name, "up")
    run("ip", "addr", "add", "192.0.2.1/24", "dev", "uplink")
    run("ip", "addr", "add", "198.18.0.1/24", "dev", "br0")
    run("ip", "addr", "add", "198.19.0.1/24", "dev", "direct0")
    run("ip", "route", "add", "default", "via", "192.0.2.2")
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    if os.path.exists('/proc/sys/net/bridge/bridge-nf-call-iptables'):
        run('sysctl', '-qw', 'net.bridge.bridge-nf-call-iptables=1')
    run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2")
    for name in ("br0", "vnet0", "direct0"):
        run("sysctl", "-qw", f"net.ipv4.conf.{name}.rp_filter=2")
    # A libvirt-style routed network permits both directions for its guest subnet.
    run("nft", "-f", "-", input=b'''table ip vm_filter {
      chain forward { type filter hook forward priority filter; policy drop;
        iifname "br0" ip saddr 198.18.0.0/24 accept
        oifname "br0" ip daddr 198.18.0.0/24 accept
        iifname "direct0" accept
      }
    }''')
    gateway_mac = ":".join(f"{b:02x}" for b in mac("gateway"))
    run("ip", "neigh", "replace", "192.0.2.2", "lladdr", gateway_mac, "nud", "permanent", "dev", "uplink")
    run("ip", "route", "add", "192.0.2.2/32", "dev", "uplink", "table", "1409287144")
    run("ip", "route", "add", "default", "via", "192.0.2.2", "dev", "uplink", "table", "1409287144")
    run("ip", "rule", "add", "pref", "25000", "fwmark", "0x540003e8", "lookup", "1409287144")
    rules = run(sys.argv[3], "--live-rules")
    run("nft", "-c", "-f", "-", input=rules)
    run("nft", "-f", "-", input=rules)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    capture.bind(("gateway", 0))
    capture.settimeout(2)
    for source, ingress in (("guest0", "br0"), ("client0", "direct0")):
        source_ip = "198.18.0.2" if source == "guest0" else "198.19.0.2"
        payload = b"skewer-interface-test-" + source.encode()
        udp = struct.pack("!HHHH", 32001, 443, 8 + len(payload), 0) + payload
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 42, 0, 64, 17, 0,
                             socket.inet_aton(source_ip), socket.inet_aton("203.0.113.9"))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        destination_mac = mac(ingress)
        frame = destination_mac + mac(source) + b"\x08\x00" + header + udp
        sender = TapSender() if source == "guest0" else socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sender.bind((source, 0))
        sender.send(frame)
        while True:
            packet = capture.recv(65535)
            if payload in packet:
                assert packet[22] == 63, "Packet must be routed, not merely bridged"
                assert packet[26:30] == socket.inet_aton(source_ip), "No implicit SNAT"
                break
        sender.close()
    guest_mac = ':'.join(f'{b:02x}' for b in mac('guest0'))
    run('ip', 'neigh', 'replace', '198.18.0.2', 'lladdr', guest_mac, 'nud', 'permanent', 'dev', 'br0')
    reply = b'skewer-return-path'
    udp = struct.pack('!HHHH', 443, 32001, 8 + len(reply), 0) + reply
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 44, 0, 64, 17, 0,
                         socket.inet_aton('203.0.113.9'), socket.inet_aton('198.18.0.2'))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    upstream = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    upstream.bind(('gateway', 0))
    upstream.send(mac('uplink') + mac('gateway') + b'\x08\x00' + header + udp)
    deadline = time.monotonic() + 2
    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([tap], [], [], remaining)[0], 'Reply did not reach VM TAP'
        packet = os.read(tap, 65535)
        if reply in packet:
            assert packet[22] == 63
            break
    # Exempt traffic remains bridged, and Release restores normal bridging.
    bridge_capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    bridge_capture.bind(("bridgepeer", 0))
    bridge_capture.settimeout(1)
    sender = TapSender()
    sender.bind(("guest0", 0))
    def bridged_packet(destination, port=443):
        payload = b"skewer-bypass-check"
        udp = struct.pack("!HHHH", 32001, port, 8 + len(payload), 0) + payload
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 43, 0, 64, 17, 0,
                             socket.inet_aton("198.18.0.2"), socket.inet_aton(destination))
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        sender.send(mac("bridgepeer") + mac("guest0") + b"\x08\x00" + header + udp)
        while True:
            packet = bridge_capture.recv(65535)
            if payload in packet:
                assert packet[22] == 64, "Exempt/released traffic must remain bridged"
                break
    bridged_packet("198.51.100.9")
    bridged_packet("203.0.113.9", 67)
    marker = b"skewer-ipv6-must-drop"
    sender.send(mac("bridgepeer") + mac("guest0") + b"\x86\xdd" + b"\x60" + bytes(39) + marker)
    try:
        while True:
            assert marker not in bridge_capture.recv(65535), "Selected IPv6 ingress escaped"
    except TimeoutError:
        pass
    run("nft", "-f", "-", input=b"delete table inet skewer_if_1000\ndelete table bridge skewer_if_1000\n")
    bridged_packet("203.0.113.9")
    # Exercise the real helper transaction too. Its /run state and lock live
    # on a private tmpfs, never on the host filesystem.
    run("ip", "rule", "del", "pref", "25000")
    run("ip", "route", "flush", "table", "1409287144")
    run("mount", "-t", "tmpfs", "tmpfs", "/run")
    helper = os.path.join(os.path.dirname(sys.argv[3]), "skewer-net-helper")
    environment = dict(os.environ, SUDO_UID="1000", PKEXEC_UID="1000")
    index = str(json.loads(run("ip", "-j", "link", "show", "vnet0"))[0]["ifindex"])
    # A foreign rule at our preferred slot must survive a rejected Attach.
    run("ip", "rule", "add", "pref", "25000", "lookup", "main")
    rejected = subprocess.run([helper, "interface-attach", "vnet0", index, "192.0.2.2"], env=environment, capture_output=True)
    assert rejected.returncode != 0
    assert b"lookup main" in run("ip", "-4", "rule", "show", "pref", "25000")
    run("ip", "rule", "del", "pref", "25000", "lookup", "main")
    run(helper, "interface-attach", "vnet0", index, "192.0.2.2", env=environment)
    run(helper, "interface-attach", "vnet0", index, "192.0.2.2", env=environment)
    direct_index = str(json.loads(run("ip", "-j", "link", "show", "direct0"))[0]["ifindex"])
    run(helper, "interface-attach", "direct0", direct_index, "192.0.2.2", env=environment)
    run("nft", "list", "table", "bridge", "skewer_if_1000")
    run(helper, "interface-release", "vnet0", index, env=environment)
    run("nft", "list", "table", "inet", "skewer_if_1000")
    run(helper, "interface-release", "direct0", direct_index, env=environment)
    assert not os.path.exists("/run/skewer-interfaces-1000.json")
    assert not run("ip", "-4", "rule", "show", "pref", "25000").strip()
    assert not run("ip", "-4", "rule", "show", "pref", "25001").strip()
    bridged_packet("203.0.113.9")
    print("Bridge and standalone ingress routed through selected next hop")


if __name__ == "__main__":
    import os
    if len(sys.argv) == 2:
        import shutil
        if any(not shutil.which(tool) for tool in ("unshare", "ip", "nft", "sysctl", "mount")):
            sys.exit(77)
        if subprocess.run(["unshare", "-Urnm", "true"], capture_output=True).returncode:
            sys.exit(77)
        identity = os.readlink("/proc/self/ns/net") + "," + os.readlink("/proc/self/ns/mnt")
        sys.exit(subprocess.call(["unshare", "-Urnm", sys.executable, __file__, "--inside", identity, sys.argv[1]]))
    main()
