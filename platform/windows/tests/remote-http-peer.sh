#!/bin/bash
set -euo pipefail
# Public, disposable test key; never a deployment credential.
test_ns=skewer-http-test
test_table=skewer_http_test
test_unit=skewer-http-tuntom
http_unit=skewer-http-endpoint
test -x /tmp/tuntom-interop-linux
for unit in "$test_unit" "$http_unit"; do
    if test "$(systemctl show "$unit.service" -p LoadState --value)" != not-found; then exit 1; fi
done
if ip netns list | cut -d' ' -f1 | grep -qx "$test_ns"; then exit 1; fi
if nft list table inet "$test_table" >/dev/null 2>&1; then exit 1; fi
if ss -H -uln | grep -q ':40242 '; then exit 1; fi
cleanup() {
    systemctl stop "$http_unit.service" "$test_unit.service" || true
    ip netns del "$test_ns" || true
    nft delete table inet "$test_table" || true
}
ip netns add "$test_ns"
trap cleanup EXIT
nft add table inet "$test_table"
nft 'add chain inet skewer_http_test input { type filter hook input priority -10; policy accept; }'
nft 'add rule inet skewer_http_test input iifname "virbr0" ip saddr 192.168.199.131 udp dport 40242 accept'
nft 'add rule inet skewer_http_test input udp dport 40242 drop'
ip -n "$test_ns" link set lo up
systemd-run --unit="$test_unit" --collect -p RuntimeMaxSec=100 \
    -p Environment=TUNTOM_SECRET=73737373737373737373737373737373 \
    /tmp/tuntom-interop-linux server 242 skhttp \
    --tun-netns "$test_ns" --tun-up --mtu 1280 --no-pmtud \
    --no-ttl-compensate --user nobody --group nogroup
for attempt in {1..50}; do
    if ip -n "$test_ns" link show skhttp >/dev/null 2>&1; then break; fi
    sleep 0.1
done
ip -n "$test_ns" addr add 198.18.254.2/30 dev skhttp
systemd-run --unit="$http_unit" --collect -p RuntimeMaxSec=95 \
    -p NetworkNamespacePath="/run/netns/$test_ns" -p User=nobody -p Group=nogroup \
    /usr/bin/python3 "$(dirname "$(readlink -f "$0")")/remote-http-endpoint.py"
echo 'READY: isolated HTTP peer'
sleep 90
