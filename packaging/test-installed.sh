#!/bin/bash
set -euo pipefail
# Run in a disposable container with the candidate DEB mounted at /packages.
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends /packages/skewer-linux-amd64.deb
skewer --version
test -x /usr/libexec/skewer-net-helper
test -x /usr/libexec/skewer-nss-helper
test -x /usr/libexec/skewer-session
test -f /usr/share/polkit-1/actions/org.saslik.skewer.policy
test -f /usr/share/icons/hicolor/scalable/apps/org.saslik.Skewer.svg
# Package names differ across distributions, but the icon engine must exist.
test -f /usr/lib/x86_64-linux-gnu/qt6/plugins/iconengines/libqsvgicon.so
for binary in /usr/bin/skewer /usr/libexec/skewer-net-helper /usr/libexec/skewer-nss-helper /usr/libexec/skewer-session; do
    dependencies=$(ldd "$binary")
    if [[ "$dependencies" == *'not found'* ]]; then
        printf '%s\n' "$dependencies"
        exit 1
    fi
done
# Exercise Qt initialization, plugin loading and the first process-tree refresh.
set +e
QT_QPA_PLATFORM=offscreen timeout 8 skewer --gui > /tmp/skewer-gui.log 2>&1
result=$?
set -e
cat /tmp/skewer-gui.log
test "$result" -eq 124
if grep -Ei 'symbol lookup error|could not load|cannot load|segmentation fault' /tmp/skewer-gui.log; then
    exit 1
fi
. /etc/os-release
printf 'PASS: %s; ' "$PRETTY_NAME"
dpkg-query -W -f='${Version}\n' skewer
