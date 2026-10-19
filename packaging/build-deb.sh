#!/bin/bash
set -euo pipefail
# Run as root inside a disposable Ubuntu 26.04 build container.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential cmake ninja-build pkg-config \
    qt6-base-dev libsystemd-dev libncurses-dev dpkg-dev file ca-certificates
cmake -S /src -B /tmp/skewer-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr
cmake --build /tmp/skewer-build --parallel 2
install -Dm644 /src/data/org.saslik.Skewer.desktop /usr/share/applications/org.saslik.Skewer.desktop
# Moving real processes requires a logged-in user's systemd manager; that test
# runs on the development host, not inside this non-systemd build container.
ctest --test-dir /tmp/skewer-build --output-on-failure -E '^cgroup_manager$'
mkdir -p /out
cd /out
cmake -S /src -B /tmp/skewer-build
cpack --config /tmp/skewer-build/CPackConfig.cmake
test "$(dpkg-deb -f skewer-linux-amd64.deb Version)" = "$(/tmp/skewer-build/skewer --version | cut -d' ' -f2)"
sha256sum skewer-linux-amd64.deb > SHA256SUMS
# Validate dependencies and installed paths in the container, not on the host.
apt-get install -y ./skewer-linux-amd64.deb
skewer --version
test -x /usr/libexec/skewer-net-helper
test -f /usr/share/icons/hicolor/scalable/apps/org.saslik.Skewer.svg
test -f /usr/share/polkit-1/actions/org.saslik.skewer.policy
