#!/bin/bash
set -euo pipefail
# Run as root inside a disposable Debian 12 baseline build container.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential cmake ninja-build pkg-config \
    qt6-base-dev libsystemd-dev libncurses-dev libnss3-dev libnspr4-dev libssl-dev dpkg-dev file ca-certificates libnss3-tools openssl
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
binary_version=$(/tmp/skewer-build/skewer --version | cut -d' ' -f2)
deb_version=$binary_version
if [[ -n "${RELEASE_TAG:-}" ]]; then
    [[ "$RELEASE_TAG" =~ ^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
    test "$RELEASE_TAG" = "$binary_version"
fi
cpack --config /tmp/skewer-build/CPackConfig.cmake -D "CPACK_DEBIAN_PACKAGE_VERSION=$deb_version"
test "$(dpkg-deb -f skewer-linux-amd64.deb Version)" = "$deb_version"
sha256sum skewer-linux-amd64.deb > SHA256SUMS
# Validate dependencies and installed paths in the container, not on the host.
apt-get install -y ./skewer-linux-amd64.deb
skewer --version
test -x /usr/libexec/skewer-net-helper
test -f /usr/share/icons/hicolor/scalable/apps/org.saslik.Skewer.svg
test -f /usr/share/polkit-1/actions/org.saslik.skewer.policy
