#!/bin/sh
set -eu

if [ "$#" -ne 6 ]; then
    echo "usage: $0 BUILD_DIR QT_DIR WINTUN_DLL WINDIVERT_DIR OUTPUT_DIR MINGW_CXX" >&2
    exit 2
fi
build=$1
qt=$2
wintun=$3
windivert=$4
output=$5
cxx=$6
version=$(sed -n 's/^project(saslik-skewer VERSION \([^ ]*\) LANGUAGES.*$/\1/p' CMakeLists.txt)
case "$version" in *[!0-9.]*|'') echo "Invalid project version: $version" >&2; exit 1;; esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root="$stage/skewer-windows-amd64-$version"
tests="$stage/skewer-windows-tests-amd64-$version"
mkdir -p "$root/platforms" "$root/styles" "$root/tls" "$root/networkinformation" \
    "$root/imageformats" "$root/licenses" "$tests/platforms" "$output"

for file in skewer.exe skewer-routing-service.exe skewer-routing-control.exe skewer-control.exe; do
    install -m 0755 "$build/platform/windows/$file" "$root/$file"
done
for file in Qt6Core.dll Qt6Gui.dll Qt6Widgets.dll Qt6Concurrent.dll Qt6Network.dll Qt6Svg.dll; do
    install -m 0644 "$qt/bin/$file" "$root/$file"
done
install -m 0644 "$qt/plugins/platforms/qwindows.dll" "$root/platforms/qwindows.dll"
install -m 0644 "$qt/plugins/styles/qmodernwindowsstyle.dll" "$root/styles/qmodernwindowsstyle.dll"
install -m 0644 "$qt/plugins/tls/qschannelbackend.dll" "$root/tls/qschannelbackend.dll"
install -m 0644 "$qt/plugins/tls/qcertonlybackend.dll" "$root/tls/qcertonlybackend.dll"
install -m 0644 "$qt/plugins/networkinformation/qnetworklistmanager.dll" \
    "$root/networkinformation/qnetworklistmanager.dll"
install -m 0644 "$qt/plugins/imageformats/qsvg.dll" "$root/imageformats/qsvg.dll"
install -m 0644 "$qt/plugins/imageformats/qico.dll" "$root/imageformats/qico.dll"

for file in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll libssp-0.dll; do
    path=$($cxx -print-file-name="$file")
    [ "$path" != "$file" ] && [ -f "$path" ] || { echo "Missing MinGW runtime: $file" >&2; exit 1; }
    install -m 0644 "$path" "$root/$file"
done
install -m 0644 "$wintun" "$root/wintun.dll"
install -m 0644 "$windivert/WinDivert.dll" "$root/WinDivert.dll"
install -m 0644 "$windivert/WinDivert64.sys" "$root/WinDivert64.sys"
install -m 0644 "$(dirname "$wintun")/../../LICENSE.txt" "$root/licenses/Wintun-LICENSE.txt"
install -m 0644 "$windivert/../LICENSE" "$root/licenses/WinDivert-LICENSE.txt"
install -m 0644 packaging/WINDOWS-NOTICES.md "$root/licenses/README.md"
install -m 0644 packaging/verify-windows-package.ps1 "$root/verify-windows-package.ps1"
install -m 0644 platform/windows/install-skewer.ps1 "$root/install-skewer.ps1"
install -m 0644 platform/windows/uninstall-skewer.ps1 "$root/uninstall-skewer.ps1"
install -m 0644 platform/windows/install-routing-service.ps1 "$root/install-routing-service.ps1"
install -m 0644 platform/windows/remove-routing-service.ps1 "$root/remove-routing-service.ps1"
install -m 0644 platform/windows/INSTALL.md "$root/INSTALL.md"

windows_tests='process_group_test selection_registry_test routing_control_test selection_auth_test
selected_packet_epoch_test udp_owners_test tcp_owners_test app_egress_guard_test udp_endpoint_test
selected_tunnel_device_test tunnel_pump_test tuntom_udp_test skewer-process-probe wintun_device_test
flow_tracking_test skewer-flow-watch pairing_snapshot_test client_report_test pairing_storage_test
paired_tunnel_test tunnel_dns_test service_installer_test runtime_trust_test ca_trust_panel_test routing_panel_test
direct_host_policy_test whole_host_policy_test owned_route_test tunnel_routes_test'
traffic_tests='tunnel_flows_test packet_rewrite_test tunnel_lease_test routing_scope_test
owner_evidence_test packet_tuple_test flow_index_test pending_packets_test selected_packets_test'
ui_tests='tunnel_contract_test process_browser_test launch_catalog_test application_shell_test'
for file in $windows_tests; do
    install -m 0755 "$build/platform/windows/$file.exe" "$tests/$file.exe"
done
for file in $traffic_tests; do
    install -m 0755 "$build/platform/windows/portable-traffic/$file.exe" "$tests/$file.exe"
done
for file in $ui_tests; do
    install -m 0755 "$build/platform/windows/portable-ui/$file.exe" "$tests/$file.exe"
done
for file in Qt6Core.dll Qt6Gui.dll Qt6Widgets.dll Qt6Concurrent.dll Qt6Network.dll Qt6Svg.dll Qt6Test.dll; do
    install -m 0644 "$qt/bin/$file" "$tests/$file"
done
install -m 0644 "$qt/plugins/platforms/qoffscreen.dll" "$tests/platforms/qoffscreen.dll"
for file in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll libssp-0.dll; do
    path=$($cxx -print-file-name="$file")
    install -m 0644 "$path" "$tests/$file"
done
install -m 0644 packaging/test-windows-unit.ps1 "$tests/run-tests.ps1"

archive="$output/skewer-windows-amd64-$version.zip"
(cd "$stage" && cmake -E tar cf "$archive" --format=zip "$(basename "$root")")
(cd "$output" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
test_archive="$output/skewer-windows-tests-amd64-$version.zip"
(cd "$stage" && cmake -E tar cf "$test_archive" --format=zip "$(basename "$tests")")
(cd "$output" && sha256sum "$(basename "$test_archive")" > "$(basename "$test_archive").sha256")
echo "$archive"
echo "$test_archive"
