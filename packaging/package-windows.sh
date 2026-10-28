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
mkdir -p "$root/platforms" "$root/styles" "$root/tls" "$output"

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

for file in libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll libssp-0.dll; do
    path=$($cxx -print-file-name="$file")
    [ "$path" != "$file" ] && [ -f "$path" ] || { echo "Missing MinGW runtime: $file" >&2; exit 1; }
    install -m 0644 "$path" "$root/$file"
done
install -m 0644 "$wintun" "$root/wintun.dll"
install -m 0644 "$windivert/WinDivert.dll" "$root/WinDivert.dll"
install -m 0644 "$windivert/WinDivert64.sys" "$root/WinDivert64.sys"
install -m 0644 platform/windows/install-routing-service.ps1 "$root/install-routing-service.ps1"
install -m 0644 platform/windows/INSTALL.md "$root/INSTALL.md"

archive="$output/skewer-windows-amd64-$version.zip"
(cd "$stage" && cmake -E tar cf "$archive" --format=zip "$(basename "$root")")
(cd "$output" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
echo "$archive"
