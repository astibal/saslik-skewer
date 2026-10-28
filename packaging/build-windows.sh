#!/bin/sh
set -eu

# Build the complete Windows package in the repository's pinned cross-build
# environment. All downloaded inputs are authenticated before they are used.
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=${SKEWER_WINDOWS_WORK_DIR:-"$root/.windows-build"}
output=${SKEWER_WINDOWS_OUTPUT_DIR:-"$root/dist/windows"}
case "$work:$output" in
    /*:/*) ;;
    *) echo "Windows build and output directories must be absolute" >&2; exit 2 ;;
esac
if [ "$work" = / ] || [ "$output" = / ]; then
    echo "Refusing to use the filesystem root as a build directory" >&2
    exit 2
fi
qt_version=6.8.3
tuntom_revision=62516bd05175270bcb1c729fe3cc3d92e5de9df7
tuntom_repository=${TUNTOM_REPOSITORY:-https://github.com/astibal/tuntom.git}
wintun_version=0.14.1
windivert_version=2.2.2-A
openssl_version=3.5.9

download() {
    url=$1
    destination=$2
    expected=$3
    if [ ! -f "$destination" ]; then
        curl --fail --location --retry 4 --output "$destination" "$url"
    fi
    actual=$(sha256sum "$destination")
    [ "${actual%% *}" = "$expected" ] || {
        echo "Checksum mismatch: $destination" >&2
        exit 1
    }
}

mkdir -p "$work/downloads" "$output"

if [ ! -d "$work/tuntom/.git" ]; then
    git clone "$tuntom_repository" "$work/tuntom"
fi
git -C "$work/tuntom" fetch --depth 1 "$tuntom_repository" "$tuntom_revision"
git -C "$work/tuntom" checkout --detach "$tuntom_revision"
[ "$(git -C "$work/tuntom" rev-parse HEAD)" = "$tuntom_revision" ]

if [ ! -f "$work/qt-target/$qt_version/mingw_64/bin/Qt6Core.dll" ]; then
    python3 -m aqt install-qt windows desktop "$qt_version" win64_mingw \
        -O "$work/qt-target" --archives qtbase qtsvg
fi
if [ ! -x "$work/qt-host/$qt_version/gcc_64/libexec/moc" ]; then
    python3 -m aqt install-qt linux desktop "$qt_version" linux_gcc_64 \
        -O "$work/qt-host" --archives qtbase icu
fi

wintun_archive="$work/downloads/wintun-$wintun_version.zip"
windivert_archive="$work/downloads/WinDivert-$windivert_version.zip"
openssl_archive="$work/downloads/openssl-$openssl_version.tar.gz"
download "https://www.wintun.net/builds/wintun-$wintun_version.zip" "$wintun_archive" \
    07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
download "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-$windivert_version.zip" \
    "$windivert_archive" 63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
download "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/openssl-$openssl_version.tar.gz" \
    "$openssl_archive" 603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

rm -rf "$work/wintun" "$work/windivert"
mkdir -p "$work/wintun" "$work/windivert"
unzip -q "$wintun_archive" -d "$work/wintun"
unzip -q "$windivert_archive" -d "$work/windivert"

docker build -t skewer-windows-cross -f "$root/platform/windows/cross.Dockerfile" \
    "$root/platform/windows"
if [ ! -f "$work/openssl/lib/libssl.a" ] || [ ! -f "$work/openssl/lib/libcrypto.a" ]; then
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e BUILD_JOBS="${BUILD_JOBS:-4}" \
        -v "$root:/src:ro" \
        -v "$work:/work" \
        skewer-windows-cross \
        /src/platform/windows/build-openssl.sh "/work/downloads/openssl-$openssl_version.tar.gz" /work/openssl
fi

docker run --rm -v "$work:/work" skewer-windows-cross rm -rf /work/build
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$root:/src:ro" \
    -v "$work:/work" \
    skewer-windows-cross sh -ec '
        cmake -S /src -B /work/build -G Ninja \
            -DCMAKE_TOOLCHAIN_FILE=/src/platform/windows/mingw-toolchain.cmake \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_PREFIX_PATH=/work/qt-target/6.8.3/mingw_64 \
            -DQT_HOST_PATH=/work/qt-host/6.8.3/gcc_64 \
            -DTUNTOM_SOURCE_DIR=/work/tuntom \
            -DSKEWER_WINDOWS_TUN=ON \
            -DSKEWER_WINDOWS_FLOW=ON \
            -DSKEWER_WINDOWS_PAIRING=ON \
            -DWINTUN_INCLUDE_DIR=/work/wintun/wintun/include \
            -DWINDIVERT_INCLUDE_DIR=/work/windivert/WinDivert-2.2.2-A/include \
            -DOPENSSL_ROOT_DIR=/work/openssl \
            -DOPENSSL_INCLUDE_DIR=/work/openssl/include \
            -DLIB_EAY=/work/openssl/lib/libcrypto.a \
            -DSSL_EAY=/work/openssl/lib/libssl.a \
            -DOPENSSL_SSL_LIBRARY=/work/openssl/lib/libssl.a \
            -DOPENSSL_CRYPTO_LIBRARY=/work/openssl/lib/libcrypto.a \
            -DBUILD_TESTING=ON
        cmake --build /work/build --parallel "${BUILD_JOBS:-4}"
    '

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$root:/src:ro" \
    -v "$work:/work" \
    -v "$output:/output" \
    -w /src \
    skewer-windows-cross \
    ./packaging/package-windows.sh \
        /work/build \
        "/work/qt-target/$qt_version/mingw_64" \
        /work/wintun/wintun/bin/amd64/wintun.dll \
        "/work/windivert/WinDivert-$windivert_version/x64" \
        /output \
        x86_64-w64-mingw32-g++
