#!/bin/sh
set -eu

# Run inside cross.Dockerfile's image. The archive is supplied by the caller;
# this script never downloads or executes an unverified dependency.
if [ "$#" -ne 2 ]; then
    echo "Usage: build-openssl.sh ARCHIVE ABSOLUTE_PREFIX" >&2
    exit 2
fi
archive=$1
prefix=$2
case "$prefix" in
    /*) ;;
    *) echo "OpenSSL prefix must be absolute" >&2; exit 2 ;;
esac
expected=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
actual=$(sha256sum "$archive")
[ "${actual%% *}" = "$expected" ] || { echo "OpenSSL archive checksum mismatch" >&2; exit 1; }
build_dir=$(mktemp -d /tmp/skewer-openssl.XXXXXX)
tar -xzf "$archive" -C "$build_dir"
cd "$build_dir/openssl-3.5.9"
perl Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- \
    no-shared no-tests no-apps no-docs --prefix="$prefix" --libdir=lib
make -j"${BUILD_JOBS:-4}"
make install_sw
