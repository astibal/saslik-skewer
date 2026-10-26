#!/usr/bin/env bash
set -euo pipefail
command -v unshare >/dev/null && command -v ip >/dev/null || exit 77
unshare -Urn true 2>/dev/null || exit 77
exec unshare -Urn "$1" "$(readlink /proc/self/ns/net)"
