#!/usr/bin/env bash
set -euo pipefail
binary=$1
if "$binary" cleanup 123 --bad-option >/dev/null 2>&1; then exit 1; else [[ $? == 2 ]]; fi
if "$binary" cleanup 123 </dev/null >/dev/null 2>&1; then exit 1; else [[ $? == 2 ]]; fi
SKEWER_SESSION=test "$binary" env --json | grep -q '"SKEWER_SESSION":"test"'
if "$binary" env --bogus >/dev/null 2>&1; then exit 1; else [[ $? == 2 ]]; fi
"$binary" status --json | grep -q '"end_to_end_verified":false'
