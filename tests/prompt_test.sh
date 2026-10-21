#!/bin/bash
set -eu
source "$1"
fixture=$(mktemp)
trap 'rm -f -- "$fixture"' EXIT
export SKEWER_STATUS_FILE="$fixture"
PS1='user:\w\$ '
printf -v now '%(%s)T' -1

printf '%s online ok\n' "$now" > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'──∈'* && $PS1 == *'[32m'* ]]
first=$PS1
_skewer_prompt_marker
[[ $PS1 == "$first" ]]
printf '%s offline unreachable\n' "$now" > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'─×∈'* && $PS1 != *'──∈'* && $PS1 == *'[31m'* ]]
printf '%s route no-api\n' "$now" > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'┄┄∈'* && $PS1 == *'[33m'* ]]
printf '%s online expired\n' "$((now - 10))" > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'┄┄∈'* ]]
printf '%s online future\n' "$((now + 10))" > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'┄┄∈'* ]]
printf 'garbage online bad\n' > "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'┄┄∈'* ]]
rm -- "$fixture"
_skewer_prompt_marker
[[ $PS1 == *'┄┄∈'* ]]
PS1='changed $ '
_skewer_prompt_marker
[[ $PS1 == changed* && $PS1 == *'┄┄∈'* ]]
printf 'prompt status, freshness and idempotency tests passed\n'
