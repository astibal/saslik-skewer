# Only read a small, atomically replaced local cache. Never run network commands here.
_skewer_prompt_marker() {
    local sampled state reason now symbol color marker='\$'
    state=unknown
    if [[ -n ${SKEWER_STATUS_FILE:-} && -f $SKEWER_STATUS_FILE ]]; then
        read -r sampled state reason < "$SKEWER_STATUS_FILE" || state=unknown
        printf -v now '%(%s)T' -1
        if [[ ! $sampled =~ ^[0-9]{1,12}$ ]] || (( now < sampled || now - sampled > 6 )); then
            state=unknown
        fi
    fi
    case $state in
        online) symbol='──∈'; color=32 ;;
        offline) symbol='─×∈'; color=31 ;;
        *) symbol='┄┄∈'; color=33 ;;
    esac
    # Preserve prompt generators and avoid accumulating markers on each redraw.
    if [[ ${PS1:-} != "${_skewer_prompt_last:-}" || ! -v _skewer_prompt_base ]]; then
        _skewer_prompt_base=${PS1:-}
    fi
    PS1=$_skewer_prompt_base
    local rendered="\[\e[${color}m\]${symbol}\[\e[0m\]"
    if [[ $PS1 == *"$marker"* ]]; then
        PS1=${PS1/"$marker"/" $rendered $marker"}
    elif [[ $PS1 == *'$'* ]]; then
        marker='$'
        PS1=${PS1/"$marker"/" $rendered $marker"}
    else
        PS1+=" $rendered "
    fi
    _skewer_prompt_last=$PS1
}
