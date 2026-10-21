# Session-local startup: retain the user's normal Bash configuration.
if [[ -r "$HOME/.bashrc" ]]; then
    source "$HOME/.bashrc"
fi

source "${BASH_SOURCE[0]%/*}/skewer-prompt.bash"

# Run after existing prompt hooks, including hooks that regenerate PS1.
PROMPT_COMMAND+=(_skewer_prompt_marker)
_skewer_prompt_marker

# Do not replace an EXIT trap installed by the user's startup file.
if [[ -z $(trap -p EXIT) ]]; then
    trap 'printf "\nSkewer shell help: man skewer-shell-scripting\n" >&2' EXIT
fi
