# The shell can reset emulator modes after it takes its terminal back. A
# detached daemon cannot safely write to another session's terminal.
if [[ $- == *i* ]] && (( BASH_VERSINFO[0] > 5 || BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1 )); then
    if ! declare -F __shuang_reset_terminal >/dev/null; then
        __shuang_reset_terminal() {
            local status=$?
            if [[ -t 0 && -t 2 && -n ${TERM-} && $TERM != dumb ]]; then
                # Disable mouse, focus, color scheme and extended key reports.
                # Readline will enable its own bracketed paste mode for editing.
                builtin printf '\e[?1000;1002;1003;1004;1006;1016;2004;2031l\e[>4m\e[=0u\e[?25h' >&2
            fi
            return "$status"
        }
        PROMPT_COMMAND=(__shuang_reset_terminal "${PROMPT_COMMAND[@]}")
    fi
fi
