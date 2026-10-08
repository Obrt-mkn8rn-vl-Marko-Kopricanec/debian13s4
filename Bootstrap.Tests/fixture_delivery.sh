# Private test transport only. Never sourced by the installer or host units.
s4_fixture_start() {
    local helper=$1 model=$2 database=$3 log=$4 root=$5 input output
    S4_FIXTURE_OWNER=$BASHPID
    S4_FIXTURE_ROOT=$root
    rm -f -- "$root/model.failed"
    coproc S4_FIXTURE { exec python3 -B -I -S -u "$helper" "$model" "$database" "$log"; }
    S4_FIXTURE_WORKER=$S4_FIXTURE_PID
    input=${S4_FIXTURE[1]}
    output=${S4_FIXTURE[0]}
    # Coprocess descriptors themselves are not available in command substitutions.
    # Explicit duplicates preserve the same single request/reply channels there.
    exec {S4_FIXTURE_INPUT}>&"$input"
    exec {S4_FIXTURE_OUTPUT}<&"$output"
    exec {input}>&-
    exec {output}<&-
    printf '%s\n' "$S4_FIXTURE_WORKER" > "$root/model.pid"
}

s4_fixture_stop() {
    # Pipeline/substitution children must never terminate the parent interpreter.
    [[ $BASHPID == "$S4_FIXTURE_OWNER" ]] || return 0
    exec {S4_FIXTURE_INPUT}>&-
    exec {S4_FIXTURE_OUTPUT}<&-
    # EOF terminates the reader; run_bash's unchanged outer deadline/session
    # cleanup still owns a blocked interpreter and every fixture descendant.
    wait "$S4_FIXTURE_WORKER" 2>/dev/null || :
}

s4_fixture_call() {
    local lock status=75 code stdout stderr
    [[ ! -e $S4_FIXTURE_ROOT/model.failed ]] || return 75
    exec {lock}<> "$S4_FIXTURE_ROOT/model.lock"
    if flock --exclusive --timeout 10 "$lock"; then
        if [[ ! -e $S4_FIXTURE_ROOT/model.failed ]] &&
            printf '%s\0' "$#" "$@" >&"$S4_FIXTURE_INPUT" &&
            IFS= read -r -d '' -t 10 code <&"$S4_FIXTURE_OUTPUT" &&
            IFS= read -r -d '' -t 10 stdout <&"$S4_FIXTURE_OUTPUT" &&
            IFS= read -r -d '' -t 10 stderr <&"$S4_FIXTURE_OUTPUT" &&
            [[ $code =~ ^(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
            if printf '%s' "$stdout" && printf '%s' "$stderr" >&2; then
                status=$code
            fi
        else
            # A partial/lost response cannot be reused as a later healthy result,
            # including when the failed caller was a pipeline/substitution child.
            : > "$S4_FIXTURE_ROOT/model.failed"
        fi
    fi
    exec {lock}>&-
    return "$status"
}
