#!/bin/bash
# Internal setup worker. The installer supplies the task bundle automatically.

S4_LIBRARY_DIR=/usr/local/lib/debian13s4
S4_STATE_DIR=/var/lib/debian13s4
S4_TIMER=debian13s4-repair.timer
S4_PHASE_TIMEOUT=30m
S4_KILL_DELAY=2m
S4_PHASE_PATH=/usr/sbin:/usr/bin:/sbin:/bin
S4_LOCK_FD=
declare -a S4_TASKS=()
declare -A S4_DEPENDENCIES=()

s4_log() {
    printf 'debian13s4: %s\n' "$*" >&2
}

s4_trusted_path() {
    local path=$1 owner mode
    if [[ $path != /* || $path == *'/../'* || $path == */.. ||
        $path == *'/./'* || $path == */. || $path == *'//'* ]]; then
        s4_log "Refusing a non-canonical path: $path"
        return 1
    fi
    while :; do
        if [[ -L $path || ! -e $path ]]; then
            s4_log "Refusing a missing or symbolic-link path: $path"
            return 1
        fi
        if ! read -r owner mode < <(stat --format='%u %a' -- "$path"); then
            return 1
        fi
        if [[ $owner != 0 ]] || (( (8#$mode & 8#022) != 0 )); then
            s4_log "Refusing a path writable by an unprivileged account: $path"
            return 1
        fi
        [[ $path == / ]] && break
        path=${path%/*}
        [[ -n $path ]] || path=/
    done
}

s4_atomic_write() {
    local target=$1 temporary
    if ! temporary=$(mktemp -- "${target}.XXXXXX"); then
        return 1
    fi
    if ! cat > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! mv -fT -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
}

s4_prepare_state() {
    local path
    if ! s4_trusted_path "${S4_STATE_DIR%/*}"; then
        return 1
    fi
    for path in "$S4_STATE_DIR" "$S4_STATE_DIR/results"; do
        if [[ -e $path || -L $path ]]; then
            s4_trusted_path "$path" && [[ -d $path ]] || return 1
        elif ! install -d -o root -g root -m 0700 -- "$path"; then
            return 1
        fi
        chmod 0700 -- "$path" || return 1
    done
}

s4_load_tasks() {
    local manifest=$S4_LIBRARY_DIR/tasks.list line task dependency
    local -a dependencies=()
    local -A seen=()
    S4_TASKS=()
    S4_DEPENDENCIES=()
    [[ -f $manifest ]] && s4_trusted_path "$manifest" || return 1
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
        if [[ $line != *:* ]]; then
            s4_log 'Task bundle contains a malformed registry entry.'
            return 1
        fi
        task=${line%%:*}
        if [[ ! $task =~ ^[a-z][a-z0-9_]{0,47}$ ]]; then
            s4_log 'Task bundle contains an invalid task name.'
            return 1
        fi
        if [[ -n ${seen[$task]+present} ]]; then
            s4_log "Task bundle repeats $task."
            return 1
        fi
        read -r -a dependencies <<< "${line#*:}"
        for dependency in "${dependencies[@]}"; do
            if [[ ! $dependency =~ ^[a-z][a-z0-9_]{0,47}$ ]] ||
                [[ -z ${seen[$dependency]+present} ]]; then
                s4_log "Task $task requires a missing, cyclic, or later dependency."
                return 1
            fi
        done
        S4_TASKS+=("$task")
        S4_DEPENDENCIES[$task]=${dependencies[*]}
        seen[$task]=1
    done < "$manifest"
    if (( ${#S4_TASKS[@]} == 0 )); then
        s4_log 'Refusing to declare an empty task bundle complete.'
        return 1
    fi
    for task in "${S4_TASKS[@]}"; do
        for line in apply verify; do
            [[ -f $S4_LIBRARY_DIR/tasks/$task/$line.sh ]] &&
                s4_trusted_path "$S4_LIBRARY_DIR/tasks/$task/$line.sh" || return 1
        done
    done
}

s4_execute_phase() {
    local phase=$1 task=$2 script
    [[ $phase == apply || $phase == verify ]] || return 1
    [[ $task =~ ^[a-z][a-z0-9_]{0,47}$ ]] || return 1
    script=$S4_LIBRARY_DIR/tasks/$task/$phase.sh
    [[ -f $script ]] && s4_trusted_path "$script" || return 1
    (
        # A child must not hold the worker's lock after the worker exits.
        if [[ -n $S4_LOCK_FD ]]; then
            exec {S4_LOCK_FD}>&-
        fi
        # A fresh interpreter keeps errexit active even when the parent checks
        # the exit status in an if statement. No inherited shell code is loaded.
        exec timeout --signal=TERM --kill-after="$S4_KILL_DELAY" "$S4_PHASE_TIMEOUT" \
            env -i PATH="$S4_PHASE_PATH" LANG=C LC_ALL=C \
            DEBIAN_FRONTEND=noninteractive \
            /bin/bash --noprofile --norc -e -u -o pipefail -- "$script"
    )
}

s4_record_task() {
    local task=$1 state=$2 reason=$3
    printf 'state=%s\nreason=%s\n' "$state" "$reason" |
        s4_atomic_write "$S4_STATE_DIR/results/$task"
}

s4_record_summary() {
    local state=$1 pending=$2
    printf 'state=%s\npending_tasks=%s\ntotal_tasks=%s\n' \
        "$state" "$pending" "${#S4_TASKS[@]}" |
        s4_atomic_write "$S4_STATE_DIR/status"
}

s4_stop_timer() {
    # Stop only the setup retry timer, never this service or upkeep timers.
    systemctl --no-block disable --now "$S4_TIMER"
}

s4_run_tasks() {
    local task dependency blocked reason code pending=0
    local -a dependencies=()
    local -A results=()
    rm -f -- "$S4_STATE_DIR/setup.ready" || return 1
    s4_record_summary pending "${#S4_TASKS[@]}" || return 1
    for task in "${S4_TASKS[@]}"; do
        blocked=0
        read -r -a dependencies <<< "${S4_DEPENDENCIES[$task]}"
        for dependency in "${dependencies[@]}"; do
            if [[ ${results[$dependency]:-pending} != complete ]]; then
                blocked=1
                break
            fi
        done
        if (( blocked )); then
            reason=dependency_pending
        elif s4_execute_phase verify "$task"; then
            results[$task]=complete
            s4_record_task "$task" complete verified || return 1
            continue
        elif s4_execute_phase apply "$task"; then
            if s4_execute_phase verify "$task"; then
                results[$task]=complete
                s4_record_task "$task" complete repaired_and_verified || return 1
                continue
            else
                code=$?
                reason=verification_failed_$code
            fi
        else
            code=$?
            reason=apply_failed_$code
        fi
        results[$task]=pending
        ((pending += 1))
        s4_record_task "$task" pending "$reason" || return 1
        s4_log "Task $task is pending ($reason)."
    done
    if (( pending )); then
        s4_record_summary pending "$pending" || return 1
        s4_log "$pending setup task(s) pending; automatic retries remain enabled."
        return 75
    fi
    printf 'verified\n' | s4_atomic_write "$S4_STATE_DIR/setup.ready" || return 1
    s4_record_summary complete 0 || return 1
    if ! s4_stop_timer; then
        rm -f -- "$S4_STATE_DIR/setup.ready" || return 1
        s4_record_summary timer_stop_pending 0 || return 1
        s4_log 'Setup is verified; disabling the retry timer will be retried.'
        return 75
    fi
    s4_log 'Every setup task is verified; the retry timer is disabled.'
}

s4_recover() {
    local result=0
    exec {S4_LOCK_FD}> "$S4_STATE_DIR/repair.lock" || return 1
    if ! flock --nonblock "$S4_LOCK_FD"; then
        s4_log 'Another setup attempt is already running.'
        exec {S4_LOCK_FD}>&-
        return 0
    fi
    if ! s4_load_tasks; then
        rm -f -- "$S4_STATE_DIR/setup.ready" || return 1
        s4_record_summary invalid_bundle 0 || return 1
        result=78
    elif s4_run_tasks; then
        result=0
    else
        result=$?
    fi
    exec {S4_LOCK_FD}>&-
    S4_LOCK_FD=
    return "$result"
}

s4_main() {
    local ID='' VERSION_ID=''
    if [[ $# == 1 && $1 == --help ]]; then
        printf '%s\n' 'Internal debian13s4 setup recovery worker.' \
            'The starting installer installs its task bundle and timer automatically.'
        return 0
    fi
    if (( $# )); then
        s4_log 'This internal worker does not accept configuration arguments.'
        return 64
    fi
    if (( EUID != 0 )); then
        s4_log 'The setup recovery worker must run as root.'
        return 77
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ $ID != debian || $VERSION_ID != 13 || ! -d /run/systemd/system ]]; then
        s4_log 'The setup recovery worker requires Debian 13 with systemd.'
        return 78
    fi
    s4_trusted_path "${BASH_SOURCE[0]}" || return 1
    s4_prepare_state || return 1
    s4_recover
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4_PHASE_PATH
    export PATH
    readonly PATH S4_LIBRARY_DIR S4_STATE_DIR S4_TIMER S4_PHASE_TIMEOUT \
        S4_KILL_DELAY S4_PHASE_PATH
    umask 077
    s4_main "$@"
fi
