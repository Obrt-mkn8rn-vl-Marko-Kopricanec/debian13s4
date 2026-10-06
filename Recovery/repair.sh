#!/bin/bash
# Internal setup worker. The installer supplies the task bundle automatically.

S4_LIBRARY_DIR=/usr/local/lib/debian13s4
S4_STATE_DIR=/var/lib/debian13s4
S4_SYSTEMD_DIR=/etc/systemd/system
S4_SERVICE=debian13s4-repair.service
S4_TIMER=debian13s4-repair.timer
S4_RESUME_SERVICE=debian13s4-resume.service
S4_PHASE_TIMEOUT_MS=1800000
S4_KILL_DELAY_MS=120000
S4_CONTROL_TIMEOUT_MS=10000
S4_CONTROL_KILL_MS=1000
S4_TASK_OVERHEAD_MS=5000
S4_ATTEMPT_OVERHEAD_MS=30000
S4_POLL_INTERVAL_MS=1000
S4_POLL_COUNT=3
# Notifications, shutdown, durable barriers and rollback need at most 32
# control calls. Reserve 32, including the poll intervals, before any task runs.
S4_CONTROL_CALL_BUDGET=32
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
        exec timeout --signal=TERM --kill-after="$(s4_seconds "$S4_KILL_DELAY_MS")" \
            "$(s4_seconds "$S4_PHASE_TIMEOUT_MS")" \
            env -i PATH="$S4_PHASE_PATH" LANG=C LC_ALL=C \
            DEBIAN_FRONTEND=noninteractive \
            /bin/bash --noprofile --norc -e -u -o pipefail -- "$script"
    )
}

s4_seconds() {
    printf '%s.%03ds' "$(($1 / 1000))" "$(($1 % 1000))"
}

s4_control() (
    if [[ -n $S4_LOCK_FD ]]; then
        exec {S4_LOCK_FD}>&-
    fi
    timeout --signal=TERM --kill-after="$(s4_seconds "$S4_CONTROL_KILL_MS")" \
        "$(s4_seconds "$S4_CONTROL_TIMEOUT_MS")" "$@"
)

s4_systemctl() {
    s4_control systemctl "$@"
}

s4_sync_filesystems() {
    # Linux syncfs waits for file data AND filesystem metadata, including
    # rename/directory entries. Unlike plain sync, errors are observable.
    s4_control sync --file-system -- "$@"
}

s4_persist_recovery_intent() {
    local marker=$S4_STATE_DIR/timer-stop.pending
    if [[ -e $marker || -L $marker ]]; then
        # Do not replace an already durable marker with a volatile inode when
        # retrying after an IO error. Its presence, not its contents, is the gate.
        [[ -f $marker && ! -L $marker ]] && s4_trusted_path "$marker" || return 1
    else
        printf 'pending\n' | s4_atomic_write "$marker" || return 1
    fi
    s4_sync_filesystems "$S4_STATE_DIR"
}

s4_persist_boot_guard() {
    local path resolved wants=$S4_SYSTEMD_DIR/multi-user.target.wants
    local -a paths=("$S4_LIBRARY_DIR" "$S4_LIBRARY_DIR/repair.sh"
        "$S4_SYSTEMD_DIR" "$S4_SYSTEMD_DIR/$S4_RESUME_SERVICE"
        "$S4_SYSTEMD_DIR/$S4_SERVICE" "$S4_SYSTEMD_DIR/$S4_TIMER" "$wants")
    for path in "${paths[@]}"; do
        s4_trusted_path "$path" || return 1
    done
    [[ -d $wants && -f $S4_SYSTEMD_DIR/$S4_RESUME_SERVICE &&
        -f $S4_SYSTEMD_DIR/$S4_SERVICE && -f $S4_SYSTEMD_DIR/$S4_TIMER &&
        -x $S4_LIBRARY_DIR/repair.sh && -L $wants/$S4_RESUME_SERVICE ]] || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4_RESUME_SERVICE") || return 1
    [[ $resolved == "$S4_SYSTEMD_DIR/$S4_RESUME_SERVICE" ]] || return 1
    # Cover the unit/code files, link parent and its ancestors even when they
    # reside on different filesystems. A read-back of enablement cannot do this.
    s4_sync_filesystems "${paths[@]}"
}

s4_persist_timer_enablement() {
    local wants=$S4_SYSTEMD_DIR/timers.target.wants
    local -a paths=("$S4_SYSTEMD_DIR")
    s4_trusted_path "$S4_SYSTEMD_DIR" || return 1
    # disable may remove an empty wants directory. Its removal is then covered
    # by the parent's filesystem; a separately mounted wants directory remains.
    if [[ -d $wants ]]; then
        s4_trusted_path "$wants" || return 1
        paths+=("$wants")
    fi
    s4_sync_filesystems "${paths[@]}"
}

s4_notify() {
    # Keep systemd-notify's acknowledgement barrier: enqueueing is insufficient.
    s4_control systemd-notify "$@"
}

s4_attempt_budget_ms() {
    local per_task overhead count=${#S4_TASKS[@]}
    per_task=$((3 * (S4_PHASE_TIMEOUT_MS + S4_KILL_DELAY_MS) + S4_TASK_OVERHEAD_MS))
    overhead=$((S4_ATTEMPT_OVERHEAD_MS + S4_CONTROL_CALL_BUDGET *
        (S4_CONTROL_TIMEOUT_MS + S4_CONTROL_KILL_MS + S4_POLL_INTERVAL_MS)))
    # The notification expresses microseconds in signed 64-bit arithmetic.
    if (( count > (9223372036854775 - overhead) / per_task )); then
        s4_log 'The admitted bundle exceeds the representable attempt budget.'
        return 1
    fi
    printf '%s\n' "$((count * per_task + overhead))"
}

s4_arm_attempt_deadline() {
    local budget
    budget=$(s4_attempt_budget_ms) || return 1
    if [[ -n ${NOTIFY_SOCKET:-} ]]; then
        # READY starts RuntimeMaxSec. Extend that running deadline only after
        # READY has been acknowledged, with room for every admitted phase.
        s4_notify --ready || return 1
        s4_notify "EXTEND_TIMEOUT_USEC=$((budget * 1000))" || return 1
    fi
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

s4_enabled_state() {
    local unit=$1 expected=$2 actual code=0
    actual=$(s4_systemctl is-enabled "$unit") || code=$?
    # is-enabled returns 1 for a disabled unit. Other errors are not evidence.
    (( code == 0 || code == 1 )) && [[ $actual == "$expected" ]]
}

s4_wait_timer_state() {
    local expected_active=$1 expected_enabled=$2 actual attempt
    for ((attempt = 0; attempt < S4_POLL_COUNT; attempt++)); do
        if actual=$(s4_systemctl show --property=ActiveState --value "$S4_TIMER") &&
            [[ $actual == "$expected_active" ]] &&
            { [[ -z $expected_enabled ]] || s4_enabled_state "$S4_TIMER" "$expected_enabled"; }; then
            return 0
        fi
        if (( attempt + 1 < S4_POLL_COUNT )); then
            sleep "$(s4_seconds "$S4_POLL_INTERVAL_MS")" || return 1
        fi
    done
    return 1
}

s4_restore_timer() {
    # Never remove the durable marker here: the worker must verify all tasks
    # and finish the transaction before the boot recovery service can skip it.
    s4_systemctl enable "$S4_TIMER" || return 1
    s4_persist_timer_enablement || return 1
    s4_systemctl start "$S4_TIMER" || return 1
    s4_wait_timer_state active enabled
}

s4_stop_timer() {
    s4_persist_recovery_intent || return 1
    # Arm a persistent boot trigger before touching timer enablement. The
    # running worker also has Restart=on-failure, independent of the timer.
    if ! s4_systemctl enable "$S4_RESUME_SERVICE" ||
        ! s4_enabled_state "$S4_RESUME_SERVICE" enabled ||
        ! s4_persist_boot_guard; then
        return 1
    fi
    # Stop while still enabled. Disable only after a bounded state check.
    # Never disable --now: its enablement write precedes reload/stop failures.
    if s4_systemctl stop "$S4_TIMER" && s4_wait_timer_state inactive '' &&
        s4_systemctl disable "$S4_TIMER" && s4_wait_timer_state inactive disabled &&
        s4_persist_timer_enablement; then
        return 0
    fi
    s4_restore_timer || s4_log 'Timer restoration is pending; service and boot recovery remain armed.'
    return 1
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
    if ! s4_stop_timer; then
        s4_record_summary timer_stop_pending 0 || return 1
        s4_log 'Setup is verified; timer finalization remains pending.'
        return 75
    fi
    if ! { printf 'verified\n' | s4_atomic_write "$S4_STATE_DIR/setup.ready"; } ||
        ! s4_record_summary complete 0 ||
        ! s4_sync_filesystems "$S4_STATE_DIR" ||
        ! rm -f -- "$S4_STATE_DIR/timer-stop.pending" ||
        ! s4_sync_filesystems "$S4_STATE_DIR"; then
        # A failed final barrier may have persisted some writes. Recreate the
        # intent and restore a durable timer trigger; never assume rollback IO
        # succeeds. Marker removal starts only after durable completion, so an
        # uncertain cleanup cannot strand unfinished setup even if IO stays bad.
        if s4_persist_recovery_intent; then
            rm -f -- "$S4_STATE_DIR/setup.ready" || s4_log 'Cannot invalidate completion publication.'
            s4_record_summary timer_stop_pending 0 || s4_log 'Cannot record pending finalization.'
            s4_sync_filesystems "$S4_STATE_DIR" || s4_log 'Pending publication synchronization failed.'
        else
            s4_log 'Recovery intent synchronization failed; preserving prior completion publication.'
        fi
        s4_restore_timer || s4_log 'Timer restoration is pending; boot recovery remains armed.'
        return 1
    fi
    s4_log 'Every setup task is verified; the retry timer is inactive and disabled.' || true
    return 0
}

s4_recover() {
    local result=0
    exec {S4_LOCK_FD}> "$S4_STATE_DIR/repair.lock" || return 1
    if ! flock --nonblock "$S4_LOCK_FD"; then
        s4_log 'Another setup attempt is already running.'
        exec {S4_LOCK_FD}>&-
        S4_LOCK_FD=
        return 0
    fi
    # Retrying a failed cleanup must not erase durable completion until another
    # durable intent exists. A genuine prior completion already armed the guard.
    if [[ -e $S4_STATE_DIR/setup.ready || -L $S4_STATE_DIR/setup.ready ]] &&
        ! s4_persist_recovery_intent; then
        result=75
    elif ! rm -f -- "$S4_STATE_DIR/setup.ready"; then
        result=1
    elif ! s4_load_tasks; then
        result=78
        if ! s4_record_summary invalid_bundle 0; then
            result=1
        fi
    elif ! s4_arm_attempt_deadline; then
        s4_log 'No tasks were started: the complete attempt deadline could not be armed.'
        result=75
        s4_record_summary deadline_pending "${#S4_TASKS[@]}" || result=1
    elif s4_run_tasks; then
        result=0
    else
        result=$?
    fi
    exec {S4_LOCK_FD}>&-
    S4_LOCK_FD=
    return "$result"
}

s4_resume() {
    local result=0
    exec {S4_LOCK_FD}> "$S4_STATE_DIR/repair.lock" || return 1
    if flock --nonblock "$S4_LOCK_FD"; then
        if [[ -f $S4_STATE_DIR/timer-stop.pending ]] && ! s4_restore_timer; then
            result=75
        fi
    fi
    exec {S4_LOCK_FD}>&-
    S4_LOCK_FD=
    return "$result"
}

s4_bootstrap_gate() {
    if [[ -e $S4_STATE_DIR/bootstrap/pending || -L $S4_STATE_DIR/bootstrap/pending ]]; then
        s4_log 'Bootstrap publication is pending; no setup task was started.'
        return 75
    fi
}

s4_main() {
    local ID='' VERSION_ID='' resume=0
    if [[ $# == 1 && $1 == --help ]]; then
        printf '%s\n' 'Internal debian13s4 setup recovery worker.' \
            'The starting installer installs its task bundle and timer automatically.'
        return 0
    fi
    if [[ $# == 1 && $1 == --resume ]]; then
        resume=1
    elif (( $# )); then
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
    # Bootstrap publishes the protected worker first and flushes it before any
    # task changes. Refuse mixed generations until its durable transaction ends.
    # A nonzero exit keeps the manager's independent Restart retry armed.
    s4_bootstrap_gate || return $?
    s4_prepare_state || return 1
    if (( resume )); then
        s4_resume
    else
        s4_recover
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4_PHASE_PATH
    export PATH
    readonly PATH S4_LIBRARY_DIR S4_STATE_DIR S4_SYSTEMD_DIR S4_SERVICE S4_TIMER S4_RESUME_SERVICE \
        S4_PHASE_TIMEOUT_MS S4_KILL_DELAY_MS S4_CONTROL_TIMEOUT_MS S4_CONTROL_KILL_MS \
        S4_TASK_OVERHEAD_MS S4_ATTEMPT_OVERHEAD_MS S4_POLL_INTERVAL_MS \
        S4_POLL_COUNT S4_CONTROL_CALL_BUDGET S4_PHASE_PATH
    umask 077
    s4_main "$@"
fi
