#!/bin/bash -p
# Source for the self-contained root setup.sh, assembled by pack.py.

S4B_STATE_DIR=/var/lib/debian13s4
S4B_BOOT_DIR=/var/lib/debian13s4/bootstrap
S4B_LIBRARY_DIR=/usr/local/lib/debian13s4
S4B_SYSTEMD_DIR=/etc/systemd/system
S4B_UNIT=debian13s4-bootstrap.service
S4B_TIMER=debian13s4-repair.timer
S4B_SERVICE=debian13s4-repair.service
S4B_RESUME=debian13s4-resume.service
S4B_PATH=/usr/sbin:/usr/bin:/sbin:/bin
S4B_LOCK_FD=
S4B_REPAIR_FD=
S4B_STAGE=

s4b_log() {
    printf 'debian13s4: %s\n' "$*" >&2
}

s4b_trusted() {
    local path=$1 owner mode
    [[ $path == /* && $path != *'/../'* && $path != */.. &&
        $path != *'/./'* && $path != */. && $path != *'//'* ]] || return 1
    while :; do
        [[ -e $path && ! -L $path ]] || return 1
        read -r owner mode < <(stat --format='%u %a' -- "$path") || return 1
        [[ $owner == 0 ]] && (( (8#$mode & 8#022) == 0 )) || return 1
        [[ $path == / ]] && return 0
        path=${path%/*}
        [[ -n $path ]] || path=/
    done
}

s4b_install() {
    env -i PATH="$S4B_PATH" LANG=C LC_ALL=C install -o root -g root "$@"
}

s4b_directory() {
    local path=$1 mode=$2
    s4b_trusted "${path%/*}" || return 1
    if [[ -e $path || -L $path ]]; then
        [[ -d $path ]] && s4b_trusted "$path" || return 1
    fi
    s4b_install -d -m "$mode" -- "$path"
}

s4b_prepare() {
    s4b_trusted "$S4B_SYSTEMD_DIR" || return 1
    s4b_trusted "${S4B_LIBRARY_DIR%/*}" || return 1
    s4b_directory "$S4B_STATE_DIR" 0700 || return 1
    s4b_directory "$S4B_STATE_DIR/results" 0700 || return 1
    s4b_directory "$S4B_BOOT_DIR" 0700 || return 1
}

s4b_control() (
    [[ -z $S4B_LOCK_FD ]] || exec {S4B_LOCK_FD}>&-
    [[ -z $S4B_REPAIR_FD ]] || exec {S4B_REPAIR_FD}>&-
    timeout --signal=TERM --kill-after=1s 10s \
        env -i PATH="$S4B_PATH" LANG=C LC_ALL=C "$@"
)

s4b_systemctl() {
    s4b_control systemctl "$@"
}

s4b_sync() {
    s4b_control sync --file-system -- "$@"
}

s4b_atomic() {
    local target=$1 mode=$2 temporary
    s4b_trusted "${target%/*}" || return 1
    if [[ -e $target || -L $target ]]; then
        [[ -f $target ]] && s4b_trusted "$target" || return 1
    fi
    temporary=$(mktemp -- "${target}.XXXXXX") || return 1
    if ! cat > "$temporary" || ! chmod "$mode" -- "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    # Keep already committed code/intent inodes on ordinary retries. For a
    # replacement, persist its complete data before publishing the rename;
    # the caller then persists destination/parent metadata before proceeding.
    if [[ -f $target ]] && cmp --silent -- "$temporary" "$target"; then
        chmod "$mode" -- "$target" && rm -f -- "$temporary"
    elif ! s4b_sync "$temporary" || ! mv -fT -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
}

s4b_enabled() {
    local unit=$1 output
    output=$(s4b_systemctl is-enabled "$unit") || return 1
    [[ $output == enabled ]]
}

s4b_inactive() {
    local unit=$1 output
    output=$(s4b_systemctl show --property=ActiveState --value "$unit") || return 1
    [[ $output == inactive ]]
}

s4b_quiesce() {
    local unit=$1 loaded
    loaded=$(s4b_systemctl show --property=LoadState --value "$unit") || return 1
    if [[ $loaded == not-found ]]; then
        return 0
    fi
    [[ $loaded == loaded ]] || return 1
    s4b_systemctl stop "$unit" && s4b_inactive "$unit"
}

s4b_enablement_paths() {
    local unit=$1 wants=$S4B_SYSTEMD_DIR/$2.target.wants resolved
    s4b_trusted "$wants" && [[ -d $wants && -L $wants/$unit ]] || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$unit") || return 1
    [[ $resolved == "$S4B_SYSTEMD_DIR/$unit" ]] || return 1
    s4b_sync "$S4B_SYSTEMD_DIR" "$S4B_SYSTEMD_DIR/$unit" "$wants"
}

s4b_write_runner() {
    # Serialize already parsed functions, never reread a caller-writable script
    # after granting root. Only these explicit functions enter the boot runner.
    printf '#!/bin/bash -p\nset -Eeuo pipefail\numask 077\n' || return 1
    declare -p S4B_STATE_DIR S4B_BOOT_DIR S4B_LIBRARY_DIR S4B_SYSTEMD_DIR \
        S4B_UNIT S4B_TIMER S4B_SERVICE S4B_RESUME S4B_PATH S4B_BUNDLE_ID \
        S4B_FILES S4B_MODES || return 1
    printf 'S4B_LOCK_FD=\nS4B_REPAIR_FD=\nS4B_STAGE=\n' || return 1
    printf 'PATH=%q\nexport PATH\n' "$S4B_PATH" || return 1
    declare -f s4b_log s4b_trusted s4b_install s4b_directory s4b_prepare \
        s4b_control s4b_systemctl s4b_sync s4b_atomic s4b_enabled \
        s4b_inactive s4b_quiesce s4b_enablement_paths s4b_write_runner s4b_write_unit \
        s4b_arm s4b_validate_bundle s4b_publish s4b_finish s4b_cleanup \
        s4b_unlock s4b_main s4b_write_bundle || return 1
    cat <<'S4B_ENTRY'
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    s4b_main "$@"
fi
S4B_ENTRY
}

s4b_write_unit() {
    local seconds
    # At most 2N+28 bounded calls, including data-before-rename and readiness
    # invalidation, with two spare slots and margins. Nine files need 693 seconds.
    seconds=$(((2 * ${#S4B_FILES[@]} + 30) * 11 + ${#S4B_FILES[@]} * 5 + 120))
    cat <<EOF
[Unit]
Description=Complete interrupted Debian 13 setup bootstrap
After=local-fs.target
ConditionPathExists=$S4B_BOOT_DIR/pending
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/bin/bash -p -- $S4B_BOOT_DIR/setup.sh --resume
User=root
Group=root
UMask=0077
TimeoutStartSec=${seconds}s
TimeoutStopSec=30s
Restart=on-failure
RestartSec=5min
KillMode=control-group
StandardInput=null
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
}

s4b_arm() {
    local pending=$S4B_BOOT_DIR/pending runner unit
    runner=$(mktemp -- "$S4B_BOOT_DIR/runner.XXXXXX") || return 1
    if ! unit=$(mktemp -- "$S4B_BOOT_DIR/unit.XXXXXX"); then
        rm -f -- "$runner"
        return 1
    fi
    # Finish and syntax-check the complete producer output before publishing
    # either guard asset; a failed serializer must not replace working code.
    if ! s4b_write_runner > "$runner" || ! /bin/bash -p -n -- "$runner" ||
        ! s4b_write_unit > "$unit" ||
        ! s4b_atomic "$S4B_BOOT_DIR/setup.sh" 0700 < "$runner" ||
        ! s4b_atomic "$S4B_SYSTEMD_DIR/$S4B_UNIT" 0644 < "$unit"; then
        rm -f -- "$runner" "$unit"
        return 1
    fi
    rm -f -- "$runner" "$unit" || return 1
    if [[ -e $pending || -L $pending ]]; then
        [[ -f $pending ]] && s4b_trusted "$pending" || return 1
    else
        printf 'pending\n' | s4b_atomic "$pending" 0600 || return 1
    fi
    # Code, intent, unit and their parent metadata precede enablement. Each
    # path is flushed separately by filesystem, including a split /etc,/var.
    s4b_sync "${S4B_STATE_DIR%/*}" "$S4B_STATE_DIR" "$S4B_BOOT_DIR" \
        "$S4B_BOOT_DIR/setup.sh" "$pending" "$S4B_SYSTEMD_DIR" \
        "$S4B_SYSTEMD_DIR/$S4B_UNIT" || return 1
    s4b_systemctl daemon-reload || return 1
    s4b_systemctl enable "$S4B_UNIT" || return 1
    s4b_enabled "$S4B_UNIT" || return 1
    s4b_enablement_paths "$S4B_UNIT" multi-user || return 1
}

s4b_validate_bundle() {
    local relative
    (cd -- "$S4B_STAGE" && sha256sum --check --strict -- files.sha256) || return 1
    for relative in "${S4B_FILES[@]}"; do
        [[ -f $S4B_STAGE/$relative ]] && s4b_trusted "$S4B_STAGE/$relative" || return 1
        if [[ $relative == *.sh ]]; then
            /bin/bash --noprofile --norc -p -n -- "$S4B_STAGE/$relative" || return 1
        fi
    done
}

s4b_publish() {
    local relative=$1 target=$2 mode=$3 parent=${2%/*}
    s4b_directory "$parent" 0755 || return 1
    s4b_atomic "$target" "$mode" < "$S4B_STAGE/$relative" || return 1
    s4b_trusted "$target" && cmp --silent -- "$target" "$S4B_STAGE/$relative"
}

s4b_finish() {
    local relative target output index
    # This service owns bootstrap recovery before any admitted worker/task is
    # changed. The worker's lock serializes publication with running phases.
    s4b_arm || return 1
    for target in "$S4B_TIMER" "$S4B_SERVICE" "$S4B_RESUME"; do
        s4b_quiesce "$target" || return 1
    done
    exec {S4B_REPAIR_FD}> "$S4B_STATE_DIR/repair.lock" || return 1
    flock --nonblock "$S4B_REPAIR_FD" || return 1
    S4B_STAGE=$(mktemp -d -- "$S4B_BOOT_DIR/bundle.XXXXXX") || return 1
    s4b_write_bundle || return 1
    s4b_validate_bundle || return 1
    # The durable bootstrap guard now owns replacement recovery. Old completion
    # must not survive publication of a bundle whose new tasks are unverified.
    printf 'state=bootstrap_pending\n' | s4b_atomic "$S4B_STATE_DIR/status" 0600 || return 1
    rm -f -- "$S4B_STATE_DIR/setup.ready" || return 1
    s4b_sync "$S4B_STATE_DIR" "$S4B_STATE_DIR/status" || return 1
    s4b_directory "$S4B_LIBRARY_DIR" 0755 || return 1
    s4b_directory "$S4B_LIBRARY_DIR/tasks" 0755 || return 1
    # First persist the worker's pending-bootstrap gate. A reboot during the
    # remaining per-file publication can then execute no mixed-generation task.
    s4b_publish lib/repair.sh "$S4B_LIBRARY_DIR/repair.sh" 0755 || return 1
    s4b_sync "${S4B_LIBRARY_DIR%/*}" "$S4B_LIBRARY_DIR" \
        "$S4B_LIBRARY_DIR/repair.sh" || return 1
    for ((index = 0; index < ${#S4B_FILES[@]}; index++)); do
        relative=${S4B_FILES[$index]}
        [[ $relative == lib/repair.sh || $relative == lib/tasks.list ]] && continue
        if [[ $relative == lib/* ]]; then
            target=$S4B_LIBRARY_DIR/${relative#lib/}
        else
            target=$S4B_SYSTEMD_DIR/${relative#units/}
        fi
        s4b_publish "$relative" "$target" "${S4B_MODES[$index]}" || return 1
        # Parent and file scopes also cover separately mounted target files.
        s4b_sync "${target%/*}" "$target" || return 1
    done
    # Admission is the last published file, after all of its phases are durable.
    s4b_publish lib/tasks.list "$S4B_LIBRARY_DIR/tasks.list" 0644 || return 1
    s4b_sync "$S4B_LIBRARY_DIR" "$S4B_LIBRARY_DIR/tasks.list" || return 1
    s4b_systemctl daemon-reload || return 1
    s4b_systemctl enable "$S4B_TIMER" || return 1
    s4b_enabled "$S4B_TIMER" || return 1
    s4b_enablement_paths "$S4B_TIMER" timers || return 1
    exec {S4B_REPAIR_FD}>&-
    S4B_REPAIR_FD=
    # A worker triggered here exits pending before acquiring its lock or running
    # tasks. Restart=on-failure keeps it retrying after the bootstrap gate clears.
    s4b_systemctl start "$S4B_TIMER" || return 1
    output=$(s4b_systemctl show --property=ActiveState --value "$S4B_TIMER") || return 1
    [[ $output == active ]] || return 1
    printf '%s\n' "$S4B_BUNDLE_ID" | s4b_atomic "$S4B_BOOT_DIR/installed" 0600 || return 1
    s4b_sync "$S4B_BOOT_DIR" || return 1
    rm -f -- "$S4B_BOOT_DIR/pending" || return 1
    s4b_sync "$S4B_BOOT_DIR" || return 1
    s4b_log 'Bootstrap verified; package prerequisites will be installed and verified automatically.' || true
}

s4b_cleanup() {
    if [[ -n $S4B_STAGE && $S4B_STAGE == "$S4B_BOOT_DIR"/bundle.* &&
        -d $S4B_STAGE && ! -L $S4B_STAGE ]]; then
        rm -rf -- "$S4B_STAGE"
    fi
}

s4b_unlock() {
    if [[ -n $S4B_REPAIR_FD ]]; then
        exec {S4B_REPAIR_FD}>&-
        S4B_REPAIR_FD=
    fi
    if [[ -n $S4B_LOCK_FD ]]; then
        exec {S4B_LOCK_FD}>&-
        S4B_LOCK_FD=
    fi
}

s4b_main() {
    local ID='' VERSION_ID='' command release result=0 resume=0
    if [[ $# == 1 && $1 == --help ]]; then
        printf '%s\n' 'Debian 13 unattended setup (package/bootstrap checkpoint).' \
            'Run this self-contained script as root; no configuration arguments are needed.' \
            'Full server hardening, web hosting and runtime setup are still under development.'
        return 0
    elif [[ $# == 1 && $1 == --resume ]]; then
        resume=1
    elif (( $# )); then
        s4b_log 'No configuration arguments are supported.'
        return 64
    fi
    (( EUID == 0 )) || { s4b_log 'Run the starting script with root permission.'; return 77; }
    s4b_trusted /etc || return 1
    release=$(readlink --canonicalize-existing -- /etc/os-release) || return 1
    s4b_trusted "$release" || return 1
    # shellcheck source=/dev/null
    . "$release"
    [[ $ID == debian && $VERSION_ID == 13 && -d /run/systemd/system ]] || return 78
    for command in install stat mktemp cat chmod mv rm timeout env flock \
        sync systemctl readlink sha256sum cmp mkdir dpkg apt-get dpkg-query; do
        command -v "$command" > /dev/null || return 69
    done
    s4b_prepare || return 1
    exec {S4B_LOCK_FD}> "$S4B_BOOT_DIR/lock" || return 1
    if ! flock --nonblock "$S4B_LOCK_FD"; then
        s4b_unlock
        # Managed retries must remain failed/pending while another attempt owns
        # the lock, rather than silently consuming the only queued boot attempt.
        return 75
    fi
    trap s4b_cleanup EXIT
    if (( resume )); then
        s4b_finish || result=75
        s4b_unlock
        return "$result"
    fi
    if ! s4b_arm; then
        s4b_unlock
        s4b_log 'Bootstrap recovery could not be durably armed; no package/task installation began.'
        return 75
    fi
    s4b_unlock
    # The persistent manager-owned service performs publication. Enqueueing is
    # not reported as completed installation. Failed attempts restart themselves
    # and the enabled conditional unit resumes pending work on subsequent boots.
    s4b_systemctl start --no-block "$S4B_UNIT" || return 75
    s4b_log 'Durable bootstrap recovery is armed; automatic setup is queued.'
    s4b_log 'This development checkpoint does not yet implement the complete hardened server.'
}

S4B_BUNDLE_ID=64f467998a85e8cbf0de17cf459a90f78ad7f3c926a59a6f2bff21c6d79090a4
S4B_FILES=(lib/repair.sh lib/tasks.list lib/tasks/prerequisites/apply.sh lib/tasks/prerequisites/verify.sh lib/tasks/prerequisites/common.sh lib/tasks/prerequisites/debian.sources units/debian13s4-repair.service units/debian13s4-repair.timer units/debian13s4-resume.service)
S4B_MODES=(0755 0644 0644 0644 0644 0644 0644 0644 0644)

s4b_write_bundle() {
    local relative
    for relative in "${S4B_FILES[@]}"; do
        mkdir -p -- "$S4B_STAGE/${relative%/*}" || return 1
    done
    cat > "$S4B_STAGE/lib/repair.sh" <<'S4_PAYLOAD_5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936' || return 1
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
S4_PAYLOAD_5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936
    cat > "$S4B_STAGE/lib/tasks.list" <<'S4_PAYLOAD_809e89587bfbaf6eeb1193fdbc4b73e664110810dbc9c5172108ddafeb6ce630' || return 1
prerequisites:
S4_PAYLOAD_809e89587bfbaf6eeb1193fdbc4b73e664110810dbc9c5172108ddafeb6ce630
    cat > "$S4B_STAGE/lib/tasks/prerequisites/apply.sh" <<'S4_PAYLOAD_f00b984fac21636c60e8a4dd9d1ade6cdf58bcd0123d669e7fba51c756346934' || return 1
#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Tasks/prerequisites/common.sh
. /usr/local/lib/debian13s4/tasks/prerequisites/common.sh

# Reuse a protected dedicated index directory even after forced termination.
# APT's list lock and a successful authenticated refresh gate installation;
# _apt can traverse the path and retains its normal download sandbox.
s4p_prepare
export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
s4p_apply
S4_PAYLOAD_f00b984fac21636c60e8a4dd9d1ade6cdf58bcd0123d669e7fba51c756346934
    cat > "$S4B_STAGE/lib/tasks/prerequisites/verify.sh" <<'S4_PAYLOAD_5c2bb90b18725176df85061f2fd7556fc5f00c286991f7ff34445d7b880693fc' || return 1
#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Tasks/prerequisites/common.sh
. /usr/local/lib/debian13s4/tasks/prerequisites/common.sh
s4p_verify
S4_PAYLOAD_5c2bb90b18725176df85061f2fd7556fc5f00c286991f7ff34445d7b880693fc
    cat > "$S4B_STAGE/lib/tasks/prerequisites/common.sh" <<'S4_PAYLOAD_f99079435a5917ee3a1a69aa9f18e32e4a98ddcd787007336997b5a4fbc2eab9' || return 1
#!/bin/bash

S4P_PACKAGES=(ca-certificates debian-archive-keyring curl gpgv nftables
    apparmor apparmor-utils unattended-upgrades needrestart)
S4P_TASK_DIR=/usr/local/lib/debian13s4/tasks/prerequisites
S4P_APT_DIR=/var/lib/apt/debian13s4

s4p_prepare() {
    local path ancestor owner mode
    for path in /var/lib/apt "$S4P_APT_DIR" "$S4P_APT_DIR/lists"; do
        ancestor=${path%/*}
        while :; do
            [[ -d $ancestor && ! -L $ancestor ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- "$ancestor") || return 1
            [[ $owner == 0 ]] && (( (8#$mode & 8#022) == 0 )) || return 1
            [[ $ancestor == / ]] && break
            ancestor=${ancestor%/*}
            [[ -n $ancestor ]] || ancestor=/
        done
        if [[ -e $path || -L $path ]]; then
            [[ -d $path && ! -L $path ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- "$path") || return 1
            [[ $owner == 0 ]] && (( (8#$mode & 8#022) == 0 )) || return 1
        fi
        install -d -o root -g root -m 0755 -- "$path" || return 1
    done
}

s4p_apt() {
    apt-get \
        -o "Dir::Etc::sourcelist=$S4P_TASK_DIR/debian.sources" \
        -o Dir::Etc::sourceparts=- \
        -o "Dir::State::lists=$S4P_APT_DIR/lists" \
        -o APT::Update::Error-Mode=any \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
        -o Acquire::Check-Date=true \
        -o Acquire::Check-Valid-Until=true \
        -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowDowngradeToInsecureRepositories=false \
        -o APT::Get::AllowUnauthenticated=false \
        -o APT::Get::allow-downgrades=false \
        -o APT::Get::allow-change-held-packages=false \
        -o APT::Get::allow-remove-essential=false \
        -o DPkg::Lock::Timeout=60 \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        --assume-yes --no-remove --no-install-recommends "$@"
}

s4p_dpkg() {
    dpkg "$@"
}

s4p_query() {
    dpkg-query --show --showformat='${Status}\n' -- "$1"
}

s4p_verify() {
    local package status audit
    for package in "${S4P_PACKAGES[@]}"; do
        status=$(s4p_query "$package") || return 1
        [[ $status == 'install ok installed' ]] || return 1
    done
    audit=$(s4p_dpkg --audit) || return 1
    [[ -z $audit ]]
}

s4p_apply() {
    # A partial index refresh must never be mistaken for a usable online run.
    # Authentication and normal dpkg/APT locks remain enabled on every retry.
    s4p_apt update || return 1
    if ! s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4p_apt --fix-broken install || return 1
        s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    s4p_apt install "${S4P_PACKAGES[@]}"
}
S4_PAYLOAD_f99079435a5917ee3a1a69aa9f18e32e4a98ddcd787007336997b5a4fbc2eab9
    cat > "$S4B_STAGE/lib/tasks/prerequisites/debian.sources" <<'S4_PAYLOAD_7d995cf7bc3d3db5461c7c21a4989495a042e0a5fc34a186cc68bc859c62b0c4' || return 1
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
S4_PAYLOAD_7d995cf7bc3d3db5461c7c21a4989495a042e0a5fc34a186cc68bc859c62b0c4
    cat > "$S4B_STAGE/units/debian13s4-repair.service" <<'S4_PAYLOAD_e21ba280c03e5c9848930e7a58b87febd59332e777a3a992e3bab1f992c1a3e5' || return 1
[Unit]
Description=Finish and verify pending Debian 13 server setup
After=network.target
ConditionPathExists=/usr/local/lib/debian13s4/tasks.list

[Service]
Type=notify
NotifyAccess=all
ExecStart=/usr/local/lib/debian13s4/repair.sh
User=root
Group=root
UMask=0077
# Admission is bounded; the worker derives and acknowledges a finite runtime
# extension for all phases of the admitted bundle before executing any task.
TimeoutStartSec=1min
RuntimeMaxSec=1min
TimeoutStopSec=2min
Restart=on-failure
RestartSec=5min
KillMode=control-group
StandardInput=null
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
S4_PAYLOAD_e21ba280c03e5c9848930e7a58b87febd59332e777a3a992e3bab1f992c1a3e5
    cat > "$S4B_STAGE/units/debian13s4-repair.timer" <<'S4_PAYLOAD_8618edcc26838d9f7f56c39d538bcfdba099e101582e8fb0adb38df413c5ce28' || return 1
[Unit]
Description=Retry unfinished Debian 13 server setup

[Timer]
OnBootSec=1min
OnUnitInactiveSec=5min
RandomizedDelaySec=30s
AccuracySec=1s
Unit=debian13s4-repair.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_8618edcc26838d9f7f56c39d538bcfdba099e101582e8fb0adb38df413c5ce28
    cat > "$S4B_STAGE/units/debian13s4-resume.service" <<'S4_PAYLOAD_a107d7016113884baa5f42ef8c5523410d1193f9970c3d320647dc0ee3d3a5f9' || return 1
[Unit]
Description=Restore setup retries after interrupted timer finalization
After=local-fs.target
ConditionPathExists=/var/lib/debian13s4/timer-stop.pending

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/repair.sh --resume
User=root
Group=root
UMask=0077
TimeoutStartSec=2min
TimeoutStopSec=2min
Restart=on-failure
RestartSec=5min
KillMode=control-group
StandardInput=null
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
S4_PAYLOAD_a107d7016113884baa5f42ef8c5523410d1193f9970c3d320647dc0ee3d3a5f9
    cat > "$S4B_STAGE/files.sha256" <<'S4_CHECKSUMS' || return 1
5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936  lib/repair.sh
809e89587bfbaf6eeb1193fdbc4b73e664110810dbc9c5172108ddafeb6ce630  lib/tasks.list
f00b984fac21636c60e8a4dd9d1ade6cdf58bcd0123d669e7fba51c756346934  lib/tasks/prerequisites/apply.sh
5c2bb90b18725176df85061f2fd7556fc5f00c286991f7ff34445d7b880693fc  lib/tasks/prerequisites/verify.sh
f99079435a5917ee3a1a69aa9f18e32e4a98ddcd787007336997b5a4fbc2eab9  lib/tasks/prerequisites/common.sh
7d995cf7bc3d3db5461c7c21a4989495a042e0a5fc34a186cc68bc859c62b0c4  lib/tasks/prerequisites/debian.sources
e21ba280c03e5c9848930e7a58b87febd59332e777a3a992e3bab1f992c1a3e5  units/debian13s4-repair.service
8618edcc26838d9f7f56c39d538bcfdba099e101582e8fb0adb38df413c5ce28  units/debian13s4-repair.timer
a107d7016113884baa5f42ef8c5523410d1193f9970c3d320647dc0ee3d3a5f9  units/debian13s4-resume.service
S4_CHECKSUMS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4B_PATH
    export PATH
    umask 077
    s4b_main "$@"
fi
