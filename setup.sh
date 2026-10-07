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
S4B_QUIESCE=("$S4B_TIMER" "$S4B_SERVICE" "$S4B_RESUME"
    debian13s4-maintenance.timer debian13s4-maintenance.service
    debian13s4-dotnet.timer debian13s4-dotnet.service)
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

s4b_open_lock() {
    local path=$1 variable=$2 descriptor descriptor_path previous_umask
    local path_identity descriptor_identity owner mode identity result=1
    [[ $variable == S4B_LOCK_FD || $variable == S4B_REPAIR_FD ]] || return 1
    [[ -z ${!variable} && -d ${path%/*} ]] && s4b_trusted "${path%/*}" || return 1
    # The prepared private parent excludes unprivileged replacement races, but
    # an existing malformed leaf must be refused before any open can follow it
    # or block on it. Never repair, remove or truncate a refused lock leaf.
    if [[ -e $path || -L $path ]]; then
        [[ ! -L $path && -f $path ]] && s4b_trusted "$path" || return 1
    fi
    previous_umask=$(umask) || return 1
    umask 077
    if ! exec {descriptor}>> "$path"; then
        umask "$previous_umask"
        return 1
    fi
    umask "$previous_umask"
    descriptor_path=/proc/$BASHPID/fd/$descriptor
    # Revalidate the pathname after the nontruncating open. Matching owner,
    # mode and device/inode transfer its root/permission trust to the actual
    # regular descriptor; descriptor inspection deliberately follows procfs.
    if [[ -f $descriptor_path && ! -L $path && -f $path ]] &&
        s4b_trusted "$path" &&
        path_identity=$(stat --format='%u %a %d:%i' -- "$path") &&
        descriptor_identity=$(stat --dereference --format='%u %a %d:%i' -- "$descriptor_path") &&
        [[ -n $path_identity && $path_identity == "$descriptor_identity" ]] &&
        read -r owner mode identity <<< "$descriptor_identity" &&
        [[ $owner == "$EUID" && $mode =~ ^[0-7]{3,4}$ && $identity =~ ^[0-9]+:[0-9]+$ ]] &&
        (( (8#$mode & 8#022) == 0 )); then
        if flock --nonblock "$descriptor"; then
            if printf -v "$variable" '%s' "$descriptor"; then
                return 0
            fi
        else
            result=75
        fi
    fi
    exec {descriptor}>&-
    return "$result"
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
        S4B_UNIT S4B_TIMER S4B_SERVICE S4B_RESUME S4B_QUIESCE S4B_PATH S4B_BUNDLE_ID \
        S4B_FILES S4B_MODES || return 1
    printf 'S4B_LOCK_FD=\nS4B_REPAIR_FD=\nS4B_STAGE=\n' || return 1
    printf 'PATH=%q\nexport PATH\n' "$S4B_PATH" || return 1
    declare -f s4b_log s4b_trusted s4b_install s4b_directory s4b_prepare s4b_open_lock \
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
    # At most 2N+19+3Q controls: each of Q old units may need load/stop/state.
    # Add two spare slots, data-before-rename and ordinary local-file margins.
    seconds=$(((2 * ${#S4B_FILES[@]} + 21 + 3 * ${#S4B_QUIESCE[@]}) * 11 + ${#S4B_FILES[@]} * 5 + 120))
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
    for target in "${S4B_QUIESCE[@]}"; do
        s4b_quiesce "$target" || return 1
    done
    s4b_open_lock "$S4B_STATE_DIR/repair.lock" S4B_REPAIR_FD || return 1
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
    # Contention returns 75: a managed attempt must remain pending rather than
    # silently consume the only queued boot attempt while another owns it.
    s4b_open_lock "$S4B_BOOT_DIR/lock" S4B_LOCK_FD || return $?
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

S4B_BUNDLE_ID=79f4df3c723594a12a95be1492de6763e606af59adea0bc6fc895367b8a7adea
S4B_FILES=(lib/repair.sh lib/tasks.list lib/tasks/prerequisites/apply.sh lib/tasks/prerequisites/verify.sh lib/tasks/prerequisites/common.sh lib/tasks/prerequisites/debian.sources units/debian13s4-repair.service units/debian13s4-repair.timer units/debian13s4-resume.service lib/maintenance/common.sh lib/maintenance/update.sh lib/maintenance/policy.conf lib/maintenance/needrestart.conf lib/maintenance/restart-policy.pl lib/maintenance/debian13s4-maintenance.service lib/maintenance/debian13s4-maintenance.timer lib/tasks/maintenance/apply.sh lib/tasks/maintenance/verify.sh lib/dotnet/common.sh lib/dotnet/update.sh lib/dotnet/verify-payload.pl lib/dotnet/policy.conf lib/dotnet/preferences lib/dotnet/microsoft-2025.asc lib/dotnet/debian13s4-dotnet.service lib/dotnet/debian13s4-dotnet.timer lib/dotnet/sources.sources lib/tasks/dotnet/apply.sh lib/tasks/dotnet/verify.sh)
S4B_MODES=(0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644)

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
    cat > "$S4B_STAGE/lib/tasks.list" <<'S4_PAYLOAD_0066b18a0c987272b59c97d9a45b23d8c8ef7ff9f3a0c565e4e5ce9ed5be9b13' || return 1
prerequisites:
maintenance:prerequisites
dotnet:prerequisites
S4_PAYLOAD_0066b18a0c987272b59c97d9a45b23d8c8ef7ff9f3a0c565e4e5ce9ed5be9b13
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
    cat > "$S4B_STAGE/lib/maintenance/common.sh" <<'S4_PAYLOAD_81662b812509fcf97d5207c42dd41c0085b76dfeeadcaff9598d3bea03a025f0' || return 1
#!/bin/bash

S4M_LIBRARY=/usr/local/lib/debian13s4/maintenance
S4M_UPDATE_POLICY=
S4M_UPDATE_READY=s4m_ready
S4M_UPDATE_PREPARE=s4p_prepare
S4M_UPDATE_UPGRADE=s4m_debian_upgrade
S4M_UPDATE_VERIFY=s4m_debian_verify
S4M_STATE=/var/lib/debian13s4
S4M_SYSTEMD=/etc/systemd/system
S4M_TIMER=debian13s4-maintenance.timer
S4M_SERVICE=debian13s4-maintenance.service
S4M_PATH=/usr/sbin:/usr/bin:/sbin:/bin
S4M_REPAIR_FD=
S4M_REBOOT_MARKER=/run/reboot-required
S4M_BOOT_FILE=/proc/sys/kernel/random/boot_id
# Match the shipped one-hour oneshot. Restart slices leave 2100 seconds for
# package work and 300 seconds for final controls; they never grow with a queue.
S4M_ATTEMPT_SECONDS=3600
S4M_PRE_RESTART_SECONDS=600
S4M_POST_RESTART_SECONDS=600
S4M_FINAL_RESERVE_SECONDS=300
S4M_CONTROL_SECONDS=10
S4M_CONTROL_GRACE_SECONDS=1
S4M_RESTART_SECONDS=300
S4M_RESTART_GRACE_SECONDS=10
# Two intent syncs, three initial properties, hook selection, four final
# properties and two completion syncs: at most twelve bounded control calls.
# Include 30 seconds for local work, scheduling and uptime-second rounding.
S4M_RESTART_BOUND_SECONDS=$((S4M_RESTART_SECONDS + S4M_RESTART_GRACE_SECONDS + \
    12 * (S4M_CONTROL_SECONDS + S4M_CONTROL_GRACE_SECONDS) + 30))
# Ordinary intents retain their original needrestart policy and hook names.
S4M_RESTARTS=()

s4m_load_packages() {
    s4m_trusted /usr/local/lib/debian13s4/tasks/prerequisites/common.sh || return 1
    # shellcheck source=Tasks/prerequisites/common.sh
    . /usr/local/lib/debian13s4/tasks/prerequisites/common.sh
}

s4m_trusted() {
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

s4m_control() (
    local descriptor=$S4M_REPAIR_FD
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after="${S4M_CONTROL_GRACE_SECONDS}s" "${S4M_CONTROL_SECONDS}s" \
        env -i PATH="$S4M_PATH" LANG=C LC_ALL=C "$@"
)

s4m_package() (
    # Maintainer scripts may start long-lived processes: none may retain the
    # installer's shared lock after this controller releases it.
    local descriptor=$S4M_REPAIR_FD
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    "$@"
)

s4m_lock() {
    local path=$S4M_STATE/repair.lock descriptor descriptor_path before after owner mode identity previous_umask
    [[ -z $S4M_REPAIR_FD && -d $S4M_STATE ]] && s4m_trusted "$S4M_STATE" || return 1
    if [[ -e $path || -L $path ]]; then
        [[ ! -L $path && -f $path ]] && s4m_trusted "$path" || return 1
    fi
    previous_umask=$(umask) || return 1
    umask 077
    if ! exec {descriptor}>> "$path"; then
        umask "$previous_umask"
        return 1
    fi
    umask "$previous_umask"
    descriptor_path=/proc/$BASHPID/fd/$descriptor
    if [[ -f $descriptor_path && ! -L $path && -f $path ]] &&
        s4m_trusted "$path" &&
        before=$(stat --format='%u %a %d:%i' -- "$path") &&
        after=$(stat --dereference --format='%u %a %d:%i' -- "$descriptor_path") &&
        [[ -n $before && $before == "$after" ]] &&
        read -r owner mode identity <<< "$after" &&
        [[ $owner == "$EUID" && $mode =~ ^[0-7]{3,4}$ && $identity =~ ^[0-9]+:[0-9]+$ ]] &&
        (( (8#$mode & 8#022) == 0 )) && flock --nonblock "$descriptor"; then
        S4M_REPAIR_FD=$descriptor
        return 0
    fi
    exec {descriptor}>&-
    return 1
}

s4m_unlock() {
    [[ -z $S4M_REPAIR_FD ]] || exec {S4M_REPAIR_FD}>&-
    S4M_REPAIR_FD=
}

s4m_systemctl() {
    s4m_control systemctl "$@"
}

s4m_sync() {
    s4m_control sync --file-system -- "$@"
}

s4m_atomic() {
    local target=$1 source=$2 mode=${3:-0644} temporary
    s4m_trusted "${target%/*}" && s4m_trusted "$source" && [[ -f $source ]] || return 1
    if [[ -e $target || -L $target ]]; then
        [[ -f $target ]] && s4m_trusted "$target" || return 1
    fi
    temporary=$(mktemp -- "${target}.XXXXXX") || return 1
    if ! cat -- "$source" > "$temporary" || ! chmod "$mode" -- "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if [[ -f $target ]] && cmp --silent -- "$source" "$target"; then
        rm -f -- "$temporary" || return 1
    elif ! s4m_sync "$temporary" || ! mv -fT -- "$temporary" "$target"; then
        rm -f -- "$temporary"
        return 1
    fi
    s4m_sync "${target%/*}" "$target"
}

s4m_property() {
    local unit=$1 property=$2 expected=$3 output
    output=$(s4m_systemctl show --property="$property" --value "$unit") || return 1
    [[ $output == "$expected" ]]
}

s4m_enabled() {
    local output
    output=$(s4m_systemctl is-enabled "$1") || return 1
    [[ $output == enabled ]]
}

s4m_verify_files() {
    local name
    s4m_trusted "$S4M_STATE" && [[ -d $S4M_STATE ]] || return 1
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl \
        debian13s4-maintenance.service debian13s4-maintenance.timer; do
        [[ -f $S4M_LIBRARY/$name ]] && s4m_trusted "$S4M_LIBRARY/$name" || return 1
    done
    [[ -x $S4M_LIBRARY/update.sh ]] || return 1
    for name in "$S4M_SERVICE" "$S4M_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4M_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4M_TIMER" && s4m_property "$S4M_TIMER" ActiveState active
}

s4m_identity() {
    local name digest
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl \
        debian13s4-maintenance.service debian13s4-maintenance.timer; do
        digest=$(sha256sum -- "$S4M_LIBRARY/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
}

s4m_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/maintenance.ready ]] && s4m_trusted "$S4M_STATE/maintenance.ready" || return 1
    s4m_verify_files || return 1
    expected=$(s4m_identity) && actual=$(cat -- "$S4M_STATE/maintenance.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4m_kernel_package() {
    local architecture release
    architecture=$(dpkg --print-architecture) && release=$(uname -r) || return 1
    case $architecture:$release in
        amd64:*-cloud-amd64) printf 'linux-image-cloud-amd64\n' ;;
        amd64:*-rt-amd64) printf 'linux-image-rt-amd64\n' ;;
        amd64:*) printf 'linux-image-amd64\n' ;;
        arm64:*-cloud-arm64) printf 'linux-image-cloud-arm64\n' ;;
        arm64:*) printf 'linux-image-arm64\n' ;;
        *) printf 'debian13s4: unattended kernel selection supports amd64/arm64 at this checkpoint.\n' >&2; return 78 ;;
    esac
}

s4m_packages() {
    local kernel
    kernel=$(s4m_kernel_package) || return 1
    S4P_PACKAGES=(unattended-upgrades needrestart "$kernel")
}

s4m_apply() {
    local unit loaded temporary wants resolved
    s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    for unit in "$S4M_TIMER" "$S4M_SERVICE"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/maintenance.ready || -L $S4M_STATE/maintenance.ready ]]; then
        [[ -f $S4M_STATE/maintenance.ready ]] && s4m_trusted "$S4M_STATE/maintenance.ready" || return 1
        rm -f -- "$S4M_STATE/maintenance.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for unit in "$S4M_TIMER" "$S4M_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    s4p_prepare && s4m_packages && s4p_apply && s4p_verify || return 1
    # The packaged kernel hook marks /run/reboot-required for the controller.
    [[ -x /etc/kernel/postinst.d/unattended-upgrades ]] &&
        s4m_trusted /etc/kernel/postinst.d/unattended-upgrades || return 1
    for unit in "$S4M_SERVICE" "$S4M_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4M_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable "$S4M_TIMER" && s4m_enabled "$S4M_TIMER" || return 1
    wants=$S4M_SYSTEMD/timers.target.wants
    [[ -d $wants && -L $wants/$S4M_TIMER ]] && s4m_trusted "$wants" || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4M_TIMER") || return 1
    [[ $resolved == "$S4M_SYSTEMD/$S4M_TIMER" ]] || return 1
    s4m_sync "$S4M_SYSTEMD" "$wants" "$S4M_SYSTEMD/$S4M_TIMER" "$S4M_SYSTEMD/$S4M_SERVICE" || return 1
    s4m_systemctl start "$S4M_TIMER" && s4m_verify_files || return 1
    temporary=$(mktemp -- "$S4M_STATE/maintenance-intent.XXXXXX") || return 1
    if ! s4m_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/maintenance.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4m_ready
}

s4m_verify() {
    s4m_packages && s4p_verify && s4m_ready
}

s4m_boot_id() {
    local identity
    [[ -f $S4M_BOOT_FILE ]] && s4m_trusted "$S4M_BOOT_FILE" || return 1
    identity=$(cat -- "$S4M_BOOT_FILE") || return 1
    [[ $identity =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || return 1
    printf '%s\n' "$identity"
}

s4m_save_restarts() {
    local temporary
    temporary=$(mktemp -- "$S4M_STATE/restart-intent.XXXXXX") || return 1
    if ! { [[ ${#S4M_RESTARTS[@]} == 0 ]] || printf '%s\n' "${S4M_RESTARTS[@]}"; } > "$temporary" ||
        ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/maintenance.restarts" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

s4m_select_restarts() {
    s4m_trusted /etc/needrestart/needrestart.conf &&
        s4m_trusted "$S4M_LIBRARY/needrestart.conf" &&
        s4m_trusted "$S4M_LIBRARY/restart-policy.pl" || return 1
    s4m_control perl "$S4M_LIBRARY/restart-policy.pl" "$S4M_LIBRARY/needrestart.conf"
}

s4m_now() {
    local uptime idle
    [[ -f /proc/uptime && ! -L /proc/uptime ]] || return 1
    read -r uptime idle < /proc/uptime || return 1
    [[ $uptime =~ ^[0-9]{1,15}[.][0-9]+$ && $idle =~ ^[0-9]+[.][0-9]+$ ]] || return 1
    uptime=${uptime%.*}
    printf '%s\n' "$((10#$uptime))"
}

s4m_unit_name() {
    local name=$1
    [[ $name =~ ^[A-Za-z0-9_.@][A-Za-z0-9_.@:\\-]*$ && ${#name} -le 255 &&
        $name != @reboot && $name != @reboot:* ]] || return 1
    [[ $name == *.service ]] || name+=.service
    (( ${#name} <= 255 )) || return 1
    printf '%s\n' "$name"
}

s4m_load_restarts() {
    local path=$S4M_STATE/maintenance.restarts target boot plan selected
    local -a names=() retained=()
    S4M_RESTARTS=()
    [[ -e $path || -L $path ]] || return 0
    [[ -f $path ]] && s4m_trusted "$path" || return 1
    mapfile -t S4M_RESTARTS < "$path" || return 1
    for target in "${S4M_RESTARTS[@]}"; do
        if [[ $target == @reboot:* ]]; then
            boot=$(s4m_boot_id) || return 1
            [[ ${target#@reboot:} =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$ ]] || return 1
            [[ $target != "@reboot:$boot" ]] || retained+=("$target")
        else
            s4m_unit_name "$target" > /dev/null || return 1
            names+=("$target")
        fi
    done
    plan=$(for target in "${names[@]}"; do printf 'NEEDRESTART-SVC: %s\n' "$target"; done) || return 1
    selected=$(s4m_select_restarts <<< "$plan") || return 1
    while IFS= read -r target; do
        [[ -n $target ]] || continue
        if [[ $target == @reboot ]]; then
            boot=$(s4m_boot_id) || return 1
            target=@reboot:$boot
        fi
        [[ " ${retained[*]} " == *" $target "* ]] || retained+=("$target")
    done <<< "$selected"
    S4M_RESTARTS=("${retained[@]}")
    # Persist exclusion/boot reconciliation even for an empty journal. Keeping
    # an empty regular file avoids an uncertain delete/recreation transaction.
    s4m_save_restarts
}

s4m_discover_restarts() {
    local output selected target boot
    output=$(NEEDRESTART_MODE=l s4m_package needrestart -c "$S4M_LIBRARY/needrestart.conf" -b -r l -l) || return 1
    selected=$(s4m_select_restarts <<< "$output") || return 1
    while IFS= read -r target; do
        [[ -n $target ]] || continue
        if [[ $target == @reboot ]]; then
            boot=$(s4m_boot_id) || return 1
            target=@reboot:$boot
        fi
        [[ " ${S4M_RESTARTS[*]} " == *" $target "* ]] || S4M_RESTARTS+=("$target")
    done <<< "$selected"
    # No stop/restart may occur before every admitted intent is durable.
    s4m_save_restarts
}

s4m_restart_command() (
    local descriptor=$S4M_REPAIR_FD hook target
    local -a command
    trap - EXIT
    target=$(s4m_unit_name "$1") || return 1
    hook=$(s4m_control perl "$S4M_LIBRARY/restart-policy.pl" "$S4M_LIBRARY/needrestart.conf" "$1") || return 1
    if [[ -n $hook ]]; then
        [[ -f $hook && -x $hook ]] && s4m_trusted "$hook" || return 1
        command=("$hook")
    else
        command=(systemctl restart -- "$target")
    fi
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after="${S4M_RESTART_GRACE_SECONDS}s" "${S4M_RESTART_SECONDS}s" \
        env -i PATH="$S4M_PATH" LANG=C LC_ALL=C "${command[@]}"
)

s4m_restart_unit() {
    local name=$1 target property value active type
    target=$(s4m_unit_name "$name") || return 1
    s4m_property "$target" LoadState loaded || return 1
    for property in RefuseManualStop RefuseManualStart; do
        value=$(s4m_systemctl show --property="$property" --value "$target") || return 1
        if [[ $value == yes ]]; then
            printf 'debian13s4: restart deliberately refused by %s: %s\n' "$property" "$target" >&2
            return 2
        fi
        [[ $value == no ]] || return 1
    done
    s4m_restart_command "$name" || return 1
    s4m_property "$target" Result success || return 1
    active=$(s4m_systemctl show --property=ActiveState --value "$target") || return 1
    [[ $active != active ]] || return 0
    type=$(s4m_systemctl show --property=Type --value "$target") || return 1
    [[ $active == inactive && $type == oneshot ]] &&
        s4m_property "$target" RemainAfterExit no
}

s4m_run_restarts() {
    local deadline=$1 target entry result now failed=0 deferred=0
    local -a admitted=("${S4M_RESTARTS[@]}") kept=()
    [[ $deadline =~ ^[0-9]{1,15}$ ]] || return 1
    deadline=$((10#$deadline))
    for target in "${admitted[@]}"; do
        [[ $target != @reboot:* ]] || continue
        now=$(s4m_now) || return 1
        if (( now + S4M_RESTART_BOUND_SECONDS > deadline )); then
            # The next intent remains untouched. Its full bounded operation
            # must fit without spending the downstream package/reboot reserve.
            deferred=1
            break
        fi
        kept=()
        for entry in "${S4M_RESTARTS[@]}"; do
            [[ $entry == "$target" ]] || kept+=("$entry")
        done
        # Rotate before the bounded attempt. A killed or perpetually failing
        # prefix cannot monopolize the next attempt's journal traversal.
        S4M_RESTARTS=("${kept[@]}" "$target")
        s4m_save_restarts || return 1
        if s4m_restart_unit "$target"; then result=0; else result=$?; fi
        if (( result == 0 || result == 2 )); then
            S4M_RESTARTS=("${kept[@]}")
            s4m_save_restarts || return 1
        else
            printf 'debian13s4: service restart remains pending: %s\n' "$target" >&2
            failed=1
        fi
    done
    (( failed == 0 )) || return 1
    (( deferred == 0 )) || return 75
    return 0
}

s4m_request_reboot() {
    local audit target needed=0
    for target in "${S4M_RESTARTS[@]}"; do
        [[ $target != @reboot:* ]] || needed=1
    done
    if [[ ! -e $S4M_REBOOT_MARKER && ! -L $S4M_REBOOT_MARKER ]]; then
        (( needed != 0 )) || return 0
    else
        [[ -f $S4M_REBOOT_MARKER ]] && s4m_trusted "$S4M_REBOOT_MARKER" || return 1
    fi
    audit=$(s4m_package s4p_dpkg --audit) || return 1
    [[ -z $audit ]] || return 1
    s4m_systemctl reboot || return 1
    # A successful command requests a reboot; only the next boot clears /run.
    # Keep the marker and report pending, so failed delivery is retried too.
    printf 'debian13s4: maintenance reboot requested; awaiting the next boot.\n' >&2
    return 75
}

# Trusted package profiles share the same locking, restart and reboot ownership.
s4m_debian_upgrade() { s4m_package unattended-upgrade --verbose; }
s4m_debian_verify() { return 0; }

s4m_update() (
    local audit target start now deadline last_restart restart_status reboot_status callback
    for callback in "$S4M_UPDATE_READY" "$S4M_UPDATE_PREPARE" "$S4M_UPDATE_UPGRADE" "$S4M_UPDATE_VERIFY"; do
        declare -F -- "$callback" > /dev/null || return 1
    done
    start=$(s4m_now) || return 1
    (( S4M_PRE_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_POST_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_PRE_RESTART_SECONDS + S4M_POST_RESTART_SECONDS +
        S4M_FINAL_RESERVE_SECONDS < S4M_ATTEMPT_SECONDS )) || return 1
    "$S4M_UPDATE_READY" || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    "$S4M_UPDATE_READY" || return 75
    "$S4M_UPDATE_PREPARE" || return 1
    # The same isolated configuration/indexes govern refresh and libapt's u-u.
    export APT_CONFIG=${S4M_UPDATE_POLICY:-$S4M_LIBRARY/policy.conf}
    [[ -f $APT_CONFIG ]] && s4m_trusted "$APT_CONFIG" || return 1
    export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
    export UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l
    s4m_load_restarts || return 1
    if (( ${#S4M_RESTARTS[@]} != 0 )); then
        audit=$(s4m_package s4p_dpkg --audit) || return 1
        if [[ -z $audit ]]; then
            # Reboot ownership gets a turn before any slow service recovery.
            for target in "${S4M_RESTARTS[@]}"; do
                if [[ $target == @reboot:* ]]; then
                    if s4m_request_reboot; then reboot_status=0; else reboot_status=$?; fi
                    (( reboot_status != 75 )) || return 75
                    break
                fi
            done
            # Already configured services recover offline, but only inside a
            # fixed fair slice. Failures/deferred intents cannot block refresh.
            s4m_run_restarts "$((start + S4M_PRE_RESTART_SECONDS))" || :
        fi
    fi
    if [[ -e $S4M_REBOOT_MARKER || -L $S4M_REBOOT_MARKER ]]; then
        # A previously installed kernel can be activated without fresh internet,
        # but partial package configuration/audit must never authorize reboot.
        [[ -f $S4M_REBOOT_MARKER ]] && s4m_trusted "$S4M_REBOOT_MARKER" || return 1
        if s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending; then
            audit=$(s4m_package s4p_dpkg --audit) || return 1
            if [[ -z $audit ]]; then
                if s4m_request_reboot; then reboot_status=0; else reboot_status=$?; fi
                (( reboot_status != 75 )) || return 75
            fi
        fi
        # Missing dependencies/partial configuration still reach authenticated
        # refresh and repair on later online attempts, rather than starving here.
    fi
    s4m_package apt-get update || return 1
    if ! s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4m_package apt-get --assume-yes --no-remove --fix-broken install || return 1
        s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    "$S4M_UPDATE_UPGRADE" || return 1
    audit=$(s4m_package s4p_dpkg --audit) || return 1
    [[ -z $audit ]] || return 1
    "$S4M_UPDATE_VERIFY" || return 1
    s4m_discover_restarts || return 1
    now=$(s4m_now) || return 1
    deadline=$((now + S4M_POST_RESTART_SECONDS))
    last_restart=$((start + S4M_ATTEMPT_SECONDS - S4M_FINAL_RESERVE_SECONDS))
    (( deadline <= last_restart )) || deadline=$last_restart
    if s4m_run_restarts "$deadline"; then restart_status=0; else restart_status=$?; fi
    # A failed/deferred restart cannot suppress a healthy-package reboot intent.
    if s4m_request_reboot; then reboot_status=0; else reboot_status=$?; fi
    (( reboot_status == 0 )) || return "$reboot_status"
    (( restart_status == 0 )) || return "$restart_status"
    (( ${#S4M_RESTARTS[@]} == 0 )) || return 75
    return 0
)
S4_PAYLOAD_81662b812509fcf97d5207c42dd41c0085b76dfeeadcaff9598d3bea03a025f0
    cat > "$S4B_STAGE/lib/maintenance/update.sh" <<'S4_PAYLOAD_49a7885c56c73c77b6c1a3466b1b6e6fafc263ad4903c89b7947f07f88d482c1' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
s4m_update
S4_PAYLOAD_49a7885c56c73c77b6c1a3466b1b6e6fafc263ad4903c89b7947f07f88d482c1
    cat > "$S4B_STAGE/lib/maintenance/policy.conf" <<'S4_PAYLOAD_ef244462f0855adfa878e7a746789ea1d2cfc9181ab31065a822a234a3afc5d4' || return 1
// This file is loaded first through APT_CONFIG. Later system fragments/main
// cannot widen these sources, origins or security options for this updater.
Dir::Etc::parts "";
Dir::Etc::main "";
Dir::Etc::sourcelist "/usr/local/lib/debian13s4/tasks/prerequisites/debian.sources";
Dir::Etc::sourceparts "-";
Dir::Etc::preferences "-";
Dir::Etc::preferencesparts "-";
Dir::State::lists "/var/lib/apt/debian13s4/lists";
APT::Update::Error-Mode "any";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
Acquire::Retries "2";
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Check-Date "true";
Acquire::Check-Valid-Until "true";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AllowUnauthenticated "false";
APT::Get::allow-downgrades "false";
APT::Get::allow-change-held-packages "false";
APT::Get::allow-remove-essential "false";
Debug::NoLocking "false";
DPkg::Lock::Timeout "60";
DPkg::Options { "--force-confdef"; "--force-confold"; };
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=trixie,label=Debian";
    "origin=Debian,codename=trixie-updates,label=Debian";
    "origin=Debian,codename=trixie-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Allow-downgrade "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Keep-Debs-After-Install "false";
// The controller checks package health and propagates reboot-request errors.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "now";
Unattended-Upgrade::OnlyOnACPower "false";
Unattended-Upgrade::Skip-Updates-On-Metered-Connections "false";
Unattended-Upgrade::SyslogEnable "true";
S4_PAYLOAD_ef244462f0855adfa878e7a746789ea1d2cfc9181ab31065a822a234a3afc5d4
    cat > "$S4B_STAGE/lib/maintenance/needrestart.conf" <<'S4_PAYLOAD_7082163c6cb6301ce36b1e9528a3d38f295abc2fbac0d29f52ad39abd5969fe3' || return 1
# Keep Debian's service exclusions, then exclude the setup/update controllers.
{
    local ($@, $!);
    my $loaded = do '/etc/needrestart/needrestart.conf';
    die "Cannot load Debian restart policy: $@ $!\n" if $@ || (!defined($loaded) && $!);
}
$nrconf{restart} = 'a';
$nrconf{override_rc}->{qr(^debian13s4-(maintenance|dotnet|bootstrap|repair|resume)(\.service)?$)} = 0;
S4_PAYLOAD_7082163c6cb6301ce36b1e9528a3d38f295abc2fbac0d29f52ad39abd5969fe3
    cat > "$S4B_STAGE/lib/maintenance/restart-policy.pl" <<'S4_PAYLOAD_4459b2afa9b1914dad46d50758e533160d1f5e63deb017310fa296b170bb4cfe' || return 1
#!/usr/bin/perl
use strict;
use warnings;

# Apply the same sorted, first-match service exclusions as Debian needrestart.
# Batch output precedes native override_rc/refusal handling, so it is only input
# to this selector; it is never permission to restart every reported service.
our %nrconf = (defno => 0, verbosity => 0, blacklist_rc => [], override_rc => {},
              restart_d => '/etc/needrestart/restart.d');
@ARGV == 1 || @ARGV == 2 or die "Expected the trusted needrestart configuration and optional original name.\n";
my $loaded = do $ARGV[0];
die "Cannot load restart policy: $@ $!\n" if $@ || (!defined($loaded) && $!);
sub validate_name {
    my ($name) = @_;
    $name =~ /\A[A-Za-z0-9_.@][A-Za-z0-9_.@:\\-]*\z/ && length($name) <= 255 &&
        $name ne '@reboot' && $name !~ /\A\@reboot:/
        or die "Invalid restart target.\n";
    my $unit = $name =~ /\.service\z/ ? $name : "$name.service";
    length($unit) <= 255 or die "Restart unit name is too long.\n";
    return $name;
}
if (@ARGV == 2) {
    my $name = validate_name($ARGV[1]);
    my $hook = "$nrconf{restart_d}/$name";
    print "$hook\n" or die "Cannot write hook path: $!\n" if -x $hook;
    exit 0;
}
my %seen;
while (my $line = <STDIN>) {
    next unless $line =~ /^NEEDRESTART-SVC: (.*)\n$/;
    my $name = validate_name($1);
    next if grep { $name =~ /$_/ } @{$nrconf{blacklist_rc}};
    my $allowed = !$nrconf{defno};
    for my $pattern (sort keys %{$nrconf{override_rc}}) {
        next unless $name =~ /$pattern/;
        $allowed = $nrconf{override_rc}->{$pattern};
        last;
    }
    next unless $allowed;
    # These pseudo-targets describe init managers, not individual services.
    # A controlled reboot activates their replacement without running the
    # unchecked multi-process init-manager hooks.
    my $target = $name;
    if ($name =~ /\A(?:systemd-manager|systemd-user|sysv-init)\z/) {
        $target = '@reboot';
    }
    # Journal the original policy/hook identity. The controller derives the
    # systemd observation name without changing what future policy checks see.
    print "$target\n" or die "Cannot write restart plan: $!\n" unless $seen{$target}++;
}
S4_PAYLOAD_4459b2afa9b1914dad46d50758e533160d1f5e63deb017310fa296b170bb4cfe
    cat > "$S4B_STAGE/lib/maintenance/debian13s4-maintenance.service" <<'S4_PAYLOAD_d2681c6dde48e6cfbd0232cc1303f589fa042b39224489331574aa49c79bd890' || return 1
[Unit]
Description=Authenticated Debian 13 package and kernel maintenance
After=network.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/maintenance/update.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
TimeoutStartSec=1h
TimeoutStopSec=5min
Restart=on-failure
RestartSec=5min
KillMode=control-group
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
S4_PAYLOAD_d2681c6dde48e6cfbd0232cc1303f589fa042b39224489331574aa49c79bd890
    cat > "$S4B_STAGE/lib/maintenance/debian13s4-maintenance.timer" <<'S4_PAYLOAD_bce83c7102c31c4e9c5ee8f2bde3ba5a7e33b702b159d1b6f453058985142209' || return 1
[Unit]
Description=Retry Debian 13 maintenance after boot and every hour

[Timer]
OnBootSec=5min
OnUnitInactiveSec=1h
RandomizedDelaySec=5min
Unit=debian13s4-maintenance.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_bce83c7102c31c4e9c5ee8f2bde3ba5a7e33b702b159d1b6f453058985142209
    cat > "$S4B_STAGE/lib/tasks/maintenance/apply.sh" <<'S4_PAYLOAD_488522a33f05b35c7c854074bdcb8d02510e2ea89f6025def2b493c4f81641ec' || return 1
#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4m_apply
S4_PAYLOAD_488522a33f05b35c7c854074bdcb8d02510e2ea89f6025def2b493c4f81641ec
    cat > "$S4B_STAGE/lib/tasks/maintenance/verify.sh" <<'S4_PAYLOAD_7aecaab921b4770b6034d966a36ed3b9d94a1e1ae35f901c067c1d4a45c2f762' || return 1
#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
s4m_verify
S4_PAYLOAD_7aecaab921b4770b6034d966a36ed3b9d94a1e1ae35f901c067c1d4a45c2f762
    cat > "$S4B_STAGE/lib/dotnet/common.sh" <<'S4_PAYLOAD_2f9f2c6196f0e2d749b8b88a90d6d851fc871d407caa9243796cc1a5345e3769' || return 1
#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages

S4D_LIBRARY=/usr/local/lib/debian13s4/dotnet
S4D_TIMER=debian13s4-dotnet.timer
S4D_SERVICE=debian13s4-dotnet.service
S4D_DOTNET=/usr/share/dotnet/dotnet
S4D_LINK=/usr/bin/dotnet
S4D_APT_DIR=/var/lib/apt/debian13s4-dotnet
S4D_PACKAGES=(aspnetcore-runtime-10.0 dotnet-runtime-10.0
    dotnet-runtime-deps-10.0 dotnet-hostfxr-10.0 dotnet-host)
S4D_FILES=(common.sh update.sh verify-payload.pl policy.conf preferences sources.sources
    microsoft-2025.asc debian13s4-dotnet.service debian13s4-dotnet.timer)

s4d_supported() {
    local architecture
    architecture=$(dpkg --print-architecture) || return 1
    [[ $architecture == amd64 || $architecture == arm64 ]]
}

s4d_prepare() {
    s4d_supported || return 78
    S4P_APT_DIR=$S4D_APT_DIR
    s4p_prepare
}

s4d_runtime() {
    local package status resolved output line core=0 web=0
    for package in "${S4D_PACKAGES[@]}"; do
        status=$(s4p_query "$package") || return 1
        [[ $status == 'install ok installed' ]] || return 1
    done
    [[ -x $S4D_DOTNET && -f $S4D_DOTNET && -L $S4D_LINK ]] &&
        s4m_trusted "$S4D_DOTNET" && s4m_trusted "${S4D_LINK%/*}" || return 1
    [[ $(stat --format='%u' -- "$S4D_LINK") == 0 ]] || return 1
    resolved=$(readlink --canonicalize-existing -- "$S4D_LINK") || return 1
    [[ $resolved == "$S4D_DOTNET" ]] || return 1
    [[ -f $S4D_LIBRARY/verify-payload.pl ]] &&
        s4m_trusted "$S4D_LIBRARY/verify-payload.pl" &&
        s4m_control perl "$S4D_LIBRARY/verify-payload.pl" || return 1
    output=$(s4m_control env DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
        "$S4D_DOTNET" --list-runtimes) || return 1
    while IFS= read -r line; do
        [[ $line =~ ^Microsoft[.]NETCore[.]App\ 10[.]0[.][0-9]+\ \[/usr/share/dotnet/shared/Microsoft[.]NETCore[.]App\]$ ]] && core=1
        [[ $line =~ ^Microsoft[.]AspNetCore[.]App\ 10[.]0[.][0-9]+\ \[/usr/share/dotnet/shared/Microsoft[.]AspNetCore[.]App\]$ ]] && web=1
    done <<< "$output"
    (( core == 1 && web == 1 ))
}

s4d_files() {
    local name
    [[ -d $S4M_STATE ]] && s4m_trusted "$S4M_STATE" || return 1
    for name in "${S4D_FILES[@]}"; do
        [[ -f $S4D_LIBRARY/$name ]] && s4m_trusted "$S4D_LIBRARY/$name" || return 1
    done
    [[ -x $S4D_LIBRARY/update.sh ]] || return 1
    for name in common.sh policy.conf needrestart.conf restart-policy.pl; do
        [[ -f $S4M_LIBRARY/$name ]] && s4m_trusted "$S4M_LIBRARY/$name" || return 1
    done
    for name in "$S4D_SERVICE" "$S4D_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4D_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4D_TIMER" && s4m_property "$S4D_TIMER" ActiveState active
}

s4d_identity() {
    local name digest
    for name in "${S4D_FILES[@]}"; do
        digest=$(sha256sum -- "$S4D_LIBRARY/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
}

s4d_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/dotnet.ready ]] && s4m_trusted "$S4M_STATE/dotnet.ready" || return 1
    s4d_files || return 1
    expected=$(s4d_identity) && actual=$(cat -- "$S4M_STATE/dotnet.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4d_upgrade() {
    # Reinstall registered packages when their installed bytes cannot be verified.
    local -a repair=()
    s4d_runtime || repair=(--reinstall)
    s4m_package apt-get --assume-yes --no-remove --no-install-recommends \
        "${repair[@]}" install "${S4D_PACKAGES[@]}"
}

s4d_apply() (
    local unit loaded temporary wants resolved APT_CONFIG=$S4D_LIBRARY/policy.conf
    local DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
    local UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l
    s4d_prepare || return 1
    s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    for unit in "$S4D_TIMER" "$S4D_SERVICE"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/dotnet.ready || -L $S4M_STATE/dotnet.ready ]]; then
        [[ -f $S4M_STATE/dotnet.ready ]] && s4m_trusted "$S4M_STATE/dotnet.ready" || return 1
        rm -f -- "$S4M_STATE/dotnet.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for unit in "$S4D_TIMER" "$S4D_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    for unit in "${S4D_FILES[@]}"; do
        [[ -f $S4D_LIBRARY/$unit ]] && s4m_trusted "$S4D_LIBRARY/$unit" || return 1
    done
    export APT_CONFIG
    export DEBIAN_FRONTEND APT_LISTCHANGES_FRONTEND UCF_FORCE_CONFFOLD NEEDRESTART_MODE
    s4m_package apt-get update || return 1
    if ! s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4m_package apt-get --assume-yes --no-remove --fix-broken install || return 1
        s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    s4d_upgrade || return 1
    s4m_package s4p_verify && s4d_runtime || return 1
    for unit in "$S4D_SERVICE" "$S4D_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4D_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable "$S4D_TIMER" &&
        s4m_enabled "$S4D_TIMER" || return 1
    wants=$S4M_SYSTEMD/timers.target.wants
    [[ -d $wants && -L $wants/$S4D_TIMER ]] && s4m_trusted "$wants" || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4D_TIMER") || return 1
    [[ $resolved == "$S4M_SYSTEMD/$S4D_TIMER" ]] || return 1
    s4m_sync "$S4M_SYSTEMD" "$wants" "$S4M_SYSTEMD/$S4D_TIMER" "$S4M_SYSTEMD/$S4D_SERVICE" || return 1
    s4m_systemctl start "$S4D_TIMER" && s4d_files || return 1
    temporary=$(mktemp -- "$S4M_STATE/dotnet-intent.XXXXXX") || return 1
    if ! s4d_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/dotnet.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4d_ready
)

s4d_verify() {
    s4d_supported && s4p_verify && s4d_runtime && s4d_ready
}

s4d_update() (
    S4M_UPDATE_POLICY=$S4D_LIBRARY/policy.conf
    S4M_UPDATE_READY=s4d_ready
    S4M_UPDATE_PREPARE=s4d_prepare
    S4M_UPDATE_UPGRADE=s4d_upgrade
    S4M_UPDATE_VERIFY=s4d_runtime
    s4m_update
)
S4_PAYLOAD_2f9f2c6196f0e2d749b8b88a90d6d851fc871d407caa9243796cc1a5345e3769
    cat > "$S4B_STAGE/lib/dotnet/update.sh" <<'S4_PAYLOAD_e2c12a417b6849a97e09d14cd33592cb7e507a2ef5f9c0dbcdd472969f56c9b0' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_update
S4_PAYLOAD_e2c12a417b6849a97e09d14cd33592cb7e507a2ef5f9c0dbcdd472969f56c9b0
    cat > "$S4B_STAGE/lib/dotnet/verify-payload.pl" <<'S4_PAYLOAD_211f3767dacd64f61fecbcd630d8957709f8467ada76f8cea28508d34296f91b' || return 1
#!/usr/bin/perl

use strict;
use warnings;
use Digest::MD5;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK S_ISDIR S_ISREG);

# The installed package database and native tools are part of the trusted base.
# These digests check installed bytes, not package authenticity or application health.
my $install_root = '/';
my $trusted_uid = 0;
my $admindir = "$install_root/var/lib/dpkg";
$admindir =~ s{^//}{/};
my $limit = 1024 * 1024;

sub fail { die "debian13s4 runtime integrity: $_[0]\n"; }

sub path {
    my ($name) = @_;
    $name =~ m{\A/[A-Za-z0-9_+./-]+\z} &&
        $name !~ m{(?:\A|/)[.][.]?(?:/|\z)|//|/\z} or fail('invalid package path');
    return $install_root eq '/' ? $name : "$install_root$name";
}

sub trusted {
    my ($name, $kind) = @_;
    my $current = $name;
    while (1) {
        my @st = lstat($current);
        @st && $st[4] == $trusted_uid && !($st[2] & 0022) or fail("untrusted path: $current");
        ($current eq $name && $kind eq 'file' ? S_ISREG($st[2]) : S_ISDIR($st[2]))
            or fail("wrong path kind: $current");
        last if $current eq $install_root;
        $current =~ s{/[^/]+\z}{};
        $current = '/' if $current eq '';
    }
}

sub query {
    open(my $child, '-|', 'dpkg-query', "--admindir=$admindir", @_) or fail('query start failed');
    my $output = '';
    while (1) {
        my $count = read($child, my $buffer, 65536);
        defined $count or fail('query read failed');
        last if $count == 0;
        $output .= $buffer;
        length($output) <= $limit or fail('package metadata exceeds bound');
    }
    close($child) or fail('query failed');
    return $output;
}

sub digest {
    my ($name, $expected) = @_;
    trusted($name, 'file');
    my @before = lstat($name);
    sysopen(my $file, $name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or fail("cannot open: $name");
    binmode($file) or fail('binary mode failed');
    my @opened = stat($file);
    @opened && S_ISREG($opened[2]) && $opened[0] == $before[0] && $opened[1] == $before[1]
        or fail('payload identity changed');
    my $actual = Digest::MD5->new->addfile($file)->hexdigest;
    my @after = stat($file);
    my @named = lstat($name);
    @after && @named && S_ISREG($named[2]) &&
        join(':', @opened[0,1,2,4,7,9,10]) eq join(':', @after[0,1,2,4,7,9,10]) &&
        join(':', @after[0,1,2,4,7,9,10]) eq join(':', @named[0,1,2,4,7,9,10])
        or fail('payload changed during verification');
    close($file) or fail('payload close failed');
    $actual eq $expected or fail("checksum mismatch: $name");
}

trusted($admindir, 'directory');
trusted("$admindir/info", 'directory');
trusted("$admindir/status", 'file');
for my $package (qw(aspnetcore-runtime-10.0 dotnet-runtime-10.0 dotnet-runtime-deps-10.0
                   dotnet-hostfxr-10.0 dotnet-host)) {
    my $identity = query('--show', '--showformat=${binary:Package}\t${Status}\t${Version}\n', '--', $package);
    $identity =~ /\A(\Q$package\E(?::(?:amd64|arm64))?)\tinstall ok installed\t(10[.]0[.][0-9]+)-[0-9A-Za-z.+~]+\n\z/
        or fail("unusable package identity: $package");
    my ($binary, $version) = ($1, $2);
    # Validate the metadata leaves before the native queries can open them.
    # --control-path is needed for trust checks, not for reading the contents:
    # binary:Package can qualify a foreign architecture even without Multi-Arch.
    my $metadata = query('--control-path', $binary, 'md5sums');
    $metadata =~ m{\A(\Q$admindir/info/$package\E(?::(?:amd64|arm64))?)[.]md5sums\n\z}
        or fail('invalid checksum metadata location');
    my $metadata_base = $1;
    trusted("$metadata_base.md5sums", 'file');
    trusted("$metadata_base.list", 'file');
    my $manifest = query('--control-show', $binary, 'md5sums');
    my $inventory = query('--listfiles', '--', $binary);
    length($manifest) && length($inventory) && $manifest =~ /\n\z/ && $inventory =~ /\n\z/
        or fail('missing package metadata');
    my (%sums, %listed, %directories);
    # The dependency-only package also owns the shared installation directory.
    $directories{'/usr/share/dotnet'} = 1;
    for my $line (split(/\n/, $manifest)) {
        $line =~ m{\A([0-9a-f]{32})  ([A-Za-z0-9_+./-]+)\z} or fail('invalid checksum metadata');
        my ($hash, $relative) = ($1, $2);
        my $name = "/$relative";
        path($name);
        exists($sums{$name}) and fail('duplicate checksum metadata');
        $sums{$name} = $hash;
        if ($name =~ m{\A/usr/share/dotnet/}) {
            my $parent = $name;
            while ($parent =~ s{/[^/]+\z}{}) { $directories{$parent} = 1; }
        }
    }
    for my $name (split(/\n/, $inventory)) {
        next if $name eq '/.' || $name eq '/';
        path($name);
        exists($listed{$name}) and fail('duplicate package inventory');
        $listed{$name} = 1;
        next unless $name =~ m{\A/usr/share/dotnet(?:/|\z)};
        if (exists($sums{$name})) {
            digest(path($name), $sums{$name});
        } else {
            $directories{$name} or fail("no checksum coverage: $name");
            trusted(path($name), 'directory');
        }
    }
    for my $name (keys %sums) {
        next unless $name =~ m{\A/usr/share/dotnet/};
        $listed{$name} or fail("checksum absent from inventory: $name");
    }
    my @required;
    if ($package eq 'dotnet-host') {
        @required = ('/usr/share/dotnet/dotnet');
    } elsif ($package eq 'dotnet-hostfxr-10.0') {
        @required = ("/usr/share/dotnet/host/fxr/$version/libhostfxr.so");
    } elsif ($package eq 'dotnet-runtime-10.0') {
        @required = map { "/usr/share/dotnet/shared/Microsoft.NETCore.App/$version/$_" }
            qw(libcoreclr.so libclrjit.so libhostpolicy.so libSystem.Native.so
               libSystem.Globalization.Native.so libSystem.IO.Compression.Native.so
               libSystem.Net.Security.Native.so libSystem.Security.Cryptography.Native.OpenSsl.so
               System.Private.CoreLib.dll System.Runtime.dll Microsoft.NETCore.App.deps.json
               Microsoft.NETCore.App.runtimeconfig.json);
    } elsif ($package eq 'aspnetcore-runtime-10.0') {
        @required = map { "/usr/share/dotnet/shared/Microsoft.AspNetCore.App/$version/$_" }
            qw(Microsoft.AspNetCore.dll Microsoft.AspNetCore.Hosting.dll Microsoft.AspNetCore.Http.dll
               Microsoft.AspNetCore.Server.Kestrel.dll Microsoft.AspNetCore.App.deps.json
               Microsoft.AspNetCore.App.runtimeconfig.json);
    }
    for my $name (@required) {
        exists($sums{$name}) && $listed{$name} or fail("required payload is not verifiable: $name");
    }
}
S4_PAYLOAD_211f3767dacd64f61fecbcd630d8957709f8467ada76f8cea28508d34296f91b
    cat > "$S4B_STAGE/lib/dotnet/policy.conf" <<'S4_PAYLOAD_13feae91abf511acb9efd9b1e4ea940e134d2f197050879f64e4b3436d519cf0' || return 1
// Inherit the authenticated Debian settings without loading host APT hooks.
#include "/usr/local/lib/debian13s4/maintenance/policy.conf";
Dir::Etc::sourcelist "/usr/local/lib/debian13s4/dotnet/sources.sources";
Dir::Etc::preferences "/usr/local/lib/debian13s4/dotnet/preferences";
Dir::State::lists "/var/lib/apt/debian13s4-dotnet/lists";
S4_PAYLOAD_13feae91abf511acb9efd9b1e4ea940e134d2f197050879f64e4b3436d519cf0
    cat > "$S4B_STAGE/lib/dotnet/preferences" <<'S4_PAYLOAD_4b7530148cfde9fcf43fd36c63f535cd34be28f0d5bfc9c80790594aa8712f75' || return 1
Package: aspnetcore-runtime-10.0 dotnet-runtime-10.0 dotnet-runtime-deps-10.0 dotnet-hostfxr-10.0
Pin: release o=microsoft-debian-trixie-prod trixie,n=trixie
Pin-Priority: 500

Package: dotnet-host
Pin: version 10.*
Pin-Priority: 500

Package: *
Pin: origin "packages.microsoft.com"
Pin-Priority: -1
S4_PAYLOAD_4b7530148cfde9fcf43fd36c63f535cd34be28f0d5bfc9c80790594aa8712f75
    cat > "$S4B_STAGE/lib/dotnet/microsoft-2025.asc" <<'S4_PAYLOAD_d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1' || return 1
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BSN Pgp v1.1.0.0

mQINBGVUhiwBEADF3TWX0HMi2+BdQfJrSdQkZTE4qk4vV2ooAMn8vWA2DGI88JOl
k1LwhZGEqJv5TsKTyNEMWb3NXhR1ZZ5uQPvf6iN0806cq83s096F85GUtjzfGLQj
Zo3FhDSKeHz3mhthQ4QP4bwYUmSpWs6e+/ZSFYYc3yU8mInDM4SNzrqr4x2ltmf+
3RWkoYYo1SpG521A9+1zi7xzz6IHpAk6MdIcTj7mHxXd6ovmXkvHUhKbXGkybHPn
iupWokDaJZgV4+q6kc7zVgTVnwmXV7NHQhWSyOm/BmYVcpmrkCSgSH18SArFjR6Q
KyJ9VuUo1mJEUGnEakQSaOn1UAYtO8Mh4cXXD4833G0BLjiFNOL0XRUNh35pKvcT
my/HnXvRXtpzAzTtANPxIbjli/veagU+JRWhtjtfONz0wQ5Bv1zFjnM9ewxFNPPo
7Jp9WCVeUKFZcZJo8r/k7Y4d0Y1WINOPniSCNhKcD0pva3gXLcxfdnZjdMSj++ba
XlAstjw0Oyty0EXoHXCMpelMoa+DQ7KSDGKrOtm5YFAP6Ki4go1Tt2q8nmul36cZ
Zot6eoPG/qKxW+dvmSrWhQCcfd74VbhECbzXiCFLHadq85C1K5rrLM6oVr1u7K6O
jlc1aitGgZECi6fvu61QhpUvHjCegRWzMIhah9qrv4lvxFFcA+a1jwXlnwARAQAB
tEJNaWNyb3NvZnQgQ29ycG9yYXRpb24gLSBHZW5lcmFsIEdQRyBTaWduZXIgPGdw
Z3NpZ25AbWljcm9zb2Z0LmNvbT6JAjgEEwEIACIFAmVUhiwCGwMGCwkIBwMCBhUI
AgkKCwQWAgMBAh4BAheAAAoJEO5Nd5L3SBgrDc0P/0Ubx0vqD/DgyhiP0bIs8euO
iA5BQvOCiroIkhSkFbAw8rT9a/XtRTRM2l4I8c2M1ZX9i/0wWihmFUJhiVHyRxkl
ZcEFv+ieBuhvD1gPOVLZg3To8yOTrcOnHe+FuKqA6u+3xBn2AmAWeck9o0NKhtnm
5ckweos+Qj9NoxaZX8UeGFstOiTBJeyhuJjthQ+3M0BvTxEaRcLXGSXSGSgZ00ii
YSLNgOMPF+C22bXBL/erClEYkIGCctqPvyrhV/GVNnGk2ALyJqdK+BaJeGh9mBJa
ZrP3l6vFxsAI0RNCNU1s5QaFzfFzFkiUnG/aoyuwh4xmsB+uyVkR+KigPK9gfF3S
nU7AqcdhSbUA6A0DGDRkHauHM5Wtc7730LdjiNDXbYwG/yXmDYNasoszmItZzh77
HiQxYA5dNB9r9QJS2rHV/qe+heAJ5Rub5kxcu33DGL30qG7Q9+HRTu0oSEOIUFyT
aOJJnNUiB2D4hoKKnr5U8FYOZ7KvDcG7cDvInqYtGpNfrnIf94VeB9WJY6DbDQSA
F5yHb6X8FS0x3lMT2H1l6RRyr0278kyO18VBudtlnonC+Y1UT7eqAk6WjS5CitPX
T3Hc7jCURugXrc51igKa+p67yAaybEIuVyWF6JaINKRqiUqEPVXnHELXPbBmiHW5
1HwdbKTMzgF8bu1JI+tQ
=lIzW
-----END PGP PUBLIC KEY BLOCK-----
S4_PAYLOAD_d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1
    cat > "$S4B_STAGE/lib/dotnet/debian13s4-dotnet.service" <<'S4_PAYLOAD_3fbeee3bb047bee13c90681563b891509386a05c075de6a28cc045320f330f96' || return 1
[Unit]
Description=Authenticated .NET 10 runtime maintenance
After=network.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/dotnet/update.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
TimeoutStartSec=1h
TimeoutStopSec=5min
Restart=on-failure
RestartSec=5min
KillMode=control-group
NoNewPrivileges=yes
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
S4_PAYLOAD_3fbeee3bb047bee13c90681563b891509386a05c075de6a28cc045320f330f96
    cat > "$S4B_STAGE/lib/dotnet/debian13s4-dotnet.timer" <<'S4_PAYLOAD_1b2f88d8a68182dadceeb0f1ef2c755affb3d5033b564315695ac3a152881a1b' || return 1
[Unit]
Description=Retry .NET runtime patches after boot and every hour

[Timer]
OnBootSec=10min
OnUnitInactiveSec=1h
RandomizedDelaySec=5min
Unit=debian13s4-dotnet.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_1b2f88d8a68182dadceeb0f1ef2c755affb3d5033b564315695ac3a152881a1b
    cat > "$S4B_STAGE/lib/dotnet/sources.sources" <<'S4_PAYLOAD_27796bdadb859d37d728f14a35255b2a95e1c10861a13fd8c821441cc4e33ce9' || return 1
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

Types: deb
URIs: https://packages.microsoft.com/debian/13/prod
Suites: trixie
Components: main
Architectures: amd64 arm64
Signed-By: /usr/local/lib/debian13s4/dotnet/microsoft-2025.asc AA86F75E427A19DD33346403EE4D7792F748182B
Check-Valid-Until: yes
Valid-Until-Max: 1209600
S4_PAYLOAD_27796bdadb859d37d728f14a35255b2a95e1c10861a13fd8c821441cc4e33ce9
    cat > "$S4B_STAGE/lib/tasks/dotnet/apply.sh" <<'S4_PAYLOAD_0ad3ad407a2b16ff7dc5f6b40aec6d74d1bda664607f336d290467e36d54acba' || return 1
#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4d_apply
S4_PAYLOAD_0ad3ad407a2b16ff7dc5f6b40aec6d74d1bda664607f336d290467e36d54acba
    cat > "$S4B_STAGE/lib/tasks/dotnet/verify.sh" <<'S4_PAYLOAD_3f885728438ec7c402eeffb157a968eaa247fabe7b341179d728f6de830193fa' || return 1
#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_verify
S4_PAYLOAD_3f885728438ec7c402eeffb157a968eaa247fabe7b341179d728f6de830193fa
    cat > "$S4B_STAGE/files.sha256" <<'S4_CHECKSUMS' || return 1
5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936  lib/repair.sh
0066b18a0c987272b59c97d9a45b23d8c8ef7ff9f3a0c565e4e5ce9ed5be9b13  lib/tasks.list
f00b984fac21636c60e8a4dd9d1ade6cdf58bcd0123d669e7fba51c756346934  lib/tasks/prerequisites/apply.sh
5c2bb90b18725176df85061f2fd7556fc5f00c286991f7ff34445d7b880693fc  lib/tasks/prerequisites/verify.sh
f99079435a5917ee3a1a69aa9f18e32e4a98ddcd787007336997b5a4fbc2eab9  lib/tasks/prerequisites/common.sh
7d995cf7bc3d3db5461c7c21a4989495a042e0a5fc34a186cc68bc859c62b0c4  lib/tasks/prerequisites/debian.sources
e21ba280c03e5c9848930e7a58b87febd59332e777a3a992e3bab1f992c1a3e5  units/debian13s4-repair.service
8618edcc26838d9f7f56c39d538bcfdba099e101582e8fb0adb38df413c5ce28  units/debian13s4-repair.timer
a107d7016113884baa5f42ef8c5523410d1193f9970c3d320647dc0ee3d3a5f9  units/debian13s4-resume.service
81662b812509fcf97d5207c42dd41c0085b76dfeeadcaff9598d3bea03a025f0  lib/maintenance/common.sh
49a7885c56c73c77b6c1a3466b1b6e6fafc263ad4903c89b7947f07f88d482c1  lib/maintenance/update.sh
ef244462f0855adfa878e7a746789ea1d2cfc9181ab31065a822a234a3afc5d4  lib/maintenance/policy.conf
7082163c6cb6301ce36b1e9528a3d38f295abc2fbac0d29f52ad39abd5969fe3  lib/maintenance/needrestart.conf
4459b2afa9b1914dad46d50758e533160d1f5e63deb017310fa296b170bb4cfe  lib/maintenance/restart-policy.pl
d2681c6dde48e6cfbd0232cc1303f589fa042b39224489331574aa49c79bd890  lib/maintenance/debian13s4-maintenance.service
bce83c7102c31c4e9c5ee8f2bde3ba5a7e33b702b159d1b6f453058985142209  lib/maintenance/debian13s4-maintenance.timer
488522a33f05b35c7c854074bdcb8d02510e2ea89f6025def2b493c4f81641ec  lib/tasks/maintenance/apply.sh
7aecaab921b4770b6034d966a36ed3b9d94a1e1ae35f901c067c1d4a45c2f762  lib/tasks/maintenance/verify.sh
2f9f2c6196f0e2d749b8b88a90d6d851fc871d407caa9243796cc1a5345e3769  lib/dotnet/common.sh
e2c12a417b6849a97e09d14cd33592cb7e507a2ef5f9c0dbcdd472969f56c9b0  lib/dotnet/update.sh
211f3767dacd64f61fecbcd630d8957709f8467ada76f8cea28508d34296f91b  lib/dotnet/verify-payload.pl
13feae91abf511acb9efd9b1e4ea940e134d2f197050879f64e4b3436d519cf0  lib/dotnet/policy.conf
4b7530148cfde9fcf43fd36c63f535cd34be28f0d5bfc9c80790594aa8712f75  lib/dotnet/preferences
d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1  lib/dotnet/microsoft-2025.asc
3fbeee3bb047bee13c90681563b891509386a05c075de6a28cc045320f330f96  lib/dotnet/debian13s4-dotnet.service
1b2f88d8a68182dadceeb0f1ef2c755affb3d5033b564315695ac3a152881a1b  lib/dotnet/debian13s4-dotnet.timer
27796bdadb859d37d728f14a35255b2a95e1c10861a13fd8c821441cc4e33ce9  lib/dotnet/sources.sources
0ad3ad407a2b16ff7dc5f6b40aec6d74d1bda664607f336d290467e36d54acba  lib/tasks/dotnet/apply.sh
3f885728438ec7c402eeffb157a968eaa247fabe7b341179d728f6de830193fa  lib/tasks/dotnet/verify.sh
S4_CHECKSUMS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4B_PATH
    export PATH
    umask 077
    s4b_main "$@"
fi
