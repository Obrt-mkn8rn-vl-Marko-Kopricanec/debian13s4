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
    debian13s4-dotnet.timer debian13s4-dotnet.service
    debian13s4-network.timer debian13s4-network.service
    debian13s4-retention.timer debian13s4-retention.service
    debian13s4-hardening.timer debian13s4-hardening.service
    debian13s4-ssh.timer debian13s4-ssh.service debian13s4-admin-ssh.service)
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

S4B_BUNDLE_ID=54c9ff23e8eddc8dcc5a69e11702ae6a91992a129e2a00e81ffd0d0184a88fb8
S4B_FILES=(lib/repair.sh lib/tasks.list lib/tasks/prerequisites/apply.sh lib/tasks/prerequisites/verify.sh lib/tasks/prerequisites/common.sh lib/tasks/prerequisites/debian.sources units/debian13s4-repair.service units/debian13s4-repair.timer units/debian13s4-resume.service lib/maintenance/common.sh lib/maintenance/update.sh lib/maintenance/policy.conf lib/maintenance/needrestart.conf lib/maintenance/restart-policy.pl lib/maintenance/retain-kernels.py lib/maintenance/debian13s4-maintenance.service lib/maintenance/debian13s4-maintenance.timer lib/tasks/maintenance/apply.sh lib/tasks/maintenance/verify.sh lib/dotnet/common.sh lib/dotnet/update.sh lib/dotnet/verify-payload.pl lib/dotnet/policy.conf lib/dotnet/preferences lib/dotnet/microsoft-2025.asc lib/dotnet/debian13s4-dotnet.service lib/dotnet/debian13s4-dotnet.timer lib/dotnet/sources.sources lib/tasks/dotnet/apply.sh lib/tasks/dotnet/verify.sh lib/network/common.sh lib/network/repair.sh lib/network/verify.py lib/network/network.conf lib/network/debian13s4-network.service lib/network/debian13s4-network.timer lib/tasks/network/apply.sh lib/tasks/network/verify.sh lib/retention/common.sh lib/retention/repair.sh lib/retention/journal.py lib/retention/clean-cache.py lib/retention/apt.conf lib/retention/journal.conf lib/retention/debian13s4-retention.service lib/retention/debian13s4-retention.timer lib/tasks/retention/apply.sh lib/tasks/retention/verify.sh lib/hardening/common.sh lib/hardening/repair.sh lib/hardening/verify.py lib/hardening/kernel.conf lib/hardening/debian13s4-hardening.service lib/hardening/debian13s4-hardening.timer lib/tasks/hardening/apply.sh lib/tasks/hardening/verify.sh lib/firewall/kernel.py lib/ssh/common.sh lib/ssh/policy.py lib/ssh/repair.sh lib/ssh/debian13s4-admin-ssh.service lib/ssh/debian13s4-ssh.service lib/ssh/debian13s4-ssh.timer lib/tasks/ssh/apply.sh lib/tasks/ssh/verify.sh)
S4B_MODES=(0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644)

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
    cat > "$S4B_STAGE/lib/tasks.list" <<'S4_PAYLOAD_c51fc882b1d507dab10b5d912d5f82b4d0902ef31da87bc7a228fd95d4cd2ec1' || return 1
prerequisites:
network:prerequisites
hardening:prerequisites
retention:prerequisites
maintenance:prerequisites
dotnet:prerequisites
ssh:prerequisites network hardening
S4_PAYLOAD_c51fc882b1d507dab10b5d912d5f82b4d0902ef31da87bc7a228fd95d4cd2ec1
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
    cat > "$S4B_STAGE/lib/tasks/prerequisites/common.sh" <<'S4_PAYLOAD_84d897f0a349e9f7dc4dbf5aa75fc86c4cb7d67a67ca1f61439a982cdf0c86b4' || return 1
#!/bin/bash

S4P_PACKAGES=(ca-certificates debian-archive-keyring curl gpgv nftables iproute2
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
S4_PAYLOAD_84d897f0a349e9f7dc4dbf5aa75fc86c4cb7d67a67ca1f61439a982cdf0c86b4
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
    cat > "$S4B_STAGE/lib/maintenance/common.sh" <<'S4_PAYLOAD_c9c5a3f1e2a4182b94132b25709ff4fdb95405457ac41372fd353437e3a55d04' || return 1
#!/bin/bash

S4M_LIBRARY=/usr/local/lib/debian13s4/maintenance
S4M_UPDATE_POLICY=
S4M_UPDATE_READY=s4m_ready
S4M_UPDATE_PREPARE=s4p_prepare
S4M_UPDATE_UPGRADE=s4m_debian_upgrade
S4M_UPDATE_VERIFY=s4m_debian_verify
S4M_UPDATE_CLEANUP=s4m_kernel_cleanup
S4M_STATE=/var/lib/debian13s4
S4M_SYSTEMD=/etc/systemd/system
S4M_TIMER=debian13s4-maintenance.timer
S4M_SERVICE=debian13s4-maintenance.service
S4M_PATH=/usr/sbin:/usr/bin:/sbin:/bin
S4M_REPAIR_FD=
S4M_REBOOT_MARKER=/run/reboot-required
S4M_BOOT_FILE=/proc/sys/kernel/random/boot_id
# Match the shipped one-hour oneshot. Restart slices and kernel cleanup leave
# 1760 seconds for package work and 300 for final controls; neither grows with a queue.
S4M_ATTEMPT_SECONDS=3600
S4M_PRE_RESTART_SECONDS=600
S4M_POST_RESTART_SECONDS=600
S4M_FINAL_RESERVE_SECONDS=300
S4M_CLEANUP_SECONDS=300
S4M_CLEANUP_GRACE_SECONDS=10
S4M_CLEANUP_BOUND_SECONDS=$((S4M_CLEANUP_SECONDS + S4M_CLEANUP_GRACE_SECONDS + 30))
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
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl retain-kernels.py \
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
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl retain-kernels.py \
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
    s4p_prepare && s4m_packages || return 1
    # An existing kernel history may need space before initial delivery too.
    # Missing prerequisites/unsafe state cannot authorize removal or prevent
    # installation and the later persistent maintenance retry from being armed.
    APT_CONFIG=$S4M_LIBRARY/policy.conf s4m_kernel_cleanup || :
    s4p_apply && s4p_verify || return 1
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
s4m_skip_cleanup() { return 0; }

s4m_kernel_cleanup() (
    trap - EXIT
    [[ -z $S4M_REPAIR_FD ]] || exec {S4M_REPAIR_FD}>&-
    [[ -f $S4M_LIBRARY/retain-kernels.py && -n ${APT_CONFIG:-} && -f $APT_CONFIG ]] &&
        s4m_trusted "$S4M_LIBRARY/retain-kernels.py" && s4m_trusted "$APT_CONFIG" || return 1
    exec timeout --signal=TERM --kill-after="${S4M_CLEANUP_GRACE_SECONDS}s" "${S4M_CLEANUP_SECONDS}s" \
        env -i PATH="$S4M_PATH" LANG=C LC_ALL=C APT_CONFIG="$APT_CONFIG" \
        DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
        UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l \
        /usr/bin/python3 -I -B "$S4M_LIBRARY/retain-kernels.py" --apply
)

s4m_update() (
    local audit target start now deadline last_restart restart_status reboot_status callback cleanup_status
    for callback in "$S4M_UPDATE_READY" "$S4M_UPDATE_PREPARE" "$S4M_UPDATE_UPGRADE" "$S4M_UPDATE_VERIFY" "$S4M_UPDATE_CLEANUP"; do
        declare -F -- "$callback" > /dev/null || return 1
    done
    start=$(s4m_now) || return 1
    (( S4M_PRE_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_POST_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_CLEANUP_SECONDS > 0 && S4M_CLEANUP_GRACE_SECONDS > 0 &&
        S4M_CLEANUP_BOUND_SECONDS >= S4M_CLEANUP_SECONDS + S4M_CLEANUP_GRACE_SECONDS &&
        S4M_PRE_RESTART_SECONDS + S4M_POST_RESTART_SECONDS + S4M_CLEANUP_BOUND_SECONDS +
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
    # One bounded offline-capable cleanup gets a turn before download/configure
    # pressure. Failure cannot suppress authenticated repair of interrupted dpkg.
    if "$S4M_UPDATE_CLEANUP"; then cleanup_status=0; else cleanup_status=$?; fi
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
    (( cleanup_status == 0 )) || return "$cleanup_status"
    (( ${#S4M_RESTARTS[@]} == 0 )) || return 75
    return 0
)
S4_PAYLOAD_c9c5a3f1e2a4182b94132b25709ff4fdb95405457ac41372fd353437e3a55d04
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
    cat > "$S4B_STAGE/lib/maintenance/policy.conf" <<'S4_PAYLOAD_bc7e6d139257f55d2b8b77c87263709c5fafb72242d728d4372d81d2915d478f' || return 1
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
// Host fragments are disabled: supply kernel protection explicitly here.
APT::Protect-Kernels "true";
APT::VersionedKernelPackages { "linux-image"; };
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
// The checked one-image controller handles both legacy and +deb13 names.
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
S4_PAYLOAD_bc7e6d139257f55d2b8b77c87263709c5fafb72242d728d4372d81d2915d478f
    cat > "$S4B_STAGE/lib/maintenance/needrestart.conf" <<'S4_PAYLOAD_9f464f118004aba860998254cb5ce0a4f6b4dce6ca84c38e861ec0f179656eec' || return 1
# Keep Debian's service exclusions, then exclude the setup/update controllers.
{
    local ($@, $!);
    my $loaded = do '/etc/needrestart/needrestart.conf';
    die "Cannot load Debian restart policy: $@ $!\n" if $@ || (!defined($loaded) && $!);
}
$nrconf{restart} = 'a';
$nrconf{override_rc}->{qr(^debian13s4-(maintenance|dotnet|network|retention|hardening|bootstrap|repair|resume)(\.service)?$)} = 0;
S4_PAYLOAD_9f464f118004aba860998254cb5ce0a4f6b4dce6ca84c38e861ec0f179656eec
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
    cat > "$S4B_STAGE/lib/maintenance/retain-kernels.py" <<'S4_PAYLOAD_b213906bff69cad34a5f2a547727622474f545c207bfca681f8a3dcac521b5ac' || return 1
"""Remove one obsolete automatic Debian kernel image, retaining boot choices."""

from functools import cmp_to_key
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


POLICY = Path("/usr/local/lib/debian13s4/maintenance/policy.conf")
TRUSTED_UID = 0
KEEP = 3
IMAGE = re.compile(
    r"linux-image-(?P<release>[1-9][0-9]*\.[0-9]+\.[0-9]+"
    r"(?:-[0-9]+|\+deb13)-(?P<flavour>(?:cloud-|rt-)?(?:amd64|arm64)))\Z"
)


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise RuntimeError("noncanonical kernel maintenance path")
    leaf = True
    while True:
        info = path.lstat()
        kind = stat.S_ISDIR if directory or not leaf else stat.S_ISREG
        if info.st_uid != TRUSTED_UID or info.st_mode & 0o022 or not kind(info.st_mode):
            raise RuntimeError("untrusted kernel maintenance path: " + str(path))
        if path == path.parent:
            return
        path, leaf = path.parent, False


def configured(package):
    import apt_pkg
    return (package.is_installed and
            package._pkg.current_state == apt_pkg.CURSTATE_INSTALLED and
            package._pkg.inst_state == apt_pkg.INSTSTATE_OK)


def select(cache, running):
    import apt_pkg
    if cache.broken_count or cache.dpkg_journal_dirty or cache.get_changes():
        raise RuntimeError("kernel cleanup requires a clean package state")
    images = [p for p in cache if p.is_installed and IMAGE.fullmatch(p.name)]
    current = [p for p in images if IMAGE.fullmatch(p.name)["release"] == running]
    if not current or any(not configured(p) for p in images):
        raise RuntimeError("running/installed kernel identities are unverifiable")
    flavour = IMAGE.fullmatch(current[0].name)["flavour"]
    meta = cache.get("linux-image-" + flavour)
    if meta is None or not configured(meta):
        raise RuntimeError("missing configured kernel metapackage")
    protected = {p.name for p in current} | {meta.name}
    for group in {IMAGE.fullmatch(p.name)["flavour"] for p in images}:
        versions = {p.installed.version for p in images if IMAGE.fullmatch(p.name)["flavour"] == group}
        latest = set(sorted(versions, key=cmp_to_key(apt_pkg.version_compare), reverse=True)[:KEEP])
        protected.update(p.name for p in images
                         if IMAGE.fullmatch(p.name)["flavour"] == group and p.installed.version in latest)
    candidates = [p for p in images if p.name not in protected and p.is_auto_installed and
                  p.is_auto_removable and p._pkg.selected_state == apt_pkg.SELSTATE_INSTALL and
                  not p.essential and p.installed.priority not in ("required", "important")]
    candidates.sort(key=cmp_to_key(lambda a, b: apt_pkg.version_compare(a.installed.version, b.installed.version)))
    retained = {name: cache[name].installed.version for name in protected}
    for package in candidates:
        # No resolver: a removal needing reverse dependencies or any other
        # transaction is deferred rather than broadening the removal scope.
        package.mark_delete(auto_fix=False, purge=False)
        changes = cache.get_changes()
        if (not cache.broken_count and cache.install_count == 0 and cache.delete_count == 1 and
                len(changes) == 1 and changes[0].name == package.name and changes[0].marked_delete):
            return package.name, retained
        cache.clear()
    return None, retained


def audit():
    result = subprocess.run(["/usr/bin/dpkg", "--audit"], capture_output=True, timeout=10, check=True)
    if result.stdout or result.stderr:
        raise RuntimeError("kernel cleanup requires an empty dpkg audit")


def transact(cache, running, apply):
    name, retained = select(cache, running)
    if name is None:
        return 0, {"removed": None, "pending": False}
    if not apply:
        return 0, {"selected": name, "retained": sorted(retained)}
    # The caller holds SystemLock from cache creation through postconditions.
    # Native commit drops/reacquires only the inner dpkg lock when required.
    if not cache.commit(allow_unauthenticated=False):
        raise RuntimeError("native kernel removal failed")
    cache.open()
    audit()
    if cache.dpkg_journal_dirty or cache.broken_count:
        raise RuntimeError("kernel removal left incomplete package state")
    if name in cache and cache[name].is_installed:
        raise RuntimeError("native kernel removal did not remove its target")
    for identity, version in retained.items():
        if identity not in cache or not configured(cache[identity]) or cache[identity].installed.version != version:
            raise RuntimeError("kernel removal changed a retained boot choice")
    next_name, _ = select(cache, running)
    cache.clear()
    return (75 if next_name else 0), {"removed": name, "pending": next_name is not None}


def main():
    if sys.argv[1:] not in (["--plan"], ["--apply"]):
        raise RuntimeError("expected --plan or --apply")
    apply = sys.argv[1] == "--apply"
    if apply and os.geteuid() != TRUSTED_UID:
        raise RuntimeError("kernel removal requires the trusted owner")
    trusted(POLICY)
    if os.environ.get("APT_CONFIG") != str(POLICY):
        raise RuntimeError("unexpected kernel APT profile")
    import apt
    import apt_pkg
    config = apt_pkg.config
    if (not config.find_b("APT::Protect-Kernels", False) or
            config.find("APT::NeverAutoRemove::KernelCount") or
            config.value_list("APT::VersionedKernelPackages") != ["linux-image"] or
            config.find_b("Debug::NoLocking", True) or
            config.find("Dir::Etc::parts") or config.find("Dir::Etc::main")):
        raise RuntimeError("unverified kernel protection configuration")
    status = Path(config.find_file("Dir::State::status"))
    trusted(status)
    trusted(status.parent, directory=True)
    extended = Path(config.find_file("Dir::State::extended_states"))
    trusted(extended.parent, directory=True)
    if extended.exists() or extended.is_symlink():
        trusted(extended)
    # --plan only reads native caches; it never enters a package-system lock or
    # commit. Production --apply takes the native lock BEFORE loading the cache.
    if apply:
        with apt_pkg.SystemLock():
            audit()
            result, message = transact(apt.Cache(memonly=True), os.uname().release, True)
    else:
        result, message = transact(apt.Cache(memonly=True), os.uname().release, False)
    print(json.dumps(message, sort_keys=True))
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 kernel retention: " + str(error), file=sys.stderr)
        sys.exit(1)
S4_PAYLOAD_b213906bff69cad34a5f2a547727622474f545c207bfca681f8a3dcac521b5ac
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
    cat > "$S4B_STAGE/lib/dotnet/common.sh" <<'S4_PAYLOAD_bc4da33d1b6068f61f3e88bf8251bc64ad5fe5dafcbbc9a98857712a177404e4' || return 1
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
    S4M_UPDATE_CLEANUP=s4m_skip_cleanup
    s4m_update
)
S4_PAYLOAD_bc4da33d1b6068f61f3e88bf8251bc64ad5fe5dafcbbc9a98857712a177404e4
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
    cat > "$S4B_STAGE/lib/network/common.sh" <<'S4_PAYLOAD_95a05f503668b3e24a05b33675d961a4d58700e17b4eab50f41da33dba72b632' || return 1
#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh

S4N_LIBRARY=/usr/local/lib/debian13s4/network
S4N_CONFIG=/etc/sysctl.d/90-debian13s4-network.conf
S4N_TIMER=debian13s4-network.timer
S4N_SERVICE=debian13s4-network.service
S4N_FILES=(common.sh repair.sh verify.py network.conf
    debian13s4-network.service debian13s4-network.timer)

s4n_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    [[ -f $S4M_LIBRARY/common.sh ]] && s4m_trusted "$S4M_LIBRARY/common.sh" || return 1
    for name in "${S4N_FILES[@]}"; do
        [[ -f $S4N_LIBRARY/$name ]] && s4m_trusted "$S4N_LIBRARY/$name" || return 1
    done
    [[ -x $S4N_LIBRARY/repair.sh ]]
}

s4n_identity() {
    local name digest
    for name in "${S4N_FILES[@]}"; do
        digest=$(sha256sum -- "$S4N_LIBRARY/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
    digest=$(sha256sum -- "$S4M_LIBRARY/common.sh") || return 1
    printf '%s maintenance/common.sh\n' "${digest%% *}"
}

s4n_controller() {
    local name
    s4n_assets || return 1
    for name in "$S4N_SERVICE" "$S4N_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4N_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" &&
            s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4N_TIMER" && s4m_property "$S4N_TIMER" ActiveState active
}

s4n_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/network.ready ]] && s4m_trusted "$S4M_STATE/network.ready" || return 1
    s4n_controller || return 1
    expected=$(s4n_identity) && actual=$(cat -- "$S4M_STATE/network.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4n_configure() {
    local directory=${S4N_CONFIG%/*}
    s4m_trusted "${directory%/*}" || return 1
    if [[ -e $directory || -L $directory ]]; then
        [[ -d $directory ]] && s4m_trusted "$directory" || return 1
    else
        mkdir -m 0755 -- "$directory" || return 1
    fi
    s4m_atomic "$S4N_CONFIG" "$S4N_LIBRARY/network.conf"
}

s4n_observe() {
    s4m_control /usr/bin/python3 -I -B "$S4N_LIBRARY/verify.py"
}

s4n_kernel() {
    # ip_forward is first in this exact policy: changing it can reset the other
    # IPv4 knobs. Native exit alone cannot prove optional/glob settings applied.
    s4m_control /usr/lib/systemd/systemd-sysctl --strict "$S4N_CONFIG" && s4n_observe
}

s4n_verify() {
    s4n_ready && [[ -f $S4N_CONFIG ]] && s4m_trusted "$S4N_CONFIG" &&
        cmp --silent -- "$S4N_LIBRARY/network.conf" "$S4N_CONFIG" && s4n_observe
}

s4n_apply() {
    local unit loaded wants resolved temporary
    s4n_assets || return 1
    for unit in "$S4N_TIMER" "$S4N_SERVICE"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/network.ready || -L $S4M_STATE/network.ready ]]; then
        [[ -f $S4M_STATE/network.ready ]] && s4m_trusted "$S4M_STATE/network.ready" || return 1
        rm -f -- "$S4M_STATE/network.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for unit in "$S4N_TIMER" "$S4N_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    s4n_configure && s4n_kernel || return 1
    for unit in "$S4N_SERVICE" "$S4N_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4N_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable "$S4N_TIMER" &&
        s4m_enabled "$S4N_TIMER" || return 1
    wants=$S4M_SYSTEMD/timers.target.wants
    [[ -d $wants && -L $wants/$S4N_TIMER ]] && s4m_trusted "$wants" || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4N_TIMER") || return 1
    [[ $resolved == "$S4M_SYSTEMD/$S4N_TIMER" ]] || return 1
    s4m_sync "$S4M_SYSTEMD" "$wants" "$S4M_SYSTEMD/$S4N_TIMER" "$S4M_SYSTEMD/$S4N_SERVICE" || return 1
    s4m_systemctl start "$S4N_TIMER" && s4n_controller || return 1
    temporary=$(mktemp -- "$S4M_STATE/network-intent.XXXXXX") || return 1
    if ! s4n_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/network.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4n_verify
}

s4n_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    # The task owns initial unit/readiness publication. Recurring repair admits
    # config drift without treating changed code/controller identity as healthy.
    s4n_ready && s4n_configure && s4n_kernel || return 75
}
S4_PAYLOAD_95a05f503668b3e24a05b33675d961a4d58700e17b4eab50f41da33dba72b632
    cat > "$S4B_STAGE/lib/network/repair.sh" <<'S4_PAYLOAD_f6c3d8720b50aad13e41edfa2a6890b2abe624d05e66920c86b003a520eaa541' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_repair
S4_PAYLOAD_f6c3d8720b50aad13e41edfa2a6890b2abe624d05e66920c86b003a520eaa541
    cat > "$S4B_STAGE/lib/network/verify.py" <<'S4_PAYLOAD_f8609255110e1e3cc5686bc366de484c9eb247028dfe817775b19b4a778d29c0' || return 1
"""Observe the host network policy; this helper never writes kernel settings."""

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path("/proc/sys")
TRUSTED_UID = 0
MAX_INTERFACES = 1024
GLOBALS = {"ip_forward": 0, "tcp_syncookies": 1,
           "icmp_echo_ignore_broadcasts": 1, "icmp_ignore_bogus_error_responses": 1}
IPV4 = {"forwarding": 0, "accept_redirects": 0, "send_redirects": 0,
        "accept_source_route": 0, "rp_filter": 2, "route_localnet": 0, "proxy_arp": 0}
IPV6 = {"forwarding": 0, "accept_redirects": 0, "accept_source_route": -1, "proxy_ndp": 0}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError(f"noncanonical path: {path}")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError(f"untrusted path: {current}")
        if current == Path("/"):
            return path.lstat()
        current = current.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def value(path):
    before = trusted(path, stat.S_ISREG)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(os.fstat(fd)) != signature(before):
            raise ValueError(f"changed descriptor: {path}")
        data = os.read(fd, 65)
        if len(data) > 64 or os.read(fd, 1) or not re.fullmatch(rb"-?[0-9]+\n?", data):
            raise ValueError(f"invalid scalar: {path}")
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError(f"changed scalar: {path}")
        return int(data)
    finally:
        os.close(fd)


def interfaces(family):
    base = PROC / "net" / family
    # A compiled-out or unloaded IPv6 stack has no namespace. Partial, symbolic
    # or unreadable namespaces cannot be confused with that optional absence.
    if family == "ipv6" and not os.path.lexists(base):
        trusted(base.parent, stat.S_ISDIR)
        return None
    directory = base / "conf"
    trusted(directory, stat.S_ISDIR)
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(names) >= MAX_INTERFACES + 2:
                raise ValueError("too many interfaces for bounded verification")
            if not entry.name or len(os.fsencode(entry.name)) > 15 or entry.name in (".", ".."):
                raise ValueError("invalid interface name")
            trusted(directory / entry.name, stat.S_ISDIR)
            names.append(entry.name)
    if not {"all", "default", "lo"}.issubset(names):
        raise ValueError(f"incomplete {family} interface inventory")
    return sorted(names)


def verify():
    inventories = {family: interfaces(family) for family in ("ipv4", "ipv6")}
    for name, expected in GLOBALS.items():
        path = PROC / "net/ipv4" / name
        if value(path) != expected:
            raise ValueError(f"policy differs: {path}")
    for family, policy in (("ipv4", IPV4), ("ipv6", IPV6)):
        for interface in inventories[family] or ():
            for name, expected in policy.items():
                path = PROC / "net" / family / "conf" / interface / name
                if value(path) != expected:
                    raise ValueError(f"policy differs: {path}")
    if any(interfaces(family) != names for family, names in inventories.items()):
        raise ValueError("interface inventory changed; retry required")


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        verify()
        return 0
    except (OSError, ValueError) as error:
        print(f"debian13s4 network verification: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
S4_PAYLOAD_f8609255110e1e3cc5686bc366de484c9eb247028dfe817775b19b4a778d29c0
    cat > "$S4B_STAGE/lib/network/network.conf" <<'S4_PAYLOAD_ba23f85b4240cf1ac9eb91929fba5ce15626c76eadad892ff2f3733aa928f696' || return 1
# Host networking, not routing. Keep ip_forward first: changing it resets IPv4 defaults.
net/ipv4/ip_forward = 0
net/ipv4/tcp_syncookies = 1
net/ipv4/icmp_echo_ignore_broadcasts = 1
net/ipv4/icmp_ignore_bogus_error_responses = 1
# Loose source validation accommodates asymmetric routes without manual configuration.
# Explicit defaults precede globs so interfaces created during application inherit policy.
net/ipv4/conf/all/forwarding = 0
net/ipv4/conf/all/accept_redirects = 0
net/ipv4/conf/all/send_redirects = 0
net/ipv4/conf/all/accept_source_route = 0
net/ipv4/conf/all/rp_filter = 2
net/ipv4/conf/all/route_localnet = 0
net/ipv4/conf/all/proxy_arp = 0
net/ipv4/conf/default/forwarding = 0
net/ipv4/conf/default/accept_redirects = 0
net/ipv4/conf/default/send_redirects = 0
net/ipv4/conf/default/accept_source_route = 0
net/ipv4/conf/default/rp_filter = 2
net/ipv4/conf/default/route_localnet = 0
net/ipv4/conf/default/proxy_arp = 0
net/ipv4/conf/*/forwarding = 0
net/ipv4/conf/*/accept_redirects = 0
net/ipv4/conf/*/send_redirects = 0
net/ipv4/conf/*/accept_source_route = 0
net/ipv4/conf/*/rp_filter = 2
net/ipv4/conf/*/route_localnet = 0
net/ipv4/conf/*/proxy_arp = 0
# IPv6 may be absent/unloaded. When present, the verifier requires every value.
# Preserve RA/SLAAC, DHCP, NDP, PMTU and IPv6 itself.
-net/ipv6/conf/all/forwarding = 0
-net/ipv6/conf/all/accept_redirects = 0
-net/ipv6/conf/all/accept_source_route = -1
-net/ipv6/conf/all/proxy_ndp = 0
-net/ipv6/conf/default/forwarding = 0
-net/ipv6/conf/default/accept_redirects = 0
-net/ipv6/conf/default/accept_source_route = -1
-net/ipv6/conf/default/proxy_ndp = 0
-net/ipv6/conf/*/forwarding = 0
-net/ipv6/conf/*/accept_redirects = 0
-net/ipv6/conf/*/accept_source_route = -1
-net/ipv6/conf/*/proxy_ndp = 0
S4_PAYLOAD_ba23f85b4240cf1ac9eb91929fba5ce15626c76eadad892ff2f3733aa928f696
    cat > "$S4B_STAGE/lib/network/debian13s4-network.service" <<'S4_PAYLOAD_eaaf6c2cdf2e36aa2bb49f9bf0a5b668c6788102813dbdb9104127413eb7a812' || return 1
[Unit]
Description=Verify and restore Debian 13 host network kernel policy
After=systemd-sysctl.service
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/sysctl.d
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/network/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# Six manager checks, two persistence barriers and two kernel controls: 110s,
# with 30s local allowance, fit this fixed deadline without interface scaling.
TimeoutStartSec=180s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=1min
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ReadOnlyPaths=/proc/sys /sys
ReadWritePaths=/etc/sysctl.d /var/lib/debian13s4 /proc/sys/net
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=~@mount
S4_PAYLOAD_eaaf6c2cdf2e36aa2bb49f9bf0a5b668c6788102813dbdb9104127413eb7a812
    cat > "$S4B_STAGE/lib/network/debian13s4-network.timer" <<'S4_PAYLOAD_13c391ea87a782aaae1b1e2ed6629a340c9bcd37841e54a09000709e4c663b03' || return 1
[Unit]
Description=Reconcile host network policy after boot and periodically

[Timer]
OnBootSec=10s
OnUnitInactiveSec=2min
AccuracySec=5s
Unit=debian13s4-network.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_13c391ea87a782aaae1b1e2ed6629a340c9bcd37841e54a09000709e4c663b03
    cat > "$S4B_STAGE/lib/tasks/network/apply.sh" <<'S4_PAYLOAD_978090bd3843e6a8dbedce17864be98ac183fa3313ba2bcece27d8b4c4ceea1b' || return 1
#!/bin/bash
# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_apply
S4_PAYLOAD_978090bd3843e6a8dbedce17864be98ac183fa3313ba2bcece27d8b4c4ceea1b
    cat > "$S4B_STAGE/lib/tasks/network/verify.sh" <<'S4_PAYLOAD_2c4a253e0fba47833ef625a9f3ea5b15062b3e43ffc36a6a6861a06dcaf2ace4' || return 1
#!/bin/bash
# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_verify
S4_PAYLOAD_2c4a253e0fba47833ef625a9f3ea5b15062b3e43ffc36a6a6861a06dcaf2ace4
    cat > "$S4B_STAGE/lib/retention/common.sh" <<'S4_PAYLOAD_c7bf108d8bf796d7db45af4030142b1ca066aa9b224639943b794e2a9626fb6a' || return 1
#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh

S4R_LIBRARY=/usr/local/lib/debian13s4/retention
S4R_CONFIG=/etc/systemd/journald.conf.d/90-debian13s4-retention.conf
S4R_TIMER=debian13s4-retention.timer
S4R_SERVICE=debian13s4-retention.service
S4R_JOURNAL=systemd-journald.service
S4R_SECONDS=180
S4R_GRACE_SECONDS=10
S4R_FILES=(common.sh repair.sh journal.py clean-cache.py apt.conf journal.conf
    debian13s4-retention.service debian13s4-retention.timer)

s4r_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    [[ -f $S4M_LIBRARY/common.sh ]] && s4m_trusted "$S4M_LIBRARY/common.sh" || return 1
    for name in "${S4R_FILES[@]}"; do
        [[ -f $S4R_LIBRARY/$name ]] && s4m_trusted "$S4R_LIBRARY/$name" || return 1
    done
    [[ -x $S4R_LIBRARY/repair.sh ]]
}

s4r_identity() {
    local name digest
    for name in "${S4R_FILES[@]}"; do
        digest=$(sha256sum -- "$S4R_LIBRARY/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
    digest=$(sha256sum -- "$S4M_LIBRARY/common.sh") || return 1
    printf '%s maintenance/common.sh\n' "${digest%% *}"
}

s4r_controller() {
    local name
    s4r_assets || return 1
    for name in "$S4R_SERVICE" "$S4R_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4R_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" &&
            s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4R_TIMER" && s4m_property "$S4R_TIMER" ActiveState active
}

s4r_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/retention.ready ]] && s4m_trusted "$S4M_STATE/retention.ready" || return 1
    s4r_controller || return 1
    expected=$(s4r_identity) && actual=$(cat -- "$S4M_STATE/retention.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4r_configure() {
    local directory=${S4R_CONFIG%/*}
    s4m_trusted "${directory%/*}" || return 1
    if [[ -e $directory || -L $directory ]]; then
        [[ -d $directory ]] && s4m_trusted "$directory" || return 1
    else
        mkdir -m 0755 -- "$directory" || return 1
    fi
    s4m_atomic "$S4R_CONFIG" "$S4R_LIBRARY/journal.conf"
}

s4r_generation() {
    local invocation
    s4m_property "$S4R_JOURNAL" FragmentPath /usr/lib/systemd/system/systemd-journald.service &&
        s4m_property "$S4R_JOURNAL" DropInPaths '' &&
        s4m_property "$S4R_JOURNAL" Result success &&
        s4m_property "$S4R_JOURNAL" ActiveState active || return 1
    invocation=$(s4m_systemctl show --property=InvocationID --value "$S4R_JOURNAL") || return 1
    [[ $invocation =~ ^[0-9a-f]{32}$ && $invocation != 00000000000000000000000000000000 ]] || return 1
    printf '%s\n' "$invocation"
}

s4r_policy() {
    local digest
    digest=$(s4m_control /usr/bin/python3 -I -B "$S4R_LIBRARY/journal.py" --config) || return 1
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

s4r_applied() {
    local digest=$1 generation=$2 actual
    [[ -f $S4M_STATE/journal.applied ]] && s4m_trusted "$S4M_STATE/journal.applied" || return 1
    actual=$(cat -- "$S4M_STATE/journal.applied") || return 1
    [[ $actual == "$digest $generation" ]]
}

s4r_bounded() (
    local descriptor=$S4M_REPAIR_FD
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after="${S4R_GRACE_SECONDS}s" "${S4R_SECONDS}s" \
        env -i PATH="$S4M_PATH" LANG=C LC_ALL=C "$@"
)

s4r_journal() {
    local digest before after observed temporary
    s4r_configure || return 1
    # This also checks default journal paths before any restart or deletion.
    digest=$(s4r_policy) || return 1
    before=$(s4m_systemctl show --property=InvocationID --value "$S4R_JOURNAL") || return 1
    observed=$(s4r_generation) || observed=
    if ! s4r_applied "$digest" "$before" || [[ $observed != "$before" ]]; then
        # A restart preserves native log-stream descriptors. Never stop and
        # then start journald separately, and never accept a queued/no-op restart.
        s4m_systemctl restart "$S4R_JOURNAL" || return 1
        after=$(s4r_generation) || return 1
        [[ $after != "$before" ]] && [[ $(s4r_policy) == "$digest" ]] || return 1
        temporary=$(mktemp -- "$S4M_STATE/journal-intent.XXXXXX") || return 1
        if ! printf '%s %s\n' "$digest" "$after" > "$temporary" ||
            ! chmod 0600 -- "$temporary" || ! s4m_atomic "$S4M_STATE/journal.applied" "$temporary" 0600; then
            rm -f -- "$temporary"
            return 1
        fi
        rm -f -- "$temporary" || return 1
    fi
    s4r_bounded /usr/bin/python3 -I -B "$S4R_LIBRARY/journal.py" --vacuum || return 1
    after=$(s4r_generation) && [[ $(s4r_policy) == "$digest" ]] && s4r_applied "$digest" "$after"
}

s4r_cache() {
    s4r_bounded /usr/bin/env APT_CONFIG="$S4R_LIBRARY/apt.conf" \
        /usr/bin/python3 -I -B "$S4R_LIBRARY/clean-cache.py" --apply
}

s4r_work() {
    local failed=0
    # Independent finite stages: journal failure/timeouts cannot suppress cache
    # repair, and this controller does not occupy the package updater's budget.
    s4r_journal || failed=1
    s4r_cache || failed=1
    (( failed == 0 ))
}

s4r_verify() {
    local digest generation
    s4r_ready && [[ -f $S4R_CONFIG ]] && s4m_trusted "$S4R_CONFIG" &&
        cmp --silent -- "$S4R_LIBRARY/journal.conf" "$S4R_CONFIG" || return 1
    digest=$(s4r_policy) && generation=$(s4r_generation) && s4r_applied "$digest" "$generation" || return 1
    s4m_control /usr/bin/python3 -I -B "$S4R_LIBRARY/journal.py" --observe
}

s4r_apply() {
    local unit loaded wants resolved temporary
    s4r_assets || return 1
    for unit in "$S4R_TIMER" "$S4R_SERVICE"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/retention.ready || -L $S4M_STATE/retention.ready ]]; then
        [[ -f $S4M_STATE/retention.ready ]] && s4m_trusted "$S4M_STATE/retention.ready" || return 1
        rm -f -- "$S4M_STATE/retention.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for unit in "$S4R_TIMER" "$S4R_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    # Generic setup repair retains ownership until all initial work succeeds.
    s4r_work || return 1
    for unit in "$S4R_SERVICE" "$S4R_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4R_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable "$S4R_TIMER" && s4m_enabled "$S4R_TIMER" || return 1
    wants=$S4M_SYSTEMD/timers.target.wants
    [[ -d $wants && -L $wants/$S4R_TIMER ]] && s4m_trusted "$wants" || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4R_TIMER") || return 1
    [[ $resolved == "$S4M_SYSTEMD/$S4R_TIMER" ]] || return 1
    s4m_sync "$S4M_SYSTEMD" "$wants" "$S4M_SYSTEMD/$S4R_TIMER" "$S4M_SYSTEMD/$S4R_SERVICE" || return 1
    s4m_systemctl start "$S4R_TIMER" && s4r_controller || return 1
    temporary=$(mktemp -- "$S4M_STATE/retention-intent.XXXXXX") || return 1
    if ! s4r_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/retention.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4r_verify
}

s4r_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    s4r_ready && s4r_work || return 75
}
S4_PAYLOAD_c7bf108d8bf796d7db45af4030142b1ca066aa9b224639943b794e2a9626fb6a
    cat > "$S4B_STAGE/lib/retention/repair.sh" <<'S4_PAYLOAD_2d85e370e47f67a7500e72a9048b78f033246f13d1ccf37d1eb79740a7e1b330' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_repair
S4_PAYLOAD_2d85e370e47f67a7500e72a9048b78f033246f13d1ccf37d1eb79740a7e1b330
    cat > "$S4B_STAGE/lib/retention/journal.py" <<'S4_PAYLOAD_d164649f35a3441e5eb6564d552a540f3cca1748f61ec8a59f18196e9fcefeb4' || return 1
"""Check the default journal's effective policy and archived-file retention."""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


TRUSTED_UID = 0
PREFIXES = tuple(Path(p) for p in ("/etc/systemd", "/run/systemd", "/usr/local/lib/systemd", "/usr/lib/systemd"))
MACHINE = Path("/etc/machine-id")
JOURNALS = ((Path("/var/log/journal"), 128 * 1024**2, 32),
            (Path("/run/log/journal"), 32 * 1024**2, 8))
POLICY = {
    "Storage": "persistent", "Compress": "yes",
    "SystemMaxUse": "128M", "RuntimeMaxUse": "32M",
    "SystemKeepFree": "512M", "RuntimeKeepFree": "64M",
    "SystemMaxFileSize": "8M", "RuntimeMaxFileSize": "4M",
    "SystemMaxFiles": "32", "RuntimeMaxFiles": "8",
    "MaxFileSec": "1day", "MaxRetentionSec": "14day",
}
MAX_INPUT = 1024**2
MAX_FILES = 100000
AGE = 14 * 86400
ARCHIVE = re.compile(r".+@[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-([0-9a-fA-F]{16})\.journal\Z")
UNCLEAN = re.compile(r".+@([0-9a-fA-F]{16})-[0-9a-fA-F]{16}\.journal~\Z")


def trusted(path, kind=stat.S_ISREG):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("noncanonical journal path")
    leaf = path
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError("untrusted journal path: " + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path):
    before = trusted(path)
    if before.st_size > MAX_INPUT:
        raise ValueError("oversized journal input")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(before) != signature(os.fstat(descriptor)):
            raise ValueError("journal input descriptor changed")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, MAX_INPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_INPUT:
                raise ValueError("oversized journal input")
        if signature(before) != signature(os.fstat(descriptor)) or signature(before) != signature(trusted(path)):
            raise ValueError("journal input changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def sources():
    result = {}
    total = 0
    def add(path):
        nonlocal total
        if len(result) >= 1024:
            raise ValueError("excessive journal configuration")
        data = read(path)
        total += len(data)
        if total > MAX_INPUT:
            raise ValueError("excessive journal configuration")
        result[str(path)] = data
    for prefix in PREFIXES:
        for path in (prefix / "journald.conf", prefix / "journald.conf.d"):
            if not path.exists() and not path.is_symlink():
                continue
            if path.name == "journald.conf":
                add(path)
            else:
                trusted(path, stat.S_ISDIR)
                for leaf in path.iterdir():
                    if leaf.name.endswith(".conf"):
                        add(leaf)
    return result


def policy(text):
    values, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        # Refuse syntax whose continuation/quoting could make this observer
        # disagree with the native parser, rather than guessing its meaning.
        if line.endswith("\\"):
            raise ValueError("continued journal configuration is unverifiable")
        if line.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z0-9]+\]", line):
                raise ValueError("invalid journal section")
            section = line[1:-1]
        elif section == "Journal":
            key, separator, value = line.partition("=")
            if not separator:
                raise ValueError("invalid journal assignment")
            if key.strip() in POLICY:
                values[key.strip()] = value.strip()
    if values != POLICY:
        raise ValueError("effective journal policy differs")


def configuration():
    before = sources()
    result = subprocess.run(["/usr/bin/systemd-analyze", "--no-pager", "cat-config", "systemd/journald.conf"],
                            capture_output=True, check=True, timeout=5)
    if result.stderr or len(result.stdout) > MAX_INPUT + 262144:
        raise ValueError("unverifiable native journal configuration")
    text = result.stdout.decode("utf-8", errors="strict")
    emitted = re.findall(r"^# (/[^\n]+)$", text, re.M)
    if not emitted or len(emitted) != len(set(emitted)) or any(path not in before for path in emitted):
        raise ValueError("untrusted native journal configuration source")
    policy(text)
    if sources() != before:
        raise ValueError("journal configuration changed")
    return hashlib.sha256(result.stdout).hexdigest()


def directories(require_persistent=False):
    data = read(MACHINE)
    if not re.fullmatch(rb"[0-9a-f]{32}\n?", data):
        raise ValueError("unverifiable journal machine identity")
    machine = data.decode("ascii", errors="strict").rstrip("\n")
    if not re.fullmatch(r"[0-9a-f]{32}", machine) or machine == "0" * 32:
        raise ValueError("unverifiable journal machine identity")
    result = []
    for base, size, count in JOURNALS:
        if base.exists() or base.is_symlink():
            trusted(base, stat.S_ISDIR)
            path = base / machine
            if path.exists() or path.is_symlink():
                trusted(path, stat.S_ISDIR)
                inventory(path)
                result.append((path, size, count))
                continue
        else:
            trusted(base.parent, stat.S_ISDIR)
        if require_persistent and base == JOURNALS[0][0]:
            raise ValueError("persistent default journal is absent")
    return result


def inventory(path):
    result = []
    for leaf in path.iterdir():
        info = trusted(leaf)
        match = ARCHIVE.fullmatch(leaf.name) or UNCLEAN.fullmatch(leaf.name)
        if match:
            stamp = min(int(match[1], 16), info.st_mtime_ns // 1000,
                        info.st_ctime_ns // 1000, info.st_atime_ns // 1000)
            result.append((leaf.name, info.st_blocks * 512, stamp))
        if len(result) > MAX_FILES:
            raise ValueError("excessive journal inventory")
    return result


def observe():
    now = int(time.time() * 1000000)
    for path, size, count in directories(require_persistent=True):
        rows = inventory(path)
        if (len(rows) > count or sum(row[1] for row in rows) > size or
                any(row[2] < max(0, now - AGE * 1000000) for row in rows)):
            raise ValueError("archived default journals still exceed retention")


def vacuum():
    directories()
    subprocess.run(["/usr/bin/journalctl", "--flush"], check=True, timeout=40)
    subprocess.run(["/usr/bin/journalctl", "--rotate"], check=True, timeout=40)
    for path, size, count in directories(require_persistent=True):
        subprocess.run(["/usr/bin/journalctl", "--directory=" + str(path),
                        "--vacuum-size=" + str(size), "--vacuum-time=14days", "--vacuum-files=" + str(count)],
                       check=True, timeout=40)
    # Native vacuum logs unlink failures but may still exit zero. Actual
    # archived-file observations are required; active files are not a quota.
    observe()


def main():
    if sys.argv[1:] == ["--config"]:
        directories()
        print(configuration())
    elif sys.argv[1:] == ["--observe"]:
        observe()
    elif sys.argv[1:] == ["--vacuum"] and os.geteuid() == TRUSTED_UID:
        vacuum()
    else:
        raise ValueError("expected --config, --observe or trusted --vacuum")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 journal retention: " + str(error), file=sys.stderr)
        sys.exit(1)
S4_PAYLOAD_d164649f35a3441e5eb6564d552a540f3cca1748f61ec8a59f18196e9fcefeb4
    cat > "$S4B_STAGE/lib/retention/clean-cache.py" <<'S4_PAYLOAD_715e936a70e166fa6c3bc4e63a4b2fed4fec56b33960c3810d2af54be01489d5' || return 1
"""Clean only APT download archives after a checked, locked package audit."""

import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


POLICY = Path("/usr/local/lib/debian13s4/retention/apt.conf")
CACHE = Path("/var/cache/apt/archives")
LISTS = Path("/var/lib/debian13s4/retention-empty-lists")
STATUS = Path("/var/lib/dpkg/status")
TRUSTED_UID = 0
MAX_FILES = 100000
RESERVED = {"lock", "partial", "auxfiles", "lost+found"}


def trusted(path, kind=stat.S_ISREG, owners=None):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError("noncanonical archive path")
    leaf = path
    while True:
        info = path.lstat()
        allowed = (owners or {TRUSTED_UID}) if path == leaf else {TRUSTED_UID}
        if path != leaf and path in {CACHE / "partial", LISTS / "partial"}:
            allowed = {TRUSTED_UID, pwd.getpwnam("_apt").pw_uid}
        if (not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_mode & 0o022 or
                info.st_uid not in allowed):
            raise ValueError("untrusted archive path: " + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def inventory(directory, partial=False):
    owners = {TRUSTED_UID, pwd.getpwnam("_apt").pw_uid}
    trusted(directory, stat.S_ISDIR, owners if partial else None)
    result = []
    for leaf in directory.iterdir():
        if not partial and leaf.name in {"partial", "auxfiles", "lost+found"}:
            trusted(leaf, stat.S_ISDIR, owners if leaf.name in {"partial", "auxfiles"} else None)
            if leaf.name == "partial":
                result.extend(inventory(leaf, partial=True))
        else:
            # Validate lock leaves too: native GetLock uses O_RDWR and must not
            # receive a FIFO/device even though it already refuses symlinks.
            trusted(leaf, owners=None if leaf.name == "lock" else owners)
            if partial or leaf.name not in RESERVED:
                result.append(leaf)
        if len(result) > MAX_FILES:
            raise ValueError("excessive archive inventory")
    return result


def prepare():
    trusted(CACHE.parent, stat.S_ISDIR)
    if not CACHE.exists() and not CACHE.is_symlink():
        CACHE.mkdir(mode=0o755)
    inventory(CACHE)
    trusted(LISTS.parent, stat.S_ISDIR)
    if not LISTS.exists() and not LISTS.is_symlink():
        LISTS.mkdir(mode=0o700)
    inventory(LISTS)


def audit():
    result = subprocess.run(["/usr/bin/dpkg", "--audit"], capture_output=True, check=True, timeout=10)
    if result.stdout or result.stderr:
        raise ValueError("archive cleanup requires an empty dpkg audit")


def configuration():
    trusted(POLICY)
    trusted(STATUS)
    if os.environ.get("APT_CONFIG") != str(POLICY):
        raise ValueError("unexpected archive APT profile")
    import apt_pkg
    apt_pkg.init()
    config = apt_pkg.config
    if (config.find("Dir::Etc::parts") or config.find("Dir::Etc::main") or
            config.find("Dir::Etc::sourcelist") != "-" or config.find("Dir::Etc::sourceparts") != "-" or
            config.find_dir("Dir::Cache::archives").rstrip("/") != str(CACHE) or
            config.find_dir("Dir::State::lists").rstrip("/") != str(LISTS) or
            config.find_file("Dir::Cache::pkgcache") or config.find_file("Dir::Cache::srcpkgcache") or
            config.find_file("Dir::State::status") != str(STATUS) or
            config.find_b("Debug::NoLocking", True) or config.find("APT::Sandbox::User") != "_apt"):
        raise ValueError("unverified archive cleanup configuration")
    return apt_pkg


def clean():
    apt_pkg = configuration()
    # Retain repair downloads while dpkg is incomplete. The native package
    # lock covers the audit, archive delivery and postconditions; apt-get clean
    # also owns the native archive lock, without disabling either lock.
    with apt_pkg.SystemLock():
        audit()
        prepare()
        subprocess.run(["/usr/bin/apt-get", "clean"], check=True, timeout=120)
        if inventory(CACHE) or inventory(LISTS):
            raise ValueError("native archive cleanup left downloaded files")
        audit()


def main():
    if sys.argv[1:] != ["--apply"] or os.geteuid() != TRUSTED_UID:
        raise ValueError("archive cleanup requires trusted --apply")
    clean()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print("debian13s4 archive retention: " + str(error), file=sys.stderr)
        sys.exit(1)
S4_PAYLOAD_715e936a70e166fa6c3bc4e63a4b2fed4fec56b33960c3810d2af54be01489d5
    cat > "$S4B_STAGE/lib/retention/apt.conf" <<'S4_PAYLOAD_dfdda3c5c5f008fc693b0fb1e47a04df8ff33aae4ddc90f4c2126f612115d6ef' || return 1
// APT_CONFIG loads this before any host fragments. Clean only downloaded
// archives: retain authenticated indexes, status and existing metadata caches.
Dir::Etc::parts "";
Dir::Etc::main "";
Dir::Etc::sourcelist "-";
Dir::Etc::sourceparts "-";
Dir::Cache::archives "/var/cache/apt/archives";
Dir::State::lists "/var/lib/debian13s4/retention-empty-lists";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Debug::NoLocking "false";
APT::Sandbox::User "_apt";
S4_PAYLOAD_dfdda3c5c5f008fc693b0fb1e47a04df8ff33aae4ddc90f4c2126f612115d6ef
    cat > "$S4B_STAGE/lib/retention/journal.conf" <<'S4_PAYLOAD_6a2cae9f09342d5f54c40602d0b5a4b10aca08ee34bd3c35bf1deb09a90c3729' || return 1
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=128M
RuntimeMaxUse=32M
SystemKeepFree=512M
RuntimeKeepFree=64M
SystemMaxFileSize=8M
RuntimeMaxFileSize=4M
SystemMaxFiles=32
RuntimeMaxFiles=8
MaxFileSec=1day
MaxRetentionSec=14day
S4_PAYLOAD_6a2cae9f09342d5f54c40602d0b5a4b10aca08ee34bd3c35bf1deb09a90c3729
    cat > "$S4B_STAGE/lib/retention/debian13s4-retention.service" <<'S4_PAYLOAD_4a18bd9011f90260329a19cdf2747f01f041bafd7184978b5cb8ac8eece4eba5' || return 1
[Unit]
Description=Reconcile journal retention and clean completed package downloads
After=systemd-journald.service
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /var/cache/apt /etc/systemd
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/retention/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# At most 32 controls (352s), two independent 180s+10s stages and 60s local
# allowance fit 900s. Neither stage can consume the other's admission budget.
TimeoutStartSec=900s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=15min
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
ProtectSystem=strict
ReadWritePaths=/etc/systemd /var/lib/debian13s4 /var/cache/apt /var/lib/dpkg -/var/log/journal -/run/log/journal
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=~@mount
S4_PAYLOAD_4a18bd9011f90260329a19cdf2747f01f041bafd7184978b5cb8ac8eece4eba5
    cat > "$S4B_STAGE/lib/retention/debian13s4-retention.timer" <<'S4_PAYLOAD_3484989b87fe25b6eed5e8759d0ff036007e85e10d1e2a6fa129d6294fb18048' || return 1
[Unit]
Description=Reconcile journal and download retention after boot and hourly

[Timer]
OnBootSec=5min
OnUnitInactiveSec=1h
RandomizedDelaySec=2min
AccuracySec=1min
Unit=debian13s4-retention.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_3484989b87fe25b6eed5e8759d0ff036007e85e10d1e2a6fa129d6294fb18048
    cat > "$S4B_STAGE/lib/tasks/retention/apply.sh" <<'S4_PAYLOAD_6a932d600d6894880eaa54c51b274d7bee8cb081fc7018371a43ecf9ac103fb2' || return 1
#!/bin/bash
# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_apply
S4_PAYLOAD_6a932d600d6894880eaa54c51b274d7bee8cb081fc7018371a43ecf9ac103fb2
    cat > "$S4B_STAGE/lib/tasks/retention/verify.sh" <<'S4_PAYLOAD_eaf8d9e89061834624d417ebec6211c3257dcecf52030178597b2c93859503dc' || return 1
#!/bin/bash
# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_verify
S4_PAYLOAD_eaf8d9e89061834624d417ebec6211c3257dcecf52030178597b2c93859503dc
    cat > "$S4B_STAGE/lib/hardening/common.sh" <<'S4_PAYLOAD_b7e4737e20c27894bbd2613f8df131614b6d0ebfc9aa589c758df9aac2de8efc' || return 1
#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh

S4H_LIBRARY=/usr/local/lib/debian13s4/hardening
S4H_CONFIG=/etc/sysctl.d/90-debian13s4-kernel.conf
S4H_TIMER=debian13s4-hardening.timer
S4H_SERVICE=debian13s4-hardening.service
S4H_FILES=(common.sh repair.sh verify.py kernel.conf
    debian13s4-hardening.service debian13s4-hardening.timer)

s4h_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    [[ -f $S4M_LIBRARY/common.sh ]] && s4m_trusted "$S4M_LIBRARY/common.sh" || return 1
    for name in "${S4H_FILES[@]}"; do
        [[ -f $S4H_LIBRARY/$name ]] && s4m_trusted "$S4H_LIBRARY/$name" || return 1
    done
    [[ -x $S4H_LIBRARY/repair.sh ]]
}

s4h_identity() {
    local name digest
    for name in "${S4H_FILES[@]}"; do
        digest=$(sha256sum -- "$S4H_LIBRARY/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
    digest=$(sha256sum -- "$S4M_LIBRARY/common.sh") || return 1
    printf '%s maintenance/common.sh\n' "${digest%% *}"
}

s4h_controller() {
    local name
    s4h_assets || return 1
    for name in "$S4H_SERVICE" "$S4H_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4H_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" &&
            s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4H_TIMER" && s4m_property "$S4H_TIMER" ActiveState active
}

s4h_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/hardening.ready ]] && s4m_trusted "$S4M_STATE/hardening.ready" || return 1
    s4h_controller || return 1
    expected=$(s4h_identity) && actual=$(cat -- "$S4M_STATE/hardening.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4h_configure() {
    local directory=${S4H_CONFIG%/*}
    s4m_trusted "${directory%/*}" || return 1
    if [[ -e $directory || -L $directory ]]; then
        [[ -d $directory ]] && s4m_trusted "$directory" || return 1
    else
        mkdir -m 0755 -- "$directory" || return 1
    fi
    s4m_atomic "$S4H_CONFIG" "$S4H_LIBRARY/kernel.conf"
}

s4h_observe() {
    s4m_control /usr/bin/python3 -I -B "$S4H_LIBRARY/verify.py"
}

s4h_kernel() {
    local plan key
    local -a options=(--strict)
    # The real observer admits every required scalar before any native write.
    # Only drifting keys are included: never weaken an existing stronger
    # ptrace/perf restriction or rewrite an irreversible healthy BPF setting.
    plan=$(s4m_control /usr/bin/python3 -I -B "$S4H_LIBRARY/verify.py" --plan) || return 1
    if [[ -n $plan ]]; then
        while IFS= read -r key; do
            [[ $key =~ ^(kernel|fs|vm)/[a-z_]+(/[a-z_]+)?$ ]] || return 1
            options+=("--prefix=$key")
        done <<< "$plan"
        s4m_control /usr/lib/systemd/systemd-sysctl "${options[@]}" "$S4H_CONFIG" || return 1
    fi
    s4h_observe
}

s4h_verify() {
    s4h_ready && [[ -f $S4H_CONFIG ]] && s4m_trusted "$S4H_CONFIG" &&
        cmp --silent -- "$S4H_LIBRARY/kernel.conf" "$S4H_CONFIG" && s4h_observe
}

s4h_apply() {
    local unit loaded wants resolved temporary
    s4h_assets || return 1
    for unit in "$S4H_TIMER" "$S4H_SERVICE"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/hardening.ready || -L $S4M_STATE/hardening.ready ]]; then
        [[ -f $S4M_STATE/hardening.ready ]] && s4m_trusted "$S4M_STATE/hardening.ready" || return 1
        rm -f -- "$S4M_STATE/hardening.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for unit in "$S4H_TIMER" "$S4H_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    s4h_configure && s4h_kernel || return 1
    for unit in "$S4H_SERVICE" "$S4H_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4H_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable "$S4H_TIMER" &&
        s4m_enabled "$S4H_TIMER" || return 1
    wants=$S4M_SYSTEMD/timers.target.wants
    [[ -d $wants && -L $wants/$S4H_TIMER ]] && s4m_trusted "$wants" || return 1
    resolved=$(readlink --canonicalize-existing -- "$wants/$S4H_TIMER") || return 1
    [[ $resolved == "$S4M_SYSTEMD/$S4H_TIMER" ]] || return 1
    s4m_sync "$S4M_SYSTEMD" "$wants" "$S4M_SYSTEMD/$S4H_TIMER" "$S4M_SYSTEMD/$S4H_SERVICE" || return 1
    s4m_systemctl start "$S4H_TIMER" && s4h_controller || return 1
    temporary=$(mktemp -- "$S4M_STATE/hardening-intent.XXXXXX") || return 1
    if ! s4h_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/hardening.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4h_verify
}

s4h_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    # The task owns initial unit/readiness publication. Recurring repair admits
    # config drift without treating changed code/controller identity as healthy.
    s4h_ready && s4h_configure && s4h_kernel || return 75
}
S4_PAYLOAD_b7e4737e20c27894bbd2613f8df131614b6d0ebfc9aa589c758df9aac2de8efc
    cat > "$S4B_STAGE/lib/hardening/repair.sh" <<'S4_PAYLOAD_7d84a4dd2ff8134daaf14cd35175acb429e89c64404db5f48a0850b5579b4fe2' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_repair
S4_PAYLOAD_7d84a4dd2ff8134daaf14cd35175acb429e89c64404db5f48a0850b5579b4fe2
    cat > "$S4B_STAGE/lib/hardening/verify.py" <<'S4_PAYLOAD_08603c329a5de83416253604ca14bf538773dd2b7fc7a39cdd97ee0afa72b424' || return 1
"""Observe required host controls and plan only their drifting sysctl keys."""

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path("/proc/sys")
TRUSTED_UID = 0
POLICY = {
    "kernel/randomize_va_space": 2,
    "kernel/kptr_restrict": 2,
    "kernel/dmesg_restrict": 1,
    "kernel/perf_event_paranoid": 3,
    "kernel/yama/ptrace_scope": 2,
    "kernel/unprivileged_bpf_disabled": 1,
    "kernel/sysrq": 0,
    "fs/suid_dumpable": 0,
    "fs/protected_symlinks": 1,
    "fs/protected_hardlinks": 1,
    "fs/protected_fifos": 2,
    "fs/protected_regular": 2,
    "vm/unprivileged_userfaultfd": 0,
}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError("noncanonical host-control path")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError("untrusted host-control path: " + str(current))
        if current == current.parent:
            return path.lstat()
        current = current.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def value(path):
    before = trusted(path, stat.S_ISREG)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(os.fstat(descriptor)) != signature(before):
            raise ValueError("host-control descriptor changed")
        data = os.read(descriptor, 65)
        if len(data) > 64 or os.read(descriptor, 1) or not re.fullmatch(rb"-?[0-9]+\n?", data):
            raise ValueError("invalid host-control scalar")
        number = int(data)
        if not -2147483648 <= number <= 2147483647:
            raise ValueError("host-control scalar outside native integer range")
        if signature(os.fstat(descriptor)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError("host-control scalar changed")
        return number
    finally:
        os.close(descriptor)


def complies(key, number):
    if key == "kernel/perf_event_paranoid":
        return number >= POLICY[key]
    if key == "kernel/yama/ptrace_scope":
        return number in (2, 3)
    return number == POLICY[key]


def plan():
    # Every control is required. Missing/partial/unverifiable namespaces fail
    # before emitting a write plan, including kernels lacking the needed LSM.
    before = {key: value(PROC / key) for key in POLICY}
    after = {key: value(PROC / key) for key in POLICY}
    if before != after:
        raise ValueError("host controls changed during observation; retry required")
    return [key for key, number in before.items() if not complies(key, number)]


def main():
    if sys.argv[1:] not in ([], ["--plan"]):
        return 64
    try:
        pending = plan()
        if sys.argv[1:]:
            if pending:
                print("\n".join(pending))
        elif pending:
            raise ValueError("host policy differs: " + ", ".join(pending))
        return 0
    except (OSError, ValueError) as error:
        print("debian13s4 host verification: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())
S4_PAYLOAD_08603c329a5de83416253604ca14bf538773dd2b7fc7a39cdd97ee0afa72b424
    cat > "$S4B_STAGE/lib/hardening/kernel.conf" <<'S4_PAYLOAD_383ca561603ed05e64f68cd788ff3f223c2ec48ad2c8d665526b96c66b0e5c7d' || return 1
# Fixed host policy; stronger live ptrace/perf values are admitted by repair.
kernel/randomize_va_space = 2
kernel/kptr_restrict = 2
kernel/dmesg_restrict = 1
kernel/perf_event_paranoid = 3
kernel/yama/ptrace_scope = 2
# Value 1 cannot be cleared from this running kernel, including by root.
kernel/unprivileged_bpf_disabled = 1
kernel/sysrq = 0
fs/suid_dumpable = 0
fs/protected_symlinks = 1
fs/protected_hardlinks = 1
fs/protected_fifos = 2
fs/protected_regular = 2
vm/unprivileged_userfaultfd = 0
S4_PAYLOAD_383ca561603ed05e64f68cd788ff3f223c2ec48ad2c8d665526b96c66b0e5c7d
    cat > "$S4B_STAGE/lib/hardening/debian13s4-hardening.service" <<'S4_PAYLOAD_6360caf81c8e4c93cbfc6cd0e62e9ddd6ddd207b843eed0b17deae08cdea811b' || return 1
[Unit]
Description=Verify and restore Debian 13 host kernel exploit-mitigation policy
After=systemd-sysctl.service
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/sysctl.d
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/hardening/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# Six manager checks, two persistence barriers and three kernel controls: 121s,
# with 30s local allowance, fit this fixed deadline without interface scaling.
TimeoutStartSec=180s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=1min
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE
ProtectSystem=strict
ReadOnlyPaths=/proc/sys /sys
ReadWritePaths=/etc/sysctl.d /var/lib/debian13s4 /proc/sys/kernel /proc/sys/fs /proc/sys/vm
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=~@mount
S4_PAYLOAD_6360caf81c8e4c93cbfc6cd0e62e9ddd6ddd207b843eed0b17deae08cdea811b
    cat > "$S4B_STAGE/lib/hardening/debian13s4-hardening.timer" <<'S4_PAYLOAD_e2de7086c2159bf4cd8a2775d8a3aba484b1c5c5237f9c4a36f7e0db4c8e371a' || return 1
[Unit]
Description=Reconcile host hardening policy after boot and periodically

[Timer]
OnBootSec=10s
OnUnitInactiveSec=2min
AccuracySec=5s
Unit=debian13s4-hardening.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_e2de7086c2159bf4cd8a2775d8a3aba484b1c5c5237f9c4a36f7e0db4c8e371a
    cat > "$S4B_STAGE/lib/tasks/hardening/apply.sh" <<'S4_PAYLOAD_896f7ea78d7f63a5858bbbe278c13fbfc1b49e34875b22c7fcf32567c32d836b' || return 1
#!/bin/bash
# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_apply
S4_PAYLOAD_896f7ea78d7f63a5858bbbe278c13fbfc1b49e34875b22c7fcf32567c32d836b
    cat > "$S4B_STAGE/lib/tasks/hardening/verify.sh" <<'S4_PAYLOAD_93f98e5dac2f0a3a4e7479eadfa4b52941ac936d4cce43adf7360ad4d08ec8f7' || return 1
#!/bin/bash
# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_verify
S4_PAYLOAD_93f98e5dac2f0a3a4e7479eadfa4b52941ac936d4cce43adf7360ad4d08ec8f7
    cat > "$S4B_STAGE/lib/firewall/kernel.py" <<'S4_PAYLOAD_c96d0066b1cb453daf45d4a7fb41d4bada3c96c499e60dfc7da7ee60dfdc562e' || return 1
#!/usr/bin/python3
"""Observe a supported kernel topology without applying network changes.

The kernel-v1 record deliberately lacks DNS, NTP and DHCP-manager admission. It
cannot be passed straight to the firewall compiler or certify firewall readiness.
"""

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

IP_BINARY = Path("/usr/bin/ip")
TRUST_ROOT = Path("/")
TRUSTED_UID = 0
QUERY_SECONDS = 3.0
ATTEMPT_SECONDS = 60.0
CLEANUP_SECONDS = 1.0
MAX_BYTES = 1048576
MAX_ITEMS = 4096
MAX_LINKS = 33
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
STATES = {"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "NONE"}
RESOLVED = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
LINK_FLAGS = set("UP BROADCAST DEBUG LOOPBACK POINTOPOINT NOTRAILERS NOARP PROMISC ALLMULTI MASTER SLAVE MULTICAST PORTSEL AUTOMEDIA DYNAMIC LOWER_UP DORMANT ECHO NO-CARRIER".split())
COMMANDS = {
    "links": ("-details", "link", "show"),
    "addresses": ("address", "show"),
    "routes4": ("-4", "route", "show", "table", "all"),
    "routes6": ("-6", "route", "show", "table", "all"),
    "rules4": ("-4", "rule", "show"),
    "rules6": ("-6", "rule", "show"),
    "neighbors4": ("-4", "neigh", "show", "nud", "all"),
    "neighbors6": ("-6", "neigh", "show", "nud", "all"),
    "proxy4": ("-4", "neigh", "show", "proxy"),
    "proxy6": ("-6", "neigh", "show", "proxy"),
}
LINK_KEYS = set("ifindex ifname flags mtu qdisc operstate group txqlen link_type address broadcast altnames linkmode inet6_addr_gen_mode promiscuity allmulti min_mtu max_mtu num_tx_queues num_rx_queues gso_max_size gso_max_segs tso_max_size tso_max_segs gro_max_size gso_ipv4_max_size gro_ipv4_max_size parentbus parentdev link_index linkinfo".split())
ADDRESS_KEYS = LINK_KEYS | {"addr_info"}
IP_KEYS = set("family local prefixlen broadcast scope label valid_life_time preferred_life_time dynamic mngtmpaddr noprefixroute tentative dadfailed deprecated temporary secondary optimistic permanent".split())
ROUTE_KEYS = set("dst dev gateway table type protocol scope metric prefsrc flags pref expires mtu advmss hoplimit features initcwnd initrwnd quickack congctl rtt rttvar rto_min window cwnd ssthresh reordering fastopen_no_cookie".split())
NEIGHBOR_KEYS = {"dst", "dev", "lladdr", "state", "router", "protocol"}


class Pending(ValueError):
    """A complete supported observation could not be established; retry later."""


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted_binary(path):
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending("noncanonical native path")
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        kind = stat.S_ISREG if current == path else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending("untrusted native binary or ancestry")
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if not before.st_mode & 0o100:
        raise Pending("native binary is not executable")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise Pending("native descriptor changed")
    finally:
        os.close(fd)
    return signature(before)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Pending("duplicate native JSON field")
        result[key] = value
    return result


def rows(value, limit=MAX_ITEMS):
    if type(value) is not list or len(value) > limit or any(type(item) is not dict for item in value):
        raise Pending("invalid native inventory")
    return value


def known(item, allowed, required=()):
    if type(item) is not dict or not set(required).issubset(item) or not set(item).issubset(allowed):
        raise Pending("missing or unsupported native fields")


def uint(value, maximum=0xffffffff):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Pending("invalid native integer")
    return value


def address(value, version, unicast=True):
    if type(value) is not str or len(value) > 45 or "%" in value:
        raise Pending("invalid native address")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as error:
        raise Pending("invalid native address") from error
    if ip.version != version or str(ip) != value or (version == 6 and ip.ipv4_mapped is not None):
        raise Pending("noncanonical or wrong-family address")
    if unicast and (ip.is_unspecified or ip.is_multicast or ip.is_loopback or (version == 4 and int(ip) == 0xffffffff)):
        raise Pending("non-unicast external address")
    return ip


def ethernet(value):
    if type(value) is not str or MAC.fullmatch(value) is None or value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        raise Pending("invalid native Ethernet identity")
    return value


def link_type(value):
    # ip -N bypasses ll_type_n2a names and prints bracketed ARPHRD values.
    if type(value) is not str or value not in ("ether", "[1]", "loopback", "[772]"):
        raise Pending("unsupported native link type")
    return "ether" if value in ("ether", "[1]") else "loopback"


def vlan_protocol(value):
    names = {"802.1Q": "802.1Q", "802.1q": "802.1Q", "[33024]": "802.1Q",
             "802.1ad": "802.1ad", "[34984]": "802.1ad"}
    if type(value) is not str or value not in names:
        raise Pending("unsupported VLAN protocol")
    return names[value]


def prefix(value, version):
    if value == "default":
        return ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
    if type(value) is not str or len(value) > 49:
        raise Pending("invalid native prefix")
    try:
        result = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise Pending("invalid native prefix") from error
    canonical = str(result) if "/" in value else str(result.network_address)
    if result.version != version or canonical != value:
        raise Pending("noncanonical native prefix")
    return result


def table(value):
    aliases = {"local": 255, "main": 254, "default": 253, "255": 255, "254": 254, "253": 253}
    if type(value) is str:
        value = aliases.get(value)
    if type(value) is not int or value not in (253, 254, 255):
        raise Pending("unsupported routing table")
    return value


def route_type(value):
    types = {"1": "unicast", "2": "local", "3": "broadcast", "5": "multicast",
             "6": "blackhole", "7": "unreachable", "8": "prohibit"}
    if type(value) is not str:
        raise Pending("invalid native route type")
    result = types.get(value, value)
    if result not in types.values():
        raise Pending("unsupported native route type")
    return result


def flags(value):
    if type(value) is not list or any(type(flag) is not str for flag in value) or len(value) != len(set(value)):
        raise Pending("invalid native flags")
    return set(value)


def finite_deadline(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def native_query(name, deadline):
    if type(name) is not str or name not in COMMANDS:
        raise Pending("native command is not an admitted read-only query")
    return _query_json(COMMANDS[name], deadline,
                       MAX_LINKS if name in ("links", "addresses") else MAX_ITEMS)


def native_route(destination, interface, deadline):
    if type(destination) is not str or len(destination) > 45 or "%" in destination:
        raise Pending("invalid route lookup destination")
    try:
        ip = ipaddress.ip_address(destination)
    except ValueError as error:
        raise Pending("invalid route lookup destination") from error
    address(destination, ip.version)
    arguments = (f"-{ip.version}", "route", "get", destination)
    if ip.version == 6 and ip.is_link_local and interface is None:
        raise Pending("link-local route lookup lacks an interface")
    if interface is not None:
        if ip.version != 6 or not ip.is_link_local or type(interface) is not str or NAME.fullmatch(interface) is None or interface == "lo":
            raise Pending("invalid scoped route lookup")
        arguments += ("oif", interface)
    return _query_json(arguments, deadline, 1)


def _query_json(arguments, deadline, limit):
    if not finite_deadline(deadline):
        raise Pending("invalid native deadline")
    identity = trusted_binary(IP_BINARY)
    end = min(deadline, now() + QUERY_SECONDS)
    if now() >= end:
        raise Pending("observation deadline expired")
    process = subprocess.Popen([str(IP_BINARY), "-j", "-N", *arguments],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"},
                               close_fds=True, start_new_session=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = end - now()
                if remaining <= 0:
                    raise Pending("native query timed out")
                for key, _ in selector.select(remaining):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending("native output limit exceeded")
                    buffer.extend(data)
            remaining = end - now()
            if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers["stderr"]:
                raise Pending("native query failed or warned")
        if trusted_binary(IP_BINARY) != identity:
            raise Pending("native binary changed during observation")
        try:
            value = json.loads(buffers["stdout"].decode("utf-8"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending("invalid native JSON") from error
        return rows(value, limit)
    except subprocess.TimeoutExpired as error:
        raise Pending("native query timed out after pipe closure") from error
    finally:
        try:
            # Keep the direct PID unreaped until group termination on a capture
            # error. A leader that exited while a child holds a pipe still owns
            # its PID, so this cannot target a newly reused process group.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=CLEANUP_SECONDS)
        finally:
            process.stdout.close()
            process.stderr.close()


def normalize(snapshot):
    if type(snapshot) is not dict or set(snapshot) != set(COMMANDS):
        raise Pending("incomplete kernel snapshot")
    count = sum(len(rows(value, MAX_LINKS if name in ("links", "addresses") else MAX_ITEMS)) for name, value in snapshot.items())
    if count > MAX_ITEMS or snapshot["proxy4"] or snapshot["proxy6"]:
        raise Pending("oversized or proxy topology")
    links, indexes, parents = {}, {}, {}
    for item in snapshot["links"]:
        known(item, LINK_KEYS, ("ifindex", "ifname", "flags", "link_type", "address"))
        index, name = uint(item["ifindex"]), item["ifname"]
        if index == 0 or index in indexes or type(name) is not str or NAME.fullmatch(name) is None or name in links:
            raise Pending("invalid or duplicate link identity")
        link_flags = flags(item["flags"])
        if not link_flags.issubset(LINK_FLAGS):
            raise Pending("unsupported link flags")
        if name == "lo":
            if link_type(item["link_type"]) != "loopback" or "LOOPBACK" not in link_flags:
                raise Pending("invalid loopback identity")
            mac = None
        else:
            if link_type(item["link_type"]) != "ether" or link_flags & {"LOOPBACK", "POINTOPOINT", "NOARP", "MASTER", "SLAVE"}:
                raise Pending("unsupported link arrangement")
            mac = ethernet(item["address"])
        info = item.get("linkinfo", {})
        known(info, {"info_kind", "info_data"})
        kind = info.get("info_kind")
        if kind not in (None, "vlan") or ("info_data" in info and kind != "vlan"):
            raise Pending("unsupported virtual link")
        vlan_identity = None
        if kind == "vlan":
            if name == "lo" or "link_index" not in item:
                raise Pending("missing VLAN parent")
            vlan = info.get("info_data")
            known(vlan, {"protocol", "id", "flags"}, ("id", "protocol"))
            vlan_flags = flags(vlan.get("flags", []))
            if not 1 <= uint(vlan["id"], 4094) or not vlan_flags.issubset({"REORDER_HDR"}):
                raise Pending("unsupported VLAN identity")
            vlan_identity = {"id": vlan["id"], "protocol": vlan_protocol(vlan["protocol"]),
                             "flags": sorted(vlan_flags)}
            parents[name] = uint(item["link_index"])
        elif "link_index" in item:
            raise Pending("unidentified parent link")
        links[name] = {"name": name, "index": index, "mac": mac,
                       "up": {"UP", "LOWER_UP"}.issubset(link_flags), "kind": "ether",
                       "flags": sorted(link_flags), "parent": parents.get(name), "vlan": vlan_identity,
                       "prefixes": set(), "gateways": {}, "neighbors": {}}
        indexes[index] = name
    if "lo" not in links:
        raise Pending("missing loopback inventory")
    for name in parents:
        visited = {name}
        current = name
        while current in parents:
            current = indexes.get(parents[current])
            if current is None or current == "lo" or current in visited or len(visited) > 4:
                raise Pending("unresolved or cyclic VLAN parent")
            visited.add(current)
    seen = set()
    ipv6_present = False
    for item in snapshot["addresses"]:
        known(item, ADDRESS_KEYS, ("ifindex", "ifname", "addr_info", "address", "link_type", "flags"))
        name = item["ifname"]
        if type(name) is not str or name not in links or name in seen or uint(item["ifindex"]) != links[name]["index"]:
            raise Pending("address/link inventory disagreement")
        if item["address"] != ("00:00:00:00:00:00" if name == "lo" else links[name]["mac"]):
            raise Pending("address/link MAC disagreement")
        if link_type(item["link_type"]) != ("loopback" if name == "lo" else "ether"):
            raise Pending("address/link kind disagreement")
        if sorted(flags(item["flags"])) != links[name]["flags"]:
            raise Pending("address/link flags disagreement")
        seen.add(name)
        for entry in rows(item["addr_info"]):
            count += 1
            known(entry, IP_KEYS, ("family", "local", "prefixlen"))
            family = entry["family"]
            if family not in ("inet", "inet6"):
                raise Pending("unsupported address family")
            version = 4 if family == "inet" else 6
            ip = address(entry["local"], version, name != "lo")
            if name == "lo" and not ip.is_loopback:
                raise Pending("external address on loopback")
            length = uint(entry["prefixlen"], ip.max_prefixlen)
            if length == 0:
                raise Pending("default assigned prefix")
            ipv6_present |= version == 6
            # An assigned mask (especially noprefixroute) is not proof of a
            # connected FIB route. Keep only this host identity here; direct
            # native routes below supply admitted on-link networks.
            links[name]["prefixes"].add(ipaddress.ip_network(str(ip)))
    if seen != set(links):
        raise Pending("partial address inventory")
    for version in (4, 6):
        rule_set = set()
        for item in snapshot[f"rules{version}"]:
            known(item, {"priority", "src", "dst", "table"}, ("priority", "src", "table"))
            priority, table_id = uint(item["priority"]), table(item["table"])
            expected = {0: 255, 32766: 254, 32767: 253}
            if item["src"] != "all" or item.get("dst", "all") != "all" or expected.get(priority) != table_id or priority in rule_set:
                raise Pending("unsupported routing policy")
            rule_set.add(priority)
        absent6 = version == 6 and not ipv6_present and not any(snapshot[name] for name in ("routes6", "rules6", "neighbors6"))
        if not absent6 and not {0, 32766}.issubset(rule_set):
            raise Pending("incomplete routing policy")
        for item in snapshot[f"routes{version}"]:
            known(item, ROUTE_KEYS, ("dst",))
            destination = prefix(item["dst"], version)
            table_id = table(item.get("table", 254))
            route_flags = flags(item.get("flags", []))
            if not route_flags.issubset({"onlink", "linkdown"}):
                raise Pending("unsupported route flags")
            kind = route_type(item.get("type", "unicast"))
            if kind in ("unreachable", "blackhole", "prohibit"):
                if "gateway" in item:
                    raise Pending("gateway on negative route")
                continue
            name = item.get("dev")
            if type(name) is not str or name not in links:
                raise Pending("route without observed link")
            if kind in ("local", "broadcast", "multicast"):
                if table_id != 255 or "gateway" in item:
                    raise Pending("unexpected local route")
                continue
            if kind != "unicast" or table_id == 255 or name == "lo":
                raise Pending("unsupported route type")
            if "gateway" in item:
                gateway = address(item["gateway"], version)
                links[name]["gateways"][gateway] = None
                if "onlink" in route_flags:
                    links[name]["prefixes"].add(ipaddress.ip_network(str(gateway)))
            else:
                if destination.prefixlen == 0:
                    raise Pending("ambiguous direct default route")
                links[name]["prefixes"].add(destination)
        for item in snapshot[f"neighbors{version}"]:
            known(item, NEIGHBOR_KEYS, ("dst", "dev"))
            name = item["dev"]
            if type(name) is not str or name not in links:
                raise Pending("neighbor without observed Ethernet link")
            states = item.get("state", ["NONE"])
            if type(states) is not list or len(states) != 1 or type(states[0]) is not str or states[0] not in STATES:
                raise Pending("unsupported neighbor state")
            state = states[0]
            router = "router" in item
            if router and item["router"] is not None and item["router"] is not True:
                raise Pending("invalid native router flag")
            if state == "NOARP" and not router:
                # Synthetic NOARP cache entries (also present on loopback)
                # cannot admit SSH or resolve a gateway.
                address(item["dst"], version, False)
                continue
            if name == "lo":
                raise Pending("unexpected resolved or router neighbor on loopback")
            ip = address(item["dst"], version)
            if state in RESOLVED and "lladdr" not in item:
                raise Pending("resolved neighbor lacks Ethernet identity")
            mac = ethernet(item["lladdr"]) if state in RESOLVED else None
            if ip in links[name]["neighbors"] and links[name]["neighbors"][ip] != (mac, state):
                raise Pending("conflicting neighbor identity")
            links[name]["neighbors"][ip] = (mac, state)
            if router:
                links[name]["gateways"].setdefault(ip, None)
    if count > MAX_ITEMS:
        raise Pending("aggregate kernel inventory too large")
    result = []
    for name, item in sorted(links.items()):
        if name == "lo":
            continue
        for ip in set(item["gateways"]) | set(item["neighbors"]):
            if not any(ip.version == net.version and ip in net for net in item["prefixes"]):
                raise Pending("off-link gateway or neighbor; no inferred prefix")
        for ip in item["gateways"]:
            item["gateways"][ip] = item["neighbors"].get(ip, (None, "NONE"))[0]
        item["prefixes"] = sorted(map(str, item["prefixes"]))
        item["gateways"] = [{"address": str(ip), "mac": mac} for ip, mac in sorted(item["gateways"].items(), key=lambda pair: str(pair[0]))]
        item["neighbors"] = [{"address": str(ip), "mac": mac, "state": state} for ip, (mac, state) in sorted(item["neighbors"].items(), key=lambda pair: str(pair[0]))]
        result.append(item)
    return result


def namespace():
    value = os.readlink("/proc/self/ns/net")
    match = re.fullmatch(r"net:\[([0-9]+)\]", value)
    if match is None:
        raise Pending("unverifiable process network namespace")
    return int(match[1])


def observe(query=native_query, scope=namespace, deadline=None):
    started = now()
    if deadline is not None and (not finite_deadline(deadline) or deadline <= started):
        raise Pending("invalid or expired inherited observation deadline")
    deadline = min(deadline, started + ATTEMPT_SECONDS) if deadline is not None else started + ATTEMPT_SECONDS
    identity = scope()
    first = normalize({name: query(name, deadline) for name in COMMANDS})
    second = normalize({name: query(name, deadline) for name in COMMANDS})
    if first != second or scope() != identity or now() >= deadline:
        raise Pending("kernel topology changed or observation expired")
    return {"schema": "debian13s4-kernel-1", "namespace": identity, "interfaces": second}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = json.dumps(observe(), sort_keys=True, separators=(",", ":")) + "\n"
        if len(result.encode()) > MAX_BYTES:
            raise Pending("normalized observation too large")
        sys.stdout.write(result)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"debian13s4 kernel observation pending: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
S4_PAYLOAD_c96d0066b1cb453daf45d4a7fb41d4bada3c96c499e60dfc7da7ee60dfdc562e
    cat > "$S4B_STAGE/lib/ssh/common.sh" <<'S4_PAYLOAD_a4a45b676286e7d553103f426645c99cc0b8413db73cc0515802671097dd743b' || return 1
#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh

S4S_LIBRARY=/usr/local/lib/debian13s4/ssh
S4S_CONFIG=/etc/ssh/debian13s4-admin.conf
S4S_HOST_KEY=/etc/ssh/ssh_host_ed25519_key
S4S_SSHD=/usr/sbin/sshd
S4S_LOADED_GENERATION=''
S4S_VENDOR=(ssh.service ssh.socket sshd.service)
S4S_SERVER=debian13s4-admin-ssh.service
S4S_SERVICE=debian13s4-ssh.service
S4S_TIMER=debian13s4-ssh.timer
S4S_FILES=(common.sh policy.py repair.sh debian13s4-admin-ssh.service
    debian13s4-ssh.service debian13s4-ssh.timer)
# The in-process preparation caps at 60s. Allow its separate owned-child
# cleanup and finite local work, then retain a separate external kill grace.
S4S_POLICY_SECONDS=65

s4s_policy() (
    local descriptor=$S4M_REPAIR_FD
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s "${S4S_POLICY_SECONDS}s" \
        env -i PATH="$S4M_PATH" LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B "$S4S_LIBRARY/policy.py" "$@"
)

s4s_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    for name in "${S4S_FILES[@]}"; do
        [[ -f $S4S_LIBRARY/$name ]] && s4m_trusted "$S4S_LIBRARY/$name" || return 1
    done
    [[ -x $S4S_LIBRARY/repair.sh && -f $S4M_LIBRARY/common.sh &&
        -f $S4S_LIBRARY/../firewall/kernel.py ]] &&
        s4m_trusted "$S4M_LIBRARY/common.sh" &&
        s4m_trusted "${S4S_LIBRARY%/*}/firewall/kernel.py"
}

s4s_identity() {
    local name digest
    for name in "${S4S_FILES[@]}"; do
        digest=$(sha256sum -- "$S4S_LIBRARY/$name") || return 1
        printf '%s ssh/%s\n' "${digest%% *}" "$name" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py; do
        digest=$(sha256sum -- "${S4S_LIBRARY%/*}/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
}

s4s_vendor_paths() {
    local unit target owner
    s4m_trusted "$S4M_SYSTEMD" || return 1
    for unit in "${S4S_VENDOR[@]}"; do
        target=$S4M_SYSTEMD/$unit
        if [[ -e $target || -L $target ]]; then
            # Only an existing root-owned mask is accepted at the local path.
            # A custom unit/alias is not silently replaced or guessed away.
            [[ -L $target ]] || return 1
            owner=$(stat --format='%u' -- "$target") || return 1
            [[ $owner == 0 && $(readlink -- "$target") == /dev/null ]] || return 1
        fi
    done
}

s4s_mask_vendor() {
    local unit loaded
    s4s_vendor_paths || return 1
    for unit in "${S4S_VENDOR[@]}"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        case $loaded in
            loaded) s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1 ;;
            masked|not-found) ;;
            *) return 1 ;;
        esac
        s4m_systemctl mask "$unit" || return 1
    done
    s4m_systemctl daemon-reload && s4m_sync "$S4M_SYSTEMD" || return 1
    s4s_vendor_masked
}

s4s_vendor_masked() {
    local unit
    s4s_vendor_paths || return 1
    for unit in "${S4S_VENDOR[@]}"; do
        [[ -L $S4M_SYSTEMD/$unit ]] &&
            s4m_property "$unit" LoadState masked &&
            s4m_property "$unit" ActiveState inactive || return 1
    done
}

s4s_packages() {
    s4m_load_packages || return 1
    S4P_PACKAGES=(openssh-server iproute2)
}

s4s_prepare_config() {
    local temporary directory=${S4S_CONFIG%/*} mode=${1:-install}
    [[ $# -le 1 && ( $mode == install || $mode == repair ) ]] || return 1
    s4m_trusted "${directory%/*}" || return 1
    if [[ -e $directory || -L $directory ]]; then
        [[ -d $directory ]] && s4m_trusted "$directory" || return 1
    else
        mkdir -m 0755 -- "$directory" || return 1
    fi
    temporary=$(mktemp -- "$S4M_STATE/ssh-policy.XXXXXX") || return 1
    if ! s4s_policy --plan > "$temporary" || ! chmod 0600 -- "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    # Compare the prospective bytes, not just the current disk file. Stop an
    # unknown/stale instance BEFORE changing its startup configuration.
    if [[ $mode == repair ]] && ! s4s_loaded "$temporary" && ! s4s_stop; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! s4m_atomic "$S4S_CONFIG" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
}

s4s_units() {
    local unit
    for unit in "$S4S_SERVER" "$S4S_SERVICE" "$S4S_TIMER"; do
        [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" &&
            cmp --silent -- "$S4S_LIBRARY/$unit" "$S4M_SYSTEMD/$unit" || return 1
        s4m_property "$unit" FragmentPath "$S4M_SYSTEMD/$unit" &&
            s4m_property "$unit" DropInPaths '' || return 1
    done
    s4m_enabled "$S4S_SERVER" && s4m_enabled "$S4S_TIMER" &&
        s4m_property "$S4S_TIMER" ActiveState active
}

s4s_observe_live() {
    local pid
    s4s_vendor_masked && s4m_property "$S4S_SERVER" ActiveState active || return 1
    pid=$(s4m_systemctl show --property=MainPID --value "$S4S_SERVER") || return 1
    [[ $pid =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    s4s_policy --live "$pid"
}

s4s_startup_inputs() {
    local config=${1:-$S4S_CONFIG} name path digest
    s4s_identity || return 1
    for name in configuration host_key executable; do
        case $name in
            configuration) path=$config ;;
            host_key) path=$S4S_HOST_KEY ;;
            executable) path=$S4S_SSHD ;;
        esac
        [[ -f $path ]] && s4m_trusted "$path" || return 1
        digest=$(sha256sum -- "$path") || return 1
        digest=${digest%% *}
        [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
        printf '%s %s\n' "$digest" "$name" || return 1
    done
    # OpenSSH may read the optional public companion at startup as well.
    path=$S4S_HOST_KEY.pub
    if [[ -e $path || -L $path ]]; then
        [[ -f $path ]] && s4m_trusted "$path" || return 1
        digest=$(sha256sum -- "$path") || return 1
        digest=${digest%% *}
        [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
        printf '%s host_public_key\n' "$digest"
    else
        printf 'absent host_public_key\n'
    fi
}

s4s_running_generation() {
    local rows key value active='' pid='' invocation=''
    rows=$(s4m_systemctl show --property=ActiveState --property=MainPID \
        --property=InvocationID "$S4S_SERVER") || return 1
    [[ ${#rows} -le 512 ]] || return 1
    while IFS='=' read -r key value; do
        case $key in
            ActiveState) [[ -z $active && $value == active ]] || return 1; active=$value ;;
            MainPID)
                [[ -z $pid && $value =~ ^[1-9][0-9]{0,9}$ ]] &&
                    (( 10#$value <= 2147483647 )) || return 1
                pid=$value ;;
            InvocationID)
                [[ -z $invocation && $value =~ ^[0-9a-f]{32}$ &&
                    $value != 00000000000000000000000000000000 ]] || return 1
                invocation=$value ;;
            *) return 1 ;;
        esac
    done <<< "$rows"
    [[ $active == active && -n $pid && -n $invocation ]] || return 1
    printf 'instance %s %s\n' "$pid" "$invocation" || return 1
    s4s_startup_inputs "${1:-$S4S_CONFIG}"
}

s4s_loaded() {
    local marker=$S4M_STATE/ssh.loaded expected actual mode size links
    [[ -f $marker ]] && s4m_trusted "$marker" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- "$marker") || return 1
    [[ $mode == 600 && $links == 1 && $size =~ ^[1-9][0-9]{0,3}$ ]] &&
        (( 10#$size <= 4096 )) || return 1
    expected=$(s4s_running_generation "${1:-$S4S_CONFIG}") &&
        actual=$(cat -- "$marker") || return 1
    [[ $expected == "$actual" ]] || return 1
    # Retain only the complete generation computed by this successful check.
    S4S_LOADED_GENERATION=$expected
}

s4s_live() {
    local before
    s4s_loaded || return 1
    before=$S4S_LOADED_GENERATION
    s4s_observe_live && s4s_loaded && [[ $before == "$S4S_LOADED_GENERATION" ]]
}

s4s_start() {
    local before after generation temporary
    # A disk check is not a loaded-state acknowledgment. Start only from a
    # confirmed inactive/no-main-PID state, with unchanged startup inputs.
    s4m_property "$S4S_SERVER" ActiveState inactive &&
        s4m_property "$S4S_SERVER" MainPID 0 || return 1
    before=$(s4s_startup_inputs) && s4m_systemctl start "$S4S_SERVER" &&
        s4s_observe_live && after=$(s4s_startup_inputs) && [[ $before == "$after" ]] || return 1
    generation=$(s4s_running_generation) || return 1
    [[ ${generation#*$'\n'} == "$before" ]] || return 1
    temporary=$(mktemp -- "$S4M_STATE/ssh-loaded.XXXXXX") || return 1
    if ! printf '%s\n' "$generation" > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/ssh.loaded" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4s_loaded
}

s4s_ready() {
    local expected actual
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/ssh.ready ]] && s4m_trusted "$S4M_STATE/ssh.ready" || return 1
    s4s_assets && s4s_units || return 1
    expected=$(s4s_identity) && actual=$(cat -- "$S4M_STATE/ssh.ready") || return 1
    [[ $expected == "$actual" ]]
}

s4s_verify() {
    s4s_ready && s4s_packages && s4p_verify && s4s_live
}

s4s_stop() {
    local marker=$S4M_STATE/ssh.loaded
    s4m_systemctl stop "$S4S_SERVER" && s4m_property "$S4S_SERVER" ActiveState inactive &&
        s4m_property "$S4S_SERVER" MainPID 0 || return 1
    if [[ -e $marker || -L $marker ]]; then
        [[ -f $marker ]] && s4m_trusted "$marker" && rm -f -- "$marker" || return 1
        s4m_sync "$S4M_STATE" || return 1
    fi
}

s4s_publish() {
    local unit wants resolved temporary
    for unit in "$S4S_SERVER" "$S4S_SERVICE" "$S4S_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$unit" "$S4S_LIBRARY/$unit" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for unit in "$S4S_SERVER" "$S4S_TIMER"; do
        s4m_systemctl enable "$unit" && s4m_enabled "$unit" || return 1
        wants=$S4M_SYSTEMD/multi-user.target.wants
        [[ $unit != "$S4S_TIMER" ]] || wants=$S4M_SYSTEMD/timers.target.wants
        [[ -d $wants && -L $wants/$unit ]] && s4m_trusted "$wants" || return 1
        resolved=$(readlink --canonicalize-existing -- "$wants/$unit") || return 1
        [[ $resolved == "$S4M_SYSTEMD/$unit" ]] || return 1
        s4m_sync "$wants" "$S4M_SYSTEMD" "$S4M_SYSTEMD/$unit" || return 1
    done
    s4s_start && s4m_systemctl start "$S4S_TIMER" &&
        s4s_units && s4s_live || return 1
    temporary=$(mktemp -- "$S4M_STATE/ssh-intent.XXXXXX") || return 1
    if ! s4s_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/ssh.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    s4s_verify
}

s4s_apply() {
    local unit loaded
    s4s_assets && s4s_vendor_paths || return 1
    for unit in "$S4S_SERVER" "$S4S_SERVICE" "$S4S_TIMER"; do
        if [[ -e $S4M_SYSTEMD/$unit || -L $S4M_SYSTEMD/$unit ]]; then
            [[ -f $S4M_SYSTEMD/$unit ]] && s4m_trusted "$S4M_SYSTEMD/$unit" || return 1
        fi
    done
    if [[ -e $S4M_STATE/ssh.ready || -L $S4M_STATE/ssh.ready ]]; then
        [[ -f $S4M_STATE/ssh.ready ]] && s4m_trusted "$S4M_STATE/ssh.ready" || return 1
        rm -f -- "$S4M_STATE/ssh.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    # Admit credentials and current admin assignment before retiring vendor SSH.
    # The config is data only until its real syntax/effective checks succeed.
    s4s_prepare_config || return 1
    for unit in "$S4S_TIMER" "$S4S_SERVICE" "$S4S_SERVER"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$unit") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$unit" && s4m_property "$unit" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then
            return 1
        fi
    done
    # Persistent masks precede package maintainer scripts, including a retry.
    if s4s_mask_vendor && s4s_packages && s4p_prepare &&
        s4m_package s4p_apply && s4p_verify && s4s_vendor_masked && s4s_policy --check && s4s_publish; then
        return 0
    fi
    s4s_stop || return 1
    return 1
}

s4s_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    if s4s_ready && s4s_packages && s4p_verify && s4s_vendor_masked &&
        s4s_prepare_config repair; then
        if s4s_live; then
            return 0
        fi
        # Stop/revalidate/start after a stale/unknown acknowledgment or failed
        # live observation. No successful no-op follows disk checks alone.
        if s4s_stop && s4s_policy --check && s4s_start; then
            return 0
        fi
    fi
    s4s_stop || return 75
    return 75
}
S4_PAYLOAD_a4a45b676286e7d553103f426645c99cc0b8413db73cc0515802671097dd743b
    cat > "$S4B_STAGE/lib/ssh/policy.py" <<'S4_PAYLOAD_a826ec818551234b1c98a344e189bb23da4bc4fb173bb00a1ab189d8031692b7' || return 1
#!/usr/bin/python3
"""Derive and check LAN-bound SSH for one existing local administrator.

This does not create credentials, configure an address or attest client locality.
The IPv6 allocation is used only when a usable assignment is actually reported.
Native delivery and the local account database belong to the trusted-base profile.
"""

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location('debian13s4_ssh_kernel',
    Path(__file__).resolve().parents[1] / 'firewall/kernel.py')
if not SPEC.origin or not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_ssh_kernel',
        Path(__file__).resolve().parents[1] / 'Firewall/kernel.py')
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
ETC = Path('/etc')
HOME = Path('/home')
CONFIG = ETC / 'ssh/debian13s4-admin.conf'
HOST_KEY = ETC / 'ssh/ssh_host_ed25519_key'
SSHD = Path('/usr/sbin/sshd')
SS = Path('/usr/bin/ss')
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
ADMIN4 = ipaddress.ip_network('192.168.90.0/24')
ADMIN6 = ipaddress.ip_network('fd51:b089:f5e0:90::/64')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 60
NAME = re.compile(r'[a-z_][a-z0-9_-]{0,31}\Z')
ACCOUNT_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z')


def fence(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('SSH observation window expired')


def trusted_read(path, owners=(0,), private=False):
    """Read a bounded unique leaf through a checked no-follow descriptor."""
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical SSH input path')
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        if not (stat.S_ISREG(info.st_mode) if current == path else stat.S_ISDIR(info.st_mode)):
            raise Pending('symbolic or unsupported SSH input')
        allowed = owners if current == path or HOME in current.parents else (TRUSTED_UID,)
        if info.st_uid not in allowed or info.st_mode & 0o022:
            raise Pending('unprotected SSH input or ancestry')
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if before.st_nlink != 1 or before.st_size > MAX_BYTES or private and before.st_mode & 0o077:
        raise Pending('nonunique, oversized or nonprivate SSH input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before):
            raise Pending('SSH input descriptor differs')
        data = bytearray()
        while True:
            part = os.read(descriptor, min(65536, MAX_BYTES + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > MAX_BYTES:
                raise Pending('SSH input byte bound exceeded')
        if (KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(data) != before.st_size):
            raise Pending('SSH input changed during read')
    finally:
        # Linux retires the number even when close reports an error: never retry.
        os.close(descriptor)
    return bytes(data), {'path': str(path), 'identity': list(KERNEL.signature(before)),
                         'sha256': hashlib.sha256(data).hexdigest()}


def database(raw, width):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('unsupported local account encoding') from error
    if not text.endswith('\n') or '\x00' in text or len(text.splitlines()) > 4096:
        raise Pending('invalid local account database')
    result, names = [], set()
    for line in text.splitlines():
        fields = line.split(':')
        if len(fields) != width or ACCOUNT_NAME.fullmatch(fields[0]) is None or fields[0] in names:
            raise Pending('malformed or duplicate local account row')
        names.add(fields[0]); result.append(fields)
    return result


def number(value, maximum=0x7fffffff):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]{0,9}', value) is None:
        raise Pending('invalid local account number')
    return KERNEL.uint(int(value), maximum)


def public_keys(raw):
    try:
        text = raw.decode('utf-8')
    except UnicodeError as error:
        raise Pending('invalid administrator key encoding') from error
    if not text.endswith('\n') or '\x00' in text or len(text.splitlines()) > 64:
        raise Pending('invalid administrator key inventory')
    seen = set()
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        words = line.split()
        if len(line.encode('utf-8')) > 16384 or len(words) < 2 or words[0] not in ('ssh-ed25519', 'ssh-rsa'):
            # Do not strip options, certificates or constraints to widen a key.
            raise Pending('unsupported administrator key or key options')
        try:
            wire = base64.b64decode(words[1], validate=True)
        except (ValueError, UnicodeError) as error:
            raise Pending('invalid administrator key wire encoding') from error
        if base64.b64encode(wire).decode('ascii') != words[1] or wire in seen:
            raise Pending('noncanonical or duplicate administrator key')
        parts, offset = [], 0
        while offset < len(wire):
            if len(wire) - offset < 4:
                raise Pending('truncated administrator key')
            size = struct.unpack_from('!I', wire, offset)[0]; offset += 4
            if size > 16384 or size > len(wire) - offset:
                raise Pending('invalid administrator key field')
            parts.append(wire[offset:offset + size]); offset += size
        if not parts or parts[0] != words[0].encode('ascii'):
            raise Pending('administrator key type disagreement')
        if words[0] == 'ssh-ed25519':
            if len(parts) != 2 or len(parts[1]) != 32:
                raise Pending('invalid Ed25519 key shape')
        else:
            if len(parts) != 3 or any(not part or part[0] & 128 or
                len(part) > 1 and part[0] == 0 and not part[1] & 128 for part in parts[1:]):
                raise Pending('invalid RSA positive mpint')
            exponent, modulus = (int.from_bytes(part, 'big') for part in parts[1:])
            if exponent < 65537 or not exponent & 1 or not 3072 <= modulus.bit_length() <= 8192 or not modulus & 1:
                raise Pending('unsupported RSA key size or exponent')
        seen.add(wire)
    if not seen:
        raise Pending('no existing supported administrator key')
    return len(seen)


def administrator():
    contents, sources = {}, {}
    for name, width in (('passwd', 7), ('group', 4), ('shadow', 9)):
        raw, sources[name] = trusted_read(ETC / name, (TRUSTED_UID,))
        if name == 'shadow' and sources[name]['identity'][2] & 0o007:
            raise Pending('shadow database is readable by other users')
        contents[name] = database(raw, width)
    groups = {row[0]: row for row in contents['group']}
    if 'sudo' not in groups:
        raise Pending('no existing local sudo administrator group')
    sudo_gid = number(groups['sudo'][2])
    members = groups['sudo'][3].split(',') if groups['sudo'][3] else []
    if len(members) != len(set(members)) or any(NAME.fullmatch(name) is None for name in members):
        raise Pending('invalid local administrator membership')
    eligible, uids = [], set()
    for row in contents['passwd']:
        uid, gid = number(row[2]), number(row[3])
        if uid in uids:
            raise Pending('duplicate local UID')
        uids.add(uid)
        if 1000 <= uid <= 59999 and (row[0] in members or gid == sudo_gid):
            eligible.append(row)
    if len(eligible) != 1:
        raise Pending('administrator discovery is missing or ambiguous')
    user = eligible[0]; name, uid, gid = user[0], number(user[2]), number(user[3])
    if (NAME.fullmatch(name) is None or user[1] != 'x' or user[5] != str(HOME / name) or
        user[6] not in ('/bin/bash', '/usr/bin/bash')):
        raise Pending('unsupported existing administrator account')
    shadows = [row for row in contents['shadow'] if row[0] == name]
    if len(shadows) != 1 or not shadows[0][1].startswith(('$y$', '$6$')) or len(shadows[0][1]) < 32:
        raise Pending('administrator password is absent, locked or unsupported')
    # Password expiry must not silently turn a key-only unattended login into
    # a required password-change dialogue. Native PAM authentication is separate.
    if shadows[0][2] in ('', '0') or shadows[0][6:9] != ['', '', '']:
        raise Pending('expired or restricted existing administrator account')
    last_change = number(shadows[0][2])
    ages = [number(value) if value else None for value in shadows[0][3:6]]
    wall = time.time()
    if not KERNEL.finite_deadline(wall) or wall <= 0:
        raise Pending('invalid trusted account-age clock')
    day = int(wall // 86400)
    if (last_change > day or ages[1] is not None and day - last_change >= ages[1] or
        ages[0] is not None and ages[1] is not None and ages[0] > ages[1]):
        raise Pending('administrator password age requires native recovery')
    key_path = HOME / name / '.ssh/authorized_keys'
    keys, sources['keys'] = trusted_read(key_path, (TRUSTED_UID, uid), True)
    directory = key_path.parent.lstat()
    if directory.st_mode & 0o077:
        raise Pending('administrator key directory is not private')
    return {'name': name, 'uid': uid, 'gid': gid, 'key_file': str(key_path),
            'key_count': public_keys(keys), 'sources': sources}


def copied(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop(); count += 1
        if count > 65536 or depth > 16:
            raise Pending('SSH delivery structure exceeds bounds')
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise Pending('nonstring SSH delivery key')
            stack.extend((entry, depth + 1) for entry in (*item.keys(), *item.values()))
        elif type(item) is list:
            stack.extend((entry, depth + 1) for entry in item)
        elif item is not None and type(item) not in (str, int, bool):
            raise Pending('unsupported SSH delivery scalar')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > KERNEL.MAX_BYTES:
        raise Pending('SSH delivery byte bound exceeded')
    return json.loads(raw, object_pairs_hook=KERNEL.unique_object)


def checked_admin(value):
    fields = {'name', 'uid', 'gid', 'key_file', 'key_count', 'sources'}
    KERNEL.known(value, fields, fields)
    name = value['name']
    if type(name) is not str or NAME.fullmatch(name) is None or not 1000 <= KERNEL.uint(value['uid'], 59999):
        raise Pending('invalid SSH administrator identity')
    KERNEL.uint(value['gid'], 0x7fffffff)
    if value['key_file'] != str(HOME / name / '.ssh/authorized_keys') or not 1 <= KERNEL.uint(value['key_count'], 64):
        raise Pending('invalid SSH administrator key identity')
    KERNEL.known(value['sources'], {'passwd', 'group', 'shadow', 'keys'}, {'passwd', 'group', 'shadow', 'keys'})
    for key, source in value['sources'].items():
        KERNEL.known(source, {'path', 'identity', 'sha256'}, {'path', 'identity', 'sha256'})
        expected = value['key_file'] if key == 'keys' else str(ETC / key)
        identity = source['identity']
        if (source['path'] != expected or type(identity) is not list or len(identity) != 8 or
            any(type(part) is not int for part in identity) or
            not stat.S_ISREG(identity[2]) or identity[2] & 0o022 or identity[1] <= 0 or
            not 0 <= identity[0] <= (1 << 64) - 1 or not identity[1] <= (1 << 64) - 1 or
            not 0 <= identity[2] <= 0o177777 or not 0 <= identity[4] <= 0xffffffff or
            any(not -(1 << 63) <= timestamp < (1 << 63) for timestamp in identity[6:]) or
            identity[3] not in ((TRUSTED_UID, value['uid']) if key == 'keys' else (TRUSTED_UID,)) or
            not 0 <= identity[5] <= MAX_BYTES or key == 'keys' and identity[2] & 0o077 or
            key == 'shadow' and identity[2] & 0o007 or type(source['sha256']) is not str or
            re.fullmatch('[0-9a-f]{64}', source['sha256']) is None):
            raise Pending('invalid SSH account delivery source')
    return value


def network(snapshot, observed=0):
    interfaces = KERNEL.normalize(snapshot)
    admitted, loopback, names, expiry = [], [], set(), None
    by_name = {item['name']: item for item in interfaces}
    for row in snapshot['addresses']:
        if row['ifname'] == 'lo':
            if not {'UP', 'LOWER_UP', 'LOOPBACK'}.issubset(KERNEL.flags(row['flags'])):
                raise Pending('loopback is not active')
            for address in row['addr_info']:
                if address['local'] in ('127.0.0.1', '::1'):
                    if (address.get('scope') not in ('host', '254') or
                        any(type(address[flag]) is not bool or address[flag] for flag in
                            ('tentative', 'dadfailed', 'deprecated', 'temporary', 'optimistic') if flag in address) or
                        any(not KERNEL.uint(address.get(key)) for key in ('valid_life_time', 'preferred_life_time')) or
                        address['local'] in loopback):
                        raise Pending('loopback assignment is not positively usable')
                    loopback.append(address['local'])
                    until = observed + min(address[key] for key in ('valid_life_time', 'preferred_life_time'))
                    expiry = min(expiry, until) if expiry is not None else until
            continue
        link = by_name[row['ifname']]
        for address in row['addr_info']:
            version = 4 if address['family'] == 'inet' else 6
            ip = KERNEL.address(address['local'], version)
            prefix = ADMIN4 if version == 4 else ADMIN6
            if ip not in prefix:
                continue
            if not link['up'] or address['prefixlen'] != prefix.prefixlen or address.get('scope') not in ('global', '0'):
                raise Pending('admin address lacks active exact-prefix global assignment')
            for flag in ('dynamic', 'mngtmpaddr', 'noprefixroute', 'tentative', 'dadfailed', 'deprecated',
                         'temporary', 'secondary', 'optimistic', 'permanent'):
                if flag in address and type(address[flag]) is not bool:
                    raise Pending('admin assignment flag is not Boolean')
            if any(address.get(flag, False) for flag in ('tentative', 'dadfailed', 'deprecated', 'temporary', 'optimistic')):
                raise Pending('admin assignment is not usable')
            if any(not KERNEL.uint(address.get(key)) for key in ('valid_life_time', 'preferred_life_time')):
                raise Pending('admin assignment has no positive typed lifetimes')
            until = observed + min(address[key] for key in ('valid_life_time', 'preferred_life_time'))
            expiry = min(expiry, until) if expiry is not None else until
            routes = [entry for entry in snapshot[f'routes{version}']
                      if entry.get('dev') == link['name'] and entry['dst'] == str(prefix)
                      and KERNEL.table(entry.get('table', 254)) == 254
                      and KERNEL.route_type(entry.get('type', 'unicast')) == 'unicast'
                      and 'gateway' not in entry and 'linkdown' not in entry.get('flags', [])
                      and entry.get('scope') in ('link', '253')]
            if (len(routes) != 1 or ip == prefix.network_address or version == 4 and ip == prefix.broadcast_address or
                'prefsrc' in routes[0] and routes[0]['prefsrc'] != str(ip)):
                raise Pending('admin assignment lacks one supported direct route')
            if str(ip) in admitted:
                raise Pending('duplicate admin listener assignment')
            names.add(link['name']); admitted.append(str(ip))
    if len(names) != 1 or '127.0.0.1' not in loopback or not any(ipaddress.ip_address(value).version == 4 for value in admitted):
        raise Pending('one active IPv4 admin interface is required')
    return {'interface': by_name[next(iter(names))], 'listeners': sorted(admitted),
            'loopback': sorted(loopback), 'kernel': interfaces}, expiry


def configuration(admin, binding):
    lines = ['# Generated from checked local administrator and assigned admin addresses.',
        'Port 22', 'AddressFamily any', 'PermitRootLogin no', 'AuthenticationMethods publickey',
        'PubkeyAuthentication yes', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'PermitEmptyPasswords no', 'HostbasedAuthentication no', 'GSSAPIAuthentication no', 'UsePAM yes',
        'StrictModes yes', 'IgnoreRhosts yes', 'UseDNS no', 'PermitUserEnvironment no',
        'DisableForwarding yes', 'PermitTunnel no', 'X11Forwarding no', 'PermitTTY yes',
        'MaxAuthTries 3', 'MaxSessions 4', 'MaxStartups 10:30:30', 'LoginGraceTime 30',
        'ClientAliveInterval 120', 'ClientAliveCountMax 2', 'LogLevel VERBOSE',
        f'HostKey {HOST_KEY}', 'PidFile /run/debian13s4-admin-ssh.pid',
        'PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
        f'AuthorizedKeysFile {admin["key_file"]}',
        f'AllowUsers {admin["name"]}@127.0.0.1/32 {admin["name"]}@::1/128 '
        f'{admin["name"]}@{ADMIN4} {admin["name"]}@{ADMIN6}']
    for value in [*binding['loopback'], *binding['listeners']]:
        lines.append(f'ListenAddress [{value}]:22' if ':' in value else f'ListenAddress {value}:22')
    return ('\n'.join(lines) + '\n').encode('ascii')


def prepare(query=KERNEL.native_query, account=administrator, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid SSH preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid SSH namespace')
    first_admin = checked_admin(copied(account()))
    records = []
    for _ in range(2):
        fence(end)
        raw, observed = {}, None
        for name in KERNEL.COMMANDS:
            fence(end)
            raw[name] = copied(query(name, end))
            if name == 'addresses':
                observed = KERNEL.now()
        raw = copied(raw)
        binding, expiry = network(raw, observed)
        end = min(end, expiry)
        fence(end)
        records.append({'raw': raw, 'binding': binding})
    last_admin = checked_admin(copied(account()))
    if first_admin != last_admin or records[0] != records[1]:
        raise Pending('SSH administrator or network deliveries changed')
    payload = configuration(last_admin, records[1]['binding'])
    if len(payload) > MAX_BYTES:
        raise Pending('SSH configuration exceeds byte bound')
    final_namespace = scope()
    if not KERNEL.uint(final_namespace, (1 << 64) - 1) or final_namespace != namespace:
        raise Pending('SSH namespace changed')
    fence(end)
    return {'namespace': namespace, 'admin': last_admin, 'binding': records[1]['binding'],
            'configuration': payload, 'deadline': end}


def capture(binary, arguments, deadline):
    fence(deadline)
    if type(arguments) is not tuple or any(type(argument) is not str for argument in arguments) or not (
        binary == SSHD and arguments in (('-t', '-f', str(CONFIG)), ('-T', '-f', str(CONFIG))) or
        binary == SS and arguments == ('-H', '-n', '-l', '-t', '-p', 'sport = :22')):
        raise Pending('unapproved SSH native read')
    identity = KERNEL.trusted_binary(binary)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    fence(end)
    process = subprocess.Popen([str(binary), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        with selectors.DefaultSelector() as selector:
            for label, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                fence(end)
                for key, _ in selector.select(end - KERNEL.now()):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj); continue
                    buffer = buffers[key.data]
                    if len(buffer) + len(data) > MAX_BYTES:
                        raise Pending('SSH native channel limit exceeded')
                    buffer.extend(data)
            fence(end)
            code = process.wait(timeout=end - KERNEL.now())
            if type(code) is not int or code != 0 or buffers['stderr']:
                raise Pending('SSH native check failed or warned')
        if KERNEL.trusted_binary(binary) != identity:
            raise Pending('SSH native executable changed')
        fence(end)
        return bytes(buffers['stdout'])
    finally:
        try:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=KERNEL.CLEANUP_SECONDS)
        finally:
            process.stdout.close(); process.stderr.close()


def effective(raw, plan):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('invalid effective sshd encoding') from error
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(' ')
        if not separator or not re.fullmatch('[a-z0-9]+', key) or not value or '\x00' in value:
            raise Pending('invalid effective sshd row')
        if key in values and key not in ('listenaddress', 'hostkey', 'allowusers'):
            raise Pending('duplicate effective sshd setting')
        values.setdefault(key, []).append(value)
    required = {'port': '22', 'addressfamily': 'any', 'permitrootlogin': 'no',
        'authenticationmethods': 'publickey', 'pubkeyauthentication': 'yes',
        'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
        'permitemptypasswords': 'no', 'hostbasedauthentication': 'no', 'gssapiauthentication': 'no',
        'usepam': 'yes', 'strictmodes': 'yes', 'usedns': 'no', 'permituserenvironment': 'no',
        'disableforwarding': 'yes', 'permittunnel': 'no', 'x11forwarding': 'no',
        'authorizedkeysfile': plan['admin']['key_file'], 'authorizedkeyscommand': 'none',
        'trustedusercakeys': 'none', 'authorizedprincipalsfile': 'none',
        'pubkeyacceptedalgorithms': 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256'}
    for key, value in required.items():
        if values.get(key) != [value]:
            raise Pending(f'effective sshd setting differs: {key}')
    users = f'{plan["admin"]["name"]}@127.0.0.1/32 {plan["admin"]["name"]}@::1/128 '
    users += f'{plan["admin"]["name"]}@{ADMIN4} {plan["admin"]["name"]}@{ADMIN6}'
    admitted_users = [pattern for row in values.get('allowusers', []) for pattern in row.split()]
    if admitted_users != users.split() or values.get('hostkey') != [str(HOST_KEY)]:
        raise Pending('effective sshd user/key authority differs')
    listeners = {f'[{value}]:22' if ':' in value else f'{value}:22'
                 for value in [*plan['binding']['loopback'], *plan['binding']['listeners']]}
    if len(values.get('listenaddress', [])) != len(listeners) or set(values.get('listenaddress', [])) != listeners:
        raise Pending('effective sshd listeners differ')


def sockets(raw, plan, pid):
    if not KERNEL.uint(pid, 0x7fffffff):
        raise Pending('invalid SSH service PID')
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('invalid SSH socket encoding') from error
    expected = {f'[{value}]:22' if ':' in value else f'{value}:22'
                for value in [*plan['binding']['loopback'], *plan['binding']['listeners']]}
    found = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 6 or parts[0] != 'LISTEN' or not all(re.fullmatch('[0-9]+', part) for part in parts[1:3]):
            raise Pending('unsupported SSH listening socket row')
        number(parts[1], 0xffffffff); number(parts[2], 0xffffffff)
        owner = re.fullmatch(r'users:\(\("sshd",pid=([1-9][0-9]*),fd=([0-9]+)\)\)', parts[5])
        if (owner is None or int(owner[1]) != pid or parts[3] not in expected or parts[3] in found or
            parts[4] not in ('0.0.0.0:*', '[::]:*', '*:*')):
            raise Pending('SSH listener is missing, foreign, duplicate or public')
        number(owner[1]); number(owner[2])
        found.add(parts[3])
    if found != expected:
        raise Pending('partial SSH listener inventory')


def check(plan=None, read=capture, live_pid=None):
    plan = prepare() if plan is None else plan
    fence(plan['deadline'])
    config, config_source = trusted_read(CONFIG, (TRUSTED_UID,), True)
    host_key = trusted_read(HOST_KEY, (TRUSTED_UID,), True)
    if config != plan['configuration']:
        raise Pending('installed SSH configuration differs from fresh preparation')
    if read(SSHD, ('-t', '-f', str(CONFIG)), plan['deadline']):
        raise Pending('sshd syntax check produced unexpected output')
    effective(read(SSHD, ('-T', '-f', str(CONFIG)), plan['deadline']), plan)
    if live_pid is not None:
        sockets(read(SS, ('-H', '-n', '-l', '-t', '-p', 'sport = :22'), plan['deadline']), plan, live_pid)
    if trusted_read(CONFIG, (TRUSTED_UID,), True) != (config, config_source) or trusted_read(
        HOST_KEY, (TRUSTED_UID,), True) != host_key:
        raise Pending('SSH configuration or host key changed during native checks')
    namespace = KERNEL.namespace()
    if not KERNEL.uint(namespace, (1 << 64) - 1) or administrator() != plan['admin'] or namespace != plan['namespace']:
        raise Pending('SSH account or namespace changed during native checks')
    fence(plan['deadline'])


def main():
    if sys.argv[1:] not in (['--plan'], ['--check']) and not (
        len(sys.argv) == 3 and sys.argv[1] == '--live' and re.fullmatch('[1-9][0-9]{0,9}', sys.argv[2])):
        return 64
    if sys.argv[1] == '--live' and int(sys.argv[2]) > 0x7fffffff:
        return 64
    try:
        sink = sys.stdout.buffer
        if not callable(sink.write) or not callable(sink.flush):
            raise Pending('SSH CLI requires a binary sink')
        if sys.argv[1] == '--plan':
            payload = prepare()['configuration']
            count = sink.write(payload)
            if type(count) is not int or count != len(payload):
                raise Pending('incomplete SSH configuration publication')
            sink.flush()
        else:
            check(live_pid=int(sys.argv[2]) if sys.argv[1] == '--live' else None)
        return 0
    except (OSError, ValueError, AttributeError, subprocess.TimeoutExpired, RecursionError) as error:
        print(f'debian13s4 SSH pending: {error}', file=sys.stderr)
        return 75


if __name__ == '__main__':
    raise SystemExit(main())
S4_PAYLOAD_a826ec818551234b1c98a344e189bb23da4bc4fb173bb00a1ab189d8031692b7
    cat > "$S4B_STAGE/lib/ssh/repair.sh" <<'S4_PAYLOAD_c695a6f939cef5eb0dec883b04722c71095877f7e0c06f9a76161b6672f35bdf' || return 1
#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_repair
S4_PAYLOAD_c695a6f939cef5eb0dec883b04722c71095877f7e0c06f9a76161b6672f35bdf
    cat > "$S4B_STAGE/lib/ssh/debian13s4-admin-ssh.service" <<'S4_PAYLOAD_1bb3285e71f2461e8159bd93ba240fae1b89d03cfcf832f811d0d8b411bac735' || return 1
[Unit]
Description=Key-authenticated Debian admin SSH on positively assigned admin LAN addresses
After=network-online.target systemd-user-sessions.service
Wants=network-online.target
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/ssh /home
ConditionPathExists=!/var/lib/debian13s4/bootstrap/pending
StartLimitIntervalSec=0

[Service]
Type=exec
ExecStartPre=/usr/bin/python3 -I -B /usr/local/lib/debian13s4/ssh/policy.py --check
ExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/debian13s4-admin.conf
User=root
Group=root
UMask=0077
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
StandardInput=null
StandardOutput=journal
StandardError=journal
TimeoutStartSec=90s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=15s
KillMode=control-group
# Login sessions need the ordinary PAM/PTY and authenticated sudo execution
# context. Applying NoNewPrivileges or a read-only mount namespace to those
# sessions would also disable the administrator's existing elevation path.

[Install]
WantedBy=multi-user.target
S4_PAYLOAD_1bb3285e71f2461e8159bd93ba240fae1b89d03cfcf832f811d0d8b411bac735
    cat > "$S4B_STAGE/lib/ssh/debian13s4-ssh.service" <<'S4_PAYLOAD_37346a701711ae61f025720ce4360cc5b8de008fce611ce077c43c1181302b59' || return 1
[Unit]
Description=Recheck and rebind the explicit admin SSH configuration
After=network-online.target
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/ssh /home
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/ssh/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# Four 66s policy admissions, at most 51 bounded 11s controls, and 60s
# finite local allowance fit 885s. The outer 900s limit does not widen them.
TimeoutStartSec=900s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=1min
KillMode=control-group
NoNewPrivileges=yes
# Read private administrator keys and the privileged listener's /proc FD links
# for the fixed ss ownership query. Home remains read-only; no ptrace call is made.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE
ProtectSystem=strict
ReadWritePaths=/etc/ssh /var/lib/debian13s4
ProtectHome=read-only
PrivateTmp=yes
ProtectClock=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=~@mount
S4_PAYLOAD_37346a701711ae61f025720ce4360cc5b8de008fce611ce077c43c1181302b59
    cat > "$S4B_STAGE/lib/ssh/debian13s4-ssh.timer" <<'S4_PAYLOAD_7554b9365ae78d6a59c1bc1dc1eedfa14a07f5f64aabc79a45f540862a12233d' || return 1
[Unit]
Description=Reconcile admin SSH after boot and periodically

[Timer]
OnBootSec=15s
OnUnitInactiveSec=1min
AccuracySec=5s
Unit=debian13s4-ssh.service

[Install]
WantedBy=timers.target
S4_PAYLOAD_7554b9365ae78d6a59c1bc1dc1eedfa14a07f5f64aabc79a45f540862a12233d
    cat > "$S4B_STAGE/lib/tasks/ssh/apply.sh" <<'S4_PAYLOAD_22ebcfa9fc38e455077130d400e76433948740c8e80c1475bf8224891813a1b9' || return 1
#!/bin/bash
# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_apply
S4_PAYLOAD_22ebcfa9fc38e455077130d400e76433948740c8e80c1475bf8224891813a1b9
    cat > "$S4B_STAGE/lib/tasks/ssh/verify.sh" <<'S4_PAYLOAD_3e0d51509cf31af2188db77617d6e06ace86350c51b57425b5c066e76059f19e' || return 1
#!/bin/bash
# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_verify
S4_PAYLOAD_3e0d51509cf31af2188db77617d6e06ace86350c51b57425b5c066e76059f19e
    cat > "$S4B_STAGE/files.sha256" <<'S4_CHECKSUMS' || return 1
5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936  lib/repair.sh
c51fc882b1d507dab10b5d912d5f82b4d0902ef31da87bc7a228fd95d4cd2ec1  lib/tasks.list
f00b984fac21636c60e8a4dd9d1ade6cdf58bcd0123d669e7fba51c756346934  lib/tasks/prerequisites/apply.sh
5c2bb90b18725176df85061f2fd7556fc5f00c286991f7ff34445d7b880693fc  lib/tasks/prerequisites/verify.sh
84d897f0a349e9f7dc4dbf5aa75fc86c4cb7d67a67ca1f61439a982cdf0c86b4  lib/tasks/prerequisites/common.sh
7d995cf7bc3d3db5461c7c21a4989495a042e0a5fc34a186cc68bc859c62b0c4  lib/tasks/prerequisites/debian.sources
e21ba280c03e5c9848930e7a58b87febd59332e777a3a992e3bab1f992c1a3e5  units/debian13s4-repair.service
8618edcc26838d9f7f56c39d538bcfdba099e101582e8fb0adb38df413c5ce28  units/debian13s4-repair.timer
a107d7016113884baa5f42ef8c5523410d1193f9970c3d320647dc0ee3d3a5f9  units/debian13s4-resume.service
c9c5a3f1e2a4182b94132b25709ff4fdb95405457ac41372fd353437e3a55d04  lib/maintenance/common.sh
49a7885c56c73c77b6c1a3466b1b6e6fafc263ad4903c89b7947f07f88d482c1  lib/maintenance/update.sh
bc7e6d139257f55d2b8b77c87263709c5fafb72242d728d4372d81d2915d478f  lib/maintenance/policy.conf
9f464f118004aba860998254cb5ce0a4f6b4dce6ca84c38e861ec0f179656eec  lib/maintenance/needrestart.conf
4459b2afa9b1914dad46d50758e533160d1f5e63deb017310fa296b170bb4cfe  lib/maintenance/restart-policy.pl
b213906bff69cad34a5f2a547727622474f545c207bfca681f8a3dcac521b5ac  lib/maintenance/retain-kernels.py
d2681c6dde48e6cfbd0232cc1303f589fa042b39224489331574aa49c79bd890  lib/maintenance/debian13s4-maintenance.service
bce83c7102c31c4e9c5ee8f2bde3ba5a7e33b702b159d1b6f453058985142209  lib/maintenance/debian13s4-maintenance.timer
488522a33f05b35c7c854074bdcb8d02510e2ea89f6025def2b493c4f81641ec  lib/tasks/maintenance/apply.sh
7aecaab921b4770b6034d966a36ed3b9d94a1e1ae35f901c067c1d4a45c2f762  lib/tasks/maintenance/verify.sh
bc4da33d1b6068f61f3e88bf8251bc64ad5fe5dafcbbc9a98857712a177404e4  lib/dotnet/common.sh
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
95a05f503668b3e24a05b33675d961a4d58700e17b4eab50f41da33dba72b632  lib/network/common.sh
f6c3d8720b50aad13e41edfa2a6890b2abe624d05e66920c86b003a520eaa541  lib/network/repair.sh
f8609255110e1e3cc5686bc366de484c9eb247028dfe817775b19b4a778d29c0  lib/network/verify.py
ba23f85b4240cf1ac9eb91929fba5ce15626c76eadad892ff2f3733aa928f696  lib/network/network.conf
eaaf6c2cdf2e36aa2bb49f9bf0a5b668c6788102813dbdb9104127413eb7a812  lib/network/debian13s4-network.service
13c391ea87a782aaae1b1e2ed6629a340c9bcd37841e54a09000709e4c663b03  lib/network/debian13s4-network.timer
978090bd3843e6a8dbedce17864be98ac183fa3313ba2bcece27d8b4c4ceea1b  lib/tasks/network/apply.sh
2c4a253e0fba47833ef625a9f3ea5b15062b3e43ffc36a6a6861a06dcaf2ace4  lib/tasks/network/verify.sh
c7bf108d8bf796d7db45af4030142b1ca066aa9b224639943b794e2a9626fb6a  lib/retention/common.sh
2d85e370e47f67a7500e72a9048b78f033246f13d1ccf37d1eb79740a7e1b330  lib/retention/repair.sh
d164649f35a3441e5eb6564d552a540f3cca1748f61ec8a59f18196e9fcefeb4  lib/retention/journal.py
715e936a70e166fa6c3bc4e63a4b2fed4fec56b33960c3810d2af54be01489d5  lib/retention/clean-cache.py
dfdda3c5c5f008fc693b0fb1e47a04df8ff33aae4ddc90f4c2126f612115d6ef  lib/retention/apt.conf
6a2cae9f09342d5f54c40602d0b5a4b10aca08ee34bd3c35bf1deb09a90c3729  lib/retention/journal.conf
4a18bd9011f90260329a19cdf2747f01f041bafd7184978b5cb8ac8eece4eba5  lib/retention/debian13s4-retention.service
3484989b87fe25b6eed5e8759d0ff036007e85e10d1e2a6fa129d6294fb18048  lib/retention/debian13s4-retention.timer
6a932d600d6894880eaa54c51b274d7bee8cb081fc7018371a43ecf9ac103fb2  lib/tasks/retention/apply.sh
eaf8d9e89061834624d417ebec6211c3257dcecf52030178597b2c93859503dc  lib/tasks/retention/verify.sh
b7e4737e20c27894bbd2613f8df131614b6d0ebfc9aa589c758df9aac2de8efc  lib/hardening/common.sh
7d84a4dd2ff8134daaf14cd35175acb429e89c64404db5f48a0850b5579b4fe2  lib/hardening/repair.sh
08603c329a5de83416253604ca14bf538773dd2b7fc7a39cdd97ee0afa72b424  lib/hardening/verify.py
383ca561603ed05e64f68cd788ff3f223c2ec48ad2c8d665526b96c66b0e5c7d  lib/hardening/kernel.conf
6360caf81c8e4c93cbfc6cd0e62e9ddd6ddd207b843eed0b17deae08cdea811b  lib/hardening/debian13s4-hardening.service
e2de7086c2159bf4cd8a2775d8a3aba484b1c5c5237f9c4a36f7e0db4c8e371a  lib/hardening/debian13s4-hardening.timer
896f7ea78d7f63a5858bbbe278c13fbfc1b49e34875b22c7fcf32567c32d836b  lib/tasks/hardening/apply.sh
93f98e5dac2f0a3a4e7479eadfa4b52941ac936d4cce43adf7360ad4d08ec8f7  lib/tasks/hardening/verify.sh
c96d0066b1cb453daf45d4a7fb41d4bada3c96c499e60dfc7da7ee60dfdc562e  lib/firewall/kernel.py
a4a45b676286e7d553103f426645c99cc0b8413db73cc0515802671097dd743b  lib/ssh/common.sh
a826ec818551234b1c98a344e189bb23da4bc4fb173bb00a1ab189d8031692b7  lib/ssh/policy.py
c695a6f939cef5eb0dec883b04722c71095877f7e0c06f9a76161b6672f35bdf  lib/ssh/repair.sh
1bb3285e71f2461e8159bd93ba240fae1b89d03cfcf832f811d0d8b411bac735  lib/ssh/debian13s4-admin-ssh.service
37346a701711ae61f025720ce4360cc5b8de008fce611ce077c43c1181302b59  lib/ssh/debian13s4-ssh.service
7554b9365ae78d6a59c1bc1dc1eedfa14a07f5f64aabc79a45f540862a12233d  lib/ssh/debian13s4-ssh.timer
22ebcfa9fc38e455077130d400e76433948740c8e80c1475bf8224891813a1b9  lib/tasks/ssh/apply.sh
3e0d51509cf31af2188db77617d6e06ace86350c51b57425b5c066e76059f19e  lib/tasks/ssh/verify.sh
S4_CHECKSUMS
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4B_PATH
    export PATH
    umask 077
    s4b_main "$@"
fi
