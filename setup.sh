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
    debian13s4-ssh.timer debian13s4-ssh.service debian13s4-admin-ssh.service
    debian13s4-postgresql.timer debian13s4-postgresql.service debian13s4-postgresql-server.service
    debian13s4-web.timer debian13s4-web.service debian13s4-web-server.service)
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

S4B_BUNDLE_ID=d6549f0a86f31fcff562dc57319fa467f23b37cc40971d3a89c7a520d0a482f1
S4B_FILES=(lib/repair.sh lib/tasks.list lib/tasks/prerequisites/apply.sh lib/tasks/prerequisites/verify.sh lib/tasks/prerequisites/common.sh lib/tasks/prerequisites/debian.sources units/debian13s4-repair.service units/debian13s4-repair.timer units/debian13s4-resume.service lib/maintenance/common.sh lib/maintenance/update.sh lib/maintenance/policy.conf lib/maintenance/needrestart.conf lib/maintenance/restart-policy.pl lib/maintenance/retain-kernels.py lib/maintenance/debian13s4-maintenance.service lib/maintenance/debian13s4-maintenance.timer lib/tasks/maintenance/apply.sh lib/tasks/maintenance/verify.sh lib/dotnet/common.sh lib/dotnet/update.sh lib/dotnet/verify-payload.pl lib/dotnet/policy.conf lib/dotnet/preferences lib/dotnet/microsoft-2025.asc lib/dotnet/debian13s4-dotnet.service lib/dotnet/debian13s4-dotnet.timer lib/dotnet/sources.sources lib/tasks/dotnet/apply.sh lib/tasks/dotnet/verify.sh lib/network/common.sh lib/network/repair.sh lib/network/verify.py lib/network/network.conf lib/network/debian13s4-network.service lib/network/debian13s4-network.timer lib/tasks/network/apply.sh lib/tasks/network/verify.sh lib/retention/common.sh lib/retention/repair.sh lib/retention/journal.py lib/retention/clean-cache.py lib/retention/apt.conf lib/retention/journal.conf lib/retention/debian13s4-retention.service lib/retention/debian13s4-retention.timer lib/tasks/retention/apply.sh lib/tasks/retention/verify.sh lib/hardening/common.sh lib/hardening/repair.sh lib/hardening/verify.py lib/hardening/kernel.conf lib/hardening/debian13s4-hardening.service lib/hardening/debian13s4-hardening.timer lib/tasks/hardening/apply.sh lib/tasks/hardening/verify.sh lib/firewall/kernel.py lib/ssh/common.sh lib/ssh/policy.py lib/ssh/repair.sh lib/ssh/debian13s4-admin-ssh.service lib/ssh/debian13s4-ssh.service lib/ssh/debian13s4-ssh.timer lib/tasks/ssh/apply.sh lib/tasks/ssh/verify.sh lib/postgresql/prepare.py lib/postgresql/live.py lib/postgresql/access.py lib/postgresql/backup.py lib/postgresql/archive_stage.py lib/postgresql/archive_inspection.py lib/postgresql/dump_stream.py lib/postgresql/selected_stage.py lib/postgresql/selected_inspection.py lib/postgresql/selected_uncertainty.py lib/postgresql/stage_manifest.py lib/postgresql/backup_attempt.py lib/postgresql/backup_lifecycle.py lib/postgresql/private_storage.py lib/postgresql/backup_status.py lib/postgresql/backup_run.py lib/postgresql/attempt_failure.py lib/postgresql/common.sh lib/postgresql/repair.sh lib/postgresql/debian13s4-postgresql-server.service lib/postgresql/debian13s4-postgresql.service lib/postgresql/debian13s4-postgresql.timer lib/tasks/postgresql/apply.sh lib/tasks/postgresql/verify.sh lib/web/prepare.py lib/web/live.py lib/web/upstream.py lib/web/common.sh lib/web/repair.sh lib/web/debian13s4-web-server.service lib/web/debian13s4-web.service lib/web/debian13s4-web.timer lib/tasks/web/apply.sh lib/tasks/web/verify.sh lib/applications/releases.py lib/applications/identities.py lib/applications/dns_service.py lib/applications/postgresql_identity.py lib/applications/sava_transport.py lib/applications/sava_ingress.py lib/applications/sava_service.py lib/applications/private_directory.py lib/applications/email_worker.py lib/applications/email_gateway.py lib/applications/prepare.py lib/applications/preflight.py lib/applications/release_manifest.py lib/applications/linux_images.py lib/applications/linux_linkage.py lib/applications/managed_runtime.py lib/applications/cli_image.py lib/applications/managed_images.py lib/applications/managed_assets.py lib/dns/prepare.py)
S4B_MODES=(0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0755 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644 0644)

s4b_write_bundle() {
    mkdir -p -- "$S4B_STAGE/"lib "$S4B_STAGE/"lib/tasks/prerequisites "$S4B_STAGE/"units "$S4B_STAGE/"lib/maintenance "$S4B_STAGE/"lib/tasks/maintenance "$S4B_STAGE/"lib/dotnet "$S4B_STAGE/"lib/tasks/dotnet "$S4B_STAGE/"lib/network "$S4B_STAGE/"lib/tasks/network "$S4B_STAGE/"lib/retention "$S4B_STAGE/"lib/tasks/retention "$S4B_STAGE/"lib/hardening "$S4B_STAGE/"lib/tasks/hardening "$S4B_STAGE/"lib/firewall "$S4B_STAGE/"lib/ssh "$S4B_STAGE/"lib/tasks/ssh "$S4B_STAGE/"lib/postgresql "$S4B_STAGE/"lib/tasks/postgresql "$S4B_STAGE/"lib/web "$S4B_STAGE/"lib/tasks/web "$S4B_STAGE/"lib/applications "$S4B_STAGE/"lib/dns || return 1
    printf '%s' "#!/bin/bash
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
    printf 'debian13s4: %s\\n' \"\$*\" >&2
}

s4_trusted_path() {
    local path=\$1 owner mode
    if [[ \$path != /* || \$path == *'/../'* || \$path == */.. ||
        \$path == *'/./'* || \$path == */. || \$path == *'//'* ]]; then
        s4_log \"Refusing a non-canonical path: \$path\"
        return 1
    fi
    while :; do
        if [[ -L \$path || ! -e \$path ]]; then
            s4_log \"Refusing a missing or symbolic-link path: \$path\"
            return 1
        fi
        if ! read -r owner mode < <(stat --format='%u %a' -- \"\$path\"); then
            return 1
        fi
        if [[ \$owner != 0 ]] || (( (8#\$mode & 8#022) != 0 )); then
            s4_log \"Refusing a path writable by an unprivileged account: \$path\"
            return 1
        fi
        [[ \$path == / ]] && break
        path=\${path%/*}
        [[ -n \$path ]] || path=/
    done
}

s4_atomic_write() {
    local target=\$1 temporary
    if ! temporary=\$(mktemp -- \"\${target}.XXXXXX\"); then
        return 1
    fi
    if ! cat > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! mv -fT -- \"\$temporary\" \"\$target\"; then
        rm -f -- \"\$temporary\"
        return 1
    fi
}

s4_prepare_state() {
    local path
    if ! s4_trusted_path \"\${S4_STATE_DIR%/*}\"; then
        return 1
    fi
    for path in \"\$S4_STATE_DIR\" \"\$S4_STATE_DIR/results\"; do
        if [[ -e \$path || -L \$path ]]; then
            s4_trusted_path \"\$path\" && [[ -d \$path ]] || return 1
        elif ! install -d -o root -g root -m 0700 -- \"\$path\"; then
            return 1
        fi
        chmod 0700 -- \"\$path\" || return 1
    done
}

s4_load_tasks() {
    local manifest=\$S4_LIBRARY_DIR/tasks.list line task dependency
    local -a dependencies=()
    local -A seen=()
    S4_TASKS=()
    S4_DEPENDENCIES=()
    [[ -f \$manifest ]] && s4_trusted_path \"\$manifest\" || return 1
    while IFS= read -r line || [[ -n \$line ]]; do
        [[ \$line =~ ^[[:space:]]*(#.*)?\$ ]] && continue
        if [[ \$line != *:* ]]; then
            s4_log 'Task bundle contains a malformed registry entry.'
            return 1
        fi
        task=\${line%%:*}
        if [[ ! \$task =~ ^[a-z][a-z0-9_]{0,47}\$ ]]; then
            s4_log 'Task bundle contains an invalid task name.'
            return 1
        fi
        if [[ -n \${seen[\$task]+present} ]]; then
            s4_log \"Task bundle repeats \$task.\"
            return 1
        fi
        read -r -a dependencies <<< \"\${line#*:}\"
        for dependency in \"\${dependencies[@]}\"; do
            if [[ ! \$dependency =~ ^[a-z][a-z0-9_]{0,47}\$ ]] ||
                [[ -z \${seen[\$dependency]+present} ]]; then
                s4_log \"Task \$task requires a missing, cyclic, or later dependency.\"
                return 1
            fi
        done
        S4_TASKS+=(\"\$task\")
        S4_DEPENDENCIES[\$task]=\${dependencies[*]}
        seen[\$task]=1
    done < \"\$manifest\"
    if (( \${#S4_TASKS[@]} == 0 )); then
        s4_log 'Refusing to declare an empty task bundle complete.'
        return 1
    fi
    for task in \"\${S4_TASKS[@]}\"; do
        for line in apply verify; do
            [[ -f \$S4_LIBRARY_DIR/tasks/\$task/\$line.sh ]] &&
                s4_trusted_path \"\$S4_LIBRARY_DIR/tasks/\$task/\$line.sh\" || return 1
        done
    done
}

s4_execute_phase() {
    local phase=\$1 task=\$2 script
    [[ \$phase == apply || \$phase == verify ]] || return 1
    [[ \$task =~ ^[a-z][a-z0-9_]{0,47}\$ ]] || return 1
    script=\$S4_LIBRARY_DIR/tasks/\$task/\$phase.sh
    [[ -f \$script ]] && s4_trusted_path \"\$script\" || return 1
    (
        # A child must not hold the worker's lock after the worker exits.
        if [[ -n \$S4_LOCK_FD ]]; then
            exec {S4_LOCK_FD}>&-
        fi
        # A fresh interpreter keeps errexit active even when the parent checks
        # the exit status in an if statement. No inherited shell code is loaded.
        exec timeout --signal=TERM --kill-after=\"\$(s4_seconds \"\$S4_KILL_DELAY_MS\")\" \\
            \"\$(s4_seconds \"\$S4_PHASE_TIMEOUT_MS\")\" \\
            env -i PATH=\"\$S4_PHASE_PATH\" LANG=C LC_ALL=C \\
            DEBIAN_FRONTEND=noninteractive \\
            /bin/bash --noprofile --norc -e -u -o pipefail -- \"\$script\"
    )
}

s4_seconds() {
    printf '%s.%03ds' \"\$((\$1 / 1000))\" \"\$((\$1 % 1000))\"
}

s4_control() (
    if [[ -n \$S4_LOCK_FD ]]; then
        exec {S4_LOCK_FD}>&-
    fi
    timeout --signal=TERM --kill-after=\"\$(s4_seconds \"\$S4_CONTROL_KILL_MS\")\" \\
        \"\$(s4_seconds \"\$S4_CONTROL_TIMEOUT_MS\")\" \"\$@\"
)

s4_systemctl() {
    s4_control systemctl \"\$@\"
}

s4_sync_filesystems() {
    # Linux syncfs waits for file data AND filesystem metadata, including
    # rename/directory entries. Unlike plain sync, errors are observable.
    s4_control sync --file-system -- \"\$@\"
}

s4_persist_recovery_intent() {
    local marker=\$S4_STATE_DIR/timer-stop.pending
    if [[ -e \$marker || -L \$marker ]]; then
        # Do not replace an already durable marker with a volatile inode when
        # retrying after an IO error. Its presence, not its contents, is the gate.
        [[ -f \$marker && ! -L \$marker ]] && s4_trusted_path \"\$marker\" || return 1
    else
        printf 'pending\\n' | s4_atomic_write \"\$marker\" || return 1
    fi
    s4_sync_filesystems \"\$S4_STATE_DIR\"
}

s4_persist_boot_guard() {
    local path resolved wants=\$S4_SYSTEMD_DIR/multi-user.target.wants
    local -a paths=(\"\$S4_LIBRARY_DIR\" \"\$S4_LIBRARY_DIR/repair.sh\"
        \"\$S4_SYSTEMD_DIR\" \"\$S4_SYSTEMD_DIR/\$S4_RESUME_SERVICE\"
        \"\$S4_SYSTEMD_DIR/\$S4_SERVICE\" \"\$S4_SYSTEMD_DIR/\$S4_TIMER\" \"\$wants\")
    for path in \"\${paths[@]}\"; do
        s4_trusted_path \"\$path\" || return 1
    done
    [[ -d \$wants && -f \$S4_SYSTEMD_DIR/\$S4_RESUME_SERVICE &&
        -f \$S4_SYSTEMD_DIR/\$S4_SERVICE && -f \$S4_SYSTEMD_DIR/\$S4_TIMER &&
        -x \$S4_LIBRARY_DIR/repair.sh && -L \$wants/\$S4_RESUME_SERVICE ]] || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4_RESUME_SERVICE\") || return 1
    [[ \$resolved == \"\$S4_SYSTEMD_DIR/\$S4_RESUME_SERVICE\" ]] || return 1
    # Cover the unit/code files, link parent and its ancestors even when they
    # reside on different filesystems. A read-back of enablement cannot do this.
    s4_sync_filesystems \"\${paths[@]}\"
}

s4_persist_timer_enablement() {
    local wants=\$S4_SYSTEMD_DIR/timers.target.wants
    local -a paths=(\"\$S4_SYSTEMD_DIR\")
    s4_trusted_path \"\$S4_SYSTEMD_DIR\" || return 1
    # disable may remove an empty wants directory. Its removal is then covered
    # by the parent's filesystem; a separately mounted wants directory remains.
    if [[ -d \$wants ]]; then
        s4_trusted_path \"\$wants\" || return 1
        paths+=(\"\$wants\")
    fi
    s4_sync_filesystems \"\${paths[@]}\"
}

s4_notify() {
    # Keep systemd-notify's acknowledgement barrier: enqueueing is insufficient.
    s4_control systemd-notify \"\$@\"
}

s4_attempt_budget_ms() {
    local per_task overhead count=\${#S4_TASKS[@]}
    per_task=\$((3 * (S4_PHASE_TIMEOUT_MS + S4_KILL_DELAY_MS) + S4_TASK_OVERHEAD_MS))
    overhead=\$((S4_ATTEMPT_OVERHEAD_MS + S4_CONTROL_CALL_BUDGET *
        (S4_CONTROL_TIMEOUT_MS + S4_CONTROL_KILL_MS + S4_POLL_INTERVAL_MS)))
    # The notification expresses microseconds in signed 64-bit arithmetic.
    if (( count > (9223372036854775 - overhead) / per_task )); then
        s4_log 'The admitted bundle exceeds the representable attempt budget.'
        return 1
    fi
    printf '%s\\n' \"\$((count * per_task + overhead))\"
}

s4_arm_attempt_deadline() {
    local budget
    budget=\$(s4_attempt_budget_ms) || return 1
    if [[ -n \${NOTIFY_SOCKET:-} ]]; then
        # READY starts RuntimeMaxSec. Extend that running deadline only after
        # READY has been acknowledged, with room for every admitted phase.
        s4_notify --ready || return 1
        s4_notify \"EXTEND_TIMEOUT_USEC=\$((budget * 1000))\" || return 1
    fi
}

s4_record_task() {
    local task=\$1 state=\$2 reason=\$3
    printf 'state=%s\\nreason=%s\\n' \"\$state\" \"\$reason\" |
        s4_atomic_write \"\$S4_STATE_DIR/results/\$task\"
}

s4_record_summary() {
    local state=\$1 pending=\$2
    printf 'state=%s\\npending_tasks=%s\\ntotal_tasks=%s\\n' \\
        \"\$state\" \"\$pending\" \"\${#S4_TASKS[@]}\" |
        s4_atomic_write \"\$S4_STATE_DIR/status\"
}

s4_enabled_state() {
    local unit=\$1 expected=\$2 actual code=0
    actual=\$(s4_systemctl is-enabled \"\$unit\") || code=\$?
    # is-enabled returns 1 for a disabled unit. Other errors are not evidence.
    (( code == 0 || code == 1 )) && [[ \$actual == \"\$expected\" ]]
}

s4_wait_timer_state() {
    local expected_active=\$1 expected_enabled=\$2 actual attempt
    for ((attempt = 0; attempt < S4_POLL_COUNT; attempt++)); do
        if actual=\$(s4_systemctl show --property=ActiveState --value \"\$S4_TIMER\") &&
            [[ \$actual == \"\$expected_active\" ]] &&
            { [[ -z \$expected_enabled ]] || s4_enabled_state \"\$S4_TIMER\" \"\$expected_enabled\"; }; then
            return 0
        fi
        if (( attempt + 1 < S4_POLL_COUNT )); then
            sleep \"\$(s4_seconds \"\$S4_POLL_INTERVAL_MS\")\" || return 1
        fi
    done
    return 1
}

s4_restore_timer() {
    # Never remove the durable marker here: the worker must verify all tasks
    # and finish the transaction before the boot recovery service can skip it.
    s4_systemctl enable \"\$S4_TIMER\" || return 1
    s4_persist_timer_enablement || return 1
    s4_systemctl start \"\$S4_TIMER\" || return 1
    s4_wait_timer_state active enabled
}

s4_stop_timer() {
    s4_persist_recovery_intent || return 1
    # Arm a persistent boot trigger before touching timer enablement. The
    # running worker also has Restart=on-failure, independent of the timer.
    if ! s4_systemctl enable \"\$S4_RESUME_SERVICE\" ||
        ! s4_enabled_state \"\$S4_RESUME_SERVICE\" enabled ||
        ! s4_persist_boot_guard; then
        return 1
    fi
    # Stop while still enabled. Disable only after a bounded state check.
    # Never disable --now: its enablement write precedes reload/stop failures.
    if s4_systemctl stop \"\$S4_TIMER\" && s4_wait_timer_state inactive '' &&
        s4_systemctl disable \"\$S4_TIMER\" && s4_wait_timer_state inactive disabled &&
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
    rm -f -- \"\$S4_STATE_DIR/setup.ready\" || return 1
    s4_record_summary pending \"\${#S4_TASKS[@]}\" || return 1
    for task in \"\${S4_TASKS[@]}\"; do
        blocked=0
        read -r -a dependencies <<< \"\${S4_DEPENDENCIES[\$task]}\"
        for dependency in \"\${dependencies[@]}\"; do
            if [[ \${results[\$dependency]:-pending} != complete ]]; then
                blocked=1
                break
            fi
        done
        if (( blocked )); then
            reason=dependency_pending
        elif s4_execute_phase verify \"\$task\"; then
            results[\$task]=complete
            s4_record_task \"\$task\" complete verified || return 1
            continue
        elif s4_execute_phase apply \"\$task\"; then
            if s4_execute_phase verify \"\$task\"; then
                results[\$task]=complete
                s4_record_task \"\$task\" complete repaired_and_verified || return 1
                continue
            else
                code=\$?
                reason=verification_failed_\$code
            fi
        else
            code=\$?
            reason=apply_failed_\$code
        fi
        results[\$task]=pending
        ((pending += 1))
        s4_record_task \"\$task\" pending \"\$reason\" || return 1
        s4_log \"Task \$task is pending (\$reason).\"
    done
    if (( pending )); then
        s4_record_summary pending \"\$pending\" || return 1
        s4_log \"\$pending setup task(s) pending; automatic retries remain enabled.\"
        return 75
    fi
    if ! s4_stop_timer; then
        s4_record_summary timer_stop_pending 0 || return 1
        s4_log 'Setup is verified; timer finalization remains pending.'
        return 75
    fi
    if ! { printf 'verified\\n' | s4_atomic_write \"\$S4_STATE_DIR/setup.ready\"; } ||
        ! s4_record_summary complete 0 ||
        ! s4_sync_filesystems \"\$S4_STATE_DIR\" ||
        ! rm -f -- \"\$S4_STATE_DIR/timer-stop.pending\" ||
        ! s4_sync_filesystems \"\$S4_STATE_DIR\"; then
        # A failed final barrier may have persisted some writes. Recreate the
        # intent and restore a durable timer trigger; never assume rollback IO
        # succeeds. Marker removal starts only after durable completion, so an
        # uncertain cleanup cannot strand unfinished setup even if IO stays bad.
        if s4_persist_recovery_intent; then
            rm -f -- \"\$S4_STATE_DIR/setup.ready\" || s4_log 'Cannot invalidate completion publication.'
            s4_record_summary timer_stop_pending 0 || s4_log 'Cannot record pending finalization.'
            s4_sync_filesystems \"\$S4_STATE_DIR\" || s4_log 'Pending publication synchronization failed.'
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
    exec {S4_LOCK_FD}> \"\$S4_STATE_DIR/repair.lock\" || return 1
    if ! flock --nonblock \"\$S4_LOCK_FD\"; then
        s4_log 'Another setup attempt is already running.'
        exec {S4_LOCK_FD}>&-
        S4_LOCK_FD=
        return 0
    fi
    # Retrying a failed cleanup must not erase durable completion until another
    # durable intent exists. A genuine prior completion already armed the guard.
    if [[ -e \$S4_STATE_DIR/setup.ready || -L \$S4_STATE_DIR/setup.ready ]] &&
        ! s4_persist_recovery_intent; then
        result=75
    elif ! rm -f -- \"\$S4_STATE_DIR/setup.ready\"; then
        result=1
    elif ! s4_load_tasks; then
        result=78
        if ! s4_record_summary invalid_bundle 0; then
            result=1
        fi
    elif ! s4_arm_attempt_deadline; then
        s4_log 'No tasks were started: the complete attempt deadline could not be armed.'
        result=75
        s4_record_summary deadline_pending \"\${#S4_TASKS[@]}\" || result=1
    elif s4_run_tasks; then
        result=0
    else
        result=\$?
    fi
    exec {S4_LOCK_FD}>&-
    S4_LOCK_FD=
    return \"\$result\"
}

s4_resume() {
    local result=0
    exec {S4_LOCK_FD}> \"\$S4_STATE_DIR/repair.lock\" || return 1
    if flock --nonblock \"\$S4_LOCK_FD\"; then
        if [[ -f \$S4_STATE_DIR/timer-stop.pending ]] && ! s4_restore_timer; then
            result=75
        fi
    fi
    exec {S4_LOCK_FD}>&-
    S4_LOCK_FD=
    return \"\$result\"
}

s4_bootstrap_gate() {
    if [[ -e \$S4_STATE_DIR/bootstrap/pending || -L \$S4_STATE_DIR/bootstrap/pending ]]; then
        s4_log 'Bootstrap publication is pending; no setup task was started.'
        return 75
    fi
}

s4_main() {
    local ID='' VERSION_ID='' resume=0
    if [[ \$# == 1 && \$1 == --help ]]; then
        printf '%s\\n' 'Internal debian13s4 setup recovery worker.' \\
            'The starting installer installs its task bundle and timer automatically.'
        return 0
    fi
    if [[ \$# == 1 && \$1 == --resume ]]; then
        resume=1
    elif (( \$# )); then
        s4_log 'This internal worker does not accept configuration arguments.'
        return 64
    fi
    if (( EUID != 0 )); then
        s4_log 'The setup recovery worker must run as root.'
        return 77
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ \$ID != debian || \$VERSION_ID != 13 || ! -d /run/systemd/system ]]; then
        s4_log 'The setup recovery worker requires Debian 13 with systemd.'
        return 78
    fi
    s4_trusted_path \"\${BASH_SOURCE[0]}\" || return 1
    # Bootstrap publishes the protected worker first and flushes it before any
    # task changes. Refuse mixed generations until its durable transaction ends.
    # A nonzero exit keeps the manager's independent Restart retry armed.
    s4_bootstrap_gate || return \$?
    s4_prepare_state || return 1
    if (( resume )); then
        s4_resume
    else
        s4_recover
    fi
}

if [[ \${BASH_SOURCE[0]} == \"\$0\" ]]; then
    set -Eeuo pipefail
    PATH=\$S4_PHASE_PATH
    export PATH
    readonly PATH S4_LIBRARY_DIR S4_STATE_DIR S4_SYSTEMD_DIR S4_SERVICE S4_TIMER S4_RESUME_SERVICE \\
        S4_PHASE_TIMEOUT_MS S4_KILL_DELAY_MS S4_CONTROL_TIMEOUT_MS S4_CONTROL_KILL_MS \\
        S4_TASK_OVERHEAD_MS S4_ATTEMPT_OVERHEAD_MS S4_POLL_INTERVAL_MS \\
        S4_POLL_COUNT S4_CONTROL_CALL_BUDGET S4_PHASE_PATH
    umask 077
    s4_main \"\$@\"
fi
" > "$S4B_STAGE/"lib/repair.sh || return 1
    printf '%s' "prerequisites:
network:prerequisites
hardening:prerequisites
retention:prerequisites
maintenance:prerequisites
dotnet:prerequisites
ssh:prerequisites network hardening
postgresql:prerequisites hardening maintenance
web:prerequisites network hardening maintenance
" > "$S4B_STAGE/"lib/tasks.list || return 1
    printf '%s' "#!/bin/bash
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
" > "$S4B_STAGE/"lib/tasks/prerequisites/apply.sh || return 1
    printf '%s' "#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Tasks/prerequisites/common.sh
. /usr/local/lib/debian13s4/tasks/prerequisites/common.sh
s4p_verify
" > "$S4B_STAGE/"lib/tasks/prerequisites/verify.sh || return 1
    printf '%s' "#!/bin/bash

S4P_PACKAGES=(ca-certificates debian-archive-keyring curl gpgv nftables iproute2
    apparmor apparmor-utils unattended-upgrades needrestart)
S4P_TASK_DIR=/usr/local/lib/debian13s4/tasks/prerequisites
S4P_APT_DIR=/var/lib/apt/debian13s4

s4p_prepare() {
    local path ancestor owner mode
    for path in /var/lib/apt \"\$S4P_APT_DIR\" \"\$S4P_APT_DIR/lists\"; do
        ancestor=\${path%/*}
        while :; do
            [[ -d \$ancestor && ! -L \$ancestor ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- \"\$ancestor\") || return 1
            [[ \$owner == 0 ]] && (( (8#\$mode & 8#022) == 0 )) || return 1
            [[ \$ancestor == / ]] && break
            ancestor=\${ancestor%/*}
            [[ -n \$ancestor ]] || ancestor=/
        done
        if [[ -e \$path || -L \$path ]]; then
            [[ -d \$path && ! -L \$path ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- \"\$path\") || return 1
            [[ \$owner == 0 ]] && (( (8#\$mode & 8#022) == 0 )) || return 1
        fi
        install -d -o root -g root -m 0755 -- \"\$path\" || return 1
    done
}

s4p_apt() {
    apt-get \\
        -o \"Dir::Etc::sourcelist=\$S4P_TASK_DIR/debian.sources\" \\
        -o Dir::Etc::sourceparts=- \\
        -o \"Dir::State::lists=\$S4P_APT_DIR/lists\" \\
        -o APT::Update::Error-Mode=any \\
        -o Acquire::Retries=2 \\
        -o Acquire::http::Timeout=30 \\
        -o Acquire::https::Timeout=30 \\
        -o Acquire::Check-Date=true \\
        -o Acquire::Check-Valid-Until=true \\
        -o Acquire::AllowInsecureRepositories=false \\
        -o Acquire::AllowDowngradeToInsecureRepositories=false \\
        -o APT::Get::AllowUnauthenticated=false \\
        -o APT::Get::allow-downgrades=false \\
        -o APT::Get::allow-change-held-packages=false \\
        -o APT::Get::allow-remove-essential=false \\
        -o DPkg::Lock::Timeout=60 \\
        -o Dpkg::Options::=--force-confdef \\
        -o Dpkg::Options::=--force-confold \\
        --assume-yes --no-remove --no-install-recommends \"\$@\"
}

s4p_dpkg() {
    dpkg \"\$@\"
}

s4p_query() {
    dpkg-query --show --showformat='\${Status}\\n' -- \"\$1\"
}

s4p_verify() {
    local package status audit
    for package in \"\${S4P_PACKAGES[@]}\"; do
        status=\$(s4p_query \"\$package\") || return 1
        [[ \$status == 'install ok installed' ]] || return 1
    done
    audit=\$(s4p_dpkg --audit) || return 1
    [[ -z \$audit ]]
}

s4p_apply() {
    # A partial index refresh must never be mistaken for a usable online run.
    # Authentication and normal dpkg/APT locks remain enabled on every retry.
    s4p_apt update || return 1
    if ! s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4p_apt --fix-broken install || return 1
        s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    s4p_apt install \"\${S4P_PACKAGES[@]}\"
}
" > "$S4B_STAGE/"lib/tasks/prerequisites/common.sh || return 1
    printf '%s' "Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
" > "$S4B_STAGE/"lib/tasks/prerequisites/debian.sources || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"units/debian13s4-repair.service || return 1
    printf '%s' "[Unit]
Description=Retry unfinished Debian 13 server setup

[Timer]
OnBootSec=1min
OnUnitInactiveSec=5min
RandomizedDelaySec=30s
AccuracySec=1s
Unit=debian13s4-repair.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"units/debian13s4-repair.timer || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"units/debian13s4-resume.service || return 1
    printf '%s' "#!/bin/bash

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
S4M_CLEANUP_BOUND_SECONDS=\$((S4M_CLEANUP_SECONDS + S4M_CLEANUP_GRACE_SECONDS + 30))
S4M_CONTROL_SECONDS=10
S4M_CONTROL_GRACE_SECONDS=1
S4M_RESTART_SECONDS=300
S4M_RESTART_GRACE_SECONDS=10
# Two intent syncs, three initial properties, hook selection, four final
# properties and two completion syncs: at most twelve bounded control calls.
# Include 30 seconds for local work, scheduling and uptime-second rounding.
S4M_RESTART_BOUND_SECONDS=\$((S4M_RESTART_SECONDS + S4M_RESTART_GRACE_SECONDS + \\
    12 * (S4M_CONTROL_SECONDS + S4M_CONTROL_GRACE_SECONDS) + 30))
# Ordinary intents retain their original needrestart policy and hook names.
S4M_RESTARTS=()

s4m_load_packages() {
    s4m_trusted /usr/local/lib/debian13s4/tasks/prerequisites/common.sh || return 1
    # shellcheck source=Tasks/prerequisites/common.sh
    . /usr/local/lib/debian13s4/tasks/prerequisites/common.sh
}

s4m_trusted() {
    local path=\$1 owner mode
    [[ \$path == /* && \$path != *'/../'* && \$path != */.. &&
        \$path != *'/./'* && \$path != */. && \$path != *'//'* ]] || return 1
    while :; do
        [[ -e \$path && ! -L \$path ]] || return 1
        read -r owner mode < <(stat --format='%u %a' -- \"\$path\") || return 1
        [[ \$owner == 0 ]] && (( (8#\$mode & 8#022) == 0 )) || return 1
        [[ \$path == / ]] && return 0
        path=\${path%/*}
        [[ -n \$path ]] || path=/
    done
}

s4m_control() (
    local descriptor=\$S4M_REPAIR_FD
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=\"\${S4M_CONTROL_GRACE_SECONDS}s\" \"\${S4M_CONTROL_SECONDS}s\" \\
        env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \"\$@\"
)

s4m_package() (
    # Maintainer scripts may start long-lived processes: none may retain the
    # installer's shared lock after this controller releases it.
    local descriptor=\$S4M_REPAIR_FD
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    \"\$@\"
)

s4m_lock() {
    local path=\$S4M_STATE/repair.lock descriptor descriptor_path before after owner mode identity previous_umask
    [[ -z \$S4M_REPAIR_FD && -d \$S4M_STATE ]] && s4m_trusted \"\$S4M_STATE\" || return 1
    if [[ -e \$path || -L \$path ]]; then
        [[ ! -L \$path && -f \$path ]] && s4m_trusted \"\$path\" || return 1
    fi
    previous_umask=\$(umask) || return 1
    umask 077
    if ! exec {descriptor}>> \"\$path\"; then
        umask \"\$previous_umask\"
        return 1
    fi
    umask \"\$previous_umask\"
    descriptor_path=/proc/\$BASHPID/fd/\$descriptor
    if [[ -f \$descriptor_path && ! -L \$path && -f \$path ]] &&
        s4m_trusted \"\$path\" &&
        before=\$(stat --format='%u %a %d:%i' -- \"\$path\") &&
        after=\$(stat --dereference --format='%u %a %d:%i' -- \"\$descriptor_path\") &&
        [[ -n \$before && \$before == \"\$after\" ]] &&
        read -r owner mode identity <<< \"\$after\" &&
        [[ \$owner == \"\$EUID\" && \$mode =~ ^[0-7]{3,4}\$ && \$identity =~ ^[0-9]+:[0-9]+\$ ]] &&
        (( (8#\$mode & 8#022) == 0 )) && flock --nonblock \"\$descriptor\"; then
        S4M_REPAIR_FD=\$descriptor
        return 0
    fi
    exec {descriptor}>&-
    return 1
}

s4m_unlock() {
    [[ -z \$S4M_REPAIR_FD ]] || exec {S4M_REPAIR_FD}>&-
    S4M_REPAIR_FD=
}

s4m_systemctl() {
    s4m_control systemctl \"\$@\"
}

s4m_sync() {
    s4m_control sync --file-system -- \"\$@\"
}

s4m_atomic() {
    local target=\$1 source=\$2 mode=\${3:-0644} temporary
    s4m_trusted \"\${target%/*}\" && s4m_trusted \"\$source\" && [[ -f \$source ]] || return 1
    if [[ -e \$target || -L \$target ]]; then
        [[ -f \$target ]] && s4m_trusted \"\$target\" || return 1
    fi
    temporary=\$(mktemp -- \"\${target}.XXXXXX\") || return 1
    if ! cat -- \"\$source\" > \"\$temporary\" || ! chmod \"\$mode\" -- \"\$temporary\"; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    if [[ -f \$target ]] && cmp --silent -- \"\$source\" \"\$target\"; then
        rm -f -- \"\$temporary\" || return 1
    elif ! s4m_sync \"\$temporary\" || ! mv -fT -- \"\$temporary\" \"\$target\"; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    s4m_sync \"\${target%/*}\" \"\$target\"
}

s4m_property() {
    local unit=\$1 property=\$2 expected=\$3 output
    output=\$(s4m_systemctl show --property=\"\$property\" --value \"\$unit\") || return 1
    [[ \$output == \"\$expected\" ]]
}

s4m_enabled() {
    local output
    output=\$(s4m_systemctl is-enabled \"\$1\") || return 1
    [[ \$output == enabled ]]
}

s4m_verify_files() {
    local name
    s4m_trusted \"\$S4M_STATE\" && [[ -d \$S4M_STATE ]] || return 1
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl retain-kernels.py \\
        debian13s4-maintenance.service debian13s4-maintenance.timer; do
        [[ -f \$S4M_LIBRARY/\$name ]] && s4m_trusted \"\$S4M_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4M_LIBRARY/update.sh ]] || return 1
    for name in \"\$S4M_SERVICE\" \"\$S4M_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4M_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4M_TIMER\" && s4m_property \"\$S4M_TIMER\" ActiveState active
}

s4m_identity() {
    local name digest
    for name in common.sh update.sh policy.conf needrestart.conf restart-policy.pl retain-kernels.py \\
        debian13s4-maintenance.service debian13s4-maintenance.timer; do
        digest=\$(sha256sum -- \"\$S4M_LIBRARY/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
}

s4m_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/maintenance.ready ]] && s4m_trusted \"\$S4M_STATE/maintenance.ready\" || return 1
    s4m_verify_files || return 1
    expected=\$(s4m_identity) && actual=\$(cat -- \"\$S4M_STATE/maintenance.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4m_kernel_package() {
    local architecture release
    architecture=\$(dpkg --print-architecture) && release=\$(uname -r) || return 1
    case \$architecture:\$release in
        amd64:*-cloud-amd64) printf 'linux-image-cloud-amd64\\n' ;;
        amd64:*-rt-amd64) printf 'linux-image-rt-amd64\\n' ;;
        amd64:*) printf 'linux-image-amd64\\n' ;;
        arm64:*-cloud-arm64) printf 'linux-image-cloud-arm64\\n' ;;
        arm64:*) printf 'linux-image-arm64\\n' ;;
        *) printf 'debian13s4: unattended kernel selection supports amd64/arm64 at this checkpoint.\\n' >&2; return 78 ;;
    esac
}

s4m_packages() {
    local kernel
    kernel=\$(s4m_kernel_package) || return 1
    S4P_PACKAGES=(unattended-upgrades needrestart \"\$kernel\")
}

s4m_apply() {
    local unit loaded temporary wants resolved
    s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for unit in \"\$S4M_TIMER\" \"\$S4M_SERVICE\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/maintenance.ready || -L \$S4M_STATE/maintenance.ready ]]; then
        [[ -f \$S4M_STATE/maintenance.ready ]] && s4m_trusted \"\$S4M_STATE/maintenance.ready\" || return 1
        rm -f -- \"\$S4M_STATE/maintenance.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for unit in \"\$S4M_TIMER\" \"\$S4M_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
            return 1
        fi
    done
    s4p_prepare && s4m_packages || return 1
    # An existing kernel history may need space before initial delivery too.
    # Missing prerequisites/unsafe state cannot authorize removal or prevent
    # installation and the later persistent maintenance retry from being armed.
    APT_CONFIG=\$S4M_LIBRARY/policy.conf s4m_kernel_cleanup || :
    s4p_apply && s4p_verify || return 1
    # The packaged kernel hook marks /run/reboot-required for the controller.
    [[ -x /etc/kernel/postinst.d/unattended-upgrades ]] &&
        s4m_trusted /etc/kernel/postinst.d/unattended-upgrades || return 1
    for unit in \"\$S4M_SERVICE\" \"\$S4M_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4M_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable \"\$S4M_TIMER\" && s4m_enabled \"\$S4M_TIMER\" || return 1
    wants=\$S4M_SYSTEMD/timers.target.wants
    [[ -d \$wants && -L \$wants/\$S4M_TIMER ]] && s4m_trusted \"\$wants\" || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4M_TIMER\") || return 1
    [[ \$resolved == \"\$S4M_SYSTEMD/\$S4M_TIMER\" ]] || return 1
    s4m_sync \"\$S4M_SYSTEMD\" \"\$wants\" \"\$S4M_SYSTEMD/\$S4M_TIMER\" \"\$S4M_SYSTEMD/\$S4M_SERVICE\" || return 1
    s4m_systemctl start \"\$S4M_TIMER\" && s4m_verify_files || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/maintenance-intent.XXXXXX\") || return 1
    if ! s4m_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/maintenance.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4m_ready
}

s4m_verify() {
    s4m_packages && s4p_verify && s4m_ready
}

s4m_boot_id() {
    local identity
    [[ -f \$S4M_BOOT_FILE ]] && s4m_trusted \"\$S4M_BOOT_FILE\" || return 1
    identity=\$(cat -- \"\$S4M_BOOT_FILE\") || return 1
    [[ \$identity =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\$ ]] || return 1
    printf '%s\\n' \"\$identity\"
}

s4m_save_restarts() {
    local temporary
    temporary=\$(mktemp -- \"\$S4M_STATE/restart-intent.XXXXXX\") || return 1
    if ! { [[ \${#S4M_RESTARTS[@]} == 0 ]] || printf '%s\\n' \"\${S4M_RESTARTS[@]}\"; } > \"\$temporary\" ||
        ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/maintenance.restarts\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\"
}

s4m_select_restarts() {
    s4m_trusted /etc/needrestart/needrestart.conf &&
        s4m_trusted \"\$S4M_LIBRARY/needrestart.conf\" &&
        s4m_trusted \"\$S4M_LIBRARY/restart-policy.pl\" || return 1
    s4m_control perl \"\$S4M_LIBRARY/restart-policy.pl\" \"\$S4M_LIBRARY/needrestart.conf\"
}

s4m_now() {
    local uptime idle
    [[ -f /proc/uptime && ! -L /proc/uptime ]] || return 1
    read -r uptime idle < /proc/uptime || return 1
    [[ \$uptime =~ ^[0-9]{1,15}[.][0-9]+\$ && \$idle =~ ^[0-9]+[.][0-9]+\$ ]] || return 1
    uptime=\${uptime%.*}
    printf '%s\\n' \"\$((10#\$uptime))\"
}

s4m_unit_name() {
    local name=\$1
    [[ \$name =~ ^[A-Za-z0-9_.@][A-Za-z0-9_.@:\\\\-]*\$ && \${#name} -le 255 &&
        \$name != @reboot && \$name != @reboot:* ]] || return 1
    [[ \$name == *.service ]] || name+=.service
    (( \${#name} <= 255 )) || return 1
    printf '%s\\n' \"\$name\"
}

s4m_load_restarts() {
    local path=\$S4M_STATE/maintenance.restarts target boot plan selected
    local -a names=() retained=()
    S4M_RESTARTS=()
    [[ -e \$path || -L \$path ]] || return 0
    [[ -f \$path ]] && s4m_trusted \"\$path\" || return 1
    mapfile -t S4M_RESTARTS < \"\$path\" || return 1
    for target in \"\${S4M_RESTARTS[@]}\"; do
        if [[ \$target == @reboot:* ]]; then
            boot=\$(s4m_boot_id) || return 1
            [[ \${target#@reboot:} =~ ^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\$ ]] || return 1
            [[ \$target != \"@reboot:\$boot\" ]] || retained+=(\"\$target\")
        else
            s4m_unit_name \"\$target\" > /dev/null || return 1
            names+=(\"\$target\")
        fi
    done
    plan=\$(for target in \"\${names[@]}\"; do printf 'NEEDRESTART-SVC: %s\\n' \"\$target\"; done) || return 1
    selected=\$(s4m_select_restarts <<< \"\$plan\") || return 1
    while IFS= read -r target; do
        [[ -n \$target ]] || continue
        if [[ \$target == @reboot ]]; then
            boot=\$(s4m_boot_id) || return 1
            target=@reboot:\$boot
        fi
        [[ \" \${retained[*]} \" == *\" \$target \"* ]] || retained+=(\"\$target\")
    done <<< \"\$selected\"
    S4M_RESTARTS=(\"\${retained[@]}\")
    # Persist exclusion/boot reconciliation even for an empty journal. Keeping
    # an empty regular file avoids an uncertain delete/recreation transaction.
    s4m_save_restarts
}

s4m_discover_restarts() {
    local output selected target boot
    output=\$(NEEDRESTART_MODE=l s4m_package needrestart -c \"\$S4M_LIBRARY/needrestart.conf\" -b -r l -l) || return 1
    selected=\$(s4m_select_restarts <<< \"\$output\") || return 1
    while IFS= read -r target; do
        [[ -n \$target ]] || continue
        if [[ \$target == @reboot ]]; then
            boot=\$(s4m_boot_id) || return 1
            target=@reboot:\$boot
        fi
        [[ \" \${S4M_RESTARTS[*]} \" == *\" \$target \"* ]] || S4M_RESTARTS+=(\"\$target\")
    done <<< \"\$selected\"
    # No stop/restart may occur before every admitted intent is durable.
    s4m_save_restarts
}

s4m_restart_command() (
    local descriptor=\$S4M_REPAIR_FD hook target
    local -a command
    trap - EXIT
    target=\$(s4m_unit_name \"\$1\") || return 1
    hook=\$(s4m_control perl \"\$S4M_LIBRARY/restart-policy.pl\" \"\$S4M_LIBRARY/needrestart.conf\" \"\$1\") || return 1
    if [[ -n \$hook ]]; then
        [[ -f \$hook && -x \$hook ]] && s4m_trusted \"\$hook\" || return 1
        command=(\"\$hook\")
    else
        command=(systemctl restart -- \"\$target\")
    fi
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=\"\${S4M_RESTART_GRACE_SECONDS}s\" \"\${S4M_RESTART_SECONDS}s\" \\
        env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \"\${command[@]}\"
)

s4m_restart_unit() {
    local name=\$1 target property value active type
    target=\$(s4m_unit_name \"\$name\") || return 1
    s4m_property \"\$target\" LoadState loaded || return 1
    for property in RefuseManualStop RefuseManualStart; do
        value=\$(s4m_systemctl show --property=\"\$property\" --value \"\$target\") || return 1
        if [[ \$value == yes ]]; then
            printf 'debian13s4: restart deliberately refused by %s: %s\\n' \"\$property\" \"\$target\" >&2
            return 2
        fi
        [[ \$value == no ]] || return 1
    done
    s4m_restart_command \"\$name\" || return 1
    s4m_property \"\$target\" Result success || return 1
    active=\$(s4m_systemctl show --property=ActiveState --value \"\$target\") || return 1
    [[ \$active != active ]] || return 0
    type=\$(s4m_systemctl show --property=Type --value \"\$target\") || return 1
    [[ \$active == inactive && \$type == oneshot ]] &&
        s4m_property \"\$target\" RemainAfterExit no
}

s4m_run_restarts() {
    local deadline=\$1 target entry result now failed=0 deferred=0
    local -a admitted=(\"\${S4M_RESTARTS[@]}\") kept=()
    [[ \$deadline =~ ^[0-9]{1,15}\$ ]] || return 1
    deadline=\$((10#\$deadline))
    for target in \"\${admitted[@]}\"; do
        [[ \$target != @reboot:* ]] || continue
        now=\$(s4m_now) || return 1
        if (( now + S4M_RESTART_BOUND_SECONDS > deadline )); then
            # The next intent remains untouched. Its full bounded operation
            # must fit without spending the downstream package/reboot reserve.
            deferred=1
            break
        fi
        kept=()
        for entry in \"\${S4M_RESTARTS[@]}\"; do
            [[ \$entry == \"\$target\" ]] || kept+=(\"\$entry\")
        done
        # Rotate before the bounded attempt. A killed or perpetually failing
        # prefix cannot monopolize the next attempt's journal traversal.
        S4M_RESTARTS=(\"\${kept[@]}\" \"\$target\")
        s4m_save_restarts || return 1
        if s4m_restart_unit \"\$target\"; then result=0; else result=\$?; fi
        if (( result == 0 || result == 2 )); then
            S4M_RESTARTS=(\"\${kept[@]}\")
            s4m_save_restarts || return 1
        else
            printf 'debian13s4: service restart remains pending: %s\\n' \"\$target\" >&2
            failed=1
        fi
    done
    (( failed == 0 )) || return 1
    (( deferred == 0 )) || return 75
    return 0
}

s4m_request_reboot() {
    local audit target needed=0
    for target in \"\${S4M_RESTARTS[@]}\"; do
        [[ \$target != @reboot:* ]] || needed=1
    done
    if [[ ! -e \$S4M_REBOOT_MARKER && ! -L \$S4M_REBOOT_MARKER ]]; then
        (( needed != 0 )) || return 0
    else
        [[ -f \$S4M_REBOOT_MARKER ]] && s4m_trusted \"\$S4M_REBOOT_MARKER\" || return 1
    fi
    audit=\$(s4m_package s4p_dpkg --audit) || return 1
    [[ -z \$audit ]] || return 1
    s4m_systemctl reboot || return 1
    # A successful command requests a reboot; only the next boot clears /run.
    # Keep the marker and report pending, so failed delivery is retried too.
    printf 'debian13s4: maintenance reboot requested; awaiting the next boot.\\n' >&2
    return 75
}

# Trusted package profiles share the same locking, restart and reboot ownership.
s4m_debian_upgrade() { s4m_package unattended-upgrade --verbose; }
s4m_debian_verify() { return 0; }
s4m_skip_cleanup() { return 0; }

s4m_kernel_cleanup() (
    trap - EXIT
    [[ -z \$S4M_REPAIR_FD ]] || exec {S4M_REPAIR_FD}>&-
    [[ -f \$S4M_LIBRARY/retain-kernels.py && -n \${APT_CONFIG:-} && -f \$APT_CONFIG ]] &&
        s4m_trusted \"\$S4M_LIBRARY/retain-kernels.py\" && s4m_trusted \"\$APT_CONFIG\" || return 1
    exec timeout --signal=TERM --kill-after=\"\${S4M_CLEANUP_GRACE_SECONDS}s\" \"\${S4M_CLEANUP_SECONDS}s\" \\
        env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C APT_CONFIG=\"\$APT_CONFIG\" \\
        DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \\
        UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l \\
        /usr/bin/python3 -I -B \"\$S4M_LIBRARY/retain-kernels.py\" --apply
)

s4m_update() (
    local audit target start now deadline last_restart restart_status reboot_status callback cleanup_status
    for callback in \"\$S4M_UPDATE_READY\" \"\$S4M_UPDATE_PREPARE\" \"\$S4M_UPDATE_UPGRADE\" \"\$S4M_UPDATE_VERIFY\" \"\$S4M_UPDATE_CLEANUP\"; do
        declare -F -- \"\$callback\" > /dev/null || return 1
    done
    start=\$(s4m_now) || return 1
    (( S4M_PRE_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_POST_RESTART_SECONDS >= S4M_RESTART_BOUND_SECONDS &&
        S4M_CLEANUP_SECONDS > 0 && S4M_CLEANUP_GRACE_SECONDS > 0 &&
        S4M_CLEANUP_BOUND_SECONDS >= S4M_CLEANUP_SECONDS + S4M_CLEANUP_GRACE_SECONDS &&
        S4M_PRE_RESTART_SECONDS + S4M_POST_RESTART_SECONDS + S4M_CLEANUP_BOUND_SECONDS +
        S4M_FINAL_RESERVE_SECONDS < S4M_ATTEMPT_SECONDS )) || return 1
    \"\$S4M_UPDATE_READY\" || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    \"\$S4M_UPDATE_READY\" || return 75
    \"\$S4M_UPDATE_PREPARE\" || return 1
    # The same isolated configuration/indexes govern refresh and libapt's u-u.
    export APT_CONFIG=\${S4M_UPDATE_POLICY:-\$S4M_LIBRARY/policy.conf}
    [[ -f \$APT_CONFIG ]] && s4m_trusted \"\$APT_CONFIG\" || return 1
    export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
    export UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l
    s4m_load_restarts || return 1
    if (( \${#S4M_RESTARTS[@]} != 0 )); then
        audit=\$(s4m_package s4p_dpkg --audit) || return 1
        if [[ -z \$audit ]]; then
            # Reboot ownership gets a turn before any slow service recovery.
            for target in \"\${S4M_RESTARTS[@]}\"; do
                if [[ \$target == @reboot:* ]]; then
                    if s4m_request_reboot; then reboot_status=0; else reboot_status=\$?; fi
                    (( reboot_status != 75 )) || return 75
                    break
                fi
            done
            # Already configured services recover offline, but only inside a
            # fixed fair slice. Failures/deferred intents cannot block refresh.
            s4m_run_restarts \"\$((start + S4M_PRE_RESTART_SECONDS))\" || :
        fi
    fi
    if [[ -e \$S4M_REBOOT_MARKER || -L \$S4M_REBOOT_MARKER ]]; then
        # A previously installed kernel can be activated without fresh internet,
        # but partial package configuration/audit must never authorize reboot.
        [[ -f \$S4M_REBOOT_MARKER ]] && s4m_trusted \"\$S4M_REBOOT_MARKER\" || return 1
        if s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending; then
            audit=\$(s4m_package s4p_dpkg --audit) || return 1
            if [[ -z \$audit ]]; then
                if s4m_request_reboot; then reboot_status=0; else reboot_status=\$?; fi
                (( reboot_status != 75 )) || return 75
            fi
        fi
        # Missing dependencies/partial configuration still reach authenticated
        # refresh and repair on later online attempts, rather than starving here.
    fi
    # One bounded offline-capable cleanup gets a turn before download/configure
    # pressure. Failure cannot suppress authenticated repair of interrupted dpkg.
    if \"\$S4M_UPDATE_CLEANUP\"; then cleanup_status=0; else cleanup_status=\$?; fi
    s4m_package apt-get update || return 1
    if ! s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4m_package apt-get --assume-yes --no-remove --fix-broken install || return 1
        s4m_package s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    \"\$S4M_UPDATE_UPGRADE\" || return 1
    audit=\$(s4m_package s4p_dpkg --audit) || return 1
    [[ -z \$audit ]] || return 1
    \"\$S4M_UPDATE_VERIFY\" || return 1
    s4m_discover_restarts || return 1
    now=\$(s4m_now) || return 1
    deadline=\$((now + S4M_POST_RESTART_SECONDS))
    last_restart=\$((start + S4M_ATTEMPT_SECONDS - S4M_FINAL_RESERVE_SECONDS))
    (( deadline <= last_restart )) || deadline=\$last_restart
    if s4m_run_restarts \"\$deadline\"; then restart_status=0; else restart_status=\$?; fi
    # A failed/deferred restart cannot suppress a healthy-package reboot intent.
    if s4m_request_reboot; then reboot_status=0; else reboot_status=\$?; fi
    (( reboot_status == 0 )) || return \"\$reboot_status\"
    (( restart_status == 0 )) || return \"\$restart_status\"
    (( cleanup_status == 0 )) || return \"\$cleanup_status\"
    (( \${#S4M_RESTARTS[@]} == 0 )) || return 75
    return 0
)
" > "$S4B_STAGE/"lib/maintenance/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
s4m_update
" > "$S4B_STAGE/"lib/maintenance/update.sh || return 1
    printf '%s' "// This file is loaded first through APT_CONFIG. Later system fragments/main
// cannot widen these sources, origins or security options for this updater.
Dir::Etc::parts \"\";
Dir::Etc::main \"\";
Dir::Etc::sourcelist \"/usr/local/lib/debian13s4/tasks/prerequisites/debian.sources\";
Dir::Etc::sourceparts \"-\";
Dir::Etc::preferences \"-\";
Dir::Etc::preferencesparts \"-\";
Dir::State::lists \"/var/lib/apt/debian13s4/lists\";
APT::Update::Error-Mode \"any\";
APT::Install-Recommends \"false\";
APT::Install-Suggests \"false\";
// Host fragments are disabled: supply kernel protection explicitly here.
APT::Protect-Kernels \"true\";
APT::VersionedKernelPackages { \"linux-image\"; };
Acquire::Retries \"2\";
Acquire::http::Timeout \"30\";
Acquire::https::Timeout \"30\";
Acquire::Check-Date \"true\";
Acquire::Check-Valid-Until \"true\";
Acquire::AllowInsecureRepositories \"false\";
Acquire::AllowDowngradeToInsecureRepositories \"false\";
APT::Get::AllowUnauthenticated \"false\";
APT::Get::allow-downgrades \"false\";
APT::Get::allow-change-held-packages \"false\";
APT::Get::allow-remove-essential \"false\";
Debug::NoLocking \"false\";
DPkg::Lock::Timeout \"60\";
DPkg::Options { \"--force-confdef\"; \"--force-confold\"; };
Unattended-Upgrade::Origins-Pattern {
    \"origin=Debian,codename=trixie,label=Debian\";
    \"origin=Debian,codename=trixie-updates,label=Debian\";
    \"origin=Debian,codename=trixie-security,label=Debian-Security\";
};
Unattended-Upgrade::AutoFixInterruptedDpkg \"true\";
Unattended-Upgrade::MinimalSteps \"true\";
Unattended-Upgrade::InstallOnShutdown \"false\";
Unattended-Upgrade::Allow-downgrade \"false\";
// The checked one-image controller handles both legacy and +deb13 names.
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"false\";
Unattended-Upgrade::Remove-Unused-Dependencies \"false\";
Unattended-Upgrade::Remove-New-Unused-Dependencies \"false\";
Unattended-Upgrade::Keep-Debs-After-Install \"false\";
// The controller checks package health and propagates reboot-request errors.
Unattended-Upgrade::Automatic-Reboot \"false\";
Unattended-Upgrade::Automatic-Reboot-WithUsers \"true\";
Unattended-Upgrade::Automatic-Reboot-Time \"now\";
Unattended-Upgrade::OnlyOnACPower \"false\";
Unattended-Upgrade::Skip-Updates-On-Metered-Connections \"false\";
Unattended-Upgrade::SyslogEnable \"true\";
" > "$S4B_STAGE/"lib/maintenance/policy.conf || return 1
    printf '%s' "# Keep Debian's service exclusions, then exclude the setup/update controllers.
{
    local (\$@, \$!);
    my \$loaded = do '/etc/needrestart/needrestart.conf';
    die \"Cannot load Debian restart policy: \$@ \$!\\n\" if \$@ || (!defined(\$loaded) && \$!);
}
\$nrconf{restart} = 'a';
\$nrconf{override_rc}->{qr(^debian13s4-(maintenance|dotnet|network|retention|hardening|bootstrap|repair|resume)(\\.service)?\$)} = 0;
" > "$S4B_STAGE/"lib/maintenance/needrestart.conf || return 1
    printf '%s' "#!/usr/bin/perl
use strict;
use warnings;

# Apply the same sorted, first-match service exclusions as Debian needrestart.
# Batch output precedes native override_rc/refusal handling, so it is only input
# to this selector; it is never permission to restart every reported service.
our %nrconf = (defno => 0, verbosity => 0, blacklist_rc => [], override_rc => {},
              restart_d => '/etc/needrestart/restart.d');
@ARGV == 1 || @ARGV == 2 or die \"Expected the trusted needrestart configuration and optional original name.\\n\";
my \$loaded = do \$ARGV[0];
die \"Cannot load restart policy: \$@ \$!\\n\" if \$@ || (!defined(\$loaded) && \$!);
sub validate_name {
    my (\$name) = @_;
    \$name =~ /\\A[A-Za-z0-9_.@][A-Za-z0-9_.@:\\\\-]*\\z/ && length(\$name) <= 255 &&
        \$name ne '@reboot' && \$name !~ /\\A\\@reboot:/
        or die \"Invalid restart target.\\n\";
    my \$unit = \$name =~ /\\.service\\z/ ? \$name : \"\$name.service\";
    length(\$unit) <= 255 or die \"Restart unit name is too long.\\n\";
    return \$name;
}
if (@ARGV == 2) {
    my \$name = validate_name(\$ARGV[1]);
    my \$hook = \"\$nrconf{restart_d}/\$name\";
    print \"\$hook\\n\" or die \"Cannot write hook path: \$!\\n\" if -x \$hook;
    exit 0;
}
my %seen;
while (my \$line = <STDIN>) {
    next unless \$line =~ /^NEEDRESTART-SVC: (.*)\\n\$/;
    my \$name = validate_name(\$1);
    next if grep { \$name =~ /\$_/ } @{\$nrconf{blacklist_rc}};
    my \$allowed = !\$nrconf{defno};
    for my \$pattern (sort keys %{\$nrconf{override_rc}}) {
        next unless \$name =~ /\$pattern/;
        \$allowed = \$nrconf{override_rc}->{\$pattern};
        last;
    }
    next unless \$allowed;
    # These pseudo-targets describe init managers, not individual services.
    # A controlled reboot activates their replacement without running the
    # unchecked multi-process init-manager hooks.
    my \$target = \$name;
    if (\$name =~ /\\A(?:systemd-manager|systemd-user|sysv-init)\\z/) {
        \$target = '@reboot';
    }
    # Journal the original policy/hook identity. The controller derives the
    # systemd observation name without changing what future policy checks see.
    print \"\$target\\n\" or die \"Cannot write restart plan: \$!\\n\" unless \$seen{\$target}++;
}
" > "$S4B_STAGE/"lib/maintenance/restart-policy.pl || return 1
    printf '%s' "\"\"\"Remove one obsolete automatic Debian kernel image, retaining boot choices.\"\"\"

from functools import cmp_to_key
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


POLICY = Path(\"/usr/local/lib/debian13s4/maintenance/policy.conf\")
TRUSTED_UID = 0
KEEP = 3
IMAGE = re.compile(
    r\"linux-image-(?P<release>[1-9][0-9]*\\.[0-9]+\\.[0-9]+\"
    r\"(?:-[0-9]+|\\+deb13)-(?P<flavour>(?:cloud-|rt-)?(?:amd64|arm64)))\\Z\"
)


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise RuntimeError(\"noncanonical kernel maintenance path\")
    leaf = True
    while True:
        info = path.lstat()
        kind = stat.S_ISDIR if directory or not leaf else stat.S_ISREG
        if info.st_uid != TRUSTED_UID or info.st_mode & 0o022 or not kind(info.st_mode):
            raise RuntimeError(\"untrusted kernel maintenance path: \" + str(path))
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
        raise RuntimeError(\"kernel cleanup requires a clean package state\")
    images = [p for p in cache if p.is_installed and IMAGE.fullmatch(p.name)]
    current = [p for p in images if IMAGE.fullmatch(p.name)[\"release\"] == running]
    if not current or any(not configured(p) for p in images):
        raise RuntimeError(\"running/installed kernel identities are unverifiable\")
    flavour = IMAGE.fullmatch(current[0].name)[\"flavour\"]
    meta = cache.get(\"linux-image-\" + flavour)
    if meta is None or not configured(meta):
        raise RuntimeError(\"missing configured kernel metapackage\")
    protected = {p.name for p in current} | {meta.name}
    for group in {IMAGE.fullmatch(p.name)[\"flavour\"] for p in images}:
        versions = {p.installed.version for p in images if IMAGE.fullmatch(p.name)[\"flavour\"] == group}
        latest = set(sorted(versions, key=cmp_to_key(apt_pkg.version_compare), reverse=True)[:KEEP])
        protected.update(p.name for p in images
                         if IMAGE.fullmatch(p.name)[\"flavour\"] == group and p.installed.version in latest)
    candidates = [p for p in images if p.name not in protected and p.is_auto_installed and
                  p.is_auto_removable and p._pkg.selected_state == apt_pkg.SELSTATE_INSTALL and
                  not p.essential and p.installed.priority not in (\"required\", \"important\")]
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
    result = subprocess.run([\"/usr/bin/dpkg\", \"--audit\"], capture_output=True, timeout=10, check=True)
    if result.stdout or result.stderr:
        raise RuntimeError(\"kernel cleanup requires an empty dpkg audit\")


def transact(cache, running, apply):
    name, retained = select(cache, running)
    if name is None:
        return 0, {\"removed\": None, \"pending\": False}
    if not apply:
        return 0, {\"selected\": name, \"retained\": sorted(retained)}
    # The caller holds SystemLock from cache creation through postconditions.
    # Native commit drops/reacquires only the inner dpkg lock when required.
    if not cache.commit(allow_unauthenticated=False):
        raise RuntimeError(\"native kernel removal failed\")
    cache.open()
    audit()
    if cache.dpkg_journal_dirty or cache.broken_count:
        raise RuntimeError(\"kernel removal left incomplete package state\")
    if name in cache and cache[name].is_installed:
        raise RuntimeError(\"native kernel removal did not remove its target\")
    for identity, version in retained.items():
        if identity not in cache or not configured(cache[identity]) or cache[identity].installed.version != version:
            raise RuntimeError(\"kernel removal changed a retained boot choice\")
    next_name, _ = select(cache, running)
    cache.clear()
    return (75 if next_name else 0), {\"removed\": name, \"pending\": next_name is not None}


def main():
    if sys.argv[1:] not in ([\"--plan\"], [\"--apply\"]):
        raise RuntimeError(\"expected --plan or --apply\")
    apply = sys.argv[1] == \"--apply\"
    if apply and os.geteuid() != TRUSTED_UID:
        raise RuntimeError(\"kernel removal requires the trusted owner\")
    trusted(POLICY)
    if os.environ.get(\"APT_CONFIG\") != str(POLICY):
        raise RuntimeError(\"unexpected kernel APT profile\")
    import apt
    import apt_pkg
    config = apt_pkg.config
    if (not config.find_b(\"APT::Protect-Kernels\", False) or
            config.find(\"APT::NeverAutoRemove::KernelCount\") or
            config.value_list(\"APT::VersionedKernelPackages\") != [\"linux-image\"] or
            config.find_b(\"Debug::NoLocking\", True) or
            config.find(\"Dir::Etc::parts\") or config.find(\"Dir::Etc::main\")):
        raise RuntimeError(\"unverified kernel protection configuration\")
    status = Path(config.find_file(\"Dir::State::status\"))
    trusted(status)
    trusted(status.parent, directory=True)
    extended = Path(config.find_file(\"Dir::State::extended_states\"))
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


if __name__ == \"__main__\":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(\"debian13s4 kernel retention: \" + str(error), file=sys.stderr)
        sys.exit(1)
" > "$S4B_STAGE/"lib/maintenance/retain-kernels.py || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/maintenance/debian13s4-maintenance.service || return 1
    printf '%s' "[Unit]
Description=Retry Debian 13 maintenance after boot and every hour

[Timer]
OnBootSec=5min
OnUnitInactiveSec=1h
RandomizedDelaySec=5min
Unit=debian13s4-maintenance.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/maintenance/debian13s4-maintenance.timer || return 1
    printf '%s' "#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \\
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4m_apply
" > "$S4B_STAGE/"lib/tasks/maintenance/apply.sh || return 1
    printf '%s' "#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
s4m_verify
" > "$S4B_STAGE/"lib/tasks/maintenance/verify.sh || return 1
    printf '%s' "#!/bin/bash

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
    architecture=\$(dpkg --print-architecture) || return 1
    [[ \$architecture == amd64 || \$architecture == arm64 ]]
}

s4d_prepare() {
    s4d_supported || return 78
    S4P_APT_DIR=\$S4D_APT_DIR
    s4p_prepare
}

s4d_runtime() {
    local package status resolved output line core=0 web=0
    for package in \"\${S4D_PACKAGES[@]}\"; do
        status=\$(s4p_query \"\$package\") || return 1
        [[ \$status == 'install ok installed' ]] || return 1
    done
    [[ -x \$S4D_DOTNET && -f \$S4D_DOTNET && -L \$S4D_LINK ]] &&
        s4m_trusted \"\$S4D_DOTNET\" && s4m_trusted \"\${S4D_LINK%/*}\" || return 1
    [[ \$(stat --format='%u' -- \"\$S4D_LINK\") == 0 ]] || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$S4D_LINK\") || return 1
    [[ \$resolved == \"\$S4D_DOTNET\" ]] || return 1
    [[ -f \$S4D_LIBRARY/verify-payload.pl ]] &&
        s4m_trusted \"\$S4D_LIBRARY/verify-payload.pl\" &&
        s4m_control perl \"\$S4D_LIBRARY/verify-payload.pl\" || return 1
    output=\$(s4m_control env DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \\
        \"\$S4D_DOTNET\" --list-runtimes) || return 1
    while IFS= read -r line; do
        [[ \$line =~ ^Microsoft[.]NETCore[.]App\\ 10[.]0[.][0-9]+\\ \\[/usr/share/dotnet/shared/Microsoft[.]NETCore[.]App\\]\$ ]] && core=1
        [[ \$line =~ ^Microsoft[.]AspNetCore[.]App\\ 10[.]0[.][0-9]+\\ \\[/usr/share/dotnet/shared/Microsoft[.]AspNetCore[.]App\\]\$ ]] && web=1
    done <<< \"\$output\"
    (( core == 1 && web == 1 ))
}

s4d_files() {
    local name
    [[ -d \$S4M_STATE ]] && s4m_trusted \"\$S4M_STATE\" || return 1
    for name in \"\${S4D_FILES[@]}\"; do
        [[ -f \$S4D_LIBRARY/\$name ]] && s4m_trusted \"\$S4D_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4D_LIBRARY/update.sh ]] || return 1
    for name in common.sh policy.conf needrestart.conf restart-policy.pl; do
        [[ -f \$S4M_LIBRARY/\$name ]] && s4m_trusted \"\$S4M_LIBRARY/\$name\" || return 1
    done
    for name in \"\$S4D_SERVICE\" \"\$S4D_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4D_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4D_TIMER\" && s4m_property \"\$S4D_TIMER\" ActiveState active
}

s4d_identity() {
    local name digest
    for name in \"\${S4D_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4D_LIBRARY/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
}

s4d_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/dotnet.ready ]] && s4m_trusted \"\$S4M_STATE/dotnet.ready\" || return 1
    s4d_files || return 1
    expected=\$(s4d_identity) && actual=\$(cat -- \"\$S4M_STATE/dotnet.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4d_upgrade() {
    # Reinstall registered packages when their installed bytes cannot be verified.
    local -a repair=()
    s4d_runtime || repair=(--reinstall)
    s4m_package apt-get --assume-yes --no-remove --no-install-recommends \\
        \"\${repair[@]}\" install \"\${S4D_PACKAGES[@]}\"
}

s4d_apply() (
    local unit loaded temporary wants resolved APT_CONFIG=\$S4D_LIBRARY/policy.conf
    local DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none
    local UCF_FORCE_CONFFOLD=1 NEEDRESTART_MODE=l
    s4d_prepare || return 1
    s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for unit in \"\$S4D_TIMER\" \"\$S4D_SERVICE\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/dotnet.ready || -L \$S4M_STATE/dotnet.ready ]]; then
        [[ -f \$S4M_STATE/dotnet.ready ]] && s4m_trusted \"\$S4M_STATE/dotnet.ready\" || return 1
        rm -f -- \"\$S4M_STATE/dotnet.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for unit in \"\$S4D_TIMER\" \"\$S4D_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
            return 1
        fi
    done
    for unit in \"\${S4D_FILES[@]}\"; do
        [[ -f \$S4D_LIBRARY/\$unit ]] && s4m_trusted \"\$S4D_LIBRARY/\$unit\" || return 1
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
    for unit in \"\$S4D_SERVICE\" \"\$S4D_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4D_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable \"\$S4D_TIMER\" &&
        s4m_enabled \"\$S4D_TIMER\" || return 1
    wants=\$S4M_SYSTEMD/timers.target.wants
    [[ -d \$wants && -L \$wants/\$S4D_TIMER ]] && s4m_trusted \"\$wants\" || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4D_TIMER\") || return 1
    [[ \$resolved == \"\$S4M_SYSTEMD/\$S4D_TIMER\" ]] || return 1
    s4m_sync \"\$S4M_SYSTEMD\" \"\$wants\" \"\$S4M_SYSTEMD/\$S4D_TIMER\" \"\$S4M_SYSTEMD/\$S4D_SERVICE\" || return 1
    s4m_systemctl start \"\$S4D_TIMER\" && s4d_files || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/dotnet-intent.XXXXXX\") || return 1
    if ! s4d_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/dotnet.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4d_ready
)

s4d_verify() {
    s4d_supported && s4p_verify && s4d_runtime && s4d_ready
}

s4d_update() (
    S4M_UPDATE_POLICY=\$S4D_LIBRARY/policy.conf
    S4M_UPDATE_READY=s4d_ready
    S4M_UPDATE_PREPARE=s4d_prepare
    S4M_UPDATE_UPGRADE=s4d_upgrade
    S4M_UPDATE_VERIFY=s4d_runtime
    S4M_UPDATE_CLEANUP=s4m_skip_cleanup
    s4m_update
)
" > "$S4B_STAGE/"lib/dotnet/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_update
" > "$S4B_STAGE/"lib/dotnet/update.sh || return 1
    printf '%s' "#!/usr/bin/perl

use strict;
use warnings;
use Digest::MD5;
use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK S_ISDIR S_ISREG);

# The installed package database and native tools are part of the trusted base.
# These digests check installed bytes, not package authenticity or application health.
my \$install_root = '/';
my \$trusted_uid = 0;
my \$admindir = \"\$install_root/var/lib/dpkg\";
\$admindir =~ s{^//}{/};
my \$limit = 1024 * 1024;

sub fail { die \"debian13s4 runtime integrity: \$_[0]\\n\"; }

sub path {
    my (\$name) = @_;
    \$name =~ m{\\A/[A-Za-z0-9_+./-]+\\z} &&
        \$name !~ m{(?:\\A|/)[.][.]?(?:/|\\z)|//|/\\z} or fail('invalid package path');
    return \$install_root eq '/' ? \$name : \"\$install_root\$name\";
}

sub trusted {
    my (\$name, \$kind) = @_;
    my \$current = \$name;
    while (1) {
        my @st = lstat(\$current);
        @st && \$st[4] == \$trusted_uid && !(\$st[2] & 0022) or fail(\"untrusted path: \$current\");
        (\$current eq \$name && \$kind eq 'file' ? S_ISREG(\$st[2]) : S_ISDIR(\$st[2]))
            or fail(\"wrong path kind: \$current\");
        last if \$current eq \$install_root;
        \$current =~ s{/[^/]+\\z}{};
        \$current = '/' if \$current eq '';
    }
}

sub query {
    open(my \$child, '-|', 'dpkg-query', \"--admindir=\$admindir\", @_) or fail('query start failed');
    my \$output = '';
    while (1) {
        my \$count = read(\$child, my \$buffer, 65536);
        defined \$count or fail('query read failed');
        last if \$count == 0;
        \$output .= \$buffer;
        length(\$output) <= \$limit or fail('package metadata exceeds bound');
    }
    close(\$child) or fail('query failed');
    return \$output;
}

sub digest {
    my (\$name, \$expected) = @_;
    trusted(\$name, 'file');
    my @before = lstat(\$name);
    sysopen(my \$file, \$name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) or fail(\"cannot open: \$name\");
    binmode(\$file) or fail('binary mode failed');
    my @opened = stat(\$file);
    @opened && S_ISREG(\$opened[2]) && \$opened[0] == \$before[0] && \$opened[1] == \$before[1]
        or fail('payload identity changed');
    my \$actual = Digest::MD5->new->addfile(\$file)->hexdigest;
    my @after = stat(\$file);
    my @named = lstat(\$name);
    @after && @named && S_ISREG(\$named[2]) &&
        join(':', @opened[0,1,2,4,7,9,10]) eq join(':', @after[0,1,2,4,7,9,10]) &&
        join(':', @after[0,1,2,4,7,9,10]) eq join(':', @named[0,1,2,4,7,9,10])
        or fail('payload changed during verification');
    close(\$file) or fail('payload close failed');
    \$actual eq \$expected or fail(\"checksum mismatch: \$name\");
}

trusted(\$admindir, 'directory');
trusted(\"\$admindir/info\", 'directory');
trusted(\"\$admindir/status\", 'file');
for my \$package (qw(aspnetcore-runtime-10.0 dotnet-runtime-10.0 dotnet-runtime-deps-10.0
                   dotnet-hostfxr-10.0 dotnet-host)) {
    my \$identity = query('--show', '--showformat=\${binary:Package}\\t\${Status}\\t\${Version}\\n', '--', \$package);
    \$identity =~ /\\A(\\Q\$package\\E(?::(?:amd64|arm64))?)\\tinstall ok installed\\t(10[.]0[.][0-9]+)-[0-9A-Za-z.+~]+\\n\\z/
        or fail(\"unusable package identity: \$package\");
    my (\$binary, \$version) = (\$1, \$2);
    # Validate the metadata leaves before the native queries can open them.
    # --control-path is needed for trust checks, not for reading the contents:
    # binary:Package can qualify a foreign architecture even without Multi-Arch.
    my \$metadata = query('--control-path', \$binary, 'md5sums');
    \$metadata =~ m{\\A(\\Q\$admindir/info/\$package\\E(?::(?:amd64|arm64))?)[.]md5sums\\n\\z}
        or fail('invalid checksum metadata location');
    my \$metadata_base = \$1;
    trusted(\"\$metadata_base.md5sums\", 'file');
    trusted(\"\$metadata_base.list\", 'file');
    my \$manifest = query('--control-show', \$binary, 'md5sums');
    my \$inventory = query('--listfiles', '--', \$binary);
    length(\$manifest) && length(\$inventory) && \$manifest =~ /\\n\\z/ && \$inventory =~ /\\n\\z/
        or fail('missing package metadata');
    my (%sums, %listed, %directories);
    # The dependency-only package also owns the shared installation directory.
    \$directories{'/usr/share/dotnet'} = 1;
    for my \$line (split(/\\n/, \$manifest)) {
        \$line =~ m{\\A([0-9a-f]{32})  ([A-Za-z0-9_+./-]+)\\z} or fail('invalid checksum metadata');
        my (\$hash, \$relative) = (\$1, \$2);
        my \$name = \"/\$relative\";
        path(\$name);
        exists(\$sums{\$name}) and fail('duplicate checksum metadata');
        \$sums{\$name} = \$hash;
        if (\$name =~ m{\\A/usr/share/dotnet/}) {
            my \$parent = \$name;
            while (\$parent =~ s{/[^/]+\\z}{}) { \$directories{\$parent} = 1; }
        }
    }
    for my \$name (split(/\\n/, \$inventory)) {
        next if \$name eq '/.' || \$name eq '/';
        path(\$name);
        exists(\$listed{\$name}) and fail('duplicate package inventory');
        \$listed{\$name} = 1;
        next unless \$name =~ m{\\A/usr/share/dotnet(?:/|\\z)};
        if (exists(\$sums{\$name})) {
            digest(path(\$name), \$sums{\$name});
        } else {
            \$directories{\$name} or fail(\"no checksum coverage: \$name\");
            trusted(path(\$name), 'directory');
        }
    }
    for my \$name (keys %sums) {
        next unless \$name =~ m{\\A/usr/share/dotnet/};
        \$listed{\$name} or fail(\"checksum absent from inventory: \$name\");
    }
    my @required;
    if (\$package eq 'dotnet-host') {
        @required = ('/usr/share/dotnet/dotnet');
    } elsif (\$package eq 'dotnet-hostfxr-10.0') {
        @required = (\"/usr/share/dotnet/host/fxr/\$version/libhostfxr.so\");
    } elsif (\$package eq 'dotnet-runtime-10.0') {
        @required = map { \"/usr/share/dotnet/shared/Microsoft.NETCore.App/\$version/\$_\" }
            qw(libcoreclr.so libclrjit.so libhostpolicy.so libSystem.Native.so
               libSystem.Globalization.Native.so libSystem.IO.Compression.Native.so
               libSystem.Net.Security.Native.so libSystem.Security.Cryptography.Native.OpenSsl.so
               System.Private.CoreLib.dll System.Runtime.dll Microsoft.NETCore.App.deps.json
               Microsoft.NETCore.App.runtimeconfig.json);
    } elsif (\$package eq 'aspnetcore-runtime-10.0') {
        @required = map { \"/usr/share/dotnet/shared/Microsoft.AspNetCore.App/\$version/\$_\" }
            qw(Microsoft.AspNetCore.dll Microsoft.AspNetCore.Hosting.dll Microsoft.AspNetCore.Http.dll
               Microsoft.AspNetCore.Server.Kestrel.dll Microsoft.AspNetCore.App.deps.json
               Microsoft.AspNetCore.App.runtimeconfig.json);
    }
    for my \$name (@required) {
        exists(\$sums{\$name}) && \$listed{\$name} or fail(\"required payload is not verifiable: \$name\");
    }
}
" > "$S4B_STAGE/"lib/dotnet/verify-payload.pl || return 1
    printf '%s' "// Inherit the authenticated Debian settings without loading host APT hooks.
#include \"/usr/local/lib/debian13s4/maintenance/policy.conf\";
Dir::Etc::sourcelist \"/usr/local/lib/debian13s4/dotnet/sources.sources\";
Dir::Etc::preferences \"/usr/local/lib/debian13s4/dotnet/preferences\";
Dir::State::lists \"/var/lib/apt/debian13s4-dotnet/lists\";
" > "$S4B_STAGE/"lib/dotnet/policy.conf || return 1
    printf '%s' "Package: aspnetcore-runtime-10.0 dotnet-runtime-10.0 dotnet-runtime-deps-10.0 dotnet-hostfxr-10.0
Pin: release o=microsoft-debian-trixie-prod trixie,n=trixie
Pin-Priority: 500

Package: dotnet-host
Pin: version 10.*
Pin-Priority: 500

Package: *
Pin: origin \"packages.microsoft.com\"
Pin-Priority: -1
" > "$S4B_STAGE/"lib/dotnet/preferences || return 1
    printf '%s' "-----BEGIN PGP PUBLIC KEY BLOCK-----
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
" > "$S4B_STAGE/"lib/dotnet/microsoft-2025.asc || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/dotnet/debian13s4-dotnet.service || return 1
    printf '%s' "[Unit]
Description=Retry .NET runtime patches after boot and every hour

[Timer]
OnBootSec=10min
OnUnitInactiveSec=1h
RandomizedDelaySec=5min
Unit=debian13s4-dotnet.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/dotnet/debian13s4-dotnet.timer || return 1
    printf '%s' "Types: deb
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
" > "$S4B_STAGE/"lib/dotnet/sources.sources || return 1
    printf '%s' "#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \\
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4d_apply
" > "$S4B_STAGE/"lib/tasks/dotnet/apply.sh || return 1
    printf '%s' "#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_verify
" > "$S4B_STAGE/"lib/tasks/dotnet/verify.sh || return 1
    printf '%s' "#!/bin/bash

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
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    [[ -f \$S4M_LIBRARY/common.sh ]] && s4m_trusted \"\$S4M_LIBRARY/common.sh\" || return 1
    for name in \"\${S4N_FILES[@]}\"; do
        [[ -f \$S4N_LIBRARY/\$name ]] && s4m_trusted \"\$S4N_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4N_LIBRARY/repair.sh ]]
}

s4n_identity() {
    local name digest
    for name in \"\${S4N_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4N_LIBRARY/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    digest=\$(sha256sum -- \"\$S4M_LIBRARY/common.sh\") || return 1
    printf '%s maintenance/common.sh\\n' \"\${digest%% *}\"
}

s4n_controller() {
    local name
    s4n_assets || return 1
    for name in \"\$S4N_SERVICE\" \"\$S4N_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4N_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" &&
            s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4N_TIMER\" && s4m_property \"\$S4N_TIMER\" ActiveState active
}

s4n_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/network.ready ]] && s4m_trusted \"\$S4M_STATE/network.ready\" || return 1
    s4n_controller || return 1
    expected=\$(s4n_identity) && actual=\$(cat -- \"\$S4M_STATE/network.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4n_configure() {
    local directory=\${S4N_CONFIG%/*}
    s4m_trusted \"\${directory%/*}\" || return 1
    if [[ -e \$directory || -L \$directory ]]; then
        [[ -d \$directory ]] && s4m_trusted \"\$directory\" || return 1
    else
        mkdir -m 0755 -- \"\$directory\" || return 1
    fi
    s4m_atomic \"\$S4N_CONFIG\" \"\$S4N_LIBRARY/network.conf\"
}

s4n_observe() {
    s4m_control /usr/bin/python3 -I -B \"\$S4N_LIBRARY/verify.py\"
}

s4n_kernel() {
    # ip_forward is first in this exact policy: changing it can reset the other
    # IPv4 knobs. Native exit alone cannot prove optional/glob settings applied.
    s4m_control /usr/lib/systemd/systemd-sysctl --strict \"\$S4N_CONFIG\" && s4n_observe
}

s4n_verify() {
    s4n_ready && [[ -f \$S4N_CONFIG ]] && s4m_trusted \"\$S4N_CONFIG\" &&
        cmp --silent -- \"\$S4N_LIBRARY/network.conf\" \"\$S4N_CONFIG\" && s4n_observe
}

s4n_apply() {
    local unit loaded wants resolved temporary
    s4n_assets || return 1
    for unit in \"\$S4N_TIMER\" \"\$S4N_SERVICE\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/network.ready || -L \$S4M_STATE/network.ready ]]; then
        [[ -f \$S4M_STATE/network.ready ]] && s4m_trusted \"\$S4M_STATE/network.ready\" || return 1
        rm -f -- \"\$S4M_STATE/network.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for unit in \"\$S4N_TIMER\" \"\$S4N_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
            return 1
        fi
    done
    s4n_configure && s4n_kernel || return 1
    for unit in \"\$S4N_SERVICE\" \"\$S4N_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4N_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable \"\$S4N_TIMER\" &&
        s4m_enabled \"\$S4N_TIMER\" || return 1
    wants=\$S4M_SYSTEMD/timers.target.wants
    [[ -d \$wants && -L \$wants/\$S4N_TIMER ]] && s4m_trusted \"\$wants\" || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4N_TIMER\") || return 1
    [[ \$resolved == \"\$S4M_SYSTEMD/\$S4N_TIMER\" ]] || return 1
    s4m_sync \"\$S4M_SYSTEMD\" \"\$wants\" \"\$S4M_SYSTEMD/\$S4N_TIMER\" \"\$S4M_SYSTEMD/\$S4N_SERVICE\" || return 1
    s4m_systemctl start \"\$S4N_TIMER\" && s4n_controller || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/network-intent.XXXXXX\") || return 1
    if ! s4n_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/network.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4n_verify
}

s4n_repair() {
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    # The task owns initial unit/readiness publication. Recurring repair admits
    # config drift without treating changed code/controller identity as healthy.
    s4n_ready && s4n_configure && s4n_kernel || return 75
}
" > "$S4B_STAGE/"lib/network/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_repair
" > "$S4B_STAGE/"lib/network/repair.sh || return 1
    printf '%s' "\"\"\"Observe the host network policy; this helper never writes kernel settings.\"\"\"

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path(\"/proc/sys\")
TRUSTED_UID = 0
MAX_INTERFACES = 1024
GLOBALS = {\"ip_forward\": 0, \"tcp_syncookies\": 1,
           \"icmp_echo_ignore_broadcasts\": 1, \"icmp_ignore_bogus_error_responses\": 1}
IPV4 = {\"forwarding\": 0, \"accept_redirects\": 0, \"send_redirects\": 0,
        \"accept_source_route\": 0, \"rp_filter\": 2, \"route_localnet\": 0, \"proxy_arp\": 0}
IPV6 = {\"forwarding\": 0, \"accept_redirects\": 0, \"accept_source_route\": -1, \"proxy_ndp\": 0}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError(f\"noncanonical path: {path}\")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError(f\"untrusted path: {current}\")
        if current == Path(\"/\"):
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
            raise ValueError(f\"changed descriptor: {path}\")
        data = os.read(fd, 65)
        if len(data) > 64 or os.read(fd, 1) or not re.fullmatch(rb\"-?[0-9]+\\n?\", data):
            raise ValueError(f\"invalid scalar: {path}\")
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError(f\"changed scalar: {path}\")
        return int(data)
    finally:
        os.close(fd)


def interfaces(family):
    base = PROC / \"net\" / family
    # A compiled-out or unloaded IPv6 stack has no namespace. Partial, symbolic
    # or unreadable namespaces cannot be confused with that optional absence.
    if family == \"ipv6\" and not os.path.lexists(base):
        trusted(base.parent, stat.S_ISDIR)
        return None
    directory = base / \"conf\"
    trusted(directory, stat.S_ISDIR)
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(names) >= MAX_INTERFACES + 2:
                raise ValueError(\"too many interfaces for bounded verification\")
            if not entry.name or len(os.fsencode(entry.name)) > 15 or entry.name in (\".\", \"..\"):
                raise ValueError(\"invalid interface name\")
            trusted(directory / entry.name, stat.S_ISDIR)
            names.append(entry.name)
    if not {\"all\", \"default\", \"lo\"}.issubset(names):
        raise ValueError(f\"incomplete {family} interface inventory\")
    return sorted(names)


def verify():
    inventories = {family: interfaces(family) for family in (\"ipv4\", \"ipv6\")}
    for name, expected in GLOBALS.items():
        path = PROC / \"net/ipv4\" / name
        if value(path) != expected:
            raise ValueError(f\"policy differs: {path}\")
    for family, policy in ((\"ipv4\", IPV4), (\"ipv6\", IPV6)):
        for interface in inventories[family] or ():
            for name, expected in policy.items():
                path = PROC / \"net\" / family / \"conf\" / interface / name
                if value(path) != expected:
                    raise ValueError(f\"policy differs: {path}\")
    if any(interfaces(family) != names for family, names in inventories.items()):
        raise ValueError(\"interface inventory changed; retry required\")


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        verify()
        return 0
    except (OSError, ValueError) as error:
        print(f\"debian13s4 network verification: {error}\", file=sys.stderr)
        return 75


if __name__ == \"__main__\":
    sys.exit(main())
" > "$S4B_STAGE/"lib/network/verify.py || return 1
    printf '%s' "# Host networking, not routing. Keep ip_forward first: changing it resets IPv4 defaults.
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
" > "$S4B_STAGE/"lib/network/network.conf || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/network/debian13s4-network.service || return 1
    printf '%s' "[Unit]
Description=Reconcile host network policy after boot and periodically

[Timer]
OnBootSec=10s
OnUnitInactiveSec=2min
AccuracySec=5s
Unit=debian13s4-network.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/network/debian13s4-network.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_apply
" > "$S4B_STAGE/"lib/tasks/network/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Network/common.sh
. /usr/local/lib/debian13s4/network/common.sh
s4n_verify
" > "$S4B_STAGE/"lib/tasks/network/verify.sh || return 1
    printf '%s' "#!/bin/bash

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
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    [[ -f \$S4M_LIBRARY/common.sh ]] && s4m_trusted \"\$S4M_LIBRARY/common.sh\" || return 1
    for name in \"\${S4R_FILES[@]}\"; do
        [[ -f \$S4R_LIBRARY/\$name ]] && s4m_trusted \"\$S4R_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4R_LIBRARY/repair.sh ]]
}

s4r_identity() {
    local name digest
    for name in \"\${S4R_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4R_LIBRARY/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    digest=\$(sha256sum -- \"\$S4M_LIBRARY/common.sh\") || return 1
    printf '%s maintenance/common.sh\\n' \"\${digest%% *}\"
}

s4r_controller() {
    local name
    s4r_assets || return 1
    for name in \"\$S4R_SERVICE\" \"\$S4R_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4R_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" &&
            s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4R_TIMER\" && s4m_property \"\$S4R_TIMER\" ActiveState active
}

s4r_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/retention.ready ]] && s4m_trusted \"\$S4M_STATE/retention.ready\" || return 1
    s4r_controller || return 1
    expected=\$(s4r_identity) && actual=\$(cat -- \"\$S4M_STATE/retention.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4r_configure() {
    local directory=\${S4R_CONFIG%/*}
    s4m_trusted \"\${directory%/*}\" || return 1
    if [[ -e \$directory || -L \$directory ]]; then
        [[ -d \$directory ]] && s4m_trusted \"\$directory\" || return 1
    else
        mkdir -m 0755 -- \"\$directory\" || return 1
    fi
    s4m_atomic \"\$S4R_CONFIG\" \"\$S4R_LIBRARY/journal.conf\"
}

s4r_generation() {
    local invocation
    s4m_property \"\$S4R_JOURNAL\" FragmentPath /usr/lib/systemd/system/systemd-journald.service &&
        s4m_property \"\$S4R_JOURNAL\" DropInPaths '' &&
        s4m_property \"\$S4R_JOURNAL\" Result success &&
        s4m_property \"\$S4R_JOURNAL\" ActiveState active || return 1
    invocation=\$(s4m_systemctl show --property=InvocationID --value \"\$S4R_JOURNAL\") || return 1
    [[ \$invocation =~ ^[0-9a-f]{32}\$ && \$invocation != 00000000000000000000000000000000 ]] || return 1
    printf '%s\\n' \"\$invocation\"
}

s4r_policy() {
    local digest
    digest=\$(s4m_control /usr/bin/python3 -I -B \"\$S4R_LIBRARY/journal.py\" --config) || return 1
    [[ \$digest =~ ^[0-9a-f]{64}\$ ]] || return 1
    printf '%s\\n' \"\$digest\"
}

s4r_applied() {
    local digest=\$1 generation=\$2 actual
    [[ -f \$S4M_STATE/journal.applied ]] && s4m_trusted \"\$S4M_STATE/journal.applied\" || return 1
    actual=\$(cat -- \"\$S4M_STATE/journal.applied\") || return 1
    [[ \$actual == \"\$digest \$generation\" ]]
}

s4r_bounded() (
    local descriptor=\$S4M_REPAIR_FD
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=\"\${S4R_GRACE_SECONDS}s\" \"\${S4R_SECONDS}s\" \\
        env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \"\$@\"
)

s4r_journal() {
    local digest before after observed temporary
    s4r_configure || return 1
    # This also checks default journal paths before any restart or deletion.
    digest=\$(s4r_policy) || return 1
    before=\$(s4m_systemctl show --property=InvocationID --value \"\$S4R_JOURNAL\") || return 1
    observed=\$(s4r_generation) || observed=
    if ! s4r_applied \"\$digest\" \"\$before\" || [[ \$observed != \"\$before\" ]]; then
        # A restart preserves native log-stream descriptors. Never stop and
        # then start journald separately, and never accept a queued/no-op restart.
        s4m_systemctl restart \"\$S4R_JOURNAL\" || return 1
        after=\$(s4r_generation) || return 1
        [[ \$after != \"\$before\" ]] && [[ \$(s4r_policy) == \"\$digest\" ]] || return 1
        temporary=\$(mktemp -- \"\$S4M_STATE/journal-intent.XXXXXX\") || return 1
        if ! printf '%s %s\\n' \"\$digest\" \"\$after\" > \"\$temporary\" ||
            ! chmod 0600 -- \"\$temporary\" || ! s4m_atomic \"\$S4M_STATE/journal.applied\" \"\$temporary\" 0600; then
            rm -f -- \"\$temporary\"
            return 1
        fi
        rm -f -- \"\$temporary\" || return 1
    fi
    s4r_bounded /usr/bin/python3 -I -B \"\$S4R_LIBRARY/journal.py\" --vacuum || return 1
    after=\$(s4r_generation) && [[ \$(s4r_policy) == \"\$digest\" ]] && s4r_applied \"\$digest\" \"\$after\"
}

s4r_cache() {
    s4r_bounded /usr/bin/env APT_CONFIG=\"\$S4R_LIBRARY/apt.conf\" \\
        /usr/bin/python3 -I -B \"\$S4R_LIBRARY/clean-cache.py\" --apply
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
    s4r_ready && [[ -f \$S4R_CONFIG ]] && s4m_trusted \"\$S4R_CONFIG\" &&
        cmp --silent -- \"\$S4R_LIBRARY/journal.conf\" \"\$S4R_CONFIG\" || return 1
    digest=\$(s4r_policy) && generation=\$(s4r_generation) && s4r_applied \"\$digest\" \"\$generation\" || return 1
    s4m_control /usr/bin/python3 -I -B \"\$S4R_LIBRARY/journal.py\" --observe
}

s4r_apply() {
    local unit loaded wants resolved temporary
    s4r_assets || return 1
    for unit in \"\$S4R_TIMER\" \"\$S4R_SERVICE\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/retention.ready || -L \$S4M_STATE/retention.ready ]]; then
        [[ -f \$S4M_STATE/retention.ready ]] && s4m_trusted \"\$S4M_STATE/retention.ready\" || return 1
        rm -f -- \"\$S4M_STATE/retention.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for unit in \"\$S4R_TIMER\" \"\$S4R_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
            return 1
        fi
    done
    # Generic setup repair retains ownership until all initial work succeeds.
    s4r_work || return 1
    for unit in \"\$S4R_SERVICE\" \"\$S4R_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4R_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable \"\$S4R_TIMER\" && s4m_enabled \"\$S4R_TIMER\" || return 1
    wants=\$S4M_SYSTEMD/timers.target.wants
    [[ -d \$wants && -L \$wants/\$S4R_TIMER ]] && s4m_trusted \"\$wants\" || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4R_TIMER\") || return 1
    [[ \$resolved == \"\$S4M_SYSTEMD/\$S4R_TIMER\" ]] || return 1
    s4m_sync \"\$S4M_SYSTEMD\" \"\$wants\" \"\$S4M_SYSTEMD/\$S4R_TIMER\" \"\$S4M_SYSTEMD/\$S4R_SERVICE\" || return 1
    s4m_systemctl start \"\$S4R_TIMER\" && s4r_controller || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/retention-intent.XXXXXX\") || return 1
    if ! s4r_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/retention.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4r_verify
}

s4r_repair() {
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    s4r_ready && s4r_work || return 75
}
" > "$S4B_STAGE/"lib/retention/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_repair
" > "$S4B_STAGE/"lib/retention/repair.sh || return 1
    printf '%s' "\"\"\"Check the default journal's effective policy and archived-file retention.\"\"\"

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


TRUSTED_UID = 0
PREFIXES = tuple(Path(p) for p in (\"/etc/systemd\", \"/run/systemd\", \"/usr/local/lib/systemd\", \"/usr/lib/systemd\"))
MACHINE = Path(\"/etc/machine-id\")
JOURNALS = ((Path(\"/var/log/journal\"), 128 * 1024**2, 32),
            (Path(\"/run/log/journal\"), 32 * 1024**2, 8))
POLICY = {
    \"Storage\": \"persistent\", \"Compress\": \"yes\",
    \"SystemMaxUse\": \"128M\", \"RuntimeMaxUse\": \"32M\",
    \"SystemKeepFree\": \"512M\", \"RuntimeKeepFree\": \"64M\",
    \"SystemMaxFileSize\": \"8M\", \"RuntimeMaxFileSize\": \"4M\",
    \"SystemMaxFiles\": \"32\", \"RuntimeMaxFiles\": \"8\",
    \"MaxFileSec\": \"1day\", \"MaxRetentionSec\": \"14day\",
}
MAX_INPUT = 1024**2
MAX_FILES = 100000
AGE = 14 * 86400
ARCHIVE = re.compile(r\".+@[0-9a-fA-F]{32}-[0-9a-fA-F]{16}-([0-9a-fA-F]{16})\\.journal\\Z\")
UNCLEAN = re.compile(r\".+@([0-9a-fA-F]{16})-[0-9a-fA-F]{16}\\.journal~\\Z\")


def trusted(path, kind=stat.S_ISREG):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError(\"noncanonical journal path\")
    leaf = path
    while True:
        info = path.lstat()
        if not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError(\"untrusted journal path: \" + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path):
    before = trusted(path)
    if before.st_size > MAX_INPUT:
        raise ValueError(\"oversized journal input\")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if signature(before) != signature(os.fstat(descriptor)):
            raise ValueError(\"journal input descriptor changed\")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, MAX_INPUT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_INPUT:
                raise ValueError(\"oversized journal input\")
        if signature(before) != signature(os.fstat(descriptor)) or signature(before) != signature(trusted(path)):
            raise ValueError(\"journal input changed\")
        return bytes(data)
    finally:
        os.close(descriptor)


def sources():
    result = {}
    total = 0
    def add(path):
        nonlocal total
        if len(result) >= 1024:
            raise ValueError(\"excessive journal configuration\")
        data = read(path)
        total += len(data)
        if total > MAX_INPUT:
            raise ValueError(\"excessive journal configuration\")
        result[str(path)] = data
    for prefix in PREFIXES:
        for path in (prefix / \"journald.conf\", prefix / \"journald.conf.d\"):
            if not path.exists() and not path.is_symlink():
                continue
            if path.name == \"journald.conf\":
                add(path)
            else:
                trusted(path, stat.S_ISDIR)
                for leaf in path.iterdir():
                    if leaf.name.endswith(\".conf\"):
                        add(leaf)
    return result


def policy(text):
    values, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((\"#\", \";\")):
            continue
        # Refuse syntax whose continuation/quoting could make this observer
        # disagree with the native parser, rather than guessing its meaning.
        if line.endswith(\"\\\\\"):
            raise ValueError(\"continued journal configuration is unverifiable\")
        if line.startswith(\"[\"):
            if not re.fullmatch(r\"\\[[A-Za-z0-9]+\\]\", line):
                raise ValueError(\"invalid journal section\")
            section = line[1:-1]
        elif section == \"Journal\":
            key, separator, value = line.partition(\"=\")
            if not separator:
                raise ValueError(\"invalid journal assignment\")
            if key.strip() in POLICY:
                values[key.strip()] = value.strip()
    if values != POLICY:
        raise ValueError(\"effective journal policy differs\")


def configuration():
    before = sources()
    result = subprocess.run([\"/usr/bin/systemd-analyze\", \"--no-pager\", \"cat-config\", \"systemd/journald.conf\"],
                            capture_output=True, check=True, timeout=5)
    if result.stderr or len(result.stdout) > MAX_INPUT + 262144:
        raise ValueError(\"unverifiable native journal configuration\")
    text = result.stdout.decode(\"utf-8\", errors=\"strict\")
    emitted = re.findall(r\"^# (/[^\\n]+)\$\", text, re.M)
    if not emitted or len(emitted) != len(set(emitted)) or any(path not in before for path in emitted):
        raise ValueError(\"untrusted native journal configuration source\")
    policy(text)
    if sources() != before:
        raise ValueError(\"journal configuration changed\")
    return hashlib.sha256(result.stdout).hexdigest()


def directories(require_persistent=False):
    data = read(MACHINE)
    if not re.fullmatch(rb\"[0-9a-f]{32}\\n?\", data):
        raise ValueError(\"unverifiable journal machine identity\")
    machine = data.decode(\"ascii\", errors=\"strict\").rstrip(\"\\n\")
    if not re.fullmatch(r\"[0-9a-f]{32}\", machine) or machine == \"0\" * 32:
        raise ValueError(\"unverifiable journal machine identity\")
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
            raise ValueError(\"persistent default journal is absent\")
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
            raise ValueError(\"excessive journal inventory\")
    return result


def observe():
    now = int(time.time() * 1000000)
    for path, size, count in directories(require_persistent=True):
        rows = inventory(path)
        if (len(rows) > count or sum(row[1] for row in rows) > size or
                any(row[2] < max(0, now - AGE * 1000000) for row in rows)):
            raise ValueError(\"archived default journals still exceed retention\")


def vacuum():
    directories()
    subprocess.run([\"/usr/bin/journalctl\", \"--flush\"], check=True, timeout=40)
    subprocess.run([\"/usr/bin/journalctl\", \"--rotate\"], check=True, timeout=40)
    for path, size, count in directories(require_persistent=True):
        subprocess.run([\"/usr/bin/journalctl\", \"--directory=\" + str(path),
                        \"--vacuum-size=\" + str(size), \"--vacuum-time=14days\", \"--vacuum-files=\" + str(count)],
                       check=True, timeout=40)
    # Native vacuum logs unlink failures but may still exit zero. Actual
    # archived-file observations are required; active files are not a quota.
    observe()


def main():
    if sys.argv[1:] == [\"--config\"]:
        directories()
        print(configuration())
    elif sys.argv[1:] == [\"--observe\"]:
        observe()
    elif sys.argv[1:] == [\"--vacuum\"] and os.geteuid() == TRUSTED_UID:
        vacuum()
    else:
        raise ValueError(\"expected --config, --observe or trusted --vacuum\")
    return 0


if __name__ == \"__main__\":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(\"debian13s4 journal retention: \" + str(error), file=sys.stderr)
        sys.exit(1)
" > "$S4B_STAGE/"lib/retention/journal.py || return 1
    printf '%s' "\"\"\"Clean only APT download archives after a checked, locked package audit.\"\"\"

import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


POLICY = Path(\"/usr/local/lib/debian13s4/retention/apt.conf\")
CACHE = Path(\"/var/cache/apt/archives\")
LISTS = Path(\"/var/lib/debian13s4/retention-empty-lists\")
STATUS = Path(\"/var/lib/dpkg/status\")
TRUSTED_UID = 0
MAX_FILES = 100000
RESERVED = {\"lock\", \"partial\", \"auxfiles\", \"lost+found\"}


def trusted(path, kind=stat.S_ISREG, owners=None):
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        raise ValueError(\"noncanonical archive path\")
    leaf = path
    while True:
        info = path.lstat()
        allowed = (owners or {TRUSTED_UID}) if path == leaf else {TRUSTED_UID}
        if path != leaf and path in {CACHE / \"partial\", LISTS / \"partial\"}:
            allowed = {TRUSTED_UID, pwd.getpwnam(\"_apt\").pw_uid}
        if (not (kind if path == leaf else stat.S_ISDIR)(info.st_mode) or info.st_mode & 0o022 or
                info.st_uid not in allowed):
            raise ValueError(\"untrusted archive path: \" + str(path))
        if path == path.parent:
            return leaf.lstat()
        path = path.parent


def inventory(directory, partial=False):
    owners = {TRUSTED_UID, pwd.getpwnam(\"_apt\").pw_uid}
    trusted(directory, stat.S_ISDIR, owners if partial else None)
    result = []
    for leaf in directory.iterdir():
        if not partial and leaf.name in {\"partial\", \"auxfiles\", \"lost+found\"}:
            trusted(leaf, stat.S_ISDIR, owners if leaf.name in {\"partial\", \"auxfiles\"} else None)
            if leaf.name == \"partial\":
                result.extend(inventory(leaf, partial=True))
        else:
            # Validate lock leaves too: native GetLock uses O_RDWR and must not
            # receive a FIFO/device even though it already refuses symlinks.
            trusted(leaf, owners=None if leaf.name == \"lock\" else owners)
            if partial or leaf.name not in RESERVED:
                result.append(leaf)
        if len(result) > MAX_FILES:
            raise ValueError(\"excessive archive inventory\")
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
    result = subprocess.run([\"/usr/bin/dpkg\", \"--audit\"], capture_output=True, check=True, timeout=10)
    if result.stdout or result.stderr:
        raise ValueError(\"archive cleanup requires an empty dpkg audit\")


def configuration():
    trusted(POLICY)
    trusted(STATUS)
    if os.environ.get(\"APT_CONFIG\") != str(POLICY):
        raise ValueError(\"unexpected archive APT profile\")
    import apt_pkg
    apt_pkg.init()
    config = apt_pkg.config
    if (config.find(\"Dir::Etc::parts\") or config.find(\"Dir::Etc::main\") or
            config.find(\"Dir::Etc::sourcelist\") != \"-\" or config.find(\"Dir::Etc::sourceparts\") != \"-\" or
            config.find_dir(\"Dir::Cache::archives\").rstrip(\"/\") != str(CACHE) or
            config.find_dir(\"Dir::State::lists\").rstrip(\"/\") != str(LISTS) or
            config.find_file(\"Dir::Cache::pkgcache\") or config.find_file(\"Dir::Cache::srcpkgcache\") or
            config.find_file(\"Dir::State::status\") != str(STATUS) or
            config.find_b(\"Debug::NoLocking\", True) or config.find(\"APT::Sandbox::User\") != \"_apt\"):
        raise ValueError(\"unverified archive cleanup configuration\")
    return apt_pkg


def clean():
    apt_pkg = configuration()
    # Retain repair downloads while dpkg is incomplete. The native package
    # lock covers the audit, archive delivery and postconditions; apt-get clean
    # also owns the native archive lock, without disabling either lock.
    with apt_pkg.SystemLock():
        audit()
        prepare()
        subprocess.run([\"/usr/bin/apt-get\", \"clean\"], check=True, timeout=120)
        if inventory(CACHE) or inventory(LISTS):
            raise ValueError(\"native archive cleanup left downloaded files\")
        audit()


def main():
    if sys.argv[1:] != [\"--apply\"] or os.geteuid() != TRUSTED_UID:
        raise ValueError(\"archive cleanup requires trusted --apply\")
    clean()
    return 0


if __name__ == \"__main__\":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(\"debian13s4 archive retention: \" + str(error), file=sys.stderr)
        sys.exit(1)
" > "$S4B_STAGE/"lib/retention/clean-cache.py || return 1
    printf '%s' "// APT_CONFIG loads this before any host fragments. Clean only downloaded
// archives: retain authenticated indexes, status and existing metadata caches.
Dir::Etc::parts \"\";
Dir::Etc::main \"\";
Dir::Etc::sourcelist \"-\";
Dir::Etc::sourceparts \"-\";
Dir::Cache::archives \"/var/cache/apt/archives\";
Dir::State::lists \"/var/lib/debian13s4/retention-empty-lists\";
Dir::Cache::pkgcache \"\";
Dir::Cache::srcpkgcache \"\";
Debug::NoLocking \"false\";
APT::Sandbox::User \"_apt\";
" > "$S4B_STAGE/"lib/retention/apt.conf || return 1
    printf '%s' "[Journal]
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
" > "$S4B_STAGE/"lib/retention/journal.conf || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/retention/debian13s4-retention.service || return 1
    printf '%s' "[Unit]
Description=Reconcile journal and download retention after boot and hourly

[Timer]
OnBootSec=5min
OnUnitInactiveSec=1h
RandomizedDelaySec=2min
AccuracySec=1min
Unit=debian13s4-retention.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/retention/debian13s4-retention.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_apply
" > "$S4B_STAGE/"lib/tasks/retention/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_verify
" > "$S4B_STAGE/"lib/tasks/retention/verify.sh || return 1
    printf '%s' "#!/bin/bash

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
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    [[ -f \$S4M_LIBRARY/common.sh ]] && s4m_trusted \"\$S4M_LIBRARY/common.sh\" || return 1
    for name in \"\${S4H_FILES[@]}\"; do
        [[ -f \$S4H_LIBRARY/\$name ]] && s4m_trusted \"\$S4H_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4H_LIBRARY/repair.sh ]]
}

s4h_identity() {
    local name digest
    for name in \"\${S4H_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4H_LIBRARY/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    digest=\$(sha256sum -- \"\$S4M_LIBRARY/common.sh\") || return 1
    printf '%s maintenance/common.sh\\n' \"\${digest%% *}\"
}

s4h_controller() {
    local name
    s4h_assets || return 1
    for name in \"\$S4H_SERVICE\" \"\$S4H_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4H_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" &&
            s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4H_TIMER\" && s4m_property \"\$S4H_TIMER\" ActiveState active
}

s4h_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/hardening.ready ]] && s4m_trusted \"\$S4M_STATE/hardening.ready\" || return 1
    s4h_controller || return 1
    expected=\$(s4h_identity) && actual=\$(cat -- \"\$S4M_STATE/hardening.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4h_configure() {
    local directory=\${S4H_CONFIG%/*}
    s4m_trusted \"\${directory%/*}\" || return 1
    if [[ -e \$directory || -L \$directory ]]; then
        [[ -d \$directory ]] && s4m_trusted \"\$directory\" || return 1
    else
        mkdir -m 0755 -- \"\$directory\" || return 1
    fi
    s4m_atomic \"\$S4H_CONFIG\" \"\$S4H_LIBRARY/kernel.conf\"
}

s4h_observe() {
    s4m_control /usr/bin/python3 -I -B \"\$S4H_LIBRARY/verify.py\"
}

s4h_kernel() {
    local plan key
    local -a options=(--strict)
    # The real observer admits every required scalar before any native write.
    # Only drifting keys are included: never weaken an existing stronger
    # ptrace/perf restriction or rewrite an irreversible healthy BPF setting.
    plan=\$(s4m_control /usr/bin/python3 -I -B \"\$S4H_LIBRARY/verify.py\" --plan) || return 1
    if [[ -n \$plan ]]; then
        while IFS= read -r key; do
            [[ \$key =~ ^(kernel|fs|vm)/[a-z_]+(/[a-z_]+)?\$ ]] || return 1
            options+=(\"--prefix=\$key\")
        done <<< \"\$plan\"
        s4m_control /usr/lib/systemd/systemd-sysctl \"\${options[@]}\" \"\$S4H_CONFIG\" || return 1
    fi
    s4h_observe
}

s4h_verify() {
    s4h_ready && [[ -f \$S4H_CONFIG ]] && s4m_trusted \"\$S4H_CONFIG\" &&
        cmp --silent -- \"\$S4H_LIBRARY/kernel.conf\" \"\$S4H_CONFIG\" && s4h_observe
}

s4h_apply() {
    local unit loaded wants resolved temporary
    s4h_assets || return 1
    for unit in \"\$S4H_TIMER\" \"\$S4H_SERVICE\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/hardening.ready || -L \$S4M_STATE/hardening.ready ]]; then
        [[ -f \$S4M_STATE/hardening.ready ]] && s4m_trusted \"\$S4M_STATE/hardening.ready\" || return 1
        rm -f -- \"\$S4M_STATE/hardening.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for unit in \"\$S4H_TIMER\" \"\$S4H_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
            return 1
        fi
    done
    s4h_configure && s4h_kernel || return 1
    for unit in \"\$S4H_SERVICE\" \"\$S4H_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4H_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_systemctl enable \"\$S4H_TIMER\" &&
        s4m_enabled \"\$S4H_TIMER\" || return 1
    wants=\$S4M_SYSTEMD/timers.target.wants
    [[ -d \$wants && -L \$wants/\$S4H_TIMER ]] && s4m_trusted \"\$wants\" || return 1
    resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$S4H_TIMER\") || return 1
    [[ \$resolved == \"\$S4M_SYSTEMD/\$S4H_TIMER\" ]] || return 1
    s4m_sync \"\$S4M_SYSTEMD\" \"\$wants\" \"\$S4M_SYSTEMD/\$S4H_TIMER\" \"\$S4M_SYSTEMD/\$S4H_SERVICE\" || return 1
    s4m_systemctl start \"\$S4H_TIMER\" && s4h_controller || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/hardening-intent.XXXXXX\") || return 1
    if ! s4h_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/hardening.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4h_verify
}

s4h_repair() {
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    # The task owns initial unit/readiness publication. Recurring repair admits
    # config drift without treating changed code/controller identity as healthy.
    s4h_ready && s4h_configure && s4h_kernel || return 75
}
" > "$S4B_STAGE/"lib/hardening/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_repair
" > "$S4B_STAGE/"lib/hardening/repair.sh || return 1
    printf '%s' "\"\"\"Observe required host controls and plan only their drifting sysctl keys.\"\"\"

import os
from pathlib import Path
import re
import stat
import sys


PROC = Path(\"/proc/sys\")
TRUSTED_UID = 0
POLICY = {
    \"kernel/randomize_va_space\": 2,
    \"kernel/kptr_restrict\": 2,
    \"kernel/dmesg_restrict\": 1,
    \"kernel/perf_event_paranoid\": 3,
    \"kernel/yama/ptrace_scope\": 2,
    \"kernel/unprivileged_bpf_disabled\": 1,
    \"kernel/sysrq\": 0,
    \"fs/suid_dumpable\": 0,
    \"fs/protected_symlinks\": 1,
    \"fs/protected_hardlinks\": 1,
    \"fs/protected_fifos\": 2,
    \"fs/protected_regular\": 2,
    \"vm/unprivileged_userfaultfd\": 0,
}


def trusted(path, kind):
    path = Path(path)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise ValueError(\"noncanonical host-control path\")
    current = path
    while True:
        info = current.lstat()
        expected = kind if current == path else stat.S_ISDIR
        if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError(\"untrusted host-control path: \" + str(current))
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
            raise ValueError(\"host-control descriptor changed\")
        data = os.read(descriptor, 65)
        if len(data) > 64 or os.read(descriptor, 1) or not re.fullmatch(rb\"-?[0-9]+\\n?\", data):
            raise ValueError(\"invalid host-control scalar\")
        number = int(data)
        if not -2147483648 <= number <= 2147483647:
            raise ValueError(\"host-control scalar outside native integer range\")
        if signature(os.fstat(descriptor)) != signature(before) or signature(path.lstat()) != signature(before):
            raise ValueError(\"host-control scalar changed\")
        return number
    finally:
        os.close(descriptor)


def complies(key, number):
    if key == \"kernel/perf_event_paranoid\":
        return number >= POLICY[key]
    if key == \"kernel/yama/ptrace_scope\":
        return number in (2, 3)
    return number == POLICY[key]


def plan():
    # Every control is required. Missing/partial/unverifiable namespaces fail
    # before emitting a write plan, including kernels lacking the needed LSM.
    before = {key: value(PROC / key) for key in POLICY}
    after = {key: value(PROC / key) for key in POLICY}
    if before != after:
        raise ValueError(\"host controls changed during observation; retry required\")
    return [key for key, number in before.items() if not complies(key, number)]


def main():
    if sys.argv[1:] not in ([], [\"--plan\"]):
        return 64
    try:
        pending = plan()
        if sys.argv[1:]:
            if pending:
                print(\"\\n\".join(pending))
        elif pending:
            raise ValueError(\"host policy differs: \" + \", \".join(pending))
        return 0
    except (OSError, ValueError) as error:
        print(\"debian13s4 host verification: \" + str(error), file=sys.stderr)
        return 75


if __name__ == \"__main__\":
    sys.exit(main())
" > "$S4B_STAGE/"lib/hardening/verify.py || return 1
    printf '%s' "# Fixed host policy; stronger live ptrace/perf values are admitted by repair.
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
" > "$S4B_STAGE/"lib/hardening/kernel.conf || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/hardening/debian13s4-hardening.service || return 1
    printf '%s' "[Unit]
Description=Reconcile host hardening policy after boot and periodically

[Timer]
OnBootSec=10s
OnUnitInactiveSec=2min
AccuracySec=5s
Unit=debian13s4-hardening.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/hardening/debian13s4-hardening.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_apply
" > "$S4B_STAGE/"lib/tasks/hardening/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Hardening/common.sh
. /usr/local/lib/debian13s4/hardening/common.sh
s4h_verify
" > "$S4B_STAGE/"lib/tasks/hardening/verify.sh || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Observe a supported kernel topology without applying network changes.

The kernel-v1 record deliberately lacks DNS, NTP and DHCP-manager admission. It
cannot be passed straight to the firewall compiler or certify firewall readiness.
\"\"\"

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

IP_BINARY = Path(\"/usr/bin/ip\")
TRUST_ROOT = Path(\"/\")
TRUSTED_UID = 0
QUERY_SECONDS = 3.0
ATTEMPT_SECONDS = 60.0
CLEANUP_SECONDS = 1.0
MAX_BYTES = 1048576
MAX_ITEMS = 4096
MAX_LINKS = 33
NAME = re.compile(r\"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\\Z\")
MAC = re.compile(r\"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\\Z\")
STATES = {\"INCOMPLETE\", \"REACHABLE\", \"STALE\", \"DELAY\", \"PROBE\", \"FAILED\", \"NOARP\", \"PERMANENT\", \"NONE\"}
RESOLVED = {\"REACHABLE\", \"STALE\", \"DELAY\", \"PROBE\", \"PERMANENT\"}
LINK_FLAGS = set(\"UP BROADCAST DEBUG LOOPBACK POINTOPOINT NOTRAILERS NOARP PROMISC ALLMULTI MASTER SLAVE MULTICAST PORTSEL AUTOMEDIA DYNAMIC LOWER_UP DORMANT ECHO NO-CARRIER\".split())
COMMANDS = {
    \"links\": (\"-details\", \"link\", \"show\"),
    \"addresses\": (\"address\", \"show\"),
    \"routes4\": (\"-4\", \"route\", \"show\", \"table\", \"all\"),
    \"routes6\": (\"-6\", \"route\", \"show\", \"table\", \"all\"),
    \"rules4\": (\"-4\", \"rule\", \"show\"),
    \"rules6\": (\"-6\", \"rule\", \"show\"),
    \"neighbors4\": (\"-4\", \"neigh\", \"show\", \"nud\", \"all\"),
    \"neighbors6\": (\"-6\", \"neigh\", \"show\", \"nud\", \"all\"),
    \"proxy4\": (\"-4\", \"neigh\", \"show\", \"proxy\"),
    \"proxy6\": (\"-6\", \"neigh\", \"show\", \"proxy\"),
}
LINK_KEYS = set(\"ifindex ifname flags mtu qdisc operstate group txqlen link_type address broadcast altnames linkmode inet6_addr_gen_mode promiscuity allmulti min_mtu max_mtu num_tx_queues num_rx_queues gso_max_size gso_max_segs tso_max_size tso_max_segs gro_max_size gso_ipv4_max_size gro_ipv4_max_size parentbus parentdev link_index linkinfo\".split())
ADDRESS_KEYS = LINK_KEYS | {\"addr_info\"}
IP_KEYS = set(\"family local prefixlen broadcast scope label valid_life_time preferred_life_time dynamic mngtmpaddr noprefixroute tentative dadfailed deprecated temporary secondary optimistic permanent\".split())
ROUTE_KEYS = set(\"dst dev gateway table type protocol scope metric prefsrc flags pref expires mtu advmss hoplimit features initcwnd initrwnd quickack congctl rtt rttvar rto_min window cwnd ssthresh reordering fastopen_no_cookie\".split())
NEIGHBOR_KEYS = {\"dst\", \"dev\", \"lladdr\", \"state\", \"router\", \"protocol\"}


class Pending(ValueError):
    \"\"\"A complete supported observation could not be established; retry later.\"\"\"


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted_binary(path):
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending(\"noncanonical native path\")
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        kind = stat.S_ISREG if current == path else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending(\"untrusted native binary or ancestry\")
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if not before.st_mode & 0o100:
        raise Pending(\"native binary is not executable\")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if signature(os.fstat(fd)) != signature(before) or signature(path.lstat()) != signature(before):
            raise Pending(\"native descriptor changed\")
    finally:
        os.close(fd)
    return signature(before)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Pending(\"duplicate native JSON field\")
        result[key] = value
    return result


def rows(value, limit=MAX_ITEMS):
    if type(value) is not list or len(value) > limit or any(type(item) is not dict for item in value):
        raise Pending(\"invalid native inventory\")
    return value


def known(item, allowed, required=()):
    if type(item) is not dict or not set(required).issubset(item) or not set(item).issubset(allowed):
        raise Pending(\"missing or unsupported native fields\")


def uint(value, maximum=0xffffffff):
    if type(value) is not int or not 0 <= value <= maximum:
        raise Pending(\"invalid native integer\")
    return value


def address(value, version, unicast=True):
    if type(value) is not str or len(value) > 45 or \"%\" in value:
        raise Pending(\"invalid native address\")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as error:
        raise Pending(\"invalid native address\") from error
    if ip.version != version or str(ip) != value or (version == 6 and ip.ipv4_mapped is not None):
        raise Pending(\"noncanonical or wrong-family address\")
    if unicast and (ip.is_unspecified or ip.is_multicast or ip.is_loopback or (version == 4 and int(ip) == 0xffffffff)):
        raise Pending(\"non-unicast external address\")
    return ip


def ethernet(value):
    if type(value) is not str or MAC.fullmatch(value) is None or value == \"00:00:00:00:00:00\" or int(value[:2], 16) & 1:
        raise Pending(\"invalid native Ethernet identity\")
    return value


def link_type(value):
    # ip -N bypasses ll_type_n2a names and prints bracketed ARPHRD values.
    if type(value) is not str or value not in (\"ether\", \"[1]\", \"loopback\", \"[772]\"):
        raise Pending(\"unsupported native link type\")
    return \"ether\" if value in (\"ether\", \"[1]\") else \"loopback\"


def vlan_protocol(value):
    names = {\"802.1Q\": \"802.1Q\", \"802.1q\": \"802.1Q\", \"[33024]\": \"802.1Q\",
             \"802.1ad\": \"802.1ad\", \"[34984]\": \"802.1ad\"}
    if type(value) is not str or value not in names:
        raise Pending(\"unsupported VLAN protocol\")
    return names[value]


def prefix(value, version):
    if value == \"default\":
        return ipaddress.ip_network(\"0.0.0.0/0\" if version == 4 else \"::/0\")
    if type(value) is not str or len(value) > 49:
        raise Pending(\"invalid native prefix\")
    try:
        result = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise Pending(\"invalid native prefix\") from error
    canonical = str(result) if \"/\" in value else str(result.network_address)
    if result.version != version or canonical != value:
        raise Pending(\"noncanonical native prefix\")
    return result


def table(value):
    aliases = {\"local\": 255, \"main\": 254, \"default\": 253, \"255\": 255, \"254\": 254, \"253\": 253}
    if type(value) is str:
        value = aliases.get(value)
    if type(value) is not int or value not in (253, 254, 255):
        raise Pending(\"unsupported routing table\")
    return value


def route_type(value):
    types = {\"1\": \"unicast\", \"2\": \"local\", \"3\": \"broadcast\", \"5\": \"multicast\",
             \"6\": \"blackhole\", \"7\": \"unreachable\", \"8\": \"prohibit\"}
    if type(value) is not str:
        raise Pending(\"invalid native route type\")
    result = types.get(value, value)
    if result not in types.values():
        raise Pending(\"unsupported native route type\")
    return result


def flags(value):
    if type(value) is not list or any(type(flag) is not str for flag in value) or len(value) != len(set(value)):
        raise Pending(\"invalid native flags\")
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
        raise Pending(\"native command is not an admitted read-only query\")
    return _query_json(COMMANDS[name], deadline,
                       MAX_LINKS if name in (\"links\", \"addresses\") else MAX_ITEMS)


def native_route(destination, interface, deadline):
    if type(destination) is not str or len(destination) > 45 or \"%\" in destination:
        raise Pending(\"invalid route lookup destination\")
    try:
        ip = ipaddress.ip_address(destination)
    except ValueError as error:
        raise Pending(\"invalid route lookup destination\") from error
    address(destination, ip.version)
    arguments = (f\"-{ip.version}\", \"route\", \"get\", destination)
    if ip.version == 6 and ip.is_link_local and interface is None:
        raise Pending(\"link-local route lookup lacks an interface\")
    if interface is not None:
        if ip.version != 6 or not ip.is_link_local or type(interface) is not str or NAME.fullmatch(interface) is None or interface == \"lo\":
            raise Pending(\"invalid scoped route lookup\")
        arguments += (\"oif\", interface)
    return _query_json(arguments, deadline, 1)


class CaptureCleanupFailure(Pending):
    \"\"\"A native capture and its independent owned cleanup failures.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('owned native capture cleanup incomplete')
        self.cause, self.cleanup = cause, cleanup


def close_capture(process, selector):
    \"\"\"Retire both channels before attempting each bounded cleanup step.\"\"\"
    streams = process.stdout, process.stderr
    process.stdout = process.stderr = None
    errors = []
    # An unreaped direct child still reserves its PID even when a descendant
    # holds the pipes. Never signal a group after the root has been reaped.
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            errors.append(error)
        try:
            process.wait(timeout=CLEANUP_SECONDS)
        except BaseException as error:
            errors.append(error)
    if selector is not None:
        try:
            selector.close()
        except BaseException as error:
            errors.append(error)
    for stream in streams:
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
    return tuple(errors)


def _query_json(arguments, deadline, limit):
    if not finite_deadline(deadline):
        raise Pending(\"invalid native deadline\")
    identity = trusted_binary(IP_BINARY)
    end = min(deadline, now() + QUERY_SECONDS)
    if now() >= end:
        raise Pending(\"observation deadline expired\")
    cause, selector = None, None
    process = subprocess.Popen([str(IP_BINARY), \"-j\", \"-N\", *arguments],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={\"PATH\": \"/usr/bin:/usr/sbin\", \"LC_ALL\": \"C\"},
                               close_fds=True, start_new_session=True)
    try:
        buffers = {\"stdout\": bytearray(), \"stderr\": bytearray()}
        selector = selectors.DefaultSelector()
        for label, stream in ((\"stdout\", process.stdout), (\"stderr\", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = end - now()
            if remaining <= 0:
                raise Pending(\"native query timed out\")
            for key, _ in selector.select(remaining):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                if len(buffer) + len(data) > MAX_BYTES:
                    raise Pending(\"native output limit exceeded\")
                buffer.extend(data)
        remaining = end - now()
        if remaining <= 0 or process.wait(timeout=remaining) != 0 or buffers[\"stderr\"]:
            raise Pending(\"native query failed or warned\")
        if trusted_binary(IP_BINARY) != identity:
            raise Pending(\"native binary changed during observation\")
        try:
            value = json.loads(buffers[\"stdout\"].decode(\"utf-8\"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Pending(\"invalid native JSON\") from error
        return rows(value, limit)
    except subprocess.TimeoutExpired as error:
        cause = Pending(\"native query timed out after pipe closure\")
        raise cause from error
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, selector = selector, None
        cleanup = close_capture(process, closing)
        if cleanup:
            if cause is None and len(cleanup) == 1:
                raise cleanup[0]
            raise CaptureCleanupFailure(cause, cleanup) from cause


def normalize(snapshot):
    if type(snapshot) is not dict or set(snapshot) != set(COMMANDS):
        raise Pending(\"incomplete kernel snapshot\")
    count = sum(len(rows(value, MAX_LINKS if name in (\"links\", \"addresses\") else MAX_ITEMS)) for name, value in snapshot.items())
    if count > MAX_ITEMS or snapshot[\"proxy4\"] or snapshot[\"proxy6\"]:
        raise Pending(\"oversized or proxy topology\")
    links, indexes, parents = {}, {}, {}
    for item in snapshot[\"links\"]:
        known(item, LINK_KEYS, (\"ifindex\", \"ifname\", \"flags\", \"link_type\", \"address\"))
        index, name = uint(item[\"ifindex\"]), item[\"ifname\"]
        if index == 0 or index in indexes or type(name) is not str or NAME.fullmatch(name) is None or name in links:
            raise Pending(\"invalid or duplicate link identity\")
        link_flags = flags(item[\"flags\"])
        if not link_flags.issubset(LINK_FLAGS):
            raise Pending(\"unsupported link flags\")
        if name == \"lo\":
            if link_type(item[\"link_type\"]) != \"loopback\" or \"LOOPBACK\" not in link_flags:
                raise Pending(\"invalid loopback identity\")
            mac = None
        else:
            if link_type(item[\"link_type\"]) != \"ether\" or link_flags & {\"LOOPBACK\", \"POINTOPOINT\", \"NOARP\", \"MASTER\", \"SLAVE\"}:
                raise Pending(\"unsupported link arrangement\")
            mac = ethernet(item[\"address\"])
        info = item.get(\"linkinfo\", {})
        known(info, {\"info_kind\", \"info_data\"})
        kind = info.get(\"info_kind\")
        if kind not in (None, \"vlan\") or (\"info_data\" in info and kind != \"vlan\"):
            raise Pending(\"unsupported virtual link\")
        vlan_identity = None
        if kind == \"vlan\":
            if name == \"lo\" or \"link_index\" not in item:
                raise Pending(\"missing VLAN parent\")
            vlan = info.get(\"info_data\")
            known(vlan, {\"protocol\", \"id\", \"flags\"}, (\"id\", \"protocol\"))
            vlan_flags = flags(vlan.get(\"flags\", []))
            if not 1 <= uint(vlan[\"id\"], 4094) or not vlan_flags.issubset({\"REORDER_HDR\"}):
                raise Pending(\"unsupported VLAN identity\")
            vlan_identity = {\"id\": vlan[\"id\"], \"protocol\": vlan_protocol(vlan[\"protocol\"]),
                             \"flags\": sorted(vlan_flags)}
            parents[name] = uint(item[\"link_index\"])
        elif \"link_index\" in item:
            raise Pending(\"unidentified parent link\")
        links[name] = {\"name\": name, \"index\": index, \"mac\": mac,
                       \"up\": {\"UP\", \"LOWER_UP\"}.issubset(link_flags), \"kind\": \"ether\",
                       \"flags\": sorted(link_flags), \"parent\": parents.get(name), \"vlan\": vlan_identity,
                       \"prefixes\": set(), \"gateways\": {}, \"neighbors\": {}}
        indexes[index] = name
    if \"lo\" not in links:
        raise Pending(\"missing loopback inventory\")
    for name in parents:
        visited = {name}
        current = name
        while current in parents:
            current = indexes.get(parents[current])
            if current is None or current == \"lo\" or current in visited or len(visited) > 4:
                raise Pending(\"unresolved or cyclic VLAN parent\")
            visited.add(current)
    seen = set()
    ipv6_present = False
    for item in snapshot[\"addresses\"]:
        known(item, ADDRESS_KEYS, (\"ifindex\", \"ifname\", \"addr_info\", \"address\", \"link_type\", \"flags\"))
        name = item[\"ifname\"]
        if type(name) is not str or name not in links or name in seen or uint(item[\"ifindex\"]) != links[name][\"index\"]:
            raise Pending(\"address/link inventory disagreement\")
        if item[\"address\"] != (\"00:00:00:00:00:00\" if name == \"lo\" else links[name][\"mac\"]):
            raise Pending(\"address/link MAC disagreement\")
        if link_type(item[\"link_type\"]) != (\"loopback\" if name == \"lo\" else \"ether\"):
            raise Pending(\"address/link kind disagreement\")
        if sorted(flags(item[\"flags\"])) != links[name][\"flags\"]:
            raise Pending(\"address/link flags disagreement\")
        seen.add(name)
        for entry in rows(item[\"addr_info\"]):
            count += 1
            known(entry, IP_KEYS, (\"family\", \"local\", \"prefixlen\"))
            family = entry[\"family\"]
            if family not in (\"inet\", \"inet6\"):
                raise Pending(\"unsupported address family\")
            version = 4 if family == \"inet\" else 6
            ip = address(entry[\"local\"], version, name != \"lo\")
            if name == \"lo\" and not ip.is_loopback:
                raise Pending(\"external address on loopback\")
            length = uint(entry[\"prefixlen\"], ip.max_prefixlen)
            if length == 0:
                raise Pending(\"default assigned prefix\")
            ipv6_present |= version == 6
            # An assigned mask (especially noprefixroute) is not proof of a
            # connected FIB route. Keep only this host identity here; direct
            # native routes below supply admitted on-link networks.
            links[name][\"prefixes\"].add(ipaddress.ip_network(str(ip)))
    if seen != set(links):
        raise Pending(\"partial address inventory\")
    for version in (4, 6):
        rule_set = set()
        for item in snapshot[f\"rules{version}\"]:
            known(item, {\"priority\", \"src\", \"dst\", \"table\"}, (\"priority\", \"src\", \"table\"))
            priority, table_id = uint(item[\"priority\"]), table(item[\"table\"])
            expected = {0: 255, 32766: 254, 32767: 253}
            if item[\"src\"] != \"all\" or item.get(\"dst\", \"all\") != \"all\" or expected.get(priority) != table_id or priority in rule_set:
                raise Pending(\"unsupported routing policy\")
            rule_set.add(priority)
        absent6 = version == 6 and not ipv6_present and not any(snapshot[name] for name in (\"routes6\", \"rules6\", \"neighbors6\"))
        if not absent6 and not {0, 32766}.issubset(rule_set):
            raise Pending(\"incomplete routing policy\")
        for item in snapshot[f\"routes{version}\"]:
            known(item, ROUTE_KEYS, (\"dst\",))
            destination = prefix(item[\"dst\"], version)
            table_id = table(item.get(\"table\", 254))
            route_flags = flags(item.get(\"flags\", []))
            if not route_flags.issubset({\"onlink\", \"linkdown\"}):
                raise Pending(\"unsupported route flags\")
            kind = route_type(item.get(\"type\", \"unicast\"))
            if kind in (\"unreachable\", \"blackhole\", \"prohibit\"):
                if \"gateway\" in item:
                    raise Pending(\"gateway on negative route\")
                continue
            name = item.get(\"dev\")
            if type(name) is not str or name not in links:
                raise Pending(\"route without observed link\")
            if kind in (\"local\", \"broadcast\", \"multicast\"):
                if table_id != 255 or \"gateway\" in item:
                    raise Pending(\"unexpected local route\")
                continue
            if kind != \"unicast\" or table_id == 255 or name == \"lo\":
                raise Pending(\"unsupported route type\")
            if \"gateway\" in item:
                gateway = address(item[\"gateway\"], version)
                links[name][\"gateways\"][gateway] = None
                if \"onlink\" in route_flags:
                    links[name][\"prefixes\"].add(ipaddress.ip_network(str(gateway)))
            else:
                if destination.prefixlen == 0:
                    raise Pending(\"ambiguous direct default route\")
                links[name][\"prefixes\"].add(destination)
        for item in snapshot[f\"neighbors{version}\"]:
            known(item, NEIGHBOR_KEYS, (\"dst\", \"dev\"))
            name = item[\"dev\"]
            if type(name) is not str or name not in links:
                raise Pending(\"neighbor without observed Ethernet link\")
            states = item.get(\"state\", [\"NONE\"])
            if type(states) is not list or len(states) != 1 or type(states[0]) is not str or states[0] not in STATES:
                raise Pending(\"unsupported neighbor state\")
            state = states[0]
            router = \"router\" in item
            if router and item[\"router\"] is not None and item[\"router\"] is not True:
                raise Pending(\"invalid native router flag\")
            if state == \"NOARP\" and not router:
                # Synthetic NOARP cache entries (also present on loopback)
                # cannot admit SSH or resolve a gateway.
                address(item[\"dst\"], version, False)
                continue
            if name == \"lo\":
                raise Pending(\"unexpected resolved or router neighbor on loopback\")
            ip = address(item[\"dst\"], version)
            if state in RESOLVED and \"lladdr\" not in item:
                raise Pending(\"resolved neighbor lacks Ethernet identity\")
            mac = ethernet(item[\"lladdr\"]) if state in RESOLVED else None
            if ip in links[name][\"neighbors\"] and links[name][\"neighbors\"][ip] != (mac, state):
                raise Pending(\"conflicting neighbor identity\")
            links[name][\"neighbors\"][ip] = (mac, state)
            if router:
                links[name][\"gateways\"].setdefault(ip, None)
    if count > MAX_ITEMS:
        raise Pending(\"aggregate kernel inventory too large\")
    result = []
    for name, item in sorted(links.items()):
        if name == \"lo\":
            continue
        for ip in set(item[\"gateways\"]) | set(item[\"neighbors\"]):
            if not any(ip.version == net.version and ip in net for net in item[\"prefixes\"]):
                raise Pending(\"off-link gateway or neighbor; no inferred prefix\")
        for ip in item[\"gateways\"]:
            item[\"gateways\"][ip] = item[\"neighbors\"].get(ip, (None, \"NONE\"))[0]
        item[\"prefixes\"] = sorted(map(str, item[\"prefixes\"]))
        item[\"gateways\"] = [{\"address\": str(ip), \"mac\": mac} for ip, mac in sorted(item[\"gateways\"].items(), key=lambda pair: str(pair[0]))]
        item[\"neighbors\"] = [{\"address\": str(ip), \"mac\": mac, \"state\": state} for ip, (mac, state) in sorted(item[\"neighbors\"].items(), key=lambda pair: str(pair[0]))]
        result.append(item)
    return result


def namespace():
    value = os.readlink(\"/proc/self/ns/net\")
    match = re.fullmatch(r\"net:\\[([0-9]+)\\]\", value)
    if match is None:
        raise Pending(\"unverifiable process network namespace\")
    return int(match[1])


def observe(query=native_query, scope=namespace, deadline=None):
    started = now()
    if deadline is not None and (not finite_deadline(deadline) or deadline <= started):
        raise Pending(\"invalid or expired inherited observation deadline\")
    deadline = min(deadline, started + ATTEMPT_SECONDS) if deadline is not None else started + ATTEMPT_SECONDS
    identity = scope()
    first = normalize({name: query(name, deadline) for name in COMMANDS})
    second = normalize({name: query(name, deadline) for name in COMMANDS})
    if first != second or scope() != identity or now() >= deadline:
        raise Pending(\"kernel topology changed or observation expired\")
    return {\"schema\": \"debian13s4-kernel-1\", \"namespace\": identity, \"interfaces\": second}


def main():
    if len(sys.argv) != 1:
        return 64
    try:
        result = json.dumps(observe(), sort_keys=True, separators=(\",\", \":\")) + \"\\n\"
        if len(result.encode()) > MAX_BYTES:
            raise Pending(\"normalized observation too large\")
        sys.stdout.write(result)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f\"debian13s4 kernel observation pending: {error}\", file=sys.stderr)
        return 75


if __name__ == \"__main__\":
    raise SystemExit(main())
" > "$S4B_STAGE/"lib/firewall/kernel.py || return 1
    printf '%s' "#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh

S4S_LIBRARY=/usr/local/lib/debian13s4/ssh
S4S_CONFIG=/etc/ssh/debian13s4-admin.conf
S4S_NETWORKS=/etc/ssh/debian13s4-admin-networks.json
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
    local descriptor=\$S4M_REPAIR_FD
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s \"\${S4S_POLICY_SECONDS}s\" \\
        env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \\
        /usr/bin/python3 -I -B \"\$S4S_LIBRARY/policy.py\" \"\$@\"
)

s4s_assets() {
    local name
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for name in \"\${S4S_FILES[@]}\"; do
        [[ -f \$S4S_LIBRARY/\$name ]] && s4m_trusted \"\$S4S_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4S_LIBRARY/repair.sh && -f \$S4M_LIBRARY/common.sh &&
        -f \$S4S_LIBRARY/../firewall/kernel.py ]] &&
        s4m_trusted \"\$S4M_LIBRARY/common.sh\" &&
        s4m_trusted \"\${S4S_LIBRARY%/*}/firewall/kernel.py\"
}

s4s_identity() {
    local name digest
    for name in \"\${S4S_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4S_LIBRARY/\$name\") || return 1
        printf '%s ssh/%s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py; do
        digest=\$(sha256sum -- \"\${S4S_LIBRARY%/*}/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
}

s4s_vendor_paths() {
    local unit target owner
    s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for unit in \"\${S4S_VENDOR[@]}\"; do
        target=\$S4M_SYSTEMD/\$unit
        if [[ -e \$target || -L \$target ]]; then
            # Only an existing root-owned mask is accepted at the local path.
            # A custom unit/alias is not silently replaced or guessed away.
            [[ -L \$target ]] || return 1
            owner=\$(stat --format='%u' -- \"\$target\") || return 1
            [[ \$owner == 0 && \$(readlink -- \"\$target\") == /dev/null ]] || return 1
        fi
    done
}

s4s_mask_vendor() {
    local unit loaded
    s4s_vendor_paths || return 1
    for unit in \"\${S4S_VENDOR[@]}\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        case \$loaded in
            loaded) s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1 ;;
            masked|not-found) ;;
            *) return 1 ;;
        esac
        s4m_systemctl mask \"\$unit\" || return 1
    done
    s4m_systemctl daemon-reload && s4m_sync \"\$S4M_SYSTEMD\" || return 1
    s4s_vendor_masked
}

s4s_vendor_masked() {
    local unit
    s4s_vendor_paths || return 1
    for unit in \"\${S4S_VENDOR[@]}\"; do
        [[ -L \$S4M_SYSTEMD/\$unit ]] &&
            s4m_property \"\$unit\" LoadState masked &&
            s4m_property \"\$unit\" ActiveState inactive || return 1
    done
}

s4s_packages() {
    s4m_load_packages || return 1
    S4P_PACKAGES=(openssh-server iproute2)
}

s4s_prepare_config() {
    local temporary directory=\${S4S_CONFIG%/*} mode=\${1:-install}
    [[ \$# -le 1 && ( \$mode == install || \$mode == repair ) ]] || return 1
    s4m_trusted \"\${directory%/*}\" || return 1
    if [[ -e \$directory || -L \$directory ]]; then
        [[ -d \$directory ]] && s4m_trusted \"\$directory\" || return 1
    else
        mkdir -m 0755 -- \"\$directory\" || return 1
    fi
    temporary=\$(mktemp -- \"\$S4M_STATE/ssh-policy.XXXXXX\") || return 1
    if ! s4s_policy --plan > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\"; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    # Compare the prospective bytes, not just the current disk file. Stop an
    # unknown/stale instance BEFORE changing its startup configuration.
    if [[ \$mode == repair ]] && ! s4s_loaded \"\$temporary\" && ! s4s_stop; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    if ! s4m_atomic \"\$S4S_CONFIG\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
}

s4s_units() {
    local unit
    for unit in \"\$S4S_SERVER\" \"\$S4S_SERVICE\" \"\$S4S_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" &&
            cmp --silent -- \"\$S4S_LIBRARY/\$unit\" \"\$S4M_SYSTEMD/\$unit\" || return 1
        s4m_property \"\$unit\" FragmentPath \"\$S4M_SYSTEMD/\$unit\" &&
            s4m_property \"\$unit\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4S_SERVER\" && s4m_enabled \"\$S4S_TIMER\" &&
        s4m_property \"\$S4S_TIMER\" ActiveState active
}

s4s_observe_live() {
    local pid
    s4s_vendor_masked && s4m_property \"\$S4S_SERVER\" ActiveState active || return 1
    pid=\$(s4m_systemctl show --property=MainPID --value \"\$S4S_SERVER\") || return 1
    [[ \$pid =~ ^[1-9][0-9]{0,9}\$ ]] || return 1
    s4s_policy --live \"\$pid\"
}

s4s_startup_inputs() {
    local config=\${1:-\$S4S_CONFIG} name path digest
    s4s_identity || return 1
    for name in configuration deployment_configuration host_key executable; do
        case \$name in
            configuration) path=\$config ;;
            deployment_configuration) path=\$S4S_NETWORKS ;;
            host_key) path=\$S4S_HOST_KEY ;;
            executable) path=\$S4S_SSHD ;;
        esac
        [[ -f \$path ]] && s4m_trusted \"\$path\" || return 1
        digest=\$(sha256sum -- \"\$path\") || return 1
        digest=\${digest%% *}
        [[ \$digest =~ ^[0-9a-f]{64}\$ ]] || return 1
        printf '%s %s\\n' \"\$digest\" \"\$name\" || return 1
    done
    # OpenSSH may read the optional public companion at startup as well.
    path=\$S4S_HOST_KEY.pub
    if [[ -e \$path || -L \$path ]]; then
        [[ -f \$path ]] && s4m_trusted \"\$path\" || return 1
        digest=\$(sha256sum -- \"\$path\") || return 1
        digest=\${digest%% *}
        [[ \$digest =~ ^[0-9a-f]{64}\$ ]] || return 1
        printf '%s host_public_key\\n' \"\$digest\"
    else
        printf 'absent host_public_key\\n'
    fi
}

s4s_running_generation() {
    local rows key value active='' pid='' invocation=''
    rows=\$(s4m_systemctl show --property=ActiveState --property=MainPID \\
        --property=InvocationID \"\$S4S_SERVER\") || return 1
    [[ \${#rows} -le 512 ]] || return 1
    while IFS='=' read -r key value; do
        case \$key in
            ActiveState) [[ -z \$active && \$value == active ]] || return 1; active=\$value ;;
            MainPID)
                [[ -z \$pid && \$value =~ ^[1-9][0-9]{0,9}\$ ]] &&
                    (( 10#\$value <= 2147483647 )) || return 1
                pid=\$value ;;
            InvocationID)
                [[ -z \$invocation && \$value =~ ^[0-9a-f]{32}\$ &&
                    \$value != 00000000000000000000000000000000 ]] || return 1
                invocation=\$value ;;
            *) return 1 ;;
        esac
    done <<< \"\$rows\"
    [[ \$active == active && -n \$pid && -n \$invocation ]] || return 1
    printf 'instance %s %s\\n' \"\$pid\" \"\$invocation\" || return 1
    s4s_startup_inputs \"\${1:-\$S4S_CONFIG}\"
}

s4s_loaded() {
    local marker=\$S4M_STATE/ssh.loaded expected actual mode size links
    [[ -f \$marker ]] && s4m_trusted \"\$marker\" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- \"\$marker\") || return 1
    [[ \$mode == 600 && \$links == 1 && \$size =~ ^[1-9][0-9]{0,3}\$ ]] &&
        (( 10#\$size <= 4096 )) || return 1
    expected=\$(s4s_running_generation \"\${1:-\$S4S_CONFIG}\") &&
        actual=\$(cat -- \"\$marker\") || return 1
    [[ \$expected == \"\$actual\" ]] || return 1
    # Retain only the complete generation computed by this successful check.
    S4S_LOADED_GENERATION=\$expected
}

s4s_live() {
    local before
    s4s_loaded || return 1
    before=\$S4S_LOADED_GENERATION
    s4s_observe_live && s4s_loaded && [[ \$before == \"\$S4S_LOADED_GENERATION\" ]]
}

s4s_start() {
    local before after generation temporary
    # A disk check is not a loaded-state acknowledgment. Start only from a
    # confirmed inactive/no-main-PID state, with unchanged startup inputs.
    s4m_property \"\$S4S_SERVER\" ActiveState inactive &&
        s4m_property \"\$S4S_SERVER\" MainPID 0 || return 1
    before=\$(s4s_startup_inputs) && s4m_systemctl start \"\$S4S_SERVER\" &&
        s4s_observe_live && after=\$(s4s_startup_inputs) && [[ \$before == \"\$after\" ]] || return 1
    generation=\$(s4s_running_generation) || return 1
    [[ \${generation#*\$'\\n'} == \"\$before\" ]] || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/ssh-loaded.XXXXXX\") || return 1
    if ! printf '%s\\n' \"\$generation\" > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/ssh.loaded\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4s_loaded
}

s4s_ready() {
    local expected actual
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/ssh.ready ]] && s4m_trusted \"\$S4M_STATE/ssh.ready\" || return 1
    s4s_assets && s4s_units || return 1
    expected=\$(s4s_identity) && actual=\$(cat -- \"\$S4M_STATE/ssh.ready\") || return 1
    [[ \$expected == \"\$actual\" ]]
}

s4s_verify() {
    s4s_ready && s4s_packages && s4p_verify && s4s_live
}

s4s_stop() {
    local marker=\$S4M_STATE/ssh.loaded
    s4m_systemctl stop \"\$S4S_SERVER\" && s4m_property \"\$S4S_SERVER\" ActiveState inactive &&
        s4m_property \"\$S4S_SERVER\" MainPID 0 || return 1
    if [[ -e \$marker || -L \$marker ]]; then
        [[ -f \$marker ]] && s4m_trusted \"\$marker\" && rm -f -- \"\$marker\" || return 1
        s4m_sync \"\$S4M_STATE\" || return 1
    fi
}

s4s_publish() {
    local unit wants resolved temporary
    for unit in \"\$S4S_SERVER\" \"\$S4S_SERVICE\" \"\$S4S_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$unit\" \"\$S4S_LIBRARY/\$unit\" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for unit in \"\$S4S_SERVER\" \"\$S4S_TIMER\"; do
        s4m_systemctl enable \"\$unit\" && s4m_enabled \"\$unit\" || return 1
        wants=\$S4M_SYSTEMD/multi-user.target.wants
        [[ \$unit != \"\$S4S_TIMER\" ]] || wants=\$S4M_SYSTEMD/timers.target.wants
        [[ -d \$wants && -L \$wants/\$unit ]] && s4m_trusted \"\$wants\" || return 1
        resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$unit\") || return 1
        [[ \$resolved == \"\$S4M_SYSTEMD/\$unit\" ]] || return 1
        s4m_sync \"\$wants\" \"\$S4M_SYSTEMD\" \"\$S4M_SYSTEMD/\$unit\" || return 1
    done
    s4s_start && s4m_systemctl start \"\$S4S_TIMER\" &&
        s4s_units && s4s_live || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/ssh-intent.XXXXXX\") || return 1
    if ! s4s_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/ssh.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" || return 1
    s4s_verify
}

s4s_apply() {
    local unit loaded
    s4s_assets && s4s_vendor_paths || return 1
    for unit in \"\$S4S_SERVER\" \"\$S4S_SERVICE\" \"\$S4S_TIMER\"; do
        if [[ -e \$S4M_SYSTEMD/\$unit || -L \$S4M_SYSTEMD/\$unit ]]; then
            [[ -f \$S4M_SYSTEMD/\$unit ]] && s4m_trusted \"\$S4M_SYSTEMD/\$unit\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/ssh.ready || -L \$S4M_STATE/ssh.ready ]]; then
        [[ -f \$S4M_STATE/ssh.ready ]] && s4m_trusted \"\$S4M_STATE/ssh.ready\" || return 1
        rm -f -- \"\$S4M_STATE/ssh.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    # Admit credentials and current admin assignment before retiring vendor SSH.
    # The config is data only until its real syntax/effective checks succeed.
    s4s_prepare_config || return 1
    for unit in \"\$S4S_TIMER\" \"\$S4S_SERVICE\" \"\$S4S_SERVER\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$unit\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$unit\" && s4m_property \"\$unit\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then
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
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
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
" > "$S4B_STAGE/"lib/ssh/common.sh || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Derive and check LAN-bound SSH for one existing local administrator.

This does not create credentials, configure an address or attest client locality.
Private deployment configuration supplies the exact allowed admin prefixes.
No default network, address assignment or domain is selected by this module.
Native delivery and the local account database belong to the trusted-base profile.
\"\"\"

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
ADMIN_NETWORKS = ETC / 'ssh/debian13s4-admin-networks.json'
MAX_NETWORK_BYTES = 4096
MAX_BYTES = 262144
ATTEMPT_SECONDS = 60
NAME = re.compile(r'[a-z_][a-z0-9_-]{0,31}\\Z')
ACCOUNT_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}\\Z')


def fence(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('SSH observation window expired')


def trusted_read(path, owners=(0,), private=False, limit=MAX_BYTES):
    \"\"\"Read a bounded unique leaf through a checked no-follow descriptor.\"\"\"
    if type(limit) is not int or not 0 < limit <= MAX_BYTES:
        raise Pending('invalid SSH input byte bound')
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
    if before.st_nlink != 1 or before.st_size > limit or private and before.st_mode & 0o077:
        raise Pending('nonunique, oversized or nonprivate SSH input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before):
            raise Pending('SSH input descriptor differs')
        data = bytearray()
        while True:
            part = os.read(descriptor, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                raise Pending('SSH input byte bound exceeded')
        if (KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(data) != before.st_size):
            raise Pending('SSH input changed during read')
    finally:
        # Linux retires the number even when close reports an error: never retry.
        os.close(descriptor)
    return bytes(data), {'path': str(path), 'identity': list(KERNEL.signature(before)),
                         'sha256': hashlib.sha256(data).hexdigest()}


def checked_networks(value):
    fields = {'schema', 'admin_ipv4', 'admin_ipv6'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported SSH deployment configuration schema')
    for field, version, length in (('admin_ipv4', 4, 24), ('admin_ipv6', 6, 64)):
        text = value[field]
        if field == 'admin_ipv6' and text is None:
            continue
        if type(text) is not str or len(text) > 49:
            raise Pending('untyped or oversized SSH admin prefix')
        prefix = ipaddress.ip_network(text, strict=True)
        # These are protocol classification ranges, not deployment defaults.
        private = (any(prefix.subnet_of(ipaddress.ip_network(block)) for block in
                       ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')) if version == 4 and prefix.version == 4
                   else prefix.version == 6 and prefix.subnet_of(ipaddress.ip_network('fd00::/8')))
        if prefix.version != version or prefix.prefixlen != length or str(prefix) != text or not private:
            raise Pending('unsupported canonical private SSH admin prefix')
    return value


def deployment_networks():
    raw, source = trusted_read(ADMIN_NETWORKS, (TRUSTED_UID,), True, MAX_NETWORK_BYTES)
    if stat.S_IMODE(source['identity'][2]) != 0o600:
        raise Pending('SSH deployment configuration is not mode600')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite SSH deployment configuration')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Pending('invalid SSH deployment configuration JSON') from error
    value = checked_networks(value)
    if raw != (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\\n').encode('ascii'):
        raise Pending('SSH deployment configuration is not canonical JSON plus LF')
    return {'configuration': value, 'source': source}


def allowed_users(admin, settings):
    value = checked_networks(settings['configuration'])
    prefixes = ['127.0.0.1/32', '::1/128', value['admin_ipv4']]
    if value['admin_ipv6'] is not None:
        prefixes.append(value['admin_ipv6'])
    return ' '.join(admin['name'] + '@' + prefix for prefix in prefixes)


def database(raw, width):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('unsupported local account encoding') from error
    if not text.endswith('\\n') or '\\x00' in text or len(text.splitlines()) > 4096:
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
    if not text.endswith('\\n') or '\\x00' in text or len(text.splitlines()) > 64:
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
    if len(shadows) != 1 or not shadows[0][1].startswith(('\$y\$', '\$6\$')) or len(shadows[0][1]) < 32:
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


def network(snapshot, settings, observed=0):
    value = checked_networks(settings['configuration'])
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
            text = value['admin_ipv4' if version == 4 else 'admin_ipv6']
            if text is None:
                continue
            prefix = ipaddress.ip_network(text)
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


def configuration(admin, binding, settings):
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
        f'AuthorizedKeysFile {admin[\"key_file\"]}',
        f'AllowUsers {allowed_users(admin, settings)}']
    for value in [*binding['loopback'], *binding['listeners']]:
        lines.append(f'ListenAddress [{value}]:22' if ':' in value else f'ListenAddress {value}:22')
    return ('\\n'.join(lines) + '\\n').encode('ascii')


def prepare(query=KERNEL.native_query, account=administrator, scope=KERNEL.namespace, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid SSH preparation deadline')
    end = min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = scope()
    if not KERNEL.uint(namespace, (1 << 64) - 1):
        raise Pending('invalid SSH namespace')
    settings = deployment_networks()
    fence(end)
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
        binding, expiry = network(raw, settings, observed)
        end = min(end, expiry)
        fence(end)
        records.append({'raw': raw, 'binding': binding})
    last_admin = checked_admin(copied(account()))
    if first_admin != last_admin or records[0] != records[1] or deployment_networks() != settings:
        raise Pending('SSH administrator or network deliveries changed')
    payload = configuration(last_admin, records[1]['binding'], settings)
    if len(payload) > MAX_BYTES:
        raise Pending('SSH configuration exceeds byte bound')
    final_namespace = scope()
    if not KERNEL.uint(final_namespace, (1 << 64) - 1) or final_namespace != namespace:
        raise Pending('SSH namespace changed')
    fence(end)
    return {'namespace': namespace, 'admin': last_admin, 'binding': records[1]['binding'],
            'configuration': payload, 'networks': settings, 'deadline': end}


def capture(binary, arguments, deadline):
    fence(deadline)
    if type(arguments) is not tuple or any(type(argument) is not str for argument in arguments) or not (
        binary == SSHD and arguments in (('-t', '-f', str(CONFIG)), ('-T', '-f', str(CONFIG))) or
        binary == SS and arguments == ('-H', '-n', '-l', '-t', '-p', 'sport = :22')):
        raise Pending('unapproved SSH native read')
    identity = KERNEL.trusted_binary(binary)
    end = min(deadline, KERNEL.now() + KERNEL.QUERY_SECONDS)
    fence(end)
    cause, selector = None, None
    process = subprocess.Popen([str(binary), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    try:
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        selector = selectors.DefaultSelector()
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
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, selector = selector, None
        cleanup = KERNEL.close_capture(process, closing)
        if cleanup:
            if cause is None and len(cleanup) == 1:
                raise cleanup[0]
            raise KERNEL.CaptureCleanupFailure(cause, cleanup) from cause


def effective(raw, plan):
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('invalid effective sshd encoding') from error
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition(' ')
        if not separator or not re.fullmatch('[a-z0-9]+', key) or not value or '\\x00' in value:
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
    users = allowed_users(plan['admin'], plan['networks'])
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
        owner = re.fullmatch(r'users:\\(\\(\"sshd\",pid=([1-9][0-9]*),fd=([0-9]+)\\)\\)', parts[5])
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
    if (not KERNEL.uint(namespace, (1 << 64) - 1) or administrator() != plan['admin'] or
        deployment_networks() != plan['networks'] or namespace != plan['namespace']):
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
" > "$S4B_STAGE/"lib/ssh/policy.py || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_repair
" > "$S4B_STAGE/"lib/ssh/repair.sh || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/ssh/debian13s4-admin-ssh.service || return 1
    printf '%s' "[Unit]
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
" > "$S4B_STAGE/"lib/ssh/debian13s4-ssh.service || return 1
    printf '%s' "[Unit]
Description=Reconcile admin SSH after boot and periodically

[Timer]
OnBootSec=15s
OnUnitInactiveSec=1min
AccuracySec=5s
Unit=debian13s4-ssh.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/ssh/debian13s4-ssh.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_apply
" > "$S4B_STAGE/"lib/tasks/ssh/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=SSH/common.sh
. /usr/local/lib/debian13s4/ssh/common.sh
s4s_verify
" > "$S4B_STAGE/"lib/tasks/ssh/verify.sh || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare local PostgreSQL intentions; never install, connect or execute SQL.

Only mk8.dns and mk8.email use this PostgreSQL profile. The other two
applications keep their separate storage contracts. Inputs are explicit private
configuration, not site defaults or authenticated deployment authority.
The ordered SQL requires a NEW cluster: it does not adopt existing objects,
make all steps atomic, supply migrations or authorize retry after an error.
\"\"\"

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_kernel',
    Path(__file__).resolve().parents[1] / 'firewall/kernel.py')
if not SPEC.origin or not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_kernel',
        Path(__file__).resolve().parents[1] / 'Firewall/kernel.py')
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
INPUT = Path('/etc/debian13s4/postgresql.json')
PASSWD = Path('/etc/passwd')
CONFIG_DIRECTORY = '/etc/debian13s4-postgresql'
DATA_DIRECTORY = '/var/lib/debian13s4-postgresql'
SOCKET_DIRECTORY = '/run/debian13s4-postgresql'
APPLICATIONS = ('mk8.dns', 'mk8.email')
IDENTIFIER = re.compile(r'[a-z][a-z0-9_]{0,30}\\Z')
MAX_INPUT = 4096
MAX_ACCOUNTS = 262144
MAX_OUTPUT = 262145
ATTEMPT_SECONDS = 10


class CleanupFailure(Pending):
    \"\"\"A protected read refused and its retired descriptor also failed to close.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('protected PostgreSQL read and descriptor cleanup incomplete')
        self.cause, self.cleanup = cause, cleanup


def close_descriptor(descriptor, cause):
    \"\"\"Close one already-retired descriptor without replacing a read refusal.\"\"\"
    try:
        os.close(descriptor)
    except BaseException as error:
        if cause is None:
            raise
        raise CleanupFailure(cause, (error,)) from cause


def fence(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('PostgreSQL preparation window expired')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\\n').encode('ascii')


def read_protected(path, limit, private, end):
    fence(end)
    if (type(path) is not type(INPUT) or not path.is_absolute() or
        os.path.normpath(str(path)) != str(path)):
        raise Pending('noncanonical PostgreSQL input path')
    path.relative_to(TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        kind = stat.S_ISREG if current == path else stat.S_ISDIR
        if not kind(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('unprotected PostgreSQL input or ancestry')
        if current == TRUST_ROOT:
            break
        current = current.parent
    before = path.lstat()
    if (before.st_nlink != 1 or before.st_size > limit or
        private and stat.S_IMODE(before.st_mode) != 0o600):
        raise Pending('nonunique, oversized or nonprivate PostgreSQL input')
    cause = None
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before):
            raise Pending('PostgreSQL input descriptor differs')
        data = bytearray()
        while True:
            fence(end)
            part = os.read(descriptor, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
            if len(data) > limit:
                raise Pending('PostgreSQL input exceeds its byte bound')
        if (KERNEL.signature(os.fstat(descriptor)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(data) != before.st_size):
            raise Pending('PostgreSQL input changed during read')
    except BaseException as error:
        cause = error
        raise
    finally:
        # One close only. Linux may retire/reuse the number before an error.
        closing, descriptor = descriptor, None
        close_descriptor(closing, cause)
    fence(end)
    raw = bytes(data)
    return raw, {'path': str(path), 'identity': list(KERNEL.signature(before)),
                 'sha256': hashlib.sha256(raw).hexdigest()}


def identifier(value):
    if (type(value) is not str or IDENTIFIER.fullmatch(value) is None or
        value.startswith('pg_') or value in {'postgres', 'template0', 'template1', 'root'}):
        raise Pending('unsupported PostgreSQL role or database identifier')
    return value


def checked(value):
    fields = {'schema', 'applications', 'max_connections', 'shared_buffers_mb'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported PostgreSQL input schema')
    for field, minimum, maximum in (('max_connections', 16, 512), ('shared_buffers_mb', 16, 16384)):
        if type(value[field]) is not int or not minimum <= value[field] <= maximum:
            raise Pending('unsupported explicit PostgreSQL capacity')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    roles, databases, total = set(), set(), 0
    for app in APPLICATIONS:
        item = value['applications'][app]
        names = {'role', 'database', 'connection_limit'}
        KERNEL.known(item, names, names)
        role, database = identifier(item['role']), identifier(item['database'])
        limit = item['connection_limit']
        if type(limit) is not int or not 1 <= limit <= 64:
            raise Pending('unsupported PostgreSQL application connection limit')
        if role in roles or database in databases:
            raise Pending('shared PostgreSQL application identity')
        roles.add(role); databases.add(database); total += limit
    if total + 8 > value['max_connections']:
        raise Pending('PostgreSQL application limits consume reserved connection capacity')
    # A plain new private object; callers cannot rewrite admitted input later.
    return json.loads(canonical(value))


def configuration(end):
    raw, source = read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite PostgreSQL input')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL configuration JSON') from error
    value = checked(value)
    if raw != canonical(value):
        raise Pending('PostgreSQL input is not canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def accounts(raw, settings):
    settings = checked(settings)
    try:
        text = raw.decode('ascii')
    except UnicodeError as error:
        raise Pending('unsupported local account encoding') from error
    if (not text.endswith('\\n') or
        any(character != '\\n' and not 32 <= ord(character) <= 126 for character in text)):
        raise Pending('unsupported local account inventory')
    # passwd records are delimited ONLY by LF. Other ASCII control bytes
    # cannot manufacture apparent accounts inside a malformed LF record.
    records = text[:-1].split('\\n')
    if len(records) > 4096:
        raise Pending('unsupported local account inventory')
    inventory, uids = {}, set()
    for line in records:
        fields = line.split(':')
        if (len(fields) != 7 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in inventory or any(re.fullmatch(r'0|[1-9][0-9]{0,9}', fields[i]) is None for i in (2, 3))):
            raise Pending('malformed or duplicate local account')
        uid, gid = (KERNEL.uint(int(fields[i]), 0x7fffffff) for i in (2, 3))
        if uid in uids:
            raise Pending('ambiguous local peer account UID')
        uids.add(uid); inventory[fields[0]] = (fields, uid, gid)
    selected = {}
    for app in APPLICATIONS:
        role = settings['applications'][app]['role']
        if role not in inventory:
            raise Pending('PostgreSQL application service account is missing')
        fields, uid, gid = inventory[role]
        if (not 100 <= uid <= 999 or gid == 0 or fields[1] not in ('x', '!', '*') or
            fields[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false')):
            raise Pending('unsupported PostgreSQL local service account')
        selected[app] = {'name': role, 'uid': uid, 'gid': gid, 'shell': fields[6]}
    return selected


def render(settings):
    settings = checked(settings)
    config = (f\"data_directory = '{DATA_DIRECTORY}'\\n\"
              f\"hba_file = '{CONFIG_DIRECTORY}/pg_hba.conf'\\n\"
              f\"ident_file = '{CONFIG_DIRECTORY}/pg_ident.conf'\\n\"
              \"listen_addresses = ''\\nport = 5432\\n\"
              f\"unix_socket_directories = '{SOCKET_DIRECTORY}'\\n\"
              \"unix_socket_permissions = 0777\\nssl = off\\n\"
              \"password_encryption = 'scram-sha-256'\\n\"
              \"fsync = on\\nfull_page_writes = on\\nsynchronous_commit = on\\n\"
              f\"max_connections = {settings['max_connections']}\\n\"
              f\"shared_buffers = '{settings['shared_buffers_mb']}MB'\\n\")
    hba = 'local all postgres peer\\n'
    roles = []
    steps = []
    connections = {}
    for app in APPLICATIONS:
        item = settings['applications'][app]
        role, database, limit = item['role'], item['database'], item['connection_limit']
        # The grammar excludes quote/backslash/metacharacters. Quotes also
        # prevent HBA keywords and SQL keywords from changing identifier meaning.
        hba += f'local \"{database}\" \"{role}\" peer\\n'
        roles.append(f'CREATE ROLE \"{role}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                     f'NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {limit} PASSWORD NULL;\\n')
        steps.append({'database': 'postgres', 'transaction': False,
            'sql': f'CREATE DATABASE \"{database}\" OWNER \"{role}\" TEMPLATE template0 '
                   f\"ENCODING 'UTF8' CONNECTION LIMIT {limit};\\n\"})
        steps.append({'database': database, 'transaction': True,
            'sql': f'BEGIN;\\nREVOKE ALL ON DATABASE \"{database}\" FROM PUBLIC;\\n'
                   'REVOKE CREATE ON SCHEMA public FROM PUBLIC;\\nCOMMIT;\\n'})
        connections[app] = (f'Host={SOCKET_DIRECTORY};Port=5432;Database={database};'
                            f'Username={role};SSL Mode=Disable;Include Error Detail=false')
    hba += ('local replication all reject\\nlocal all all reject\\n'
            'host all all 0.0.0.0/0 reject\\nhost all all ::/0 reject\\n'
            'host replication all 0.0.0.0/0 reject\\nhost replication all ::/0 reject\\n')
    steps.insert(0, {'database': 'postgres', 'transaction': True,
                    'sql': 'BEGIN;\\n' + ''.join(roles) + 'COMMIT;\\n'})
    files = {'postgresql.conf': config, 'pg_hba.conf': hba,
             'pg_ident.conf': '# No peer identity remapping is admitted.\\n'}
    return {'files': files, 'sql_steps': steps, 'connections': connections,
            'initdb_argv': ['/usr/lib/postgresql/17/bin/initdb', '--pgdata', DATA_DIRECTORY,
                '--username=postgres', '--auth-local=peer', '--auth-host=reject',
                '--encoding=UTF8', '--locale=C.UTF-8', '--data-checksums', '--no-instructions']}


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited PostgreSQL deadline')
        end = min(end, deadline)
    fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing PostgreSQL caller namespace')
    settings = configuration(end)
    raw, account_source = read_protected(PASSWD, MAX_ACCOUNTS, False, end)
    selected = accounts(raw, settings['value'])
    plan = render(settings['value'])
    record = {'schema': 1, 'profile': 'postgresql17-local-peer-new-cluster-intention-v1',
        'state': 'local-peer-provisioning-intention-only', 'namespace': context,
        'configuration': settings, 'account_source': account_source, 'accounts': selected, 'plan': plan}
    payload = canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('PostgreSQL intention exceeds its complete output byte bound')
    # Everything above is encoded before the repeated protected input reads
    # and final context/time admission. Only these exact prepared bytes return.
    if configuration(end) != settings:
        raise Pending('PostgreSQL configuration changed during preparation')
    after_raw, after_source = read_protected(PASSWD, MAX_ACCOUNTS, False, end)
    if after_raw != raw or after_source != account_source:
        raise Pending('PostgreSQL local account inventory changed')
    final_context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if final_context != context:
        raise Pending('PostgreSQL caller namespace changed')
    fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('PostgreSQL preparation has no input/configuration overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete PostgreSQL intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/prepare.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Check an explicitly enrolled, pre-provisioned local PostgreSQL 17 cluster.

No package, account, cluster, role, database or SQL mutation is performed here.
The installer startup join consumes existing private cluster enrollment.
Public system identifiers and honest native replies are not authentication,
ownership, complete catalog safety, application migration or runtime attestation.
\"\"\"
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_prepare', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
ENROLLMENT = Path('/etc/debian13s4/postgresql-cluster.json')
DATA = Path(PREP.DATA_DIRECTORY)
CONFIG = Path(PREP.CONFIG_DIRECTORY)
RUNUSER = Path('/usr/sbin/runuser')
PSQL = Path('/usr/lib/postgresql/17/bin/psql')
CONTROL = Path('/usr/lib/postgresql/17/bin/pg_controldata')
SERVER = Path('/usr/lib/postgresql/17/bin/postgres')
ATTEMPT_SECONDS = 10
MAX_BYTES = 262144
SETTING_NAMES = ('data_directory', 'config_file', 'hba_file', 'ident_file', 'listen_addresses', 'port',
    'unix_socket_directories', 'unix_socket_permissions', 'ssl', 'fsync', 'full_page_writes',
    'synchronous_commit', 'password_encryption', 'max_connections', 'shared_buffers',
    'shared_preload_libraries', 'session_preload_libraries', 'local_preload_libraries', 'default_transaction_read_only')
# Fixed read-only query. No application identifier is interpolated into SQL.
SQL = \"\"\"SELECT pg_catalog.json_build_object(
 'version',pg_catalog.current_setting('server_version_num')::integer,
 'identifier',(pg_catalog.pg_control_system()).system_identifier::text,
 'user',current_user,'database',pg_catalog.current_database(),
 'client',pg_catalog.inet_client_addr()::text,'authentication',system_user,
 'start',pg_catalog.pg_postmaster_start_time()::text,'recovery',pg_catalog.pg_is_in_recovery(),
 'settings',(SELECT pg_catalog.json_object_agg(name,pg_catalog.json_build_object(
   'value',setting,'unit',unit,'pending_restart',pending_restart)) FROM pg_catalog.pg_settings
   WHERE name IN ('data_directory','config_file','hba_file','ident_file','listen_addresses','port',
   'unix_socket_directories','unix_socket_permissions','ssl','fsync','full_page_writes',
   'synchronous_commit','password_encryption','max_connections','shared_buffers',
   'shared_preload_libraries','session_preload_libraries','local_preload_libraries','default_transaction_read_only')),
 'roles',(SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',rolname,'super',rolsuper,
   'inherit',rolinherit,'createdb',rolcreatedb,'createrole',rolcreaterole,'login',rolcanlogin,
   'replication',rolreplication,'bypass',rolbypassrls,'limit',rolconnlimit,'password',rolpassword,
   'valid_until',rolvaliduntil)) FROM pg_catalog.pg_authid WHERE pg_catalog.left(rolname,3)<>'pg_'),
 'overrides',(SELECT count(*) FROM pg_catalog.pg_db_role_setting),
 'memberships',(SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member IN
   (SELECT oid FROM pg_catalog.pg_authid WHERE pg_catalog.left(rolname,3)<>'pg_')),
 'databases',(SELECT pg_catalog.json_agg(pg_catalog.json_build_object('name',datname,
   'owner',pg_catalog.pg_get_userbyid(datdba),'encoding',pg_catalog.pg_encoding_to_char(encoding),
   'limit',datconnlimit,'allow',datallowconn,'template',datistemplate,
   'public_access',EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(datacl,
     pg_catalog.acldefault('d',datdba))) WHERE grantee=0))) FROM pg_catalog.pg_database));
\"\"\"


# Fixed read-only application session/privilege query: no caller SQL or names.
PEER_SQL = \"\"\"SELECT pg_catalog.json_build_object(
 'version',pg_catalog.current_setting('server_version_num')::integer,
 'user',current_user,'database',pg_catalog.current_database(),
 'client',pg_catalog.inet_client_addr()::text,'authentication',system_user,
 'start',pg_catalog.pg_postmaster_start_time()::text,'recovery',pg_catalog.pg_is_in_recovery(),
 'read_only',pg_catalog.current_setting('transaction_read_only')='on',
 'role',(SELECT pg_catalog.json_build_object('super',rolsuper,'inherit',rolinherit,
   'createdb',rolcreatedb,'createrole',rolcreaterole,'login',rolcanlogin,
   'replication',rolreplication,'bypass',rolbypassrls)
   FROM pg_catalog.pg_roles WHERE rolname=current_user),
 'database_access',(SELECT pg_catalog.json_build_object(
   'owner',pg_catalog.pg_get_userbyid(datdba),'encoding',pg_catalog.pg_encoding_to_char(encoding),
   'connect',pg_catalog.has_database_privilege(datname,'CONNECT'),
   'create',pg_catalog.has_database_privilege(datname,'CREATE'),
   'temp',pg_catalog.has_database_privilege(datname,'TEMPORARY'),
   'public_access',EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(datacl,
     pg_catalog.acldefault('d',datdba))) WHERE grantee=0))
   FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
 'schema_access',(SELECT pg_catalog.json_build_object(
   'owner',pg_catalog.pg_get_userbyid(nspowner),
   'usage',pg_catalog.has_schema_privilege(oid,'USAGE'),
   'create',pg_catalog.has_schema_privilege(oid,'CREATE'),
   'public_create',EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(nspacl,
     pg_catalog.acldefault('n',nspowner))) WHERE grantee=0 AND privilege_type='CREATE'))
   FROM pg_catalog.pg_namespace WHERE nspname='public'));
\"\"\"


def end_window(deadline):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid PostgreSQL inherited window')
        end = min(end, deadline)
    PREP.fence(end)
    return end


def enrollment(end):
    raw, source = PREP.read_protected(ENROLLMENT, 4096, True, end)
    value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
        parse_constant=lambda value: (_ for _ in ()).throw(Pending('nonfinite enrollment')))
    KERNEL.known(value, {'schema', 'system_identifier'}, {'schema', 'system_identifier'})
    if type(value['schema']) is not int or value['schema'] != 1 or not KERNEL.uint(value['system_identifier'], 2**64-1):
        raise Pending('unsupported explicit PostgreSQL cluster enrollment')
    if raw != PREP.canonical(value): raise Pending('noncanonical PostgreSQL cluster enrollment')
    return {'value': value, 'source': source}


def postgres_account(end):
    raw, _ = PREP.read_protected(PREP.PASSWD, PREP.MAX_ACCOUNTS, False, end)
    # Admit the complete original grammar and selected application accounts too.
    settings = PREP.configuration(end); PREP.accounts(raw, settings['value'])
    rows = [line.split(':') for line in raw.decode('ascii')[:-1].split('\\n')]
    selected = [row for row in rows if row[0] == 'postgres']
    if len(selected) != 1: raise Pending('missing dedicated PostgreSQL system account')
    row = selected[0]; uid, gid = int(row[2]), int(row[3])
    if not 100 <= uid <= 999 or gid == 0 or row[1] not in ('x', '!', '*'):
        raise Pending('unsupported PostgreSQL system account')
    app_uids = {int(item[2]) for item in rows if item[0] in
        {settings['value']['applications'][app]['role'] for app in PREP.APPLICATIONS}}
    if uid in app_uids: raise Pending('shared PostgreSQL server/application identity')
    return uid, gid


def data_read(path, end):
    \"\"\"Allow the existing postgres-owned private leaf; never create/follow it.\"\"\"
    uid, gid = postgres_account(end); PREP.fence(end)
    if not DATA.is_absolute() or os.path.normpath(str(DATA))!=str(DATA):
        raise Pending('noncanonical PostgreSQL data directory')
    DATA.relative_to(PREP.TRUST_ROOT)
    if path.parent != DATA: raise Pending('unapproved PostgreSQL data leaf')
    current = DATA.parent
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != PREP.TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('unprotected PostgreSQL data ancestry')
        if current == PREP.TRUST_ROOT: break
        current = current.parent
    directory = DATA.lstat(); before = path.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid or directory.st_gid != gid or
        stat.S_IMODE(directory.st_mode) != 0o700 or not stat.S_ISREG(before.st_mode) or
        before.st_uid != uid or before.st_gid != gid or stat.S_IMODE(before.st_mode) != 0o600 or
        before.st_nlink != 1 or before.st_size > 4096):
        raise Pending('unsupported PostgreSQL data directory/leaf identity')
    cause = None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if KERNEL.signature(os.fstat(fd)) != KERNEL.signature(before): raise Pending('PostgreSQL data FD differs')
        raw = bytearray()
        while True:
            PREP.fence(end); part = os.read(fd, 4097-len(raw))
            if not part: break
            raw.extend(part)
            if len(raw)>4096: raise Pending('PostgreSQL data leaf exceeds bound')
        if (KERNEL.signature(os.fstat(fd)) != KERNEL.signature(before) or
            KERNEL.signature(path.lstat()) != KERNEL.signature(before) or len(raw)!=before.st_size or
            KERNEL.signature(DATA.lstat()) != KERNEL.signature(directory)):
            raise Pending('PostgreSQL data leaf/ancestry changed')
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, fd = fd, None
        PREP.close_descriptor(closing, cause)
    PREP.fence(end)
    return bytes(raw), {'path': str(path), 'identity': list(KERNEL.signature(before)),
                        'sha256': hashlib.sha256(raw).hexdigest()}


class CleanupFailure(Pending):
    \"\"\"Keep a capture refusal and its separate owned cleanup failures.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('PostgreSQL native capture cleanup incomplete')
        self.cause, self.cleanup = cause, cleanup


def close_child(child, selector):
    \"\"\"Retire known channels before one close each; attempt every cleanup step.\"\"\"
    streams = child.stdout, child.stderr
    child.stdout = child.stderr = None
    errors = []
    if child.returncode is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            errors.append(error)
        try:
            child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        except BaseException as error:
            errors.append(error)
    if selector is not None:
        try:
            selector.close()
        except BaseException as error:
            errors.append(error)
    for stream in streams:
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
    return tuple(errors)


def native(kind, end):
    user = 'postgres'
    if kind == 'control': binary, arguments = CONTROL, ('--pgdata', str(DATA))
    elif kind == 'catalog':
        binary = PSQL
        arguments = ('--no-psqlrc', '--no-password', '--host', PREP.SOCKET_DIRECTORY, '--port', '5432',
                     '--username', 'postgres', '--dbname', 'postgres', '--tuples-only', '--no-align',
                     '--set', 'ON_ERROR_STOP=1', '--command', SQL)
    elif kind in ('peer:mk8.dns', 'peer:mk8.email'):
        # Only real protected, validated deployment settings select argv fields.
        item = PREP.configuration(end)['value']['applications'][kind[5:]]
        user, database = item['role'], item['database']
        binary = PSQL
        arguments = ('--no-psqlrc', '--no-password', '--host', PREP.SOCKET_DIRECTORY, '--port', '5432',
                     '--username', user, '--dbname', database, '--tuples-only', '--no-align',
                     '--set', 'ON_ERROR_STOP=1', '--command', PEER_SQL)
    else: raise Pending('unapproved PostgreSQL native read')
    PREP.fence(end); before = (KERNEL.trusted_binary(RUNUSER), KERNEL.trusted_binary(binary))
    until = min(end, KERNEL.now()+KERNEL.QUERY_SECONDS); PREP.fence(until)
    cause, selector = None, None
    child = subprocess.Popen([str(RUNUSER), '-u', user, '--', str(binary), *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}, close_fds=True, start_new_session=True)
    try:
        buffers = {'stdout':bytearray(), 'stderr':bytearray()}
        selector = selectors.DefaultSelector()
        for name, stream in (('stdout',child.stdout),('stderr',child.stderr)):
            os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map():
            PREP.fence(until)
            remaining=until-KERNEL.now()
            if remaining<=0:raise Pending('PostgreSQL native read window expired')
            for key,_ in selector.select(remaining):
                part=os.read(key.fileobj.fileno(),65536)
                if not part: selector.unregister(key.fileobj); continue
                buffer=buffers[key.data]
                if len(buffer)+len(part)>MAX_BYTES: raise Pending('PostgreSQL native channel bound')
                buffer.extend(part)
        PREP.fence(until); remaining=until-KERNEL.now()
        if remaining<=0:raise Pending('PostgreSQL native wait window expired')
        code=child.wait(timeout=remaining)
        if type(code) is not int or code!=0 or buffers['stderr']: raise Pending('PostgreSQL native read failed/warned')
        if (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(binary))!=before:
            raise Pending('PostgreSQL native executable changed')
        PREP.fence(until); return bytes(buffers['stdout'])
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, selector = selector, None
        cleanup = close_child(child, closing)
        if cleanup:
            if cause is None and len(cleanup) == 1:
                raise cleanup[0]
            raise CleanupFailure(cause, cleanup) from cause


def intention(end):
    # Real accepted preparation, not a caller-supplied manifest/healthy flag.
    record=json.loads(PREP.prepare(deadline=end))
    return record, enrollment(end)


def prestart(read=native, deadline=None):
    end=end_window(deadline); record, registered=intention(end)
    version,_=data_read(DATA/'PG_VERSION',end)
    if version!=b'17\\n': raise Pending('unsupported pre-provisioned PostgreSQL major version')
    if (DATA/'postmaster.pid').exists() or (DATA/'postmaster.pid').is_symlink():
        raise Pending('PostgreSQL data has an existing or unverifiable postmaster')
    raw,_=data_read(DATA/'postgresql.auto.conf',end)
    if any(line.strip() and not line.startswith(b'#') for line in raw.split(b'\\n')):
        raise Pending('PostgreSQL automatic startup overrides refuse')
    text=read('control',end).decode('ascii'); values={}
    for line in text.split('\\n'):
        if not line: continue
        name, separator,value=line.partition(':')
        if not separator or name in values or any(ord(c)<32 or ord(c)>126 for c in line):
            raise Pending('unsupported pg_controldata representation')
        values[name]=value.strip()
    required={'Database system identifier','Database cluster state','Data page checksum version'}
    if not required<=values.keys() or values['Database cluster state']!='shut down' or values['Data page checksum version']!='1':
        raise Pending('PostgreSQL cluster is not cleanly stopped/checksummed')
    if values['Database system identifier']!=str(registered['value']['system_identifier']):
        raise Pending('PostgreSQL offline identifier differs from enrollment')
    if enrollment(end)!=registered or json.loads(PREP.prepare(deadline=end))!=record:
        raise Pending('PostgreSQL prestart inputs changed')
    PREP.fence(end); return record


def settings_expected(record):
    value=record['configuration']['value']
    return {'data_directory':str(DATA),'config_file':str(CONFIG/'postgresql.conf'),
        'hba_file':str(CONFIG/'pg_hba.conf'),'ident_file':str(CONFIG/'pg_ident.conf'),'listen_addresses':'',
        'port':'5432','unix_socket_directories':PREP.SOCKET_DIRECTORY,'unix_socket_permissions':'0777',
        'ssl':'off','fsync':'on','full_page_writes':'on','synchronous_commit':'on','password_encryption':'scram-sha-256',
        'max_connections':str(value['max_connections']),'shared_buffers':str(value['shared_buffers_mb']*128),
        'shared_preload_libraries':'','session_preload_libraries':'','local_preload_libraries':'','default_transaction_read_only':'off'}


def catalog(value, record, registered):
    fields={'version','identifier','user','database','client','authentication','start','recovery','settings','roles','memberships','overrides','databases'}
    KERNEL.known(value,fields,fields)
    if (type(value['version']) is not int or not 170000<=value['version']<180000 or
        type(value['identifier']) is not str or value['identifier']!=str(registered['value']['system_identifier']) or
        value['user']!='postgres' or value['database']!='postgres' or value['client'] is not None or
        value['authentication']!='peer:postgres' or value['recovery'] is not False or
        type(value['start']) is not str or not 1<=len(value['start'])<=64 or
        any(ord(c)<32 or ord(c)>126 for c in value['start']) or type(value['memberships']) is not int or value['memberships']!=0 or
        type(value['overrides']) is not int or value['overrides']!=0):
        raise Pending('unsupported PostgreSQL server/session identity')
    expected=settings_expected(record); KERNEL.known(value['settings'],set(expected),set(expected))
    for name,wanted in expected.items():
        row=value['settings'][name]; KERNEL.known(row,{'value','unit','pending_restart'},{'value','unit','pending_restart'})
        if row['value']!=wanted or row['pending_restart'] is not False or row['unit']!=('8kB' if name=='shared_buffers' else None):
            raise Pending('PostgreSQL loaded setting differs or awaits restart')
    roles=KERNEL.rows(value['roles'],3); by_name={}
    applications=record['configuration']['value']['applications']
    expected_roles={item['role']:item['connection_limit'] for item in applications.values()}
    for row in roles:
        fields={'name','super','inherit','createdb','createrole','login','replication','bypass','limit','password','valid_until'}
        KERNEL.known(row,fields,fields); name=row['name']
        if type(name) is not str or name in by_name or name not in {'postgres',*expected_roles}:
            raise Pending('foreign or duplicate PostgreSQL login role')
        privileged=name=='postgres'
        for key in ('super','inherit','createdb','createrole','replication','bypass'):
            if row[key] is not privileged: raise Pending('unexpected PostgreSQL role privilege')
        if row['login'] is not True or type(row['limit']) is not int or row['limit']!=(-1 if privileged else expected_roles[name]) or row['password'] is not None or row['valid_until'] is not None:
            raise Pending('unexpected PostgreSQL role authentication/limit')
        by_name[name]=row
    if set(by_name)!={'postgres',*expected_roles}: raise Pending('missing PostgreSQL application role')
    databases=KERNEL.rows(value['databases'],5); seen=set()
    owned={item['database']:item for item in applications.values()}
    for row in databases:
        fields={'name','owner','encoding','limit','allow','template','public_access'};KERNEL.known(row,fields,fields)
        name=row['name']
        if type(name) is not str or name in seen or name not in {'postgres','template0','template1',*owned}:
            raise Pending('foreign/duplicate PostgreSQL database')
        if name in owned:
            item=owned[name]
            if (row['owner']!=item['role'] or row['encoding']!='UTF8' or type(row['limit']) is not int or
                row['limit']!=item['connection_limit'] or row['allow'] is not True or row['template'] is not False or row['public_access'] is not False):
                raise Pending('PostgreSQL application database differs')
        elif (row['owner']!='postgres' or row['encoding']!='UTF8' or type(row['limit']) is not int or row['limit']!=-1 or
              row['allow'] is not (name!='template0') or row['template'] is not (name!='postgres') or type(row['public_access']) is not bool):
            raise Pending('unsupported PostgreSQL template/admin database')
        seen.add(name)
    if seen!={'postgres','template0','template1',*owned}: raise Pending('missing PostgreSQL database')
    return json.loads(PREP.canonical(value))


def check(read=native, deadline=None):
    end=end_window(deadline); record,registered=intention(end)
    version,_=data_read(DATA/'PG_VERSION',end)
    if version!=b'17\\n': raise Pending('unsupported PostgreSQL data version')
    expected_files=record['plan']['files']; sources={}
    for name,text in expected_files.items():
        raw,source=PREP.read_protected(CONFIG/name,4096,False,end)
        if raw!=text.encode('ascii'): raise Pending('PostgreSQL published config differs')
        sources[name]=source
    auto,_=data_read(DATA/'postgresql.auto.conf',end)
    if any(line.strip() and not line.startswith(b'#') for line in auto.split(b'\\n')): raise Pending('PostgreSQL automatic overrides refuse')
    first=catalog(json.loads(read('catalog',end).decode('utf-8'),object_pairs_hook=KERNEL.unique_object),record,registered)
    second=catalog(json.loads(read('catalog',end).decode('utf-8'),object_pairs_hook=KERNEL.unique_object),record,registered)
    if first!=second: raise Pending('PostgreSQL complete selected catalog drift')
    payload=PREP.canonical({'schema':1,'state':'enrolled-local-postgresql-source-only','namespace':record['namespace'],
        'enrollment':registered,'accounts':record['accounts'],'catalog':second})
    if len(payload)>PREP.MAX_OUTPUT: raise Pending('PostgreSQL receipt bound exceeded')
    if enrollment(end)!=registered: raise Pending('PostgreSQL enrollment changed')
    final=json.loads(PREP.prepare(deadline=end))
    if final!=record: raise Pending('PostgreSQL preparation inputs changed')
    for name,source in sources.items():
        raw,after=PREP.read_protected(CONFIG/name,4096,False,end)
        if source!=after or raw!=expected_files[name].encode('ascii'): raise Pending('PostgreSQL config changed')
    after,_=data_read(DATA/'postgresql.auto.conf',end)
    if auto!=after: raise Pending('PostgreSQL startup overrides changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:
        raise Pending('PostgreSQL final context changed')
    PREP.fence(end); return payload


def startup(deadline=None):
    end=end_window(deadline);record,registered=intention(end);files={}
    for name,text in record['plan']['files'].items():
        raw,source=PREP.read_protected(CONFIG/name,4096,False,end)
        if raw!=text.encode('ascii'):raise Pending('PostgreSQL startup config differs')
        files[name]=source
    version,version_source=data_read(DATA/'PG_VERSION',end)
    auto,auto_source=data_read(DATA/'postgresql.auto.conf',end)
    if version!=b'17\\n' or any(line.strip() and not line.startswith(b'#') for line in auto.split(b'\\n')):
        raise Pending('unsupported PostgreSQL startup data')
    executables={}
    for path in (RUNUSER,PSQL,CONTROL,SERVER):
        signature=KERNEL.trusted_binary(path)
        _,source=PREP.read_protected(path,67108864,False,end)
        if list(signature)!=source['identity']:raise Pending('PostgreSQL executable changed')
        executables[str(path)]=source
    payload=PREP.canonical({'configuration':record['configuration'],'accounts':record['accounts'],
        'account_source':record['account_source'],
        'namespace':record['namespace'],'enrollment':registered,'files':files,'version':version_source,
        'automatic_configuration':auto_source,'executables':executables})
    if len(payload)>16384:raise Pending('PostgreSQL startup identity exceeds bound')
    if json.loads(PREP.prepare(deadline=end))!=record or enrollment(end)!=registered:
        raise Pending('PostgreSQL startup inputs changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:
        raise Pending('PostgreSQL final startup context changed')
    PREP.fence(end);return payload


def main():
    try:
        args=sys.argv[1:]
        sink=sys.stdout.buffer
        if not callable(getattr(sink,'write',None)) or not callable(getattr(sink,'flush',None)):
            raise Pending('binary output required')
        if args==['--check']: payload=check()
        elif args==['--prestart']: prestart(); return 0
        elif args==['--identity']: payload=startup()
        elif len(args)==2 and args[0]=='--file' and args[1] in ('postgresql.conf','pg_hba.conf','pg_ident.conf'):
            end=end_window(None);record,_=intention(end);payload=record['plan']['files'][args[1]].encode('ascii');PREP.fence(end)
        else: raise Pending('unsupported PostgreSQL startup action')
        count=sink.write(payload)
        if type(count) is not int or count!=len(payload): raise Pending('short PostgreSQL output')
        sink.flush();return 0
    except (Pending,OSError,ValueError,TypeError,AttributeError,UnicodeError,RecursionError,subprocess.TimeoutExpired) as error:
        print('Pending: '+str(error),file=sys.stderr);return 75


if __name__=='__main__':sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/live.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Require reported local peer access for BOTH configured application identities.

Read-only SOURCE admission, not migration/CRUD/Npgsql, NSS/origin authentication,
complete object safety or physical readiness. Default check WOULD read protected
host files and connect to PostgreSQL; host calling is unauthorized here. No role,
account, SQL mutation, provisioning, adoption or retry operation is supplied.
\"\"\"
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_postgresql_access_live', Path(__file__).with_name('live.py'))
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)
PREP, KERNEL, Pending = LIVE.PREP, LIVE.KERNEL, LIVE.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 2 * PREP.MAX_OUTPUT + 8192


def decoded(raw, limit):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Pending('invalid PostgreSQL access byte delivery')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(Pending('nonfinite PostgreSQL access JSON')),
            parse_float=lambda value: (_ for _ in ()).throw(Pending('noninteger PostgreSQL access JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL access JSON') from error


def peer(value, app, record, admin):
    \"\"\"Complete selected reported facts, never a caller health/hash verdict.\"\"\"
    if type(app) is not str or app not in PREP.APPLICATIONS:
        raise Pending('unsupported PostgreSQL application identity')
    item = record['configuration']['value']['applications'][app]
    fields = {'version', 'user', 'database', 'client', 'authentication', 'start',
              'recovery', 'read_only', 'role', 'database_access', 'schema_access'}
    KERNEL.known(value, fields, fields)
    if (type(value['version']) is not int or value['version'] != admin['version'] or
        value['user'] != item['role'] or value['database'] != item['database'] or
        value['client'] is not None or value['authentication'] != 'peer:' + item['role'] or
        value['start'] != admin['start'] or value['recovery'] is not False or value['read_only'] is not False):
        raise Pending('PostgreSQL application session differs from enrolled server/peer intention')
    flags = {'super', 'inherit', 'createdb', 'createrole', 'login', 'replication', 'bypass'}
    KERNEL.known(value['role'], flags, flags)
    for flag in flags:
        if value['role'][flag] is not (flag == 'login'):
            raise Pending('PostgreSQL application peer role privileges differ')
    database = value['database_access']
    names = {'owner', 'encoding', 'connect', 'create', 'temp', 'public_access'}
    KERNEL.known(database, names, names)
    if (database['owner'] != item['role'] or database['encoding'] != 'UTF8' or
        any(database[name] is not True for name in ('connect', 'create', 'temp')) or
        database['public_access'] is not False):
        raise Pending('PostgreSQL application database ownership/access differs')
    schema = value['schema_access']
    names = {'owner', 'usage', 'create', 'public_create'}
    KERNEL.known(schema, names, names)
    if (schema['owner'] not in (item['role'], 'pg_database_owner') or
        schema['usage'] is not True or schema['create'] is not True or schema['public_create'] is not False):
        raise Pending('PostgreSQL application public schema ownership/access differs')
    return decoded(PREP.canonical(value), LIVE.MAX_BYTES)


def check(read=None, deadline=None):
    \"\"\"Real admin admission plus two complete application rounds and final inputs.\"\"\"
    if read is None:
        read = LIVE.native
    if not callable(read):
        raise Pending('unsupported PostgreSQL access delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid PostgreSQL access inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    namespace = KERNEL.uint(KERNEL.namespace(), 2 ** 64 - 1)
    if not namespace:
        raise Pending('missing PostgreSQL access context')
    PREP.fence(end)
    before = LIVE.check(read=read, deadline=end)
    admin = decoded(before, PREP.MAX_OUTPUT)
    record, registered = LIVE.intention(end)
    if (admin['namespace'] != namespace or record['namespace'] != namespace or
        admin['enrollment'] != registered or admin['accounts'] != record['accounts']):
        raise Pending('PostgreSQL access and real preparation identities differ')
    rounds = []
    for _ in range(2):
        observed = {}
        for app in PREP.APPLICATIONS:
            PREP.fence(end)
            observed[app] = peer(decoded(read('peer:' + app, end), LIVE.MAX_BYTES), app, record, admin['catalog'])
            PREP.fence(end)
        rounds.append(observed)
    if PREP.canonical(rounds[0]) != PREP.canonical(rounds[1]):
        raise Pending('complete PostgreSQL application peer SOURCE changed')
    # The real admin checker, not a supplied health flag, fences selected server,
    # roles/databases/settings/config/enrollment again AFTER all peer reads.
    if LIVE.check(read=read, deadline=end) != before:
        raise Pending('complete PostgreSQL admin SOURCE changed around application access')
    payload = PREP.canonical({'schema': 1, 'state': 'enrolled-local-postgresql-peer-source-only',
        'profile': 'postgresql17-dns-email-local-peer-owner-access-v1', 'namespace': namespace,
        'admin': admin, 'applications': rounds[-1]})
    if len(payload) > MAX_OUTPUT:
        raise Pending('PostgreSQL application access receipt exceeds bound')
    # All output encoding precedes these real complete protected input reads and
    # the final typed scope/time fence. Equal reads are sequential, not atomic.
    final_record, final_registered = LIVE.intention(end)
    if final_record != record or final_registered != registered:
        raise Pending('PostgreSQL application access protected inputs changed')
    final = KERNEL.namespace()
    if type(final) is not int or final != namespace:
        raise Pending('PostgreSQL application access context changed')
    PREP.fence(end)
    return payload


def main():
    try:
        if sys.argv[1:] != ['--access']:
            raise Pending('unsupported PostgreSQL application access action')
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL application access requires binary output')
        payload = check()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('short PostgreSQL application access output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError,
            RecursionError, subprocess.TimeoutExpired) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/access.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Protected logical-backup intentions for the two configured local databases.

This does not dump, open/create an archive, inspect one, restore, publish, delete
or schedule anything. Default preparation WOULD connect through the accepted
read-only access checker; real-host calling is unauthorized here. Selected
access is not complete object/RLS/extension safety or restore compatibility.
\"\"\"
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_backup_access',
    Path(__file__).with_name('access.py'))
ACCESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCESS)
PREP, KERNEL, Pending = ACCESS.PREP, ACCESS.KERNEL, ACCESS.Pending
INPUT = Path('/etc/debian13s4/postgresql-backup.json')
DUMP = '/usr/lib/postgresql/17/bin/pg_dump'
RESTORE = '/usr/lib/postgresql/17/bin/pg_restore'
RUNUSER = '/usr/sbin/runuser'
MAX_INPUT = 4096
MAX_OUTPUT = ACCESS.MAX_OUTPUT + PREP.MAX_OUTPUT + 16384
ATTEMPT_SECONDS = 60


def checked(value):
    fields = {'schema', 'directory', 'generation', 'archive_limit_bytes',
              'inventory_limit_bytes', 'dump_timeout_seconds', 'lock_wait_ms'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported PostgreSQL backup intention schema')
    path = value['directory']
    if (type(path) is not str or not 6 <= len(path) <= 240 or
        re.fullmatch(r'/[A-Za-z0-9_./-]+', path) is None or
        os.path.normpath(path) != path or
        any(part in ('', '.', '..') for part in path.split('/')[1:]) or
        not any(path.startswith(root + '/') for root in ('/srv', '/var/backups'))):
        raise Pending('unsupported explicit PostgreSQL backup directory intention')
    generation = value['generation']
    if (type(generation) is not str or re.fullmatch(r'[0-9a-f]{64}', generation) is None or
        generation == '0' * 64):
        raise Pending('unsupported explicit PostgreSQL backup generation')
    for field, minimum, maximum in (
        ('archive_limit_bytes', 1024, 1 << 40),
        ('inventory_limit_bytes', 1024, 1 << 26),
        ('dump_timeout_seconds', 1, 3600), ('lock_wait_ms', 1, 60000)):
        number = value[field]
        if type(number) is not int or not minimum <= number <= maximum:
            raise Pending('unsupported explicit PostgreSQL backup bound')
    return json.loads(PREP.canonical(value))


def configuration(end):
    raw, source = PREP.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite backup input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid PostgreSQL backup input') from error
    if raw != PREP.canonical(value):
        raise Pending('backup input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def render(settings, record):
    settings = checked(settings)
    deployment = PREP.checked(record['configuration']['value'])
    jobs = {}
    for app in PREP.APPLICATIONS:
        item = deployment['applications'][app]
        archive = settings['directory'] + '/' + settings['generation'] + '-' + app + '.dump'
        jobs[app] = {
            'role': item['role'], 'database': item['database'], 'archive': archive,
            # Binary stdout goes to a future independently protected writer;
            # runuser's application identity does not own the archive directory.
            'dump_argv': [RUNUSER, '-u', item['role'], '--', DUMP,
                '--format=custom', '--no-password', '--host', PREP.SOCKET_DIRECTORY,
                '--port', '5432', '--username', item['role'], '--dbname', item['database'],
                '--lock-wait-timeout=' + str(settings['lock_wait_ms'])],
            'dump_environment': {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'},
            'dump_stdout': 'custom-archive-bytes-for-protected-writer',
            'archive_limit_bytes': settings['archive_limit_bytes'],
            'dump_timeout_seconds': settings['dump_timeout_seconds'],
            'inspection_argv': [RESTORE, '--list', archive],
            'inspection_environment': {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'},
            'inventory_limit_bytes': settings['inventory_limit_bytes']}
    return jobs


def prepare(read=None, deadline=None):
    if read is None:
        read = ACCESS.LIVE.native
    if not callable(read):
        raise Pending('unsupported PostgreSQL backup access delivery')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited PostgreSQL backup window')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    PREP.fence(end)
    namespace = KERNEL.uint(KERNEL.namespace(), (1 << 64) - 1)
    if not namespace:
        raise Pending('missing PostgreSQL backup context')
    def capture(kind, window):
        if not KERNEL.finite_deadline(window) or window > end:
            raise Pending('PostgreSQL backup query exceeds inherited window')
        PREP.fence(end)
        PREP.fence(window)
        raw = read(kind, window)
        PREP.fence(window)
        PREP.fence(end)
        return raw

    settings = configuration(end)
    record, enrolled = ACCESS.LIVE.intention(end)
    before = ACCESS.check(read=capture, deadline=end)
    access = ACCESS.decoded(before, ACCESS.MAX_OUTPUT)
    if (access['namespace'] != namespace or record['namespace'] != namespace or
        access['admin']['enrollment'] != enrolled or access['admin']['accounts'] != record['accounts']):
        raise Pending('PostgreSQL backup and access source identities differ')
    for app in PREP.APPLICATIONS:
        item = record['configuration']['value']['applications'][app]
        if (access['applications'][app]['user'] != item['role'] or
            access['applications'][app]['database'] != item['database']):
            raise Pending('PostgreSQL backup application source differs')
    payload = PREP.canonical({'schema': 1, 'profile': 'postgresql17-selected-logical-backup-intention-v1',
        'state': 'postgresql-logical-backup-intention-only', 'namespace': namespace,
        'configuration': settings, 'source_intention': record, 'enrollment': enrolled,
        'access': access, 'jobs': render(settings['value'], record)})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete PostgreSQL backup intention exceeds bound')
    # Complete immutable encoding precedes every final real input/access read.
    if configuration(end) != settings:
        raise Pending('PostgreSQL backup configuration changed')
    if ACCESS.check(read=capture, deadline=end) != before:
        raise Pending('PostgreSQL backup access source changed')
    final_record, final_enrolled = ACCESS.LIVE.intention(end)
    if final_record != record or final_enrolled != enrolled:
        raise Pending('PostgreSQL backup protected source changed')
    final = KERNEL.namespace()
    if type(final) is not int or final != namespace:
        raise Pending('PostgreSQL backup context changed')
    PREP.fence(end)
    return payload


def main():
    try:
        if sys.argv[1:] != ['--prepare']:
            raise Pending('unsupported PostgreSQL backup action')
        sink = getattr(sys.stdout, 'buffer', None)
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('PostgreSQL backup preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete PostgreSQL backup intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError,
            RecursionError, subprocess.TimeoutExpired) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/backup.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Create-only OPAQUE private .partial bytes, never a valid or published backup.

No pg_dump/pg_restore/process/connection/CLI/auto-directory/reset/adoption/retry
is provided. Any existing target blocks; failed acquired targets remain closed.
Caller streams/receipts are not native archive attestation. Honest ancestry,
cooperating locks and finite IO are required; fsync is not power-loss proof.
\"\"\"
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat

SPEC = importlib.util.spec_from_file_location('debian13s4_archive_inputs',
    Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
MAX_BYTES = 1 << 40
CHUNK = 65536
MAX_RECEIPT = 4096
ATTEMPT_SECONDS = 3600


class Blocked(RuntimeError):
    \"\"\"An existing or acquired .partial target is not automatically retryable.\"\"\"


class CleanupFailure(Blocked):
    \"\"\"Keep the original failure and each separate checked-close failure.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('private archive operation and cleanup incomplete; no automatic retry')
        self.cause, self.cleanup = cause, cleanup


def close_retired(cause, *descriptors):
    \"\"\"Close already-retired owned descriptors once, even if an earlier close fails.\"\"\"
    errors = []
    for descriptor in descriptors:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
    if errors:
        if cause is None and len(errors) == 1:
            raise errors[0]
        raise CleanupFailure(cause, tuple(errors)) from cause


def cleanup_errors(cause):
    \"\"\"Collect owned archive close errors from the original bounded cause chain.\"\"\"
    groups, seen = [], set()
    while cause is not None and id(cause) not in seen and len(seen) < 16:
        seen.add(id(cause))
        if type(cause) is CleanupFailure:
            groups.append(cause.cleanup)
        cause = cause.__cause__
    errors, seen = [], set()
    for group in reversed(groups):
        for error in group:
            if id(error) not in seen:
                seen.add(id(error)); errors.append(error)
    return tuple(errors)


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('private archive staging window expired')


def window(deadline):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid archive staging inherited deadline')
    return min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS


def directory_identity(path):
    if (type(path) is not type(TRUST_ROOT) or not path.is_absolute() or
        len(str(path)) > 512 or os.path.normpath(str(path)) != str(path)):
        raise Pending('noncanonical private archive directory')
    path.relative_to(TRUST_ROOT)
    current = path; leaf = None
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('untrusted private archive ancestry')
        value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if current == path:
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise Pending('archive staging directory is not private')
            leaf = value
        if current == TRUST_ROOT:
            return leaf
        current = current.parent


def directory_matches(path, fd, before):
    info = os.fstat(fd)
    value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    if value != before or directory_identity(path) != before:
        raise Pending('private archive directory descriptor or path changed')


def file_identity(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID or
        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise Pending('untrusted private archive stage')
    return KERNEL.signature(info) + (info.st_nlink,)


def file_matches(directory, name, fd):
    value = file_identity(os.fstat(fd))
    if value[0] != os.fstat(directory).st_dev or value != file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
        raise Pending('private archive stage descriptor or name changed')
    return value


def readback(directory, name, identity, count, digest, end):
    admission(end)
    if file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != identity:
        raise Pending('private archive readback identity changed')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    cause = None
    try:
        if file_matches(directory, name, fd) != identity:
            raise Pending('private archive readback descriptor changed')
        total = 0; hashed = hashlib.sha256()
        while True:
            admission(end)
            part = os.read(fd, min(CHUNK, count - total + 1))
            admission(end)
            if not part:
                break
            total += len(part)
            if total > count:
                raise Pending('private archive readback exceeds committed size')
            hashed.update(part)
        if total != count or hashed.hexdigest() != digest or file_matches(directory, name, fd) != identity:
            raise Pending('private archive bytes or identity changed during readback')
        admission(end)
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, fd = fd, None
        close_retired(cause, closing)


def stage(path, name, stream, limit, deadline=None):
    end = window(deadline)
    if (type(name) is not str or
        re.fullmatch(r'[0-9a-f]{64}-mk8\\.(dns|email)\\.dump\\.partial', name) is None or
        name.startswith('0' * 64 + '-')):
        raise Pending('unsupported private archive staging leaf')
    if type(limit) is not int or not 1 <= limit <= MAX_BYTES or not callable(getattr(stream, 'read', None)):
        raise Pending('unsupported private archive stream or bound')
    admission(end); before = directory_identity(path)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    fd = None; acquired = False; cause = None
    try:
        directory_matches(path, directory, before)
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory_matches(path, directory, before); admission(end)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        acquired = True
        os.fchmod(fd, 0o600)
        file_matches(directory, name, fd)
        total = 0; hashed = hashlib.sha256()
        while True:
            admission(end)
            requested = min(CHUNK, limit - total + 1)
            part = stream.read(requested)
            admission(end)
            if type(part) is not bytes or len(part) > requested:
                raise Pending('untyped or oversized private archive stream delivery')
            if not part:
                break
            if total + len(part) > limit:
                raise Pending('private archive stream exceeds byte bound')
            offset = 0
            while offset < len(part):
                admission(end)
                count = os.write(fd, part[offset:])
                if type(count) is not int or not 0 < count <= len(part) - offset:
                    raise Pending('private archive write did not advance')
                offset += count
            total += len(part); hashed.update(part)
        if total == 0:
            raise Pending('empty private archive staging stream')
        os.fsync(fd)
        identity = file_matches(directory, name, fd)
        if identity[5] != total:
            raise Pending('private archive stage size disagrees')
        receipt = PREP.canonical({'schema':1, 'state':'private-unverified-archive-stage-only',
            'directory':str(path), 'directory_identity':list(before), 'leaf':name,
            'bytes':total, 'limit_bytes':limit, 'sha256':hashed.hexdigest(), 'identity':list(identity)})
        if len(receipt) > MAX_RECEIPT:
            raise Pending('private archive staging receipt exceeds bound')
        if file_matches(directory, name, fd) != identity:
            raise Pending('private archive stage changed after encoding')
        directory_matches(path, directory, before); admission(end)
        closing, fd = fd, None
        os.close(closing)
        os.fsync(directory)
        readback(directory, name, identity, total, hashed.hexdigest(), end)
        directory_matches(path, directory, before); admission(end)
        return receipt
    except BaseException as error:
        cause = error
        if acquired or isinstance(error, FileExistsError):
            cause = Blocked('archive staging target exists or may be visible; no automatic retry')
            raise cause from error
        raise
    finally:
        closing_file, fd = fd, None
        closing_directory, directory = directory, None
        close_retired(cause, closing_file, closing_directory)
" > "$S4B_STAGE/"lib/postgresql/archive_stage.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Protected .partial listing SOURCE only, not archive completeness or restore.

The default delivery WOULD execute pg_restore --list against the supplied file.
No database option, dump, restore, mutation, promotion, retry or installer join
is supplied. Listing bytes and public receipts are not native origin attestation.
Path reopening, cooperating locks and repeated reads are sequential, not atomic
or non-ABA guarantees; finite IO/cleanup and honest immutable modules are assumed.
\"\"\"
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess

SPEC = importlib.util.spec_from_file_location('debian13s4_inspection_stage',
    Path(__file__).with_name('archive_stage.py'))
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)
KERNEL, PREP, Pending = STAGE.KERNEL, STAGE.PREP, STAGE.Pending
RESTORE = Path('/usr/lib/postgresql/17/bin/pg_restore')
MAX_LISTING = 67108864
MAX_OUTPUT = 2 * MAX_LISTING + 16384
ATTEMPT_SECONDS = 60


def checked(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= STAGE.MAX_RECEIPT:
        raise Pending('unsupported archive stage receipt bytes')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda s: (_ for _ in ()).throw(Pending('nonfinite stage receipt')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid archive stage receipt') from error
    fields = {'schema', 'state', 'directory', 'directory_identity', 'leaf',
              'bytes', 'limit_bytes', 'sha256', 'identity'}
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['state'] != 'private-unverified-archive-stage-only' or
        type(value['directory']) is not str or not 1 <= len(value['directory']) <= 512 or
        any(ord(c) < 32 or ord(c) > 126 for c in value['directory']) or
        not Path(value['directory']).is_absolute() or os.path.normpath(value['directory']) != value['directory'] or
        type(value['leaf']) is not str or
        re.fullmatch(r'[0-9a-f]{64}-mk8\\.(dns|email)\\.dump\\.partial', value['leaf']) is None or
        value['leaf'].startswith('0' * 64 + '-') or
        type(value['bytes']) is not int or type(value['limit_bytes']) is not int or
        not 1 <= value['bytes'] <= value['limit_bytes'] <= STAGE.MAX_BYTES or
        type(value['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is None):
        raise Pending('unsupported archive stage receipt fields')
    for field, width in (('directory_identity', 5), ('identity', 9)):
        row = value[field]
        if type(row) is not list or len(row) != width or any(type(n) is not int for n in row):
            raise Pending('untyped archive stage identity')
    directory, leaf = value['directory_identity'], value['identity']
    if (any(n < 0 for n in directory) or any(leaf[n] < 0 for n in (0, 1, 2, 3, 4, 5, 8)) or
        directory[2] != stat.S_IFDIR | 0o700 or directory[3] != STAGE.TRUSTED_UID or
        leaf[0] != directory[0] or leaf[2] != stat.S_IFREG | 0o600 or
        leaf[3] != STAGE.TRUSTED_UID or leaf[5] != value['bytes'] or leaf[8] != 1):
        raise Pending('unsupported archive stage identity facts')
    if raw != PREP.canonical(value):
        raise Pending('noncanonical archive stage receipt')
    return value


def close_child(child, selector):
    \"\"\"Retire known channels before cleanup; retain each independent failure.\"\"\"
    streams = child.stdout, child.stderr
    child.stdout = child.stderr = None
    errors = []
    if child.returncode is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            errors.append(error)
        # A signal error must not skip the separate bounded root-wait attempt.
        try:
            child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        except BaseException as error:
            errors.append(error)
    if selector is not None:
        try:
            selector.close()
        except BaseException as error:
            errors.append(error)
    for stream in streams:
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
    return tuple(errors)


def native(path, maximum, end):
    \"\"\"Fixed read-only listing primitive; calling real host tools needs authority.\"\"\"
    STAGE.admission(end)
    if type(maximum) is not int or not 1 <= maximum <= MAX_LISTING:
        raise Pending('unsupported archive listing bound')
    if (type(path) is not type(RESTORE) or not path.is_absolute() or
        os.path.normpath(str(path)) != str(path) or len(str(path)) > 1024 or
        any(ord(c) < 32 or ord(c) > 126 for c in str(path)) or
        re.fullmatch(r'[0-9a-f]{64}-mk8\\.(dns|email)\\.dump\\.partial', path.name) is None or
        path.name.startswith('0' * 64 + '-')):
        raise Pending('unsupported archive listing input pathname')
    before = KERNEL.trusted_binary(RESTORE)
    context = KERNEL.uint(KERNEL.namespace(), 2**64 - 1)
    if context == 0:
        raise Pending('invalid archive listing namespace')
    until = min(end, KERNEL.now() + KERNEL.QUERY_SECONDS)
    STAGE.admission(until)
    cause, selector = None, None
    child = subprocess.Popen([str(RESTORE), '--list', str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C'}, close_fds=True, start_new_session=True)
    try:
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        selector = selectors.DefaultSelector()
        for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            STAGE.admission(until)
            remaining = until - KERNEL.now()
            if remaining <= 0:
                raise Pending('archive listing capture window expired')
            for key, _ in selector.select(remaining):
                part = os.read(key.fileobj.fileno(), min(65536, maximum + 1 - len(buffers[key.data])))
                if not part:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                if len(buffer) + len(part) > maximum:
                    raise Pending('archive listing channel exceeds bound')
                buffer.extend(part)
        STAGE.admission(until)
        remaining = until - KERNEL.now()
        if remaining <= 0:
            raise Pending('archive listing completion window expired')
        code = child.wait(timeout=remaining)
        if type(code) is not int or code != 0 or buffers['stderr']:
            raise Pending('archive listing failed or warned')
        if KERNEL.trusted_binary(RESTORE) != before or KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive listing executable or context changed')
        STAGE.admission(until)
        return bytes(buffers['stdout'])
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, selector = selector, None
        cleanup = close_child(child, closing)
        if cleanup:
            raise STAGE.CleanupFailure(cause, cleanup) from cause


def inspect_stage(raw, maximum, read=None, deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid archive inspection inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    if type(maximum) is not int or not 1 <= maximum <= MAX_LISTING or read is not None and not callable(read):
        raise Pending('unsupported archive inspection delivery or bound')
    record = checked(raw)
    context = KERNEL.uint(KERNEL.namespace(), 2**64 - 1)
    if context == 0:
        raise Pending('invalid archive inspection namespace')
    path = Path(record['directory'])
    STAGE.admission(end)
    before = STAGE.directory_identity(path)
    if list(before) != record['directory_identity']:
        raise Pending('archive staging directory differs from receipt')
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    cause = None
    try:
        STAGE.directory_matches(path, directory, before)
        fcntl.flock(directory, fcntl.LOCK_SH | fcntl.LOCK_NB)
        identity = tuple(record['identity'])
        STAGE.readback(directory, record['leaf'], identity, record['bytes'], record['sha256'], end)
        STAGE.directory_matches(path, directory, before)
        executable = KERNEL.trusted_binary(RESTORE)
        STAGE.admission(end)
        if KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive inspection pre-entry context changed')
        listing = (native if read is None else read)(path / record['leaf'], maximum, end)
        STAGE.admission(end)
        if type(listing) is not bytes or not 1 <= len(listing) <= maximum:
            raise Pending('unsupported or oversized archive listing bytes')
        payload = PREP.canonical({'schema': 1, 'state': 'private-archive-listing-source-only',
            'stage': record, 'stage_sha256': hashlib.sha256(raw).hexdigest(), 'namespace': context,
            'argv': [str(RESTORE), '--list', str(path / record['leaf'])],
            'executable': list(executable), 'listing_limit_bytes': maximum,
            'listing_bytes': len(listing), 'listing_sha256': hashlib.sha256(listing).hexdigest(),
            'listing_hex': listing.hex()})
        if len(payload) > MAX_OUTPUT:
            raise Pending('archive inspection receipt exceeds bound')
        STAGE.readback(directory, record['leaf'], identity, record['bytes'], record['sha256'], end)
        STAGE.directory_matches(path, directory, before)
        if KERNEL.trusted_binary(RESTORE) != executable or KERNEL.uint(KERNEL.namespace(), 2**64 - 1) != context:
            raise Pending('archive inspection final executable or context changed')
        STAGE.admission(end)
        return payload
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, directory = directory, None
        STAGE.close_retired(cause, closing)
" > "$S4B_STAGE/"lib/postgresql/archive_inspection.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"One lazy fixed dump-child stream; no real-host calling authority or publication.

Caller role/database inputs are validated syntax, NOT protected enrollment/NSS
or peer authentication. A future orchestrator must bind fresh backup intentions.
Constructing this stream does not start a child; an exclusive stage writer can
acquire its target before the first read. Failures poison the stream, never reset
it. EOF is returned only after both channels close, root zero/no warning and
checked completion. This is not archive validity, restore, durability or ownership.
\"\"\"
import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import signal
import subprocess

SPEC = importlib.util.spec_from_file_location('debian13s4_dump_inputs', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
RUNUSER = Path('/usr/sbin/runuser')
DUMP = Path('/usr/lib/postgresql/17/bin/pg_dump')
MAX_BYTES = 1 << 40
MAX_STDERR = 1048576
CHUNK = 65536
MAX_RECEIPT = 16384


class Uncertain(RuntimeError):
    \"\"\"Preserve the original cause and separate cleanup failures; no second child.\"\"\"
    def __init__(self, cause, evidence, cleanup):
        super().__init__('dump child may have entered; no automatic retry')
        self.cause, self.evidence, self.cleanup = cause, evidence, cleanup


class DumpStream:
    def __init__(self, role, database, limit, stderr_limit, seconds, lock_wait_ms, deadline=None):
        role, database = PREP.identifier(role), PREP.identifier(database)
        for value, low, high in ((limit,1024,MAX_BYTES),(stderr_limit,1,MAX_STDERR),
                                 (seconds,1,3600),(lock_wait_ms,1,60000)):
            if type(value) is not int or not low <= value <= high:
                raise Pending('unsupported explicit dump stream bound')
        start = KERNEL.now()
        if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
            raise Pending('invalid inherited dump stream deadline')
        self.end = min(start+seconds,deadline) if deadline is not None else start+seconds
        self.argv = (str(RUNUSER),'-u',role,'--',str(DUMP),'--format=custom','--no-password',
            '--host',PREP.SOCKET_DIRECTORY,'--port','5432','--username',role,'--dbname',database,
            '--lock-wait-timeout='+str(lock_wait_ms))
        self.limit, self.stderr_limit = limit, stderr_limit
        self.child, self.selector, self.context, self.executables = None, None, None, None
        self.streams = {}; self.received = 0; self.hashed = hashlib.sha256(); self.stderr = bytearray()
        self.started, self.closed, self.done = False, False, False
        self.receipt, self.poison = None, None

    def fence(self):
        if KERNEL.now() >= self.end:
            raise Pending('dump stream admission window expired')
        if self.context is not None:
            current = KERNEL.namespace()
            if type(current) is not int or current != self.context:
                raise Pending('dump stream namespace changed')

    def start(self):
        if self.started or self.closed:
            raise Pending('dump stream cannot enter twice')
        self.fence()
        context = KERNEL.uint(KERNEL.namespace(),2**64-1)
        if not context: raise Pending('missing dump stream namespace')
        self.context = context
        self.executables = (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(DUMP))
        self.fence()
        self.started = True # A Popen error may follow an attempted child entry.
        self.child = subprocess.Popen(self.argv,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'},close_fds=True,start_new_session=True)
        self.streams = {'stdout':self.child.stdout,'stderr':self.child.stderr}
        self.selector = selectors.DefaultSelector()
        for name, stream in self.streams.items():
            os.set_blocking(stream.fileno(),False)
            self.selector.register(stream,selectors.EVENT_READ,name)

    def evidence(self):
        return (self.argv,self.context,self.executables,self.received,self.hashed.hexdigest(),
                bytes(self.stderr),None if self.child is None else self.child.returncode,
                self.started,self.closed)

    def close(self):
        if self.closed: return ()
        self.closed = True # Retirement precedes every cleanup attempt.
        errors = []
        if self.child is not None and self.child.returncode is None:
            try:
                os.killpg(self.child.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            except BaseException as error: errors.append(error)
            try:
                self.child.wait(timeout=KERNEL.CLEANUP_SECONDS)
            except BaseException as error: errors.append(error)
        selector,self.selector = self.selector,None
        if selector is not None:
            try: selector.close()
            except BaseException as error: errors.append(error)
        for name in ('stdout','stderr'):
            stream = self.streams.pop(name,None)
            if self.child is not None:
                if stream is None: stream = getattr(self.child,name,None)
                setattr(self.child,name,None) # Retire the Popen reference before close.
            if stream is not None:
                try: stream.close()
                except BaseException as error: errors.append(error)
        return tuple(errors)

    def fail(self, cause):
        cleanup = self.close()
        if self.started:
            self.poison = Uncertain(cause,self.evidence(),cleanup)
            raise self.poison from cause
        if cleanup:
            raise Uncertain(cause,self.evidence(),cleanup) from cause
        raise cause

    def finish(self):
        self.fence()
        remaining = self.end-KERNEL.now()
        if remaining <= 0: raise Pending('dump completion window expired')
        code = self.child.wait(timeout=remaining)
        self.fence()
        if type(code) is not int or code != 0 or self.stderr or not self.received:
            raise Pending('dump child failed, warned or produced no archive bytes')
        receipt = PREP.canonical({'schema':1,'state':'dump-stream-receipt-only',
            'argv':list(self.argv),'namespace':self.context,
            'executables':[list(row) for row in self.executables],
            'received_bytes':self.received,'received_sha256':self.hashed.hexdigest(),
            'limit_bytes':self.limit,'stderr_limit_bytes':self.stderr_limit,
            'root_exit':code,'stderr_hex':bytes(self.stderr).hex()})
        if len(receipt)>MAX_RECEIPT: raise Pending('dump stream receipt exceeds bound')
        if (KERNEL.trusted_binary(RUNUSER),KERNEL.trusted_binary(DUMP))!=self.executables:
            raise Pending('dump stream executable changed')
        self.fence()
        cleanup = self.close()
        if cleanup: raise Uncertain(cleanup[0],self.evidence(),cleanup[1:]) from cleanup[0]
        self.receipt, self.done = receipt, True

    def read(self, requested):
        if self.poison is not None: raise self.poison
        if type(requested) is not int or not 1 <= requested <= CHUNK:
            self.fail(Pending('unsupported dump stream read size'))
        if self.done: return b''
        if self.closed: raise Pending('dump stream is retired')
        try:
            if not self.started: self.start()
            self.fence()
            while self.selector.get_map():
                self.fence(); remaining = self.end-KERNEL.now()
                if remaining<=0: raise Pending('dump capture window expired')
                chunk = None
                for key,_ in self.selector.select(remaining):
                    size = min(requested,self.limit-self.received+1) if key.data=='stdout' else min(CHUNK,self.stderr_limit-len(self.stderr)+1)
                    part = os.read(key.fileobj.fileno(),size)
                    self.fence()
                    if not part:
                        self.selector.unregister(key.fileobj);continue
                    if key.data=='stdout':
                        self.received += len(part);self.hashed.update(part)
                        if self.received>self.limit: raise Pending('dump stdout exceeds byte bound')
                        chunk = part
                    else:
                        self.stderr.extend(part)
                        if len(self.stderr)>self.stderr_limit: raise Pending('dump stderr exceeds byte bound')
                if chunk is not None: return chunk
            self.finish(); return b''
        except BaseException as error:
            if isinstance(error,Uncertain) and self.closed:
                self.poison=error;raise
            self.fail(error)
" > "$S4B_STAGE/"lib/postgresql/dump_stream.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Fresh protected selected backup intention -> one create-only partial stage.

Default calls WOULD connect to PG and run a dump; real-host calling is unauthorized.
No directory provisioning, native archive inspection, final backup publication,
restore, durable uncertainty, retry or controller/installer join is supplied.
All receipts are SOURCE only; private ancestry/modules/native delivery are trusted,
read/lock equality is sequential/non-atomic/ABA/future, not ownership authentication.
\"\"\"
import importlib.util
import json
import os
from pathlib import Path
import fcntl


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


BACKUP = module('debian13s4_selected_backup', 'backup.py')
DUMP = module('debian13s4_selected_dump', 'dump_stream.py')
INSPECT = module('debian13s4_selected_inspection', 'archive_inspection.py')
STAGE = INSPECT.STAGE
PREP, KERNEL, Pending = BACKUP.PREP, BACKUP.KERNEL, BACKUP.Pending
# Contains two independent60s preparations and at most3600s dump admission;
# no accepted primitive window is widened, and these are not hard IO budgets.
ATTEMPT_SECONDS = 2 * BACKUP.ATTEMPT_SECONDS + 3600
MAX_OUTPUT = BACKUP.MAX_OUTPUT + DUMP.MAX_RECEIPT + STAGE.MAX_RECEIPT + 8192


class Incomplete(RuntimeError):
    \"\"\"Preserve original failure/uncertainty, known receipts and separate cleanup.\"\"\"
    def __init__(self, cause, uncertainty, stream_receipt, stage_receipt, cleanup, provenance):
        super().__init__('selected backup stage may exist; no automatic retry or publication')
        self.cause, self.uncertainty = cause, uncertainty
        self.stream_receipt, self.stage_receipt, self.cleanup = stream_receipt, stage_receipt, cleanup
        self.provenance = provenance # Original immutable intention and AFTER-cleanup capture.


def fence(end, context):
    PREP.fence(end)
    for kernel in (KERNEL, DUMP.KERNEL, STAGE.KERNEL):
        current = kernel.namespace()
        if type(current) is not int or current != context:
            raise Pending('selected backup stage namespace changed')


def intention(read, end):
    raw = BACKUP.prepare(read=read, deadline=end)
    value = BACKUP.ACCESS.decoded(raw, BACKUP.MAX_OUTPUT)
    if (type(value.get('schema')) is not int or value['schema'] != 1 or
        value.get('profile') != 'postgresql17-selected-logical-backup-intention-v1' or
        value.get('state') != 'postgresql-logical-backup-intention-only' or
        value['jobs'] != BACKUP.render(value['configuration']['value'], value['source_intention']) or
        raw != PREP.canonical(value)):
        raise Pending('selected stage requires the complete real canonical backup intention')
    return raw, value


def stage_selected(application, stderr_limit, read=None, deadline=None):
    if type(application) is not str or application not in PREP.APPLICATIONS:
        raise Pending('unsupported selected PostgreSQL backup application')
    if type(stderr_limit) is not int or not 1 <= stderr_limit <= DUMP.MAX_STDERR or read is not None and not callable(read):
        raise Pending('unsupported explicit selected dump delivery or stderr bound')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid selected backup inherited deadline')
    end = min(start + ATTEMPT_SECONDS, deadline) if deadline is not None else start + ATTEMPT_SECONDS
    context = KERNEL.uint(KERNEL.namespace(), 2**64-1)
    if not context: raise Pending('missing selected backup context')
    fence(end, context)
    original, value = intention(read, end)
    if type(value['namespace']) is not int or value['namespace'] != context:
        raise Pending('selected backup intention context differs')
    settings = BACKUP.checked(value['configuration']['value']); job = value['jobs'][application]
    path = STAGE.TRUST_ROOT / Path(settings['directory']).relative_to('/')
    leaf = settings['generation'] + '-' + application + '.dump.partial'
    stream = DUMP.DumpStream(job['role'],job['database'],settings['archive_limit_bytes'],stderr_limit,
        settings['dump_timeout_seconds'],settings['lock_wait_ms'],deadline=end)
    staged = None; directory = None
    try:
        if tuple(job['dump_argv']) != stream.argv or job['dump_environment'] != {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}:
            raise Pending('selected dump argv or environment differs from protected intention')
        fence(end, context)
        staged = STAGE.stage(path,leaf,stream,settings['archive_limit_bytes'],deadline=end)
        if stream.done is not True or stream.closed is not True or type(stream.receipt) is not bytes:
            raise Pending('selected stage lacks checked dump completion')
        stage_value = INSPECT.checked(staged)
        stream_value = BACKUP.ACCESS.decoded(stream.receipt,DUMP.MAX_RECEIPT)
        expected = {'schema':1,'state':'dump-stream-receipt-only','argv':list(stream.argv),
            'namespace':stream.context,'executables':[list(row) for row in stream.executables],
            'received_bytes':stream.received,'received_sha256':stream.hashed.hexdigest(),
            'limit_bytes':stream.limit,'stderr_limit_bytes':stream.stderr_limit,
            'root_exit':stream.child.returncode,'stderr_hex':bytes(stream.stderr).hex()}
        if type(stream.child.returncode) is not int or stream.child.returncode != 0 or stream.stderr or stream.receipt != PREP.canonical(expected):
            raise Pending('complete dump receipt differs from actual captured completion')
        if (stream_value['namespace'] != context or stream_value['argv'] != job['dump_argv'] or
            stream_value['root_exit'] != 0 or stream_value['stderr_hex'] != '' or
            stream_value['received_bytes'] != stage_value['bytes'] or
            stream_value['received_sha256'] != stage_value['sha256']):
            raise Pending('selected protected stage and received dump bytes differ')
        before = tuple(stage_value['directory_identity'])
        directory = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(path,directory,before)
        fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload = PREP.canonical({'schema':1,'state':'protected-selected-dump-stage-source-only',
            'application':application,'namespace':context,'backup_intention':value,
            'stream':stream_value,'stage':stage_value})
        if len(payload)>MAX_OUTPUT: raise Pending('selected backup stage receipt exceeds bound')
        final, _ = intention(read,end)
        if final != original: raise Pending('complete protected backup intention changed after staging')
        STAGE.readback(directory,leaf,tuple(stage_value['identity']),stage_value['bytes'],stage_value['sha256'],end)
        STAGE.directory_matches(path,directory,before)
        if [list(DUMP.KERNEL.trusted_binary(p)) for p in (DUMP.RUNUSER,DUMP.DUMP)] != stream_value['executables']:
            raise Pending('selected dump executable changed after staging')
        fence(end,context)
        closing, directory = directory, None
        os.close(closing)
        cleanup = stream.close()
        if cleanup: raise DUMP.Uncertain(cleanup[0],stream.evidence(),cleanup[1:]) from cleanup[0]
        return payload
    except BaseException as cause:
        cleanup = list(STAGE.cleanup_errors(cause))
        if directory is not None:
            closing, directory = directory, None
            try: os.close(closing)
            except BaseException as error: cleanup.append(error)
        try: cleanup.extend(stream.close())
        except BaseException as error: cleanup.append(error)
        uncertainty = stream.poison
        if isinstance(cause,DUMP.Uncertain): uncertainty = cause
        if uncertainty is None and stream.started and not stream.done:
            uncertainty = DUMP.Uncertain(cause,stream.evidence(),tuple(cleanup))
        raise Incomplete(cause,uncertainty,stream.receipt,staged,tuple(cleanup),
            (original,application,stderr_limit,stream.evidence())) from cause
" > "$S4B_STAGE/"lib/postgresql/selected_stage.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Fresh protected selection -> whole private staged-byte listing SOURCE only.

Default calls WOULD protected-read/connect PG/run pg_restore --list on the host;
none is authorized here. Reported historical dump success/public receipts are
forgeable, not origin, ownership, archive validity/completeness or backup proof.
This entry never creates/dumps/promotes/restores/deletes/retries a stage. Separate
locks/equal reads are non-atomic/ABA/future; honest modules/native delivery/private
ancestry/finite IO and caller custody of failures remain required.
\"\"\"
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('debian13s4_selected_listing_history',Path(__file__).with_name('selected_uncertainty.py'))
HISTORY = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(HISTORY)
SELECTED, BACKUP, PREP, KERNEL, Pending = HISTORY.SELECTED, HISTORY.BACKUP, HISTORY.PREP, HISTORY.KERNEL, HISTORY.Pending
INSPECT, STAGE = SELECTED.INSPECT, SELECTED.STAGE
ATTEMPT_SECONDS = 2 * BACKUP.ATTEMPT_SECONDS + INSPECT.ATTEMPT_SECONDS
MAX_OUTPUT = SELECTED.MAX_OUTPUT + INSPECT.MAX_OUTPUT + 8192


class Incomplete(RuntimeError):
    \"\"\"Original selection and known listing remain distinct; no retry permission.\"\"\"
    def __init__(self, cause, selection, listing, cleanup):
        super().__init__('selected stage listing incomplete; stage retained, no promotion or automatic retry')
        self.cause, self.selection, self.listing, self.cleanup = cause, selection, listing, cleanup


def checked(raw):
    \"\"\"Historical rendering/type correspondence ONLY, no fresh observer or clock.\"\"\"
    value = BACKUP.ACCESS.decoded(raw,SELECTED.MAX_OUTPUT)
    HISTORY.fields(value,'schema state application namespace backup_intention stream stage')
    app = value['application']
    if type(value['schema']) is not int or value['schema'] != 1 or value['state'] != 'protected-selected-dump-stage-source-only' or type(app) is not str or app not in PREP.APPLICATIONS or type(value['namespace']) is not int or not 0 < value['namespace'] < 2**64:
        raise Pending('unsupported historical selected-stage receipt')
    plan = HISTORY.intention(PREP.canonical(value['backup_intention']))
    settings = BACKUP.checked(plan['configuration']['value']);job = plan['jobs'][app]
    stage = INSPECT.checked(PREP.canonical(value['stage']))
    path = STAGE.TRUST_ROOT/Path(settings['directory']).relative_to('/')
    if stage['directory'] != str(path) or stage['leaf'] != settings['generation']+'-'+app+'.dump.partial' or stage['limit_bytes'] != settings['archive_limit_bytes'] or plan['namespace'] != value['namespace']:
        raise Pending('historical selected stage differs from protected job intention')
    stream = value['stream']
    HISTORY.fields(stream,'schema state argv namespace executables received_bytes received_sha256 limit_bytes stderr_limit_bytes root_exit stderr_hex')
    if type(stream['schema']) is not int or stream['schema'] != 1 or stream['state'] != 'dump-stream-receipt-only' or stream['argv'] != job['dump_argv'] or type(stream['namespace']) is not int or stream['namespace'] != value['namespace'] or type(stream['root_exit']) is not int or stream['root_exit'] != 0 or stream['stderr_hex'] != '' or type(stream['stderr_limit_bytes']) is not int or not 1 <= stream['stderr_limit_bytes'] <= SELECTED.DUMP.MAX_STDERR:
        raise Pending('historical selected dump receipt types or job differ')
    if type(stream['received_bytes']) is not int or stream['received_bytes'] != stage['bytes'] or stream['received_sha256'] != stage['sha256'] or type(stream['limit_bytes']) is not int or stream['limit_bytes'] != stage['limit_bytes']:
        raise Pending('historical dump capture and stage bytes differ')
    rows = stream['executables']
    if type(rows) is not list or len(rows) != 2 or any(type(row) is not list or len(row) != 8 or any(type(n) is not int for n in row) for row in rows):
        raise Pending('untyped historical dump executable signatures')
    if raw != PREP.canonical(value):raise Pending('selected-stage receipt is not canonical')
    return value


def fence(end, context):
    PREP.fence(end)
    for kernel in (KERNEL,INSPECT.KERNEL):
        current = kernel.namespace()
        if type(current) is not int or current != context:raise Pending('selected inspection namespace changed')


def inspect_selected(raw, read=None, listing=None, deadline=None):
    if read is not None and not callable(read) or listing is not None and not callable(listing):
        raise Pending('unsupported selected inspection deliveries')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):raise Pending('invalid selected inspection inherited deadline')
    end = min(start+ATTEMPT_SECONDS,deadline) if deadline is not None else start+ATTEMPT_SECONDS
    context = KERNEL.uint(KERNEL.namespace(),2**64-1)
    if not context:raise Pending('missing selected inspection context')
    fence(end,context);value = checked(raw)
    if value['namespace'] != context:raise Pending('historical selected-stage context differs')
    original = PREP.canonical(value['backup_intention']);settings = BACKUP.checked(value['backup_intention']['configuration']['value'])
    job = value['backup_intention']['jobs'][value['application']];stage = value['stage']
    path = Path(stage['directory']);target = path/stage['leaf']
    if job['inspection_argv'][0] != str(INSPECT.RESTORE) or job['inspection_environment'] != {'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'}:
        raise Pending('selected inspection binary or environment differs from protected intention')
    listing_receipt, directory = None, None
    try:
        fresh,_ = SELECTED.intention(read,end)
        if fresh != original:raise Pending('complete fresh backup intention differs before listing')
        fence(end,context)
        listing_receipt = INSPECT.inspect_stage(PREP.canonical(stage),settings['inventory_limit_bytes'],read=listing,deadline=end)
        observed = BACKUP.ACCESS.decoded(listing_receipt,INSPECT.MAX_OUTPUT)
        # The owned library supplies this receipt. Complete typed byte equality
        # prevents Boolean/int aliasing or a substituted partial receipt.
        expected = {'schema':1,'state':'private-archive-listing-source-only','stage':stage,
            'stage_sha256':hashlib.sha256(PREP.canonical(stage)).hexdigest(),'namespace':context,
            'argv':[str(INSPECT.RESTORE),'--list',str(target)],'executable':observed['executable'],
            'listing_limit_bytes':settings['inventory_limit_bytes'],'listing_bytes':observed['listing_bytes'],
            'listing_sha256':observed['listing_sha256'],'listing_hex':observed['listing_hex']}
        data = HISTORY.hex_bytes(observed['listing_hex'],settings['inventory_limit_bytes'])
        if not data or type(observed['listing_bytes']) is not int or observed['listing_bytes'] != len(data) or observed['listing_sha256'] != hashlib.sha256(data).hexdigest() or listing_receipt != PREP.canonical(expected):
            raise Pending('complete selected listing receipt differs')
        executable = observed['executable']
        if type(executable) is not list or len(executable) != 8 or any(type(n) is not int for n in executable):raise Pending('untyped selected listing executable')
        before = tuple(stage['directory_identity'])
        directory = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(path,directory,before);fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload = PREP.canonical({'schema':1,'state':'protected-selected-stage-listing-source-only',
            'namespace':context,'selection':value,'selection_sha256':hashlib.sha256(raw).hexdigest(),
            'inspection':observed,'inspection_sha256':hashlib.sha256(listing_receipt).hexdigest()})
        if len(payload)>MAX_OUTPUT:raise Pending('selected listing outer receipt exceeds bound')
        final,_ = SELECTED.intention(read,end)
        if final != original:raise Pending('complete fresh backup intention changed after listing')
        STAGE.readback(directory,stage['leaf'],tuple(stage['identity']),stage['bytes'],stage['sha256'],end)
        STAGE.directory_matches(path,directory,before)
        if list(INSPECT.KERNEL.trusted_binary(INSPECT.RESTORE)) != executable:raise Pending('selected inspection executable changed')
        fence(end,context)
        closing,directory = directory,None;os.close(closing)
        return payload
    except BaseException as cause:
        cleanup = list(STAGE.cleanup_errors(cause))
        if directory is not None:
            closing,directory = directory,None
            try:os.close(closing)
            except BaseException as error:cleanup.append(error)
        raise Incomplete(cause,raw,listing_receipt,tuple(cleanup)) from cause
" > "$S4B_STAGE/"lib/postgresql/selected_inspection.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Private historical selected-stage failure custody; NEVER a retry decision.

No stage/dump/source observation is called here. Original intentions, captures,
exceptions and public hashes are reported/forgeable historical DATA. Known
receipts are retained as OPAQUE bytes, including rejected receipt spellings;
none is promoted to archive validity, completion, ownership or publication.
Separate history failure MUST leave the original Incomplete/Uncertain intact.
Trusted modules/private ancestry/cooperating locks/finite IO are required;
equal samples and sync are not atomicity, non-ABA or power-loss guarantees.
\"\"\"
import hashlib
import importlib.util
from pathlib import Path
import re


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


SELECTED = module('debian13s4_selected_history_source', Path(__file__).with_name('selected_stage.py'))
_STORAGE = module('debian13s4_selected_history_storage', Path(__file__).with_name('private_storage.py'))
BACKUP, DUMP, PREP, KERNEL, Pending = SELECTED.BACKUP, SELECTED.DUMP, SELECTED.PREP, SELECTED.KERNEL, SELECTED.Pending
LEAF = 'selected-stage-incomplete.json'
STATE = 'historical-selected-stage-incomplete-no-retry'
MAX_RECORD = 6 * BACKUP.MAX_OUTPUT + 4 * DUMP.MAX_STDERR + 2 * DUMP.MAX_RECEIPT + 2 * SELECTED.STAGE.MAX_RECEIPT + 65536
MAX_BYTES = 2 * MAX_RECORD + 4096


def encoded(value):
    return PREP.canonical(value)


def fields(value, names):
    KERNEL.known(value, set(names.split()), set(names.split()))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_bytes(value, limit):
    if type(value) is not str or len(value) > 2 * limit or len(value) % 2 or re.fullmatch('[0-9a-f]*', value) is None:
        raise Pending('unsupported historical binary prefix')
    return bytes.fromhex(value)


def diagnostic(value):
    if type(value) is not list or len(value) != 2 or type(value[0]) is not str or re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',value[0]) is None or type(value[1]) is not str or len(value[1]) > 1024:
        raise Pending('unsupported historical failure diagnostic')
    value[1].encode('utf-8')


def diagnostics(values):
    if type(values) is not list or len(values) > 16:raise Pending('historical diagnostic inventory exceeds bound')
    for value in values:diagnostic(value)


def describe(error):
    if not isinstance(error,BaseException):raise Pending('historical failure is not an exception')
    row = [type(error).__name__,str(error)[:1024]];diagnostic(row);return row


def chain(error):
    rows, seen = [], set()
    while error is not None:
        if id(error) in seen or len(rows) == 16:raise Pending('cyclic or excessive historical cause chain')
        seen.add(id(error));rows.append(describe(error))
        error = error.__cause__ if error.__cause__ is not None else (None if error.__suppress_context__ else error.__context__)
    return rows


def intention(raw):
    \"\"\"Re-render historical jobs/PG plan; preserve access/account facts as DATA.\"\"\"
    value = BACKUP.ACCESS.decoded(raw,BACKUP.MAX_OUTPUT)
    fields(value,'schema profile state namespace configuration source_intention enrollment access jobs')
    if type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != 'postgresql17-selected-logical-backup-intention-v1' or value['state'] != 'postgresql-logical-backup-intention-only' or type(value['namespace']) is not int or not 0 < value['namespace'] < 2**64:
        raise Pending('unsupported historical selected backup intention')
    fields(value['configuration'],'value source');settings = BACKUP.checked(value['configuration']['value'])
    source = value['source_intention']
    fields(source,'schema profile state namespace configuration account_source accounts plan')
    fields(source['configuration'],'value source')
    deployment = PREP.checked(source['configuration']['value'])
    if type(source['schema']) is not int or source['schema'] != 1 or source['namespace'] != value['namespace'] or type(source['namespace']) is not int or source['profile'] != 'postgresql17-local-peer-new-cluster-intention-v1' or source['state'] != 'local-peer-provisioning-intention-only' or encoded(source['plan']) != encoded(PREP.render(deployment)) or encoded(value['jobs']) != encoded(BACKUP.render(settings,source)) or raw != encoded(value):
        raise Pending('historical protected intention rendering or encoding differs')
    return value


def evidence(value, plan, application, stderr_limit):
    if type(value) is not list or len(value) != 9:raise Pending('unsupported historical dump capture')
    argv, context, executables, count, sha, stderr, code, started, closed = value
    job = plan['jobs'][application];settings = plan['configuration']['value']
    if type(argv) is not list or argv != job['dump_argv'] or type(count) is not int or not 0 <= count <= settings['archive_limit_bytes'] + 1 or type(sha) is not str or re.fullmatch('[0-9a-f]{64}',sha) is None or type(started) is not bool or closed is not True or (code is not None and (type(code) is not int or not -(1<<31) <= code < (1<<31))):
        raise Pending('historical dump capture types or job differ')
    hex_bytes(stderr,stderr_limit+1)
    if context is not None and (type(context) is not int or context != plan['namespace']):raise Pending('historical dump context differs')
    if executables is not None:
        if type(executables) is not list or len(executables) != 2:raise Pending('unsupported historical executable inventory')
        for row in executables:
            if type(row) is not list or len(row) != 8 or any(type(n) is not int for n in row):raise Pending('untyped historical executable signature')
    if started and (context is None or executables is None):raise Pending('entered dump lacks reported source identity')
    if not started and (count or stderr or code is not None):raise Pending('pre-entry capture reports produced bytes or exit')
    if count == 0 and sha != digest(b''):raise Pending('empty received prefix hash differs')


def checked(raw):
    value = BACKUP.ACCESS.decoded(raw,MAX_RECORD)
    fields(value,'schema state intention intention_sha256 application stderr_limit_bytes cause cleanup capture uncertainty stream_receipt_hex stage_receipt_hex')
    if value['schema'] != 'debian13s4-selected-stage-incomplete-1' or value['state'] != STATE or type(value['intention']) is not str or type(value['application']) is not str or value['application'] not in PREP.APPLICATIONS or type(value['stderr_limit_bytes']) is not int or not 1 <= value['stderr_limit_bytes'] <= DUMP.MAX_STDERR:
        raise Pending('unsupported selected-stage history schema or bounds')
    original = value['intention'].encode('utf-8');plan = intention(original)
    if value['intention_sha256'] != digest(original):raise Pending('historical intention hash differs')
    diagnostics(value['cause']);diagnostics(value['cleanup'])
    if not value['cause']:raise Pending('missing historical original failure')
    evidence(value['capture'],plan,value['application'],value['stderr_limit_bytes'])
    uncertain = value['uncertainty']
    if uncertain is not None:
        fields(uncertain,'cause cleanup capture');diagnostics(uncertain['cause']);diagnostics(uncertain['cleanup'])
        if not uncertain['cause']:raise Pending('missing uncertainty cause')
        evidence(uncertain['capture'],plan,value['application'],value['stderr_limit_bytes'])
    for field,maximum in (('stream_receipt_hex',DUMP.MAX_RECEIPT),('stage_receipt_hex',SELECTED.STAGE.MAX_RECEIPT)):
        if value[field] is not None:hex_bytes(value[field],maximum)
    if raw != encoded(value):raise Pending('historical selected-stage bytes are not canonical')
    return value


def copy_capture(row):
    if type(row) is not tuple or len(row) != 9 or type(row[0]) is not tuple or type(row[5]) is not bytes or (row[2] is not None and (type(row[2]) is not tuple or any(type(item) is not tuple for item in row[2]))):
        raise Pending('unsupported immutable selected dump evidence')
    if len(row[0]) != 16 or any(type(item) is not str or len(item) > 512 for item in row[0]) or (row[2] is not None and (len(row[2]) != 2 or any(len(item) != 8 for item in row[2]))):
        raise Pending('historical capture inventory exceeds bound')
    if len(row[5]) > DUMP.MAX_STDERR+1:raise Pending('historical warning prefix exceeds bound')
    return [list(row[0]),row[1],None if row[2] is None else [list(item) for item in row[2]],row[3],row[4],row[5].hex(),row[6],row[7],row[8]]


def capture(error):
    if type(error) is not SELECTED.Incomplete or type(error.provenance) is not tuple or len(error.provenance) != 4 or type(error.cleanup) is not tuple or len(error.cleanup) > 16:
        raise Pending('exact selected-stage incomplete delivery is required')
    original, app, stderr_limit, row = error.provenance
    intention(original)
    receipts = []
    for raw, maximum in ((error.stream_receipt,DUMP.MAX_RECEIPT),(error.stage_receipt,SELECTED.STAGE.MAX_RECEIPT)):
        if raw is not None and (type(raw) is not bytes or len(raw) > maximum):raise Pending('known opaque receipt exceeds bound')
        receipts.append(None if raw is None else raw.hex())
    uncertain = error.uncertainty
    if uncertain is not None:
        if type(uncertain) is not DUMP.Uncertain or type(uncertain.cleanup) is not tuple or len(uncertain.cleanup) > 16:raise Pending('unsupported original selected dump uncertainty')
        uncertain = {'cause':chain(uncertain.cause),'cleanup':[describe(e) for e in uncertain.cleanup],'capture':copy_capture(uncertain.evidence)}
    raw = encoded({'schema':'debian13s4-selected-stage-incomplete-1','state':STATE,
        'intention':original.decode('utf-8'),'intention_sha256':digest(original),'application':app,'stderr_limit_bytes':stderr_limit,
        'cause':chain(error.cause),'cleanup':[describe(e) for e in error.cleanup],'capture':copy_capture(row),
        'uncertainty':uncertain,'stream_receipt_hex':receipts[0],'stage_receipt_hex':receipts[1]})
    checked(raw);return raw


def envelope(payload):
    checked(payload)
    raw = encoded({'schema':'debian13s4-selected-stage-incomplete-history-1','state':STATE,
        'payload':payload.decode('utf-8'),'payload_sha256':digest(payload)})
    if len(raw)>MAX_BYTES:raise Pending('selected-stage history envelope exceeds bound')
    return raw


def stored(raw):
    value = BACKUP.ACCESS.decoded(raw,MAX_BYTES);fields(value,'schema state payload payload_sha256')
    if value['schema'] != 'debian13s4-selected-stage-incomplete-history-1' or value['state'] != STATE or type(value['payload']) is not str:raise Pending('unsupported selected-stage history envelope')
    payload = value['payload'].encode('utf-8');checked(payload)
    if value['payload_sha256'] != digest(payload) or raw != encoded(value):raise Pending('selected-stage history envelope differs')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES, _STORAGE.envelope, _STORAGE.checked = LEAF, MAX_BYTES, envelope, stored


def record(path, error, deadline=None):
    \"\"\"Storage errors propagate separately; they NEVER discharge original failure.\"\"\"
    end = _STORAGE.window(deadline);raw = capture(error);_STORAGE.admission(end)
    return _STORAGE.create(path,raw,deadline=end)


def load(path, deadline=None):
    return _STORAGE.load(path,deadline=deadline)
" > "$S4B_STAGE/"lib/postgresql/selected_uncertainty.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Retain whole selected-stage/listing SOURCE correspondence in private history.

This is a historical source manifest, NEVER completed/valid backup metadata or
promotion, restore, retry, ownership, native-origin or readiness authority.
No native/source observer/default directory/CLI/controller is called. Whole
reported receipts and public hashes/generation may be forged. Existing private
storage requires honest ancestry/modules/cooperating locks/finite IO; sync and
sequential equal samples are not atomicity/non-ABA/physical persistence proof.
\"\"\"
import hashlib
import importlib.util
from pathlib import Path
import stat


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


LISTING=module('debian13s4_stage_manifest_listing',Path(__file__).with_name('selected_inspection.py'))
_STORAGE=module('debian13s4_stage_manifest_storage',Path(__file__).with_name('private_storage.py'))
HISTORY, PREP, KERNEL, Pending=LISTING.HISTORY,LISTING.PREP,LISTING.KERNEL,LISTING.Pending
LEAF='selected-stage-manifest.json'
STATE='historical-selected-listing-manifest-only'
MAX_RECORD=2*LISTING.MAX_OUTPUT+4096
MAX_BYTES=2*MAX_RECORD+4096


def encoded(value):return PREP.canonical(value)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def listing_checked(raw):
    \"\"\"Recompute typed correspondence; never observe current state or re-list.\"\"\"
    value=LISTING.BACKUP.ACCESS.decoded(raw,LISTING.MAX_OUTPUT)
    HISTORY.fields(value,'schema state namespace selection selection_sha256 inspection inspection_sha256')
    if type(value['schema']) is not int or value['schema']!=1 or value['state']!='protected-selected-stage-listing-source-only' or type(value['namespace']) is not int or not 0<value['namespace']<2**64:
        raise Pending('unsupported historical selected listing profile')
    selection=encoded(value['selection']);selected=LISTING.checked(selection)
    plan=selected['backup_intention'];app=selected['application'];settings=LISTING.BACKUP.checked(plan['configuration']['value'])
    observed=value['inspection']
    HISTORY.fields(observed,'schema state stage stage_sha256 namespace argv executable listing_limit_bytes listing_bytes listing_sha256 listing_hex')
    stage=selected['stage'];stage_raw=encoded(stage)
    data=HISTORY.hex_bytes(observed['listing_hex'],settings['inventory_limit_bytes'])
    expected={'schema':1,'state':'private-archive-listing-source-only','stage':stage,'stage_sha256':digest(stage_raw),
        'namespace':selected['namespace'],'argv':[str(LISTING.INSPECT.RESTORE),'--list',str(Path(stage['directory'])/stage['leaf'])],
        'executable':observed['executable'],'listing_limit_bytes':settings['inventory_limit_bytes'],
        'listing_bytes':len(data),'listing_sha256':digest(data),'listing_hex':data.hex()}
    row=observed['executable']
    if type(row) is not list or len(row)!=8 or any(type(item) is not int for item in row):raise Pending('untyped historical listing executable')
    if any(item<0 for item in row[:6]) or not row[1] or not stat.S_ISREG(row[2]) or not row[2]&0o100 or row[2]&0o022 or row[3]!=LISTING.INSPECT.KERNEL.TRUSTED_UID:
        raise Pending('unsupported reported listing executable kind/owner/mode')
    if not data or value['namespace']!=selected['namespace'] or encoded(observed)!=encoded(expected) or value['selection_sha256']!=digest(selection) or value['inspection_sha256']!=digest(encoded(observed)) or raw!=encoded(value):
        raise Pending('whole historical selected listing correspondence differs')
    return value


def capture(raw):
    value=listing_checked(raw);selected=value['selection'];settings=selected['backup_intention']['configuration']['value']
    payload=encoded({'schema':'debian13s4-selected-stage-source-manifest-1','state':STATE,
        'application':selected['application'],'generation':settings['generation'],
        'selected_listing':raw.decode('utf-8'),'selected_listing_sha256':digest(raw)})
    checked(payload);return payload


def checked(raw):
    value=LISTING.BACKUP.ACCESS.decoded(raw,MAX_RECORD)
    HISTORY.fields(value,'schema state application generation selected_listing selected_listing_sha256')
    if value['schema']!='debian13s4-selected-stage-source-manifest-1' or value['state']!=STATE or type(value['selected_listing']) is not str:
        raise Pending('unsupported selected-stage source manifest')
    payload=value['selected_listing'].encode('utf-8');source=listing_checked(payload);selected=source['selection']
    if type(value['application']) is not str or value['application']!=selected['application'] or value['generation']!=selected['backup_intention']['configuration']['value']['generation'] or value['selected_listing_sha256']!=digest(payload) or raw!=encoded(value):
        raise Pending('historical source manifest label/integrity differs')
    return value


def envelope(payload):
    checked(payload)
    raw=encoded({'schema':'debian13s4-selected-stage-source-manifest-history-1','state':STATE,
        'payload':payload.decode('utf-8'),'payload_sha256':digest(payload)})
    if len(raw)>MAX_BYTES:raise Pending('historical source manifest envelope exceeds bound')
    return raw


def stored(raw):
    value=LISTING.BACKUP.ACCESS.decoded(raw,MAX_BYTES);HISTORY.fields(value,'schema state payload payload_sha256')
    if value['schema']!='debian13s4-selected-stage-source-manifest-history-1' or value['state']!=STATE or type(value['payload']) is not str:raise Pending('unsupported source manifest history envelope')
    payload=value['payload'].encode('utf-8');checked(payload)
    if value['payload_sha256']!=digest(payload) or raw!=encoded(value):raise Pending('source manifest envelope differs')
    return payload


_STORAGE.LEAF,_STORAGE.MAX_BYTES,_STORAGE.envelope,_STORAGE.checked=LEAF,MAX_BYTES,envelope,stored


def record(path,listing,deadline=None):
    \"\"\"No-replace historical storage; failure may leave bytes, never retry authority.\"\"\"
    end=_STORAGE.window(deadline);payload=capture(listing);_STORAGE.admission(end)
    return _STORAGE.create(path,payload,deadline=end)


def load(path,deadline=None):return _STORAGE.load(path,deadline=deadline)
" > "$S4B_STAGE/"lib/postgresql/stage_manifest.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"One create-only private backup-attempt slot; no reset or retry authority.

Every existing target blocks, including identical or partially written data.
Acquired files remain on failures. Public random correlation is not a credential,
registration/globaldedup/ownership/native completion or physical persistence.
Honest modules/private ancestry/cooperating locks/finite IO are required.
\"\"\"
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets

SPEC=importlib.util.spec_from_file_location('debian13s4_backup_attempt_storage',Path(__file__).with_name('private_storage.py'))
_STORAGE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(_STORAGE)
KERNEL,Pending=_STORAGE.KERNEL,_STORAGE.Pending
LEAF='selected-backup-attempt.json'
MAX_BYTES=4096
APPLICATIONS=('mk8.dns','mk8.email')


class Blocked(RuntimeError):
    \"\"\"The attempt slot remains closed even if acquisition or sync failed.\"\"\"


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')+b'\\n'


def checked(raw):
    value=_STORAGE.decoded(raw,MAX_BYTES)
    fields={'schema','state','namespace','application','correlation_id'}
    KERNEL.known(value,fields,fields)
    if value['schema']!='debian13s4-selected-backup-attempt-1' or value['state']!='backup-attempt-reserved-no-retry' or type(value['namespace']) is not int or not 0<value['namespace']<2**64 or type(value['application']) is not str or value['application'] not in APPLICATIONS or type(value['correlation_id']) is not str or re.fullmatch('[0-9a-f]{64}',value['correlation_id']) is None or value['correlation_id']=='0'*64 or raw!=encoded(value):
        raise Pending('unsupported historical backup attempt slot')
    return raw


def envelope(application,namespace):
    if type(application) is not str or application not in APPLICATIONS or type(namespace) is not int or not 0<namespace<2**64:raise Pending('unsupported backup attempt selector/context')
    marker=secrets.token_hex(32)
    raw=encoded({'schema':'debian13s4-selected-backup-attempt-1','state':'backup-attempt-reserved-no-retry','namespace':namespace,'application':application,'correlation_id':marker})
    checked(raw);return raw


_STORAGE.LEAF,_STORAGE.MAX_BYTES,_STORAGE.checked=LEAF,MAX_BYTES,checked


def reserve(path, application, namespace, deadline=None):
    \"\"\"Exclusive reservation; NEVER treat an identical existing record as success.\"\"\"
    end = _STORAGE.window(deadline)
    raw = envelope(application, namespace)
    _STORAGE.admission(end)
    directory, before = _STORAGE.locked(path, end)
    fd, acquired = None, False
    cause = None
    try:
        try:
            fd = os.open(LEAF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            acquired = True
            os.fchmod(fd, 0o600)
            identity = _STORAGE.file_identity(os.fstat(fd))
            if identity[0] != before[0] or identity != _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)):
                raise Pending('backup reservation descriptor or path disagrees')
            offset = 0
            while offset < len(raw):
                _STORAGE.admission(end)
                count = os.write(fd, raw[offset:])
                if type(count) is not int or not 0 < count <= len(raw) - offset:
                    raise Pending('backup reservation write did not advance')
                offset += count
            os.fsync(fd)
            identity = _STORAGE.file_identity(os.fstat(fd))
            if identity != _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)):
                raise Pending('backup reservation changed during write')
            _STORAGE.directory_matches(path, directory, before)
            _STORAGE.admission(end)
            closing, fd = fd, None
            os.close(closing)  # retire ownership before its ONE checked close
            os.fsync(directory)
            if checked(_STORAGE.read_at(directory, end)) != raw or \\
                    _STORAGE.file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False)) != identity:
                raise Pending('backup reservation readback or identity disagrees')
            _STORAGE.directory_matches(path, directory, before)
            _STORAGE.admission(end)
            return raw
        except BaseException as error:
            cause = error
            raise
        finally:
            closing, closing_directory, fd, directory = fd, directory, None, None
            _STORAGE.close_retired(cause, closing, closing_directory)
    except FileExistsError as error:
        raise Blocked('backup attempt slot already exists; no automatic retry') from error
    except BaseException as error:
        if acquired:
            raise Blocked('backup reservation may be visible; no automatic retry') from error
        raise


def load(path,deadline=None):return _STORAGE.load(path,deadline=deadline)
" > "$S4B_STAGE/"lib/postgresql/backup_attempt.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"One reserved selected-stage/listing/history SOURCE attempt; no host authority.

Default calls WOULD protected-read/connect PG/run dump/createpartial/list/store;
real-host calling remains unauthorized. No archive validity/completeness, final
backup, publication, restore, native recovery, reset or retry is supplied. Slots
are per-directory/cooperating history, not authenticated/global deduplication.
Sequential locks/reads/public hashes/markers are non-atomic/ABA/future; finite IO,
scheduling, honest modules/native delivery/private ancestry are assumed.
\"\"\"
import fcntl
import importlib.util
import os
from pathlib import Path


def module(name,leaf):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(leaf))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


MANIFEST=module('debian13s4_backup_lifecycle_manifest','stage_manifest.py')
ATTEMPT=module('debian13s4_backup_lifecycle_attempt','backup_attempt.py')
FAILURE=module('debian13s4_backup_lifecycle_failure','attempt_failure.py')
LISTING=MANIFEST.LISTING
UNCERTAINTY=LISTING.HISTORY
SELECTED=UNCERTAINTY.SELECTED # EXACT class consumed by historical uncertainty capture.
BACKUP,PREP,KERNEL,Pending=LISTING.BACKUP,LISTING.PREP,LISTING.KERNEL,LISTING.Pending
STAGE=SELECTED.STAGE
ATTEMPT_SECONDS=SELECTED.ATTEMPT_SECONDS+LISTING.ATTEMPT_SECONDS+BACKUP.ATTEMPT_SECONDS+30
MAX_OUTPUT=SELECTED.MAX_OUTPUT+LISTING.MAX_OUTPUT+MANIFEST.MAX_RECORD+ATTEMPT.MAX_BYTES+8192


class Blocked(RuntimeError):
    \"\"\"Keep original cause, known source outcomes and separate history/cleanup.\"\"\"
    def __init__(self,cause,reservation,selection,listing,manifest,history_error,cleanup):
        super().__init__('backup SOURCE attempt incomplete; reserved slot forbids automatic retry')
        self.cause,self.reservation,self.selection=cause,reservation,selection
        self.listing,self.manifest,self.history_error,self.cleanup=listing,manifest,history_error,cleanup
        self.failure_record,self.failure_record_error=None,None
        self.phase=None


def admission(end,context):LISTING.fence(end,context)


def cleanup_errors(cause):
    owned = (STAGE.CleanupFailure, *(module._STORAGE.CleanupFailure for module in
             (ATTEMPT, MANIFEST, UNCERTAINTY, FAILURE)))
    groups, seen = [], set()
    while cause is not None and id(cause) not in seen and len(seen) < 16:
        seen.add(id(cause))
        if type(cause) in owned: groups.append(cause.cleanup)
        cause = cause.__cause__
    errors, seen = [], set()
    for group in reversed(groups):
        for error in group:
            if id(error) not in seen:
                seen.add(id(error)); errors.append(error)
    return tuple(errors)


def outcomes_absent(path,end):
    backend=ATTEMPT._STORAGE;until=backend.window(end);directory,before=backend.locked(path,until)
    cause=None
    try:
        for leaf in (MANIFEST.LEAF,UNCERTAINTY.LEAF,FAILURE.LEAF):
            backend.admission(until)
            try:os.stat(leaf,dir_fd=directory,follow_symlinks=False)
            except FileNotFoundError:continue
            if leaf==FAILURE.LEAF:
                raise ATTEMPT.Blocked('backup failure history closes this attempt; no automatic retry')
            raise Pending('existing backup outcome history forbids another attempt')
        backend.directory_matches(path,directory,before);backend.admission(until)
    except BaseException as error:
        cause=error
        raise
    finally:
        closing,directory=directory,None
        backend.close_retired(cause,closing)


def run_once(path,application,stderr_limit,read=None,listing=None,deadline=None):
    if type(application) is not str or application not in PREP.APPLICATIONS or type(stderr_limit) is not int or not 1<=stderr_limit<=SELECTED.DUMP.MAX_STDERR or read is not None and not callable(read) or listing is not None and not callable(listing):
        raise Pending('unsupported explicit backup lifecycle selector/bounds/deliveries')
    start=KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline<=start):raise Pending('invalid backup lifecycle inherited deadline')
    end=min(start+ATTEMPT_SECONDS,deadline) if deadline is not None else start+ATTEMPT_SECONDS
    context=KERNEL.uint(KERNEL.namespace(),2**64-1)
    if not context:raise Pending('missing backup lifecycle context')
    query=BACKUP.ACCESS.LIVE.native if read is None else read
    inspect=LISTING.INSPECT.native if listing is None else listing
    def delivered(operation,*args):
        window=args[-1]
        if not KERNEL.finite_deadline(window) or window>end:raise Pending('backup delivery exceeds inherited window')
        admission(end,context);PREP.fence(window)
        raw=operation(*args)
        PREP.fence(window);admission(end,context)
        return raw
    def capture(kind,window):return delivered(query,kind,window)
    def list_stage(archive,maximum,window):return delivered(inspect,archive,maximum,window)
    admission(end,context);outcomes_absent(path,end)
    reservation=ATTEMPT.reserve(path,application,context,deadline=end)
    selected,listed,manifest,directory=None,None,None,None
    phase='pre-stage'
    try:
        outcomes_absent(path,end)
        if ATTEMPT.load(path,deadline=end)!=reservation:raise Pending('backup attempt changed before fresh stage')
        admission(end,context)
        phase='stage'
        selected=SELECTED.stage_selected(application,stderr_limit,read=capture,deadline=end)
        phase='pre-listing'
        outcomes_absent(path,end)
        if ATTEMPT.load(path,deadline=end)!=reservation:raise Pending('backup attempt changed before listing')
        admission(end,context)
        phase='listing'
        listed=LISTING.inspect_selected(selected,read=capture,listing=list_stage,deadline=end)
        phase='manifest'
        outcomes_absent(path,end)
        manifest=MANIFEST.record(path,listed,deadline=end)
        phase='final-validation'
        stage=LISTING.checked(selected)['stage'];result=MANIFEST.listing_checked(listed)
        original=PREP.canonical(result['selection']['backup_intention'])
        archive=Path(stage['directory']);before=tuple(stage['directory_identity'])
        directory=os.open(archive,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        STAGE.directory_matches(archive,directory,before);fcntl.flock(directory,fcntl.LOCK_SH|fcntl.LOCK_NB)
        payload=PREP.canonical({'schema':1,'state':'single-attempt-selected-backup-source-only','namespace':context,
            'application':application,'reservation':BACKUP.ACCESS.decoded(reservation,ATTEMPT.MAX_BYTES),
            'selection':result['selection'],'listing':result,'manifest':MANIFEST.checked(manifest)})
        if len(payload)>MAX_OUTPUT:raise Pending('backup lifecycle SOURCE result exceeds bound')
        final,_=SELECTED.intention(capture,end)
        if final!=original:raise Pending('complete protected backup intention changed after history')
        STAGE.readback(directory,stage['leaf'],tuple(stage['identity']),stage['bytes'],stage['sha256'],end)
        STAGE.directory_matches(archive,directory,before)
        if list(LISTING.INSPECT.KERNEL.trusted_binary(LISTING.INSPECT.RESTORE))!=result['inspection']['executable'] or [list(SELECTED.DUMP.KERNEL.trusted_binary(p)) for p in (SELECTED.DUMP.RUNUSER,SELECTED.DUMP.DUMP)]!=result['selection']['stream']['executables']:
            raise Pending('backup executable identities changed after history')
        if ATTEMPT.load(path,deadline=end)!=reservation or MANIFEST.load(path,deadline=end)!=manifest:raise Pending('checked backup attempt/outcome history changed')
        admission(end,context)
        closing,directory=directory,None;os.close(closing)
        return payload
    except BaseException as cause:
        cleanup=list(cleanup_errors(cause))
        if directory is not None:
            closing,directory=directory,None
            try:os.close(closing)
            except BaseException as error:cleanup.append(error)
        history_error=None
        if type(cause) is SELECTED.Incomplete:
            try:UNCERTAINTY.record(path,cause,deadline=end)
            except BaseException as failure:history_error=failure
        blocked=Blocked(cause,reservation,selected,listed,manifest,history_error,tuple(cleanup))
        blocked.phase=phase
        try:
            blocked.failure_record=FAILURE.record(path,reservation,phase,cause,
                {'selection':selected,'listing':listed,'manifest':manifest},history_error,tuple(cleanup),deadline=end)
        except BaseException as failure:
            blocked.failure_record_error=failure
        raise blocked from cause
" > "$S4B_STAGE/"lib/postgresql/backup_lifecycle.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Private historical storage shared by the PostgreSQL backup record schemas.

The bounded filesystem operations are retained from Firewall/proposal_store.py.
This module owns only Kernel utilities, without the firewall compiler/observer
import graph. Each owning record module loads an isolated instance and supplies
its exact leaf, byte cap, envelope and checker. Unbound schemas always refuse.

History remains historical: resync/link recovery does not authorize a dump,
retry, reset or publication. Honest ancestry, cooperating locks and finite IO
are required. Sync success is not physical persistence or crash completeness.
\"\"\"
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat

ROOT = Path(__file__).resolve().parents[1]
KERNEL_PATH = ROOT/'firewall/kernel.py'
if not KERNEL_PATH.is_file():
    KERNEL_PATH = ROOT/'Firewall/kernel.py'
SPEC = importlib.util.spec_from_file_location('debian13s4_backup_storage_kernel', KERNEL_PATH)
KERNEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KERNEL)
Pending = KERNEL.Pending
TRUST_ROOT = Path('/')
TRUSTED_UID = 0
LEAF = ''
MAX_BYTES = 0
ATTEMPT_SECONDS = 10


class CleanupFailure(Pending):
    \"\"\"Retain the original operation failure and separate cleanup failures.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('private history operation or cleanup incomplete; preserve visible history')
        self.cause, self.cleanup = cause, cleanup


def close_retired(cause, *descriptors, errors=()):
    \"\"\"Close already-retired descriptors once; never replace the original cause.\"\"\"
    failures = list(errors)
    for descriptor in descriptors:
        if descriptor is not None:
            try: os.close(descriptor)
            except BaseException as error: failures.append(error)
    if failures:
        if cause is None and len(failures) == 1: raise failures[0]
        raise CleanupFailure(cause, tuple(failures)) from cause


def cleanup_errors(cause):
    \"\"\"Extract only this owned storage instance's bounded cleanup diagnostics.\"\"\"
    groups, seen = [], set()
    while cause is not None and id(cause) not in seen and len(seen) < 16:
        seen.add(id(cause))
        if type(cause) is CleanupFailure: groups.append(cause.cleanup)
        cause = cause.__cause__
    result, seen = [], set()
    for group in reversed(groups):
        for error in group:
            if id(error) not in seen:
                seen.add(id(error)); result.append(error)
    return tuple(result)


def intent(raw):
    raise Pending('no backup history schema is bound to this operation')


def envelope(payload):
    raise Pending('no backup history envelope is bound')


def checked(raw):
    raise Pending('no backup history checker is bound')


def admission(end):
    if not KERNEL.finite_deadline(end) or KERNEL.now() >= end:
        raise Pending('proposal storage window expired or invalid')


def window(deadline):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid proposal storage deadline')
    return min(deadline, start + ATTEMPT_SECONDS) if deadline is not None else start + ATTEMPT_SECONDS


def decoded(raw, limit):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Pending('invalid proposal byte delivery')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
                           parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite proposal JSON')))
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid proposal JSON') from error


def directory_identity(path):
    if not isinstance(path, Path) or not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical proposal directory')
    path.relative_to(TRUST_ROOT)
    current, leaf = path, None
    while True:
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise Pending('untrusted proposal directory or ancestry')
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if current == path:
            if stat.S_IMODE(info.st_mode) != 0o700:raise Pending('proposal directory is not private')
            leaf = identity
        if current == TRUST_ROOT:return leaf
        current = current.parent


def directory_matches(path, fd, before):
    info = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) != before or directory_identity(path) != before:
        raise Pending('proposal directory descriptor or path changed')


def file_identity(info, links=1):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID or \\
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != links:
        raise Pending('untrusted proposal leaf kind, owner, mode or links')
    return KERNEL.signature(info) + (info.st_nlink,)


def read_at(directory, end, sync=False, links=1):
    admission(end)
    before = file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), links)
    if before[0] != os.fstat(directory).st_dev:raise Pending('proposal leaf device disagrees')
    fd = os.open(LEAF, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    cause = None
    try:
        if file_identity(os.fstat(fd), links) != before:raise Pending('proposal leaf descriptor changed')
        data = bytearray()
        while True:
            admission(end)
            part = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
            if not part:break
            data.extend(part)
            if len(data) > MAX_BYTES:raise Pending('proposal leaf exceeds bound')
        if sync:os.fsync(fd)
        if file_identity(os.fstat(fd), links) != before or \\
                file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), links) != before:
            raise Pending('proposal leaf changed during read')
        admission(end)
        return bytes(data)
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, fd = fd, None
        close_retired(cause, closing)


def locked(path, end):
    admission(end)
    before = directory_identity(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        directory_matches(path, fd, before)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory_matches(path, fd, before);admission(end)
        return fd, before
    except BaseException as cause:
        closing, fd = fd, None
        close_retired(cause, closing)
        raise


def load(path, deadline=None):
    end = window(deadline)
    directory, before = locked(path, end)
    cause = None
    try:
        payload = checked(read_at(directory, end))
        directory_matches(path, directory, before);admission(end)
        return payload
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, directory = directory, None
        close_retired(cause, closing)


def reconcile_link(path, directory, before, payload, end):
    try:
        info = os.stat(LEAF, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:return
    if info.st_nlink != 2:return
    identity = file_identity(info, 2)
    if checked(read_at(directory, end, sync=True, links=2)) != payload:
        raise Pending('linked history belongs to a different proposal')
    matches = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries, 1):
            admission(end)
            if count > 32:raise Pending('proposal staging inventory exceeds recovery bound')
            if re.fullmatch(r'\\.proposal-[0-9a-f]{32}', entry.name):
                stage = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                if (stage.st_dev, stage.st_ino) == identity[:2]:
                    if file_identity(stage, 2) != identity:raise Pending('proposal staging link changed')
                    matches.append(entry.name)
    if len(matches) != 1:raise Pending('linked proposal lacks one positively identified private staging name')
    directory_matches(path, directory, before);admission(end)
    if file_identity(os.stat(LEAF, dir_fd=directory, follow_symlinks=False), 2) != identity or \\
            file_identity(os.stat(matches[0], dir_fd=directory, follow_symlinks=False), 2) != identity:
        raise Pending('proposal links changed before reconciliation')
    os.unlink(matches[0], dir_fd=directory)
    os.fsync(directory)
    directory_matches(path, directory, before);admission(end)


def staging_identity(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID:
        raise Pending('untrusted acquired staging descriptor or path')
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid


def create(path, payload, deadline=None):
    end = window(deadline)
    raw = envelope(payload);admission(end)
    directory, before = locked(path, end)
    temporary, owned, fd = None, None, None
    cause = None
    try:
        reconcile_link(path, directory, before, payload, end)
        try:
            current = read_at(directory, end, sync=True)
        except FileNotFoundError:
            current = None
        if current is not None:
            if checked(current) != payload:raise Pending('a different historical proposal already exists')
            os.fsync(directory);directory_matches(path, directory, before);admission(end)
            return payload
        candidate = '.proposal-' + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        owned = staging_identity(os.fstat(fd))
        if owned[0] != before[0]:raise Pending('acquired staging device disagrees')
        temporary = candidate
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            admission(end)
            count = os.write(fd, raw[offset:])
            if type(count) is not int or not 0 < count <= len(raw) - offset:
                raise Pending('proposal write did not advance')
            offset += count
        os.fsync(fd)
        identity = file_identity(os.fstat(fd))
        if identity != file_identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)):
            raise Pending('proposal staging descriptor or path changed')
        directory_matches(path, directory, before);admission(end)
        os.link(temporary, LEAF, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory);temporary = None
        closing, fd = fd, None
        os.close(closing)
        os.fsync(directory)
        result = checked(read_at(directory, end))
        if result != payload:raise Pending('published proposal differs from the intended bytes')
        directory_matches(path, directory, before);admission(end)
        return result
    except BaseException as error:
        cause = error
        raise
    finally:
        errors = []
        try:
            if temporary is not None:
                directory_matches(path, directory, before)
                if staging_identity(os.fstat(fd)) != owned or \\
                        staging_identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)) != owned:
                    raise Pending('owned staging identity changed before cleanup')
                os.unlink(temporary, dir_fd=directory)
        except BaseException as error:
            errors.append(error)
        finally:
            closing, closing_directory, fd, directory = fd, directory, None, None
            close_retired(cause, closing, closing_directory, errors=errors)
" > "$S4B_STAGE/"lib/postgresql/private_storage.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Inspect one existing private backup history directory without native work.

All states describe retained history only. No state authorizes retry, proves a
valid/completed backup, inspects a database/archive, or promotes/deletes a file.
\"\"\"
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_backup_status_lifecycle',
    Path(__file__).resolve().with_name('backup_lifecycle.py'))
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)
Pending = LIFECYCLE.Pending
MAX_OUTPUT = 16384


def snapshot(directory, end):
    \"\"\"Check each whole envelope; only an initially absent leaf is absent.\"\"\"
    raw, records = {}, {}
    for tag, module in (('reservation', LIFECYCLE.ATTEMPT),
                        ('manifest', LIFECYCLE.MANIFEST),
                        ('incomplete', LIFECYCLE.UNCERTAINTY),
                        ('failure', LIFECYCLE.FAILURE)):
        storage = module._STORAGE
        until = storage.window(end)
        try:
            os.stat(storage.LEAF, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            raw[tag], records[tag] = None, None
            continue
        data = storage.read_at(directory, until)
        payload = storage.checked(data)
        value = LIFECYCLE.BACKUP.ACCESS.decoded(payload, storage.MAX_BYTES)
        raw[tag], records[tag] = data, value
    return raw, records


def classify(records):
    reservation, manifest, incomplete = (records[tag] for tag in ('reservation', 'manifest', 'incomplete'))
    failure = records.get('failure')
    if manifest is not None and incomplete is not None:
        raise Pending('conflicting backup outcome records; preserve history and investigate')
    if reservation is None:
        if manifest is not None or incomplete is not None or failure is not None:
            raise Pending('backup outcome exists without its reservation; preserve history')
        return 'no-recorded-attempt', None
    for outcome in (manifest, incomplete, failure):
        if outcome is not None and outcome['application'] != reservation['application']:
            raise Pending('backup reservation and outcome applications differ')
    state = ('historical-attempt-incomplete-recorded' if failure is not None else
             'historical-listing-recorded' if manifest is not None else
             'historical-incomplete-recorded' if incomplete is not None else
             'reserved-outcome-unknown')
    return state, reservation['application']


def inspect(path, deadline=None):
    storage = LIFECYCLE.ATTEMPT._STORAGE
    end = storage.window(deadline)
    directory, before = storage.locked(path, end)
    cause = None
    try:
        raw, records = snapshot(directory, end)
        state, application = classify(records)
        if records['failure'] is not None and records['failure']['reservation'].encode('utf-8') != raw['reservation']:
            raise Pending('recorded lifecycle failure belongs to a different reservation')
        observed = {}
        for tag, data in raw.items():
            observed[tag] = {'present': data is not None}
            if data is not None:
                observed[tag].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                                     state=records[tag]['state'])
                if tag == 'failure':
                    kind, detail = records[tag]['cause'][-1]
                    observed[tag].update(phase=records[tag]['phase'],
                        diagnostic={'type': kind, 'detail': detail[:256]},
                        diagnostic_truncated=len(detail) > 256)
        payload = LIFECYCLE.PREP.canonical({'schema': 1, 'state': state,
            'scope': 'historical-backup-records-only', 'directory': str(path),
            'application': application, 'records': observed,
            'retry_authorized': False, 'backup_complete': False})
        if len(payload) > MAX_OUTPUT:
            raise Pending('backup history summary exceeds its output bound')
        if snapshot(directory, end)[0] != raw:
            raise Pending('backup history changed after summary encoding')
        storage.directory_matches(path, directory, before)
        storage.admission(end)
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, directory = directory, None
        storage.close_retired(cause, closing)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True,
                        help='existing private directory containing one reserved attempt')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        raw = inspect(args.directory)
        if args.format == 'text':
            value = LIFECYCLE.BACKUP.ACCESS.decoded(raw, MAX_OUTPUT)
            lines = ['Backup history: '+value['state'], 'Directory: '+value['directory']]
            if value['application'] is not None:
                lines.append('Application: '+value['application'])
            lines.extend(tag+': '+('present' if row['present'] else 'absent')
                         for tag, row in value['records'].items())
            failure = value['records']['failure']
            if failure['present']:
                lines.append('Failure phase: '+failure['phase'])
                lines.append('Recorded cause prefix: '+json.dumps(failure['diagnostic'], ensure_ascii=True))
            lines.append('Historical records do not establish a completed backup or authorize retry.')
            raw = ('\\n'.join(lines)+'\\n').encode('utf-8')
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete backup status output')
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/backup_status.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Explicit command interface for one reserved backup SOURCE attempt.

status reads existing history only. run-once launches the configured native
PostgreSQL queries, dump and listing and writes private stage/history files;
it requires separate operational authorization. No automatic scheduler, retry,
reset, promotion, completed-backup certification or restore is provided.
\"\"\"
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

APPLICATIONS = ('mk8.dns', 'mk8.email')
MAX_STDERR = 1048576
MAX_DIAGNOSTIC = 1048576


class Pending(ValueError):
    pass


def owned():
    # Argument errors and --help must not load the preparation/native graph.
    spec = importlib.util.spec_from_file_location('debian13s4_backup_command_status',
        Path(__file__).resolve().with_name('backup_status.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stderr_bound(value):
    if re.fullmatch('[1-9][0-9]{0,6}', value) is None or int(value) > MAX_STDERR:
        raise argparse.ArgumentTypeError('stderr bytes must be an integer from 1 through 1048576')
    return int(value)


def write(stream, raw, maximum):
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise Pending('unsupported bounded backup command output')
    count = stream.write(raw)
    if type(count) is not int or count != len(raw):
        raise Pending('incomplete backup command output')
    stream.flush()


def commitment(raw):
    if raw is None:
        return {'returned': False}
    if type(raw) is not bytes:
        return {'returned': True, 'supported_bytes': False}
    return {'returned': True, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def describe(error):
    # Diagnostic formatting must not replace an existing lifecycle failure.
    name = type(error).__name__[:128]
    try:
        message = str(error)[:1024]
    except BaseException as formatting_error:
        message = '<message unavailable: '+type(formatting_error).__name__[:128]+'>'
    return {'type': name, 'message_prefix': message}


def chain(error):
    rows, seen = [], set()
    while error is not None and id(error) not in seen and len(rows) < 16:
        seen.add(id(error)); rows.append(describe(error))
        error = error.__cause__ if error.__cause__ is not None else (
            None if error.__suppress_context__ else error.__context__)
    return {'entries': rows, 'truncated_or_cyclic': error is not None}


def failure(error, status, operation, phase, directory, result):
    value = {'schema': 1, 'state': 'backup-command-failed-no-retry',
        'operation': operation, 'phase': phase, 'directory': str(directory),
        'backup_complete': False, 'retry_authorized': False, 'diagnostics_only': True,
        'cause': chain(error), 'known_result': commitment(result)}
    if status is not None and isinstance(error, status.LIFECYCLE.Blocked):
        value['state'] = 'reserved-backup-attempt-incomplete-no-retry'
        value['lifecycle'] = {'phase': error.phase, 'reservation': commitment(error.reservation),
            'known': {name: commitment(getattr(error, name)) for name in ('selection', 'listing', 'manifest')},
            'history_error': None if error.history_error is None else chain(error.history_error),
            'failure_record': commitment(error.failure_record),
            'failure_record_error': None if error.failure_record_error is None else chain(error.failure_record_error),
            'cleanup': [describe(item) for item in error.cleanup[:16]],
            'cleanup_truncated': len(error.cleanup) > 16}
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)+'\\n').encode('ascii')
    if len(raw) > MAX_DIAGNOSTIC:
        raise Pending('backup command diagnostics exceed their output bound')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    history = actions.add_parser('status', help='read existing history without a native operation')
    history.add_argument('--directory', type=Path, required=True)
    run = actions.add_parser('run-once', help='perform one explicit reserved native dump/listing attempt')
    run.add_argument('--directory', type=Path, required=True, help='existing private history directory')
    run.add_argument('--application', choices=APPLICATIONS, required=True)
    run.add_argument('--stderr-bytes', type=stderr_bound, required=True,
                     help='explicit bounded raw dump-warning capacity')
    args = parser.parse_args(argv)
    status, result, phase = None, None, 'admission'
    try:
        status = owned()
        if args.action == 'status':
            phase = 'history-read'
            result = status.inspect(args.directory)
            maximum = status.MAX_OUTPUT
        else:
            lifecycle = status.LIFECYCLE
            if tuple(lifecycle.PREP.APPLICATIONS) != APPLICATIONS or lifecycle.SELECTED.DUMP.MAX_STDERR != MAX_STDERR:
                raise Pending('backup command and owned lifecycle bounds differ')
            phase = 'lifecycle'
            result = lifecycle.run_once(args.directory, args.application, args.stderr_bytes)
            maximum = lifecycle.MAX_OUTPUT
        phase = 'output'
        write(sys.stdout.buffer, result, maximum)
        return 0
    except (OSError, ValueError, RuntimeError, TypeError, AttributeError, UnicodeError, RecursionError, KeyboardInterrupt) as error:
        try:
            diagnostic = failure(error, status, args.action, phase, args.directory, result)
            write(sys.stderr.buffer, diagnostic, MAX_DIAGNOSTIC)
        except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
            # An unavailable diagnostic sink still cannot turn failure into success.
            pass
        return 130 if isinstance(error, KeyboardInterrupt) else 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/postgresql/backup_run.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Retain a reserved lifecycle failure without discharging its original error.

Known returned receipts are opaque historical bytes, not archive validation or
native completion. Recording can itself fail or leave visible data without
success. Neither outcome authorizes a second attempt, reset or publication.
\"\"\"
import hashlib
import importlib.util
from pathlib import Path


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(leaf))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


MANIFEST = module('debian13s4_attempt_failure_manifest', 'stage_manifest.py')
ATTEMPT = module('debian13s4_attempt_failure_reservation', 'backup_attempt.py')
_STORAGE = module('debian13s4_attempt_failure_storage', 'private_storage.py')
HISTORY, PREP, Pending = MANIFEST.HISTORY, MANIFEST.PREP, MANIFEST.Pending
LEAF = 'selected-backup-incomplete.json'
STATE = 'historical-backup-attempt-incomplete-no-retry'
PHASES = ('pre-stage', 'stage', 'pre-listing', 'listing', 'manifest', 'final-validation')
LIMITS = {'selection': HISTORY.SELECTED.MAX_OUTPUT,
          'listing': MANIFEST.LISTING.MAX_OUTPUT, 'manifest': MANIFEST.MAX_RECORD}
MAX_RECORD = 2 * sum(LIMITS.values()) + 2 * ATTEMPT.MAX_BYTES + 131072
MAX_BYTES = 2 * MAX_RECORD + 4096


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def opaque(raw, maximum):
    if raw is None:
        return None
    if type(raw) is not bytes or len(raw) > maximum:
        raise Pending('known backup outcome is not bounded immutable bytes')
    return {'bytes': len(raw), 'sha256': digest(raw), 'hex': raw.hex()}


def checked(raw):
    value = HISTORY.BACKUP.ACCESS.decoded(raw, MAX_RECORD)
    HISTORY.fields(value, 'schema state application reservation reservation_sha256 phase cause known history_error cleanup')
    if value['schema'] != 'debian13s4-backup-attempt-incomplete-1' or value['state'] != STATE or \\
            type(value['reservation']) is not str or type(value['phase']) is not str or value['phase'] not in PHASES:
        raise Pending('unsupported backup attempt failure profile')
    reservation = value['reservation'].encode('utf-8')
    ATTEMPT.checked(reservation)
    slot = HISTORY.BACKUP.ACCESS.decoded(reservation, ATTEMPT.MAX_BYTES)
    if type(value['application']) is not str or value['application'] != slot['application'] or \\
            value['reservation_sha256'] != digest(reservation):
        raise Pending('backup failure and reserved attempt differ')
    HISTORY.diagnostics(value['cause'])
    HISTORY.diagnostics(value['cleanup'])
    if not value['cause']:
        raise Pending('missing original backup failure')
    if value['history_error'] is not None:
        HISTORY.diagnostics(value['history_error'])
        if not value['history_error']:
            raise Pending('missing separate history failure')
    HISTORY.fields(value['known'], 'selection listing manifest')
    for tag, maximum in LIMITS.items():
        row = value['known'][tag]
        if row is not None:
            HISTORY.fields(row, 'bytes sha256 hex')
            data = HISTORY.hex_bytes(row['hex'], maximum)
            if type(row['bytes']) is not int or row['bytes'] != len(data) or row['sha256'] != digest(data):
                raise Pending('known opaque backup outcome commitment differs')
    if raw != PREP.canonical(value):
        raise Pending('backup attempt failure is not canonical')
    return value


def capture(reservation, phase, cause, known, history_error, cleanup):
    ATTEMPT.checked(reservation)
    slot = HISTORY.BACKUP.ACCESS.decoded(reservation, ATTEMPT.MAX_BYTES)
    if type(phase) is not str or phase not in PHASES or type(cleanup) is not tuple or len(cleanup) > 16:
        raise Pending('unsupported backup failure phase or cleanup inventory')
    HISTORY.fields(known, 'selection listing manifest')
    # Known receipts are never parsed into a fabricated successful outcome here.
    outcomes = {tag: opaque(known[tag], maximum) for tag, maximum in LIMITS.items()}
    raw = PREP.canonical({'schema': 'debian13s4-backup-attempt-incomplete-1', 'state': STATE,
        'application': slot['application'], 'reservation': reservation.decode('utf-8'),
        'reservation_sha256': digest(reservation), 'phase': phase, 'cause': HISTORY.chain(cause),
        'known': outcomes, 'history_error': None if history_error is None else HISTORY.chain(history_error),
        'cleanup': [HISTORY.describe(error) for error in cleanup]})
    checked(raw)
    return raw


def envelope(payload):
    checked(payload)
    raw = PREP.canonical({'schema': 'debian13s4-backup-attempt-failure-history-1', 'state': STATE,
                          'payload': payload.decode('utf-8'), 'payload_sha256': digest(payload)})
    if len(raw) > MAX_BYTES:
        raise Pending('backup failure history exceeds its storage bound')
    return raw


def stored(raw):
    value = HISTORY.BACKUP.ACCESS.decoded(raw, MAX_BYTES)
    HISTORY.fields(value, 'schema state payload payload_sha256')
    if value['schema'] != 'debian13s4-backup-attempt-failure-history-1' or value['state'] != STATE or type(value['payload']) is not str:
        raise Pending('unsupported backup failure history envelope')
    payload = value['payload'].encode('utf-8')
    checked(payload)
    if value['payload_sha256'] != digest(payload) or raw != PREP.canonical(value):
        raise Pending('backup failure envelope changed')
    return payload


_STORAGE.LEAF, _STORAGE.MAX_BYTES, _STORAGE.envelope, _STORAGE.checked = LEAF, MAX_BYTES, envelope, stored


def record(path, reservation, phase, cause, known, history_error, cleanup, deadline=None):
    end = _STORAGE.window(deadline)
    payload = capture(reservation, phase, cause, known, history_error, cleanup)
    _STORAGE.admission(end)
    return _STORAGE.create(path, payload, deadline=end)


def load(path, deadline=None):
    return _STORAGE.load(path, deadline=deadline)
" > "$S4B_STAGE/"lib/postgresql/attempt_failure.py || return 1
    printf '%s' "#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
S4G_LIBRARY=/usr/local/lib/debian13s4/postgresql
S4G_CONFIG=/etc/debian13s4-postgresql
S4G_SERVER=debian13s4-postgresql-server.service
S4G_SERVICE=debian13s4-postgresql.service
S4G_TIMER=debian13s4-postgresql.timer
S4G_LOADED_GENERATION=''
S4G_FILES=(prepare.py live.py access.py common.sh repair.sh debian13s4-postgresql-server.service
    debian13s4-postgresql.service debian13s4-postgresql.timer)

s4g_policy() (
    local descriptor=\$S4M_REPAIR_FD script=live.py
    [[ \${1-} != --access ]] || script=access.py
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 15s env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \\
        /usr/bin/python3 -I -B \"\$S4G_LIBRARY/\$script\" \"\$@\"
)

s4g_action() (
    local descriptor=\$S4M_REPAIR_FD action=\$1
    trap - EXIT
    [[ \$action == stop || \$action == start ]] || return 1
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 120s env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \\
        systemctl \"\$action\" \"\$S4G_SERVER\"
)

s4g_assets() {
    local name
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for name in \"\${S4G_FILES[@]}\"; do
        [[ -f \$S4G_LIBRARY/\$name ]] && s4m_trusted \"\$S4G_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4G_LIBRARY/repair.sh ]] && s4m_trusted \"\$S4M_LIBRARY/common.sh\" &&
        s4m_trusted \"\${S4G_LIBRARY%/*}/firewall/kernel.py\"
}

s4g_identity() {
    local name digest
    for name in \"\${S4G_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4G_LIBRARY/\$name\") || return 1
        printf '%s postgresql/%s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py; do
        digest=\$(sha256sum -- \"\${S4G_LIBRARY%/*}/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
}

s4g_packages() (
    # This supported join requires pre-installed packages and pre-provisioned
    # enrolled data. It never invokes APT or vendor cluster-creation scripts.
    s4m_load_packages || return 1
    S4P_PACKAGES=(postgresql-17 postgresql-client-17)
    s4p_query() {
        s4m_control dpkg-query --show --showformat=\"\\\${Status}\\n\" -- \"\$1\"
    }
    s4p_dpkg() {
        [[ \$# == 1 && \$1 == --audit ]] || return 1
        s4m_control dpkg --audit
    }
    s4p_verify
)

s4g_stop() {
    local loaded marker=\$S4M_STATE/postgresql.loaded
    loaded=\$(s4m_systemctl show --property=LoadState --value \"\$S4G_SERVER\") || return 1
    if [[ \$loaded == loaded ]]; then
        s4g_action stop && s4m_property \"\$S4G_SERVER\" ActiveState inactive &&
            s4m_property \"\$S4G_SERVER\" MainPID 0 || return 1
    elif [[ \$loaded != not-found ]]; then
        return 1
    fi
    if [[ -e \$marker || -L \$marker ]]; then
        [[ -f \$marker ]] && s4m_trusted \"\$marker\" && rm -f -- \"\$marker\" || return 1
        s4m_sync \"\$S4M_STATE\" || return 1
    fi
}

s4g_configure() {
    local name temporary
    # Stop/confirm inactive before any startup-input replacement. Prestart
    # positively checks enrolled existing stopped data, not just disk syntax.
    s4g_stop && s4g_policy --prestart || return 1
    if [[ -e \$S4G_CONFIG || -L \$S4G_CONFIG ]]; then
        [[ -d \$S4G_CONFIG ]] && s4m_trusted \"\$S4G_CONFIG\" || return 1
    else
        s4m_trusted \"\${S4G_CONFIG%/*}\" && mkdir -m 0755 -- \"\$S4G_CONFIG\" || return 1
    fi
    for name in postgresql.conf pg_hba.conf pg_ident.conf; do
        temporary=\$(mktemp -- \"\$S4M_STATE/postgresql-config.XXXXXX\") || return 1
        if ! s4g_policy --file \"\$name\" > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
            ! s4m_atomic \"\$S4G_CONFIG/\$name\" \"\$temporary\" 0644; then
            rm -f -- \"\$temporary\"
            return 1
        fi
        rm -f -- \"\$temporary\" || return 1
    done
}

s4g_generation() {
    local rows key value active='' pid='' invocation=''
    rows=\$(s4m_systemctl show --property=ActiveState --property=MainPID \\
        --property=InvocationID \"\$S4G_SERVER\") || return 1
    [[ \${#rows} -le 512 ]] || return 1
    while IFS='=' read -r key value; do
        case \$key in
            ActiveState) [[ -z \$active && \$value == active ]] || return 1; active=\$value ;;
            MainPID)
                [[ -z \$pid && \$value =~ ^[1-9][0-9]{0,9}\$ ]] &&
                    (( 10#\$value <= 2147483647 )) || return 1; pid=\$value ;;
            InvocationID)
                [[ -z \$invocation && \$value =~ ^[0-9a-f]{32}\$ &&
                    \$value != 00000000000000000000000000000000 ]] || return 1; invocation=\$value ;;
            *) return 1 ;;
        esac
    done <<< \"\$rows\"
    [[ \$active == active && -n \$pid && -n \$invocation ]] || return 1
    printf 'instance %s %s\\n' \"\$pid\" \"\$invocation\" && s4g_identity && s4g_policy --identity
}

s4g_loaded() {
    local marker=\$S4M_STATE/postgresql.loaded mode size links actual expected
    [[ -f \$marker ]] && s4m_trusted \"\$marker\" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- \"\$marker\") || return 1
    [[ \$mode == 600 && \$links == 1 && \$size =~ ^[1-9][0-9]{0,4}\$ ]] &&
        (( 10#\$size <= 24576 )) || return 1
    expected=\$(s4g_generation) && actual=\$(cat -- \"\$marker\") && [[ \$expected == \"\$actual\" ]] || return 1
    S4G_LOADED_GENERATION=\$expected
}

s4g_live() {
    local before
    s4g_loaded || return 1
    before=\$S4G_LOADED_GENERATION
    s4g_policy --access && s4g_loaded && [[ \$before == \"\$S4G_LOADED_GENERATION\" ]]
}

s4g_start() {
    local before after generation temporary
    s4m_property \"\$S4G_SERVER\" ActiveState inactive && s4m_property \"\$S4G_SERVER\" MainPID 0 || return 1
    before=\$(s4g_identity && s4g_policy --identity) && s4g_action start &&
        s4g_policy --access && after=\$(s4g_identity && s4g_policy --identity) && [[ \$before == \"\$after\" ]] || return 1
    generation=\$(s4g_generation) && [[ \${generation#*\$'\\n'} == \"\$before\" ]] || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/postgresql-loaded.XXXXXX\") || return 1
    if ! printf '%s\\n' \"\$generation\" > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/postgresql.loaded\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4g_loaded
}

s4g_units() {
    local name
    for name in \"\$S4G_SERVER\" \"\$S4G_SERVICE\" \"\$S4G_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4G_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" &&
            s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4G_SERVER\" && s4m_enabled \"\$S4G_TIMER\" && s4m_property \"\$S4G_TIMER\" ActiveState active
}

s4g_ready() {
    local actual expected mode size links
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/postgresql.ready ]] && s4m_trusted \"\$S4M_STATE/postgresql.ready\" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- \"\$S4M_STATE/postgresql.ready\") || return 1
    [[ \$mode == 600 && \$links == 1 && \$size =~ ^[1-9][0-9]{0,3}\$ ]] &&
        (( 10#\$size <= 4096 )) || return 1
    s4g_assets && s4g_units || return 1
    expected=\$(s4g_identity) && actual=\$(cat -- \"\$S4M_STATE/postgresql.ready\") && [[ \$expected == \"\$actual\" ]]
}

s4g_verify() {
    s4g_ready && s4g_packages && s4g_live
}

s4g_publish() {
    local name wants resolved temporary
    for name in \"\$S4G_SERVER\" \"\$S4G_SERVICE\" \"\$S4G_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$name\" \"\$S4G_LIBRARY/\$name\" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for name in \"\$S4G_SERVER\" \"\$S4G_TIMER\"; do
        s4m_systemctl enable \"\$name\" && s4m_enabled \"\$name\" || return 1
        wants=\$S4M_SYSTEMD/multi-user.target.wants
        [[ \$name != \"\$S4G_TIMER\" ]] || wants=\$S4M_SYSTEMD/timers.target.wants
        [[ -d \$wants && -L \$wants/\$name ]] && s4m_trusted \"\$wants\" || return 1
        resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$name\") && [[ \$resolved == \"\$S4M_SYSTEMD/\$name\" ]] || return 1
        s4m_sync \"\$wants\" \"\$S4M_SYSTEMD\" \"\$S4M_SYSTEMD/\$name\" || return 1
    done
    s4g_start && s4m_systemctl start \"\$S4G_TIMER\" && s4g_units && s4g_live || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/postgresql-ready.XXXXXX\") || return 1
    if ! s4g_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/postgresql.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4g_verify
}

s4g_apply() {
    local name loaded
    s4g_assets && s4g_packages || return 1
    for name in \"\$S4G_SERVER\" \"\$S4G_SERVICE\" \"\$S4G_TIMER\"; do
        if [[ -e \$S4M_SYSTEMD/\$name || -L \$S4M_SYSTEMD/\$name ]]; then
            [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/postgresql.ready || -L \$S4M_STATE/postgresql.ready ]]; then
        [[ -f \$S4M_STATE/postgresql.ready ]] && s4m_trusted \"\$S4M_STATE/postgresql.ready\" &&
            rm -f -- \"\$S4M_STATE/postgresql.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for name in \"\$S4G_TIMER\" \"\$S4G_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$name\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$name\" && s4m_property \"\$name\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then return 1; fi
    done
    if s4g_configure && s4g_publish; then return 0; fi
    s4g_stop || return 1
    return 1
}

s4g_repair() {
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    if s4g_ready && s4g_packages; then
        if s4g_live; then return 0; fi
        if s4g_configure && s4g_start && s4g_live; then return 0; fi
    fi
    s4g_stop || return 75
    return 75
}
" > "$S4B_STAGE/"lib/postgresql/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77
# shellcheck source=PostgreSQL/common.sh
. /usr/local/lib/debian13s4/postgresql/common.sh
s4g_repair
" > "$S4B_STAGE/"lib/postgresql/repair.sh || return 1
    printf '%s' "[Unit]
Description=Enrolled pre-provisioned local-only Debian PostgreSQL 17
After=local-fs.target
RequiresMountsFor=/usr/local/lib/debian13s4 /etc/debian13s4 /etc/debian13s4-postgresql /var/lib/debian13s4-postgresql
ConditionPathExists=!/var/lib/debian13s4/bootstrap/pending
StartLimitIntervalSec=0

[Service]
Type=notify
NotifyAccess=main
User=postgres
Group=postgres
# The root prestart checker needs private enrollment and performs bounded
# read-only runuser/pg_controldata delivery. '+' is deliberate, not isolation.
ExecStartPre=+/usr/bin/python3 -I -B /usr/local/lib/debian13s4/postgresql/live.py --prestart
ExecStart=/usr/lib/postgresql/17/bin/postgres -D /var/lib/debian13s4-postgresql -c config_file=/etc/debian13s4-postgresql/postgresql.conf
UMask=0077
RuntimeDirectory=debian13s4-postgresql
RuntimeDirectoryMode=0755
StandardInput=null
StandardOutput=journal
StandardError=journal
TimeoutStartSec=120s
TimeoutStopSec=120s
KillSignal=SIGINT
KillMode=control-group
Restart=on-failure
RestartSec=30s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/debian13s4-postgresql /run/debian13s4-postgresql
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
" > "$S4B_STAGE/"lib/postgresql/debian13s4-postgresql-server.service || return 1
    printf '%s' "[Unit]
Description=Check and restore the enrolled local PostgreSQL startup generation
After=local-fs.target
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/debian13s4 /etc/debian13s4-postgresql /var/lib/debian13s4-postgresql
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/postgresql/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# Finite honest-work admission: 60 controls*11 + 15 policy*16 + 3 server
# actions*121 + 60 local seconds =1323, below1500. Not stalled-work proof.
TimeoutStartSec=1500s
TimeoutStopSec=30s
KillMode=control-group
Restart=on-failure
RestartSec=1min
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
" > "$S4B_STAGE/"lib/postgresql/debian13s4-postgresql.service || return 1
    printf '%s' "[Unit]
Description=Periodic enrolled local PostgreSQL source and loaded-generation check

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
AccuracySec=15s
Persistent=yes
Unit=debian13s4-postgresql.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/postgresql/debian13s4-postgresql.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=PostgreSQL/common.sh
. /usr/local/lib/debian13s4/postgresql/common.sh
s4g_apply
" > "$S4B_STAGE/"lib/tasks/postgresql/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=PostgreSQL/common.sh
. /usr/local/lib/debian13s4/postgresql/common.sh
s4g_verify
" > "$S4B_STAGE/"lib/tasks/postgresql/verify.sh || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare a PARTIAL nginx HTTPS ingress intention; never run or publish it.

Three existing private HTTPS gateways are required. DNS UDP/TCP service, mail
TCP protocols, application provisioning, certificate cryptography/validity,
nginx syntax/loaded generation and client locality are outside this profile.
Protected file bytes are bound, not authenticated or certified usable.
\"\"\"

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_web_inputs',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
if not SPEC.origin or not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_web_inputs',
        Path(__file__).resolve().parents[1] / 'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL = BASE.KERNEL
Pending = BASE.Pending
INPUT = Path('/etc/debian13s4/web.json')
APPLICATIONS = ('mk8.sava', 'mk8.drava', 'mk8.email')
MAX_INPUT = 8192
MAX_PEM = 65536
MAX_OUTPUT = 131073
ATTEMPT_SECONDS = 10
# These are product protocol routes, not deployment domains or allocations.
MAIL_EXACT = ('/.well-known/jmap', '/jmap/session', '/jmap/api', '/jmap/event',
    '/.well-known/caldav', '/.well-known/carddav', '/dav',
    '/ews/exchange.asmx', '/autodiscover/autodiscover.xml',
    '/.well-known/oauth-authorization-server', '/.well-known/openid-configuration',
    '/oauth/jwks', '/oauth/userinfo', '/oauth/authorize', '/oauth/token', '/oauth/revoke')
MAIL_PREFIX = ('/jmap/upload/', '/jmap/download/', '/dav/')


def hostname(value):
    if (type(value) is not str or not 3 <= len(value) <= 253 or value != value.lower() or
        '.' not in value or re.fullmatch(r'[a-z0-9.-]+', value) is None):
        raise Pending('unsupported explicit ingress hostname')
    labels = value.split('.')
    if (any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) is None
            for part in labels) or re.fullmatch(r'[a-z][a-z0-9-]*', labels[-1]) is None):
        raise Pending('noncanonical ingress DNS name')
    return value


def material_path(value):
    if (type(value) is not str or not 2 <= len(value) <= 240 or
        re.fullmatch(r'/[A-Za-z0-9_./-]+', value) is None or
        any(part in ('', '.', '..') for part in value.split('/')[1:]) or
        os.path.normpath(value) != value):
        raise Pending('unsupported explicit ingress material path')
    return value


def checked(value):
    fields = {'schema', 'applications'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported ingress input schema')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    names, ports, keys, public = set(), set(), set(), set()
    fields = {'hostname', 'certificate', 'private_key', 'upstream_port',
              'upstream_name', 'upstream_ca', 'body_bytes', 'idle_seconds'}
    for app in APPLICATIONS:
        item = value['applications'][app]
        KERNEL.known(item, fields, fields)
        name = hostname(item['hostname']); hostname(item['upstream_name'])
        for field, minimum, maximum in (('upstream_port', 1024, 65535),
            ('body_bytes', 1024, 1073741824), ('idle_seconds', 10, 600)):
            if type(item[field]) is not int or not minimum <= item[field] <= maximum:
                raise Pending('unsupported explicit ingress bound')
        port = item['upstream_port']
        if name in names or port in ports or port == 5432:
            raise Pending('shared or reserved ingress identity')
        names.add(name); ports.add(port)
        for field in ('certificate', 'private_key', 'upstream_ca'):
            material_path(item[field])
        keys.add(item['private_key'])
        public.update((item['certificate'], item['upstream_ca']))
    if keys & public:
        raise Pending('private key reused as public ingress material')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite ingress input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid ingress JSON') from error
    if raw != BASE.canonical(value):
        raise Pending('ingress input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def pem(raw, private):
    # A narrow PEM delivery grammar ONLY. This deliberately does not decode
    # ASN.1, verify signatures/names/dates/key pairing, or trust the issuer.
    label = b'PRIVATE KEY' if private else b'CERTIFICATE'
    begin = b'-----BEGIN ' + label + b'-----\\n'
    end = b'-----END ' + label + b'-----\\n'
    remaining, blocks = raw, 0
    while remaining:
        if not remaining.startswith(begin) or end not in remaining:
            raise Pending('unsupported ingress PEM framing')
        body, remaining = remaining[len(begin):].split(end, 1)
        lines = body[:-1].split(b'\\n') if body.endswith(b'\\n') else []
        if (not lines or any(len(line) != 64 for line in lines[:-1]) or
            not 1 <= len(lines[-1]) <= 64):
            raise Pending('unsupported ingress PEM line grammar')
        encoded = b''.join(lines)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise Pending('invalid ingress PEM base64') from error
        if not decoded or base64.b64encode(decoded) != encoded:
            raise Pending('noncanonical or empty ingress PEM')
        blocks += 1
        if blocks > (1 if private else 16):
            raise Pending('ingress PEM block count exceeds profile')
    if blocks == 0:
        raise Pending('missing ingress PEM')
    return blocks


def materials(settings, end):
    inputs = {}
    for app in APPLICATIONS:
        item = settings['applications'][app]
        for field in ('certificate', 'private_key', 'upstream_ca'):
            name = item[field]
            if name in inputs:
                continue
            raw, source = BASE.read_protected(Path(name), MAX_PEM, field == 'private_key', end)
            count = pem(raw, field == 'private_key')
            inputs[name] = {'source': source, 'pem_blocks': count,
                            'kind': 'private-key' if field == 'private_key' else 'certificate'}
    return inputs


def proxy(item):
    return (f\"            proxy_pass https://127.0.0.1:{item['upstream_port']};\\n\"
        '            proxy_http_version 1.1;\\n'
        f\"            proxy_set_header Host {item['hostname']};\\n\"
        '            proxy_set_header X-Forwarded-Host \$host;\\n'
        '            proxy_set_header X-Forwarded-Proto https;\\n'
        '            proxy_set_header X-Forwarded-For \$remote_addr;\\n'
        '            proxy_set_header X-Real-IP \$remote_addr;\\n'
        '            proxy_set_header Forwarded \"\";\\n'
        '            proxy_set_header Proxy \"\";\\n'
        '            proxy_set_header Upgrade \$http_upgrade;\\n'
        '            proxy_set_header Connection \$s4_connection;\\n'
        '            proxy_ssl_server_name on;\\n'
        f\"            proxy_ssl_name {item['upstream_name']};\\n\"
        f\"            proxy_ssl_trusted_certificate {item['upstream_ca']};\\n\"
        '            proxy_ssl_verify on;\\n            proxy_ssl_verify_depth 4;\\n'
        '            proxy_ssl_protocols TLSv1.2 TLSv1.3;\\n'
        '            proxy_next_upstream off;\\n            proxy_redirect off;\\n'
        '            proxy_buffering off;\\n            proxy_request_buffering off;\\n'
        '            proxy_ignore_headers X-Accel-Redirect X-Accel-Buffering;\\n'
        '            proxy_max_temp_file_size 0;\\n            proxy_connect_timeout 5s;\\n'
        f\"            proxy_read_timeout {item['idle_seconds']}s;\\n\"
        f\"            proxy_send_timeout {item['idle_seconds']}s;\\n\")


def render(settings):
    settings = checked(settings)
    text = ('user www-data;\\nworker_processes auto;\\npid /run/debian13s4-web/nginx.pid;\\n'
        'error_log stderr warn;\\nevents { worker_connections 1024; }\\nhttp {\\n'
        '    server_tokens off;\\n    access_log off;\\n    merge_slashes on;\\n'
        '    client_header_timeout 10s;\\n    client_body_timeout 30s;\\n'
        '    send_timeout 30s;\\n    keepalive_timeout 30s;\\n'
        '    client_body_temp_path /run/debian13s4-web/body;\\n'
        '    map \$http_upgrade \$s4_connection { default upgrade; \"\" close; }\\n'
        '    server { listen 80 default_server; listen [::]:80 default_server;\\n'
        '        server_name \"\"; return 444; }\\n'
        '    server { listen 443 ssl default_server; listen [::]:443 ssl default_server;\\n'
        '        ssl_reject_handshake on; return 444; }\\n')
    for index, app in enumerate(APPLICATIONS):
        name = settings['applications'][app]['hostname']
        text += (f'    map \$http_host \$s4_host_{index} {{ default 0; '
                 f'{name} 1; {name}:443 1; }}\\n')
    for index, app in enumerate(APPLICATIONS):
        item = settings['applications'][app]; name = item['hostname']
        text += (f'    server {{ listen 80; listen [::]:80; server_name {name};\\n'
                 f'        return 308 https://{name}\$request_uri; }}\\n'
                 f'    server {{ listen 443 ssl; listen [::]:443 ssl; server_name {name};\\n'
                 f'        ssl_certificate {item[\"certificate\"]};\\n'
                 f'        ssl_certificate_key {item[\"private_key\"]};\\n'
                 '        ssl_protocols TLSv1.2 TLSv1.3;\\n'
                 '        ssl_session_tickets off;\\n'
                 f'        client_max_body_size {item[\"body_bytes\"]};\\n'
                 f'        if (\$ssl_server_name != {name}) {{ return 421; }}\\n'
                 f'        if (\$host != {name}) {{ return 421; }}\\n'
                 f'        if (\$s4_host_{index} = 0) {{ return 421; }}\\n'
                 '        add_header Strict-Transport-Security \"max-age=86400\" always;\\n'
                 '        add_header X-Content-Type-Options nosniff always;\\n')
        if app == 'mk8.email':
            # Block double decoding and encoded separators before the allowlist.
            # nginx location matching normalizes URI, while proxy_pass without a
            # URI preserves the client's URI. No public admin catch-all exists.
            text += '        if (\$request_uri ~* \"%25|%2f|%5c|%00\") { return 400; }\\n'
            for path in MAIL_EXACT:
                text += f'        location = {path} {{\\n' + proxy(item) + '        }\\n'
            for path in MAIL_PREFIX:
                text += f'        location ^~ {path} {{\\n' + proxy(item) + '        }\\n'
            text += '        location / { return 404; }\\n'
        else:
            if app == 'mk8.drava':
                text += ('        location ^~ /mk8.drava.proxy.v1.ServiceRegistry/ { return 404; }\\n')
            text += ('        location ~* ^/(health|metrics|internal|admin|_drava)(/|\$) { return 404; }\\n'
                     '        location / {\\n' + proxy(item) + '        }\\n')
        text += '    }\\n'
    return text + '}\\n'


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited ingress deadline')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing ingress caller context')
    settings = configuration(end)
    inputs = materials(settings['value'], end)
    config = render(settings['value'])
    record = {'schema': 1, 'profile': 'nginx-private-https-three-gateway-intention-v1',
        'state': 'ingress-configuration-intention-only', 'namespace': context,
        'configuration': settings, 'materials': inputs, 'nginx': config,
        'nginx_sha256': hashlib.sha256(config.encode('ascii')).hexdigest()}
    payload = BASE.canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('ingress intention exceeds output bound')
    if configuration(end) != settings or materials(settings['value'], end) != inputs:
        raise Pending('ingress configuration or TLS material changed')
    if KERNEL.uint(scope(), 0xffffffffffffffff) != context:
        raise Pending('ingress caller context changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('ingress preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('ingress preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete ingress intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/web/prepare.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Bound existing TLS inputs, fixed native checks and reported nginx listeners.

Calling default checks reads native host state and nginx -t may open/create
referenced runtime files. Controller start/publication is MUTATING. Neither is
operationally authorized by source review or by the private fixture evidence.
Honest native replies/manager reports are not loaded-memory or client proof.
\"\"\"
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location('debian13s4_web_prepare', Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
CONFIG = Path('/etc/debian13s4-web/nginx.conf')
NGINX = Path('/usr/sbin/nginx')
OPENSSL = Path('/usr/bin/openssl')
SS = Path('/usr/bin/ss')
PASSWD = Path('/etc/passwd')
GROUP = Path('/etc/group')
CA = Path('/etc/ssl/certs/ca-certificates.crt')
PROC = Path('/proc')
MAX_BYTES = 262144
ATTEMPT_SECONDS = 60


def window(deadline, seconds=ATTEMPT_SECONDS):
    end = KERNEL.now() + seconds
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited web window')
        end = min(end, deadline)
    PREP.BASE.fence(end); return end


def worker(raw):
    try: text=raw.decode('ascii')
    except UnicodeError as error: raise Pending('unsupported web account encoding') from error
    if not text.endswith('\\n') or any(c!='\\n' and not 32<=ord(c)<=126 for c in text):
        raise Pending('unsupported web account inventory')
    rows=text[:-1].split('\\n'); seen=set();uids=set();primary_gids={};selected=None
    if len(rows)>4096:raise Pending('web account row bound')
    for line in rows:
        row=line.split(':')
        if len(row)!=7 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',row[0]) is None or row[0] in seen:
            raise Pending('malformed web account')
        if any(re.fullmatch(r'0|[1-9][0-9]{0,9}',row[i]) is None for i in (2,3)):
            raise Pending('malformed web account identity')
        uid,gid=(KERNEL.uint(int(row[i]),0x7fffffff) for i in (2,3))
        if uid in uids:raise Pending('shared web account UID')
        seen.add(row[0]);uids.add(uid);primary_gids[row[0]]=gid
        if row[0]=='www-data':
            if (not 1<=uid<=999 or gid==0 or row[1] not in ('x','!','*') or
                row[6] not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false')):
                raise Pending('unsupported existing nginx worker account')
            selected={'uid':uid,'gid':gid,'name':'www-data'}
    if selected is None:raise Pending('missing existing nginx worker account')
    if any(name!=selected['name'] and gid==selected['gid'] for name,gid in primary_gids.items()):
        raise Pending('shared nginx worker primary group')
    return selected


def groups(raw,account):
    text=raw.decode('ascii')
    if not text.endswith('\\n') or any(c!='\\n' and not 32<=ord(c)<=126 for c in text):
        raise Pending('unsupported web group inventory')
    rows=text[:-1].split('\\n');names=set();gids=set();selected=False
    if len(rows)>4096:raise Pending('web group row bound')
    for line in rows:
        row=line.split(':')
        if (len(row)!=4 or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',row[0]) is None or
            row[0] in names or re.fullmatch(r'0|[1-9][0-9]{0,9}',row[2]) is None):
            raise Pending('malformed web group')
        gid=KERNEL.uint(int(row[2]),0x7fffffff)
        if gid in gids:raise Pending('ambiguous web group GID')
        names.add(row[0]);gids.add(gid)
        members=row[3].split(',') if row[3] else []
        if len(set(members))!=len(members) or any(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}',member) is None for member in members):
            raise Pending('malformed web group membership')
        if row[0]=='www-data':
            if gid!=account['gid'] or any(member!='www-data' for member in members):
                raise Pending('shared or changed nginx worker group')
            selected=True
        elif 'www-data' in members:raise Pending('supplementary nginx worker group refuses')
    if not selected:raise Pending('missing dedicated nginx worker group')


def inputs(end):
    record=json.loads(PREP.prepare(deadline=end))
    raw,source=PREP.BASE.read_protected(PASSWD,262144,False,end)
    account=worker(raw)
    group,group_source=PREP.BASE.read_protected(GROUP,262144,False,end);groups(group,account)
    ca,ca_source=PREP.BASE.read_protected(CA,524288,False,end)
    if not ca:raise Pending('empty fixed system CA bundle')
    config,config_source=PREP.BASE.read_protected(CONFIG,PREP.MAX_OUTPUT,False,end)
    if config!=record['nginx'].encode('ascii'):raise Pending('installed nginx configuration differs')
    binaries={}
    for path in (NGINX,OPENSSL,SS):
        before=KERNEL.trusted_binary(path)
        _,fact=PREP.BASE.read_protected(path,16777216,False,end)
        if KERNEL.trusted_binary(path)!=before:raise Pending('web native executable changed')
        binaries[str(path)]={'signature':list(before),'source':fact}
    return {'intention':record,'account':account,'account_source':source,'group_source':group_source,'ca_source':ca_source,
            'config_source':config_source,'binaries':binaries}


def arguments(kind,item=None,epoch=None):
    if kind=='nginx':return NGINX,('-t','-q','-c',str(CONFIG),'-p',str(CONFIG.parent)+'/')
    if kind=='sockets':return SS,('-H','-n','-l','-t','-p','sport = :80 or sport = :443')
    if kind not in ('certificate-key','private-key','key-check','verify'):raise Pending('unapproved web native check')
    if type(item) is not dict:raise Pending('missing checked TLS item')
    for field in ('certificate','private_key','upstream_ca'):PREP.material_path(item[field])
    PREP.hostname(item['hostname'])
    if kind=='certificate-key':args=('x509','-in',item['certificate'],'-pubkey','-noout')
    elif kind=='private-key':args=('pkey','-in',item['private_key'],'-pubout','-passin','pass:')
    elif kind=='key-check':args=('pkey','-in',item['private_key'],'-check','-noout','-passin','pass:')
    else:
        if type(epoch) is not int or not 1<=epoch<=0x7fffffff:raise Pending('invalid explicit TLS verification time')
        args=('verify','-x509_strict','-auth_level','2','-purpose','sslserver','-verify_hostname',item['hostname'],
            '-attime',str(epoch),'-CAfile',str(CA),'-no-CApath','-no-CAstore',
            '-untrusted',item['certificate'],item['certificate'])
    return OPENSSL,args


class CleanupFailure(Pending):
    \"\"\"Keep the original capture refusal and separate owned cleanup errors.\"\"\"
    def __init__(self, cause, cleanup):
        super().__init__('web native capture cleanup incomplete')
        self.cause, self.cleanup = cause, cleanup


def close_child(child, selector):
    \"\"\"Retire known pipes before cleanup; do not let one error skip another step.\"\"\"
    streams = child.stdout, child.stderr
    child.stdout = child.stderr = None
    errors = []
    if child.returncode is None:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            errors.append(error)
        try:
            child.wait(timeout=KERNEL.CLEANUP_SECONDS)
        except BaseException as error:
            errors.append(error)
    if selector is not None:
        try:
            selector.close()
        except BaseException as error:
            errors.append(error)
    for stream in streams:
        if stream is not None:
            try:
                stream.close()
            except BaseException as error:
                errors.append(error)
    return tuple(errors)


def native(kind,item,end,epoch=None):
    PREP.BASE.fence(end);binary,args=arguments(kind,item,epoch)
    before=KERNEL.trusted_binary(binary)
    until=min(end,KERNEL.now()+KERNEL.QUERY_SECONDS);PREP.BASE.fence(until)
    cause, selector = None, None
    child=subprocess.Popen([str(binary),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,bufsize=0,env={'PATH':'/usr/bin:/usr/sbin','LC_ALL':'C'},
        close_fds=True,start_new_session=True)
    try:
        buffers={'stdout':bytearray(),'stderr':bytearray()}
        selector = selectors.DefaultSelector()
        for name,stream in (('stdout',child.stdout),('stderr',child.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        while selector.get_map():
            PREP.BASE.fence(until);remaining=until-KERNEL.now()
            if remaining<=0:raise Pending('web native capture window expired')
            for key,_ in selector.select(remaining):
                part=os.read(key.fileobj.fileno(),65536)
                if not part:selector.unregister(key.fileobj);continue
                buffer=buffers[key.data]
                if len(buffer)+len(part)>MAX_BYTES:raise Pending('web native channel bound')
                buffer.extend(part)
        PREP.BASE.fence(until);remaining=until-KERNEL.now()
        if remaining<=0:raise Pending('web native root wait window expired')
        code=child.wait(timeout=remaining)
        if type(code) is not int or code!=0 or buffers['stderr']:raise Pending('web native check failed/warned')
        if KERNEL.trusted_binary(binary)!=before:raise Pending('web native executable drift')
        PREP.BASE.fence(until);return bytes(buffers['stdout'])
    except BaseException as error:
        cause = error
        raise
    finally:
        closing, selector = selector, None
        cleanup = close_child(child, closing)
        if cleanup:
            if cause is None and len(cleanup) == 1:
                raise cleanup[0]
            raise CleanupFailure(cause, cleanup) from cause


def public_key(raw):
    if type(raw) is not bytes or len(raw)>16384:raise Pending('invalid native public key bytes')
    prefix=b'-----BEGIN PUBLIC KEY-----\\n';suffix=b'-----END PUBLIC KEY-----\\n'
    if not raw.startswith(prefix) or not raw.endswith(suffix):raise Pending('invalid native public key framing')
    body=raw[len(prefix):-len(suffix)]
    if not body.endswith(b'\\n'):raise Pending('invalid native public key newline')
    lines=body[:-1].split(b'\\n')
    if not lines or any(len(line)!=64 for line in lines[:-1]) or not 1<=len(lines[-1])<=64:
        raise Pending('invalid native public key line grammar')
    encoded=b''.join(lines)
    try:decoded=base64.b64decode(encoded,validate=True)
    except ValueError as error:raise Pending('invalid native public key base64') from error
    if not decoded or base64.b64encode(decoded)!=encoded:raise Pending('noncanonical native public key')
    return raw


def process_stat(raw,pid):
    if type(raw) is not bytes or len(raw)>4096:raise Pending('web process stat bound')
    prefix=str(pid).encode()+b' (';end=raw.rfind(b')')
    if not raw.startswith(prefix) or end<0:raise Pending('unsupported web process stat identity')
    fields=raw[end+2:].split()
    if len(fields)<20 or any(re.fullmatch(rb'[0-9]+',fields[i]) is None for i in (1,19)):
        raise Pending('unsupported web process parent/start fields')
    return KERNEL.uint(int(fields[1]),0x7fffffff),KERNEL.uint(int(fields[19]),2**64-1)


def process_credentials(raw):
    if type(raw) is not bytes or len(raw)>65536:raise Pending('web process status bound')
    rows=raw.decode('ascii').split('\\n');result={}
    for name in ('Uid','Gid'):
        selected=[row for row in rows if row.startswith(name+':')]
        if len(selected)!=1 or re.fullmatch(name+r':\\s+[0-9]+\\s+[0-9]+\\s+[0-9]+\\s+[0-9]+',selected[0]) is None:
            raise Pending('unsupported web process credentials')
        values=[KERNEL.uint(int(value),0x7fffffff) for value in selected[0].split()[1:]]
        if len(set(values))!=1:raise Pending('mixed web process credentials')
        result[name.lower()]=values[0]
    return result


def process(pid):
    # Honest procfs SOURCE identity; mutable CPU/fault/state counters are not
    # loaded-generation identity and may change during normal serving traffic.
    if not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid web listener PID')
    root=PROC/str(pid)
    ppid,start=process_stat((root/'stat').read_bytes(),pid)
    credentials=process_credentials((root/'status').read_bytes())
    loaded=(root/'exe').stat();current=NGINX.stat()
    if Path(os.readlink(root/'exe'))!=NGINX or (loaded.st_dev,loaded.st_ino)!=(current.st_dev,current.st_ino):
        raise Pending('web process executable differs')
    if (process_stat((root/'stat').read_bytes(),pid)!=(ppid,start) or
        process_credentials((root/'status').read_bytes())!=credentials):
        raise Pending('web process credentials/parent/start changed')
    final=(root/'exe').stat();current_after=NGINX.stat()
    if (Path(os.readlink(root/'exe'))!=NGINX or
        (final.st_dev,final.st_ino)!=(loaded.st_dev,loaded.st_ino) or
        (current_after.st_dev,current_after.st_ino)!=(current.st_dev,current.st_ino)):
        raise Pending('web process executable changed')
    return {**credentials,'ppid':ppid,'start':start}


def sockets(raw,pid,account,proc=process):
    if not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid nginx master PID')
    if type(raw) is not bytes or len(raw)>MAX_BYTES:raise Pending('invalid nginx listener bytes')
    text=raw.decode('ascii')
    if not text.endswith('\\n') or any(c!='\\n' and not 32<=ord(c)<=126 for c in text):raise Pending('unsupported nginx listener encoding')
    expected={'0.0.0.0:80','[::]:80','0.0.0.0:443','[::]:443'};found=set();owners={}
    for line in text[:-1].split('\\n'):
        parts=line.split()
        if (len(parts)!=6 or parts[0]!='LISTEN' or parts[3] not in expected or parts[3] in found or
            parts[4] not in ('0.0.0.0:*','[::]:*','*:*') or
            any(re.fullmatch(r'[0-9]+',value) is None for value in parts[1:3])):
            raise Pending('unsupported/foreign nginx listener row')
        for value in parts[1:3]:KERNEL.uint(int(value))
        if not parts[5].startswith('users:(') or not parts[5].endswith(')'):raise Pending('missing nginx owner data')
        body=parts[5][7:-1];matches=re.findall(r'\\(\"nginx\",pid=([1-9][0-9]*),fd=([0-9]+)\\)',body)
        if not matches or ','.join(f'(\"nginx\",pid={p},fd={fd})' for p,fd in matches)!=body:
            raise Pending('foreign or malformed nginx socket owners')
        ids=[]
        for p,fd in matches:
            number=KERNEL.uint(int(p),0x7fffffff);KERNEL.uint(int(fd));ids.append(number)
            if number not in owners:owners[number]=proc(number)
            info=owners[number]
            KERNEL.known(info,{'uid','gid','ppid','start'},{'uid','gid','ppid','start'})
            for field in ('uid','gid','ppid'):KERNEL.uint(info[field],0x7fffffff)
            if not KERNEL.uint(info['start'],2**64-1):raise Pending('missing process start identity')
            if number==pid:
                if info['uid']!=0 or info['gid']!=0:raise Pending('nonroot reported nginx master')
            elif info['uid']!=account['uid'] or info['gid']!=account['gid'] or info['ppid']!=pid:raise Pending('foreign nginx worker')
        if pid not in ids or len(set(ids))!=len(ids):raise Pending('missing/duplicate nginx master owner')
        if not any(number!=pid for number in ids):raise Pending('missing validated nginx worker owner')
        found.add(parts[3])
    if found!=expected:raise Pending('incomplete public nginx listener inventory')
    for number,before in owners.items():
        if proc(number)!=before:raise Pending('nginx process owner changed')


def file_payload(deadline=None):
    end=window(deadline,10)
    first=PREP.prepare(deadline=end);record=json.loads(first)
    payload=record['nginx'].encode('ascii')
    # Projection/encoding precedes a SECOND complete accepted preparation and
    # the final outer scope/time fence; only these exact cached bytes return.
    if PREP.prepare(deadline=end)!=first:raise Pending('web configuration projection changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=record['namespace']:raise Pending('web projection context changed')
    PREP.BASE.fence(end);return payload


def identity(deadline=None):
    end=window(deadline,10);first=inputs(end)
    payload=PREP.BASE.canonical({'schema':1,'namespace':first['intention']['namespace'],
        'startup_sha256':hashlib.sha256(PREP.BASE.canonical(first)).hexdigest()})
    if inputs(end)!=first:raise Pending('web startup inputs changed')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=first['intention']['namespace']:raise Pending('web identity context changed')
    PREP.BASE.fence(end);return payload


def check(read=native,deadline=None,pid=None,proc=process):
    end=window(deadline)
    if pid is not None and not KERNEL.uint(pid,0x7fffffff):raise Pending('invalid nginx master PID')
    first=inputs(end)
    timestamp=time.time()
    if type(timestamp) not in (int,float) or not math.isfinite(timestamp) or not 1<=timestamp<=0x7fffffff-3600:
        raise Pending('invalid web wallclock sample')
    epoch=int(timestamp)
    for app in PREP.APPLICATIONS:
        item=first['intention']['configuration']['value']['applications'][app]
        certificate=public_key(read('certificate-key',item,end))
        if public_key(read('private-key',item,end))!=certificate:raise Pending('TLS certificate/private key differ')
        if read('key-check',item,end)!=b'Key is valid\\n':raise Pending('native private key validation differs')
        for at in (epoch,epoch+3600):
            if read('verify',item,end,at)!=(item['certificate']+': OK\\n').encode('ascii'):
                raise Pending('native TLS purpose/name/chain/current-or-hour check failed')
    if read('nginx',None,end):raise Pending('nginx quiet syntax check produced output')
    if pid is not None:sockets(read('sockets',None,end),pid,first['account'],proc)
    if inputs(end)!=first:raise Pending('web startup inputs drifted during native checks')
    if KERNEL.uint(KERNEL.namespace(),2**64-1)!=first['intention']['namespace']:raise Pending('web native context changed')
    final=time.time()
    if type(final) not in (int,float) or not math.isfinite(final) or not timestamp<=final<timestamp+ATTEMPT_SECONDS:
        raise Pending('web wallclock changed or native admission expired')
    PREP.BASE.fence(end)


def main():
    try:
        args=sys.argv[1:]
        if args not in (['--file'],['--identity'],['--check']) and not (
            len(args)==2 and args[0]=='--live' and re.fullmatch(r'[1-9][0-9]{0,9}',args[1])):
            return 64
        sink=sys.stdout.buffer
        if not callable(getattr(sink,'write',None)) or not callable(getattr(sink,'flush',None)):raise Pending('web policy requires binary stdout')
        if args==['--file']:payload=file_payload()
        elif args==['--identity']:payload=identity()
        else:
            check(pid=int(args[1]) if args[0]=='--live' else None);return 0
        count=sink.write(payload)
        if type(count) is not int or count!=len(payload):raise Pending('web policy incomplete byte publication')
        sink.flush();return 0
    except (Pending,OSError,ValueError,TypeError,AttributeError,UnicodeError,RecursionError,subprocess.TimeoutExpired) as error:
        print('debian13s4 web pending: '+str(error),file=sys.stderr);return 75


if __name__=='__main__':sys.exit(main())
" > "$S4B_STAGE/"lib/web/live.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Bound protected private HTTPS readiness/liveness SOURCE observations.

Default invocation CONNECTS to three configured loopback gateways. It is not
authorized by source acceptance or private delivery tests. TLS verifies the
supplied CA and SAN hostname under honest Python/OpenSSL; it does not prove
process ownership, app release/catalog identity, CRUD or future readiness.
Drava supplies liveness ONLY. This standalone entry is not a controller join.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import socket
import ssl
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_upstream_prepare',
    Path(__file__).with_name('prepare.py'))
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
KERNEL, Pending = PREP.KERNEL, PREP.Pending
ROUTES = {'mk8.sava': '/health/ready', 'mk8.drava': '/_drava/live',
          'mk8.email': '/health/ready'}
MAX_HEADERS = 8192
MAX_BODY = 65536
MAX_RESPONSE = MAX_HEADERS + MAX_BODY + 4
MAX_CERTIFICATE = 65536
MAX_OUTPUT = PREP.MAX_OUTPUT + 32768
ATTEMPT_SECONDS = 30


def timeout(end):
    PREP.BASE.fence(end)
    remaining = end - KERNEL.now()
    if remaining <= 0:
        raise Pending('upstream operation admission expired')
    return remaining


def request(app, item):
    if app not in ROUTES:
        raise Pending('unsupported upstream application')
    PREP.hostname(item['hostname']); PREP.hostname(item['upstream_name'])
    if type(item['upstream_port']) is not int or not 1024 <= item['upstream_port'] <= 65535:
        raise Pending('invalid explicit upstream port')
    return (f'GET {ROUTES[app]} HTTP/1.0\\r\\nHost: {item[\"hostname\"]}\\r\\n'
            'Connection: close\\r\\nAccept: application/json, text/plain\\r\\n'
            'Accept-Encoding: identity\\r\\n\\r\\n').encode('ascii')


def native(app, item, ca, end):
    # No DNS, proxy, environment CA defaults, redirects, client credential,
    # retry, key logging or unchecked CA pathname reopen. Every blocking socket
    # operation inherits the SAME capped BOOTTIME admission, not a hard timer.
    payload = request(app, item)
    if type(ca) is not bytes or not ca or len(ca) > PREP.MAX_PEM:
        raise Pending('invalid protected upstream CA bytes')
    until = min(end, KERNEL.now() + KERNEL.QUERY_SECONDS)
    timeout(until)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.set_alpn_protocols(['http/1.1'])
    context.load_verify_locations(cadata=ca.decode('ascii'))
    # Ownership transfers only after wrap_socket succeeds. The retired raw
    # descriptor must not be closed a second time by this module.
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw.settimeout(timeout(until))
        channel = context.wrap_socket(raw, server_hostname=item['upstream_name'],
            do_handshake_on_connect=False, suppress_ragged_eofs=False)
    except BaseException:
        raw.close()
        raise
    try:
        channel.settimeout(timeout(until))
        channel.connect(('127.0.0.1', item['upstream_port']))
        channel.settimeout(timeout(until)); channel.do_handshake()
        certificate = channel.getpeercert(binary_form=True)
        version, alpn = channel.version(), channel.selected_alpn_protocol()
        if (type(certificate) is not bytes or not 1 <= len(certificate) <= MAX_CERTIFICATE or
            version not in ('TLSv1.2', 'TLSv1.3') or alpn not in (None, 'http/1.1')):
            raise Pending('unsupported upstream TLS observation')
        channel.settimeout(timeout(until)); channel.sendall(payload)
        parts = bytearray()
        while True:
            channel.settimeout(timeout(until))
            part = channel.recv(min(4096, MAX_RESPONSE + 1 - len(parts)))
            if not part:
                break
            parts.extend(part)
            if len(parts) > MAX_RESPONSE:
                raise Pending('upstream response exceeds capture bound')
        timeout(until)
        return {'tls': version, 'certificate': certificate, 'response': bytes(parts)}
    finally:
        channel.close()


def response(raw, app):
    if type(raw) is not bytes or not raw or len(raw) > MAX_RESPONSE:
        raise Pending('invalid immutable upstream response')
    header, separator, body = raw.partition(b'\\r\\n\\r\\n')
    if not separator or len(header) > MAX_HEADERS or len(body) > MAX_BODY:
        raise Pending('upstream header/body bound or delimiter')
    lines = header.split(b'\\r\\n')
    if re.fullmatch(rb'HTTP/1\\.[01] 200 [\\x20-\\x7e]*', lines[0]) is None:
        raise Pending('upstream response is not final success')
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        if (not colon or re.fullmatch(rb\"[!#\$%&'*+.^_\`|~0-9A-Za-z-]+\", name) is None or
            any(byte < 32 or byte > 126 for byte in value)):
            raise Pending('unsupported upstream header grammar')
        name = name.lower()
        if name in fields:
            raise Pending('duplicate upstream header')
        fields[name] = value.strip(b' ')
    if any(name in fields for name in (b'transfer-encoding', b'content-encoding', b'location')):
        raise Pending('encoded/redirected upstream response is outside profile')
    if b'content-length' in fields:
        value = fields[b'content-length']
        if re.fullmatch(rb'0|[1-9][0-9]{0,5}', value) is None or int(value) != len(body):
            raise Pending('upstream content length differs')
    media = fields.get(b'content-type', b'').lower().replace(b' ', b'')
    if app == 'mk8.drava':
        if media not in (b'text/plain', b'text/plain;charset=utf-8') or body != b'running':
            raise Pending('Drava liveness response differs')
        return {'kind': 'gateway-liveness-only', 'status': 'running'}
    if media not in (b'application/json', b'application/json;charset=utf-8'):
        raise Pending('upstream readiness JSON media type differs')
    try:
        value = json.loads(body.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite readiness JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid upstream readiness JSON') from error
    if app == 'mk8.email':
        KERNEL.known(value, {'status'}, {'status'})
        if value['status'] != 'ready':
            raise Pending('Email application transport is not reported ready')
    elif app == 'mk8.sava':
        fields = {'status', 'component', 'application', 'metadata', 'integrity'}
        KERNEL.known(value, fields, fields)
        if (value['status'] != 'ready' or value['component'] != 'gateway' or
            value['application'] != 'ready' or value['metadata'] != 'ready'):
            raise Pending('Sava gateway/application/metadata is not reported ready')
        integrity = value['integrity']
        fields = {'status', 'complete', 'checkedChunks', 'missingChunks', 'corruptChunks',
                  'customerKeyChunks', 'checkedAt'}
        KERNEL.known(integrity, fields, fields)
        if integrity['status'] != 'healthy' or type(integrity['complete']) is not bool:
            raise Pending('unsupported reported Sava integrity')
        for name in ('checkedChunks', 'missingChunks', 'corruptChunks', 'customerKeyChunks'):
            KERNEL.uint(integrity[name], 0x7fffffffffffffff)
        if integrity['missingChunks'] or integrity['corruptChunks']:
            raise Pending('reported Sava chunk failures')
        at = integrity['checkedAt']
        if at is not None and (type(at) is not str or len(at) > 64 or
                              re.fullmatch(r'[0-9T:+.Z-]+', at) is None):
            raise Pending('unsupported reported Sava integrity timestamp')
    else:
        raise Pending('unsupported readiness application')
    return {'kind': 'gateway-reported-readiness', 'report': value}


def check(read=None, deadline=None):
    if read is None:
        read = native
    if not callable(read):
        raise Pending('unsupported HTTPS observation delivery')
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited upstream window')
        end = min(end, deadline)
    timeout(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing upstream caller context')
    original = PREP.prepare(deadline=end)
    intention = json.loads(original)
    if intention['namespace'] != context:
        raise Pending('upstream preparation caller differs')
    observations = {}
    for app in PREP.APPLICATIONS:
        item = intention['configuration']['value']['applications'][app]
        ca, fact = PREP.BASE.read_protected(Path(item['upstream_ca']), PREP.MAX_PEM, False, end)
        if fact != intention['materials'][item['upstream_ca']]['source']:
            raise Pending('protected upstream CA changed before entry')
        timeout(end)
        observed = read(app, item, ca, end)
        KERNEL.known(observed, {'tls', 'certificate', 'response'}, {'tls', 'certificate', 'response'})
        certificate = observed['certificate']
        if (observed['tls'] not in ('TLSv1.2', 'TLSv1.3') or type(certificate) is not bytes or
            not 1 <= len(certificate) <= MAX_CERTIFICATE):
            raise Pending('invalid upstream TLS delivery')
        report = response(observed['response'], app)
        observations[app] = {'endpoint': ['127.0.0.1', item['upstream_port']],
            'server_name': item['upstream_name'], 'host': item['hostname'], 'path': ROUTES[app],
            'tls': observed['tls'], 'certificate_sha256': hashlib.sha256(certificate).hexdigest(),
            'response_sha256': hashlib.sha256(observed['response']).hexdigest(), 'report': report}
        timeout(end)
    payload = PREP.BASE.canonical({'schema': 1, 'profile': 'private-https-three-gateway-probes-v1',
        'state': 'upstream-readiness-liveness-source-only', 'namespace': context,
        'intention': intention, 'observations': observations})
    if len(payload) > MAX_OUTPUT:
        raise Pending('upstream receipt output bound')
    if PREP.prepare(deadline=end) != original:
        raise Pending('protected upstream inputs changed during probes')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('upstream caller context changed')
    timeout(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('upstream probes accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('upstream probes require binary stdout')
        payload = check()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete upstream receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('debian13s4 upstream pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/web/upstream.py || return 1
    printf '%s' "#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
S4W_LIBRARY=/usr/local/lib/debian13s4/web
S4W_CONFIG=/etc/debian13s4-web
S4W_SERVER=debian13s4-web-server.service
S4W_SERVICE=debian13s4-web.service
S4W_TIMER=debian13s4-web.timer
S4W_LOADED_GENERATION=''
S4W_FILES=(prepare.py live.py upstream.py common.sh repair.sh debian13s4-web-server.service
    debian13s4-web.service debian13s4-web.timer)

s4w_policy() (
    local descriptor=\$S4M_REPAIR_FD seconds=10 script=live.py
    [[ \${1-} != --check && \${1-} != --live ]] || seconds=65
    if [[ \${1-} == --upstream ]]; then
        [[ \$# == 1 ]] || return 1
        script=upstream.py
        seconds=15
        shift
    fi
    trap - EXIT
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s \"\${seconds}s\" env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \\
        /usr/bin/python3 -I -B \"\$S4W_LIBRARY/\$script\" \"\$@\"
)

s4w_action() (
    local descriptor=\$S4M_REPAIR_FD action=\$1
    trap - EXIT
    [[ \$action == stop || \$action == start ]] || return 1
    [[ -z \$descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 120s env -i PATH=\"\$S4M_PATH\" LANG=C LC_ALL=C \\
        systemctl \"\$action\" \"\$S4W_SERVER\"
)

s4w_assets() {
    local name
    [[ -d \$S4M_STATE && -d \$S4M_SYSTEMD ]] &&
        s4m_trusted \"\$S4M_STATE\" && s4m_trusted \"\$S4M_SYSTEMD\" || return 1
    for name in \"\${S4W_FILES[@]}\"; do
        [[ -f \$S4W_LIBRARY/\$name ]] && s4m_trusted \"\$S4W_LIBRARY/\$name\" || return 1
    done
    [[ -x \$S4W_LIBRARY/repair.sh ]] && s4m_trusted \"\$S4M_LIBRARY/common.sh\" &&
        s4m_trusted \"\${S4W_LIBRARY%/*}/firewall/kernel.py\" &&
        s4m_trusted \"\${S4W_LIBRARY%/*}/postgresql/prepare.py\"
}

s4w_identity() {
    local name digest
    for name in \"\${S4W_FILES[@]}\"; do
        digest=\$(sha256sum -- \"\$S4W_LIBRARY/\$name\") || return 1
        printf '%s web/%s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py postgresql/prepare.py; do
        digest=\$(sha256sum -- \"\${S4W_LIBRARY%/*}/\$name\") || return 1
        printf '%s %s\\n' \"\${digest%% *}\" \"\$name\" || return 1
    done
}

s4w_packages() (
    # This supported join requires pre-installed nginx/crypto packages, existing private TLS
    # inputs and an inactive vendor nginx service. It never invokes APT.
    s4m_load_packages || return 1
    S4P_PACKAGES=(nginx nginx-common openssl ca-certificates)
    s4p_query() {
        s4m_control dpkg-query --show --showformat=\"\\\${Status}\\n\" -- \"\$1\"
    }
    s4p_dpkg() {
        [[ \$# == 1 && \$1 == --audit ]] || return 1
        s4m_control dpkg --audit
    }
    s4p_verify
)

s4w_stop() {
    local loaded marker=\$S4M_STATE/web.loaded
    loaded=\$(s4m_systemctl show --property=LoadState --value \"\$S4W_SERVER\") || return 1
    if [[ \$loaded == loaded ]]; then
        s4w_action stop && s4m_property \"\$S4W_SERVER\" ActiveState inactive &&
            s4m_property \"\$S4W_SERVER\" MainPID 0 || return 1
    elif [[ \$loaded != not-found ]]; then
        return 1
    fi
    if [[ -e \$marker || -L \$marker ]]; then
        [[ -f \$marker ]] && s4m_trusted \"\$marker\" && rm -f -- \"\$marker\" || return 1
        s4m_sync \"\$S4M_STATE\" || return 1
    fi
}

s4w_vendor_inactive() {
    local loaded
    loaded=\$(s4m_systemctl show --property=LoadState --value nginx.service) || return 1
    if [[ \$loaded == loaded || \$loaded == masked ]]; then
        s4m_property nginx.service ActiveState inactive && s4m_property nginx.service MainPID 0
    else
        [[ \$loaded == not-found ]]
    fi
}

s4w_configure() {
    local temporary
    # No foreign/vendor stop or adoption. Only our own server is stopped,
    # and inactivity is confirmed BEFORE replacing any startup configuration.
    s4w_vendor_inactive && s4w_stop || return 1
    if [[ -e \$S4W_CONFIG || -L \$S4W_CONFIG ]]; then
        [[ -d \$S4W_CONFIG ]] && s4m_trusted \"\$S4W_CONFIG\" || return 1
    else
        s4m_trusted \"\${S4W_CONFIG%/*}\" && mkdir -m 0755 -- \"\$S4W_CONFIG\" || return 1
    fi
    temporary=\$(mktemp -- \"\$S4M_STATE/web-config.XXXXXX\") || return 1
    if ! s4w_policy --file > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4W_CONFIG/nginx.conf\" \"\$temporary\" 0644; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4w_policy --identity > /dev/null
}

s4w_generation() {
    local rows key value active='' pid='' invocation=''
    rows=\$(s4m_systemctl show --property=ActiveState --property=MainPID \\
        --property=InvocationID \"\$S4W_SERVER\") || return 1
    [[ \${#rows} -le 512 ]] || return 1
    while IFS='=' read -r key value; do
        case \$key in
            ActiveState) [[ -z \$active && \$value == active ]] || return 1; active=\$value ;;
            MainPID)
                [[ -z \$pid && \$value =~ ^[1-9][0-9]{0,9}\$ ]] &&
                    (( 10#\$value <= 2147483647 )) || return 1; pid=\$value ;;
            InvocationID)
                [[ -z \$invocation && \$value =~ ^[0-9a-f]{32}\$ &&
                    \$value != 00000000000000000000000000000000 ]] || return 1; invocation=\$value ;;
            *) return 1 ;;
        esac
    done <<< \"\$rows\"
    [[ \$active == active && -n \$pid && -n \$invocation ]] || return 1
    printf 'instance %s %s\\n' \"\$pid\" \"\$invocation\" && s4w_identity && s4w_policy --identity
}

s4w_loaded() {
    local marker=\$S4M_STATE/web.loaded mode size links actual expected
    [[ -f \$marker ]] && s4m_trusted \"\$marker\" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- \"\$marker\") || return 1
    [[ \$mode == 600 && \$links == 1 && \$size =~ ^[1-9][0-9]{0,4}\$ ]] &&
        (( 10#\$size <= 24576 )) || return 1
    expected=\$(s4w_generation) && actual=\$(cat -- \"\$marker\") && [[ \$expected == \"\$actual\" ]] || return 1
    S4W_LOADED_GENERATION=\$expected
}

s4w_live() {
    local before pid
    s4w_loaded || return 1
    before=\$S4W_LOADED_GENERATION
    pid=\${before%%\$'\\n'*}; pid=\${pid#instance }; pid=\${pid%% *}
    s4w_vendor_inactive && s4w_policy --live \"\$pid\" && s4w_policy --upstream > /dev/null &&
        s4w_loaded && [[ \$before == \"\$S4W_LOADED_GENERATION\" ]]
}

s4w_start() {
    local before after generation temporary pid
    s4m_property \"\$S4W_SERVER\" ActiveState inactive && s4m_property \"\$S4W_SERVER\" MainPID 0 || return 1
    s4w_vendor_inactive || return 1
    s4w_policy --upstream > /dev/null || return 1
    before=\$(s4w_identity && s4w_policy --identity) && s4w_action start &&
        after=\$(s4w_identity && s4w_policy --identity) && [[ \$before == \"\$after\" ]] || return 1
    generation=\$(s4w_generation) && [[ \${generation#*\$'\\n'} == \"\$before\" ]] || return 1
    pid=\${generation%%\$'\\n'*}; pid=\${pid#instance }; pid=\${pid%% *}
    s4w_policy --live \"\$pid\" && s4w_policy --upstream > /dev/null &&
        [[ \$(s4w_generation) == \"\$generation\" ]] || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/web-loaded.XXXXXX\") || return 1
    if ! printf '%s\\n' \"\$generation\" > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/web.loaded\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4w_loaded
}

s4w_units() {
    local name
    for name in \"\$S4W_SERVER\" \"\$S4W_SERVICE\" \"\$S4W_TIMER\"; do
        [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" &&
            cmp --silent -- \"\$S4W_LIBRARY/\$name\" \"\$S4M_SYSTEMD/\$name\" || return 1
        s4m_property \"\$name\" FragmentPath \"\$S4M_SYSTEMD/\$name\" &&
            s4m_property \"\$name\" DropInPaths '' || return 1
    done
    s4m_enabled \"\$S4W_SERVER\" && s4m_enabled \"\$S4W_TIMER\" && s4m_property \"\$S4W_TIMER\" ActiveState active
}

s4w_ready() {
    local actual expected mode size links
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending &&
        -f \$S4M_STATE/web.ready ]] && s4m_trusted \"\$S4M_STATE/web.ready\" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- \"\$S4M_STATE/web.ready\") || return 1
    [[ \$mode == 600 && \$links == 1 && \$size =~ ^[1-9][0-9]{0,3}\$ ]] &&
        (( 10#\$size <= 4096 )) || return 1
    s4w_assets && s4w_units || return 1
    expected=\$(s4w_identity) && actual=\$(cat -- \"\$S4M_STATE/web.ready\") && [[ \$expected == \"\$actual\" ]]
}

s4w_verify() {
    s4w_ready && s4w_packages && s4w_live
}

s4w_publish() {
    local name wants resolved temporary
    for name in \"\$S4W_SERVER\" \"\$S4W_SERVICE\" \"\$S4W_TIMER\"; do
        s4m_atomic \"\$S4M_SYSTEMD/\$name\" \"\$S4W_LIBRARY/\$name\" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for name in \"\$S4W_SERVER\" \"\$S4W_TIMER\"; do
        s4m_systemctl enable \"\$name\" && s4m_enabled \"\$name\" || return 1
        wants=\$S4M_SYSTEMD/multi-user.target.wants
        [[ \$name != \"\$S4W_TIMER\" ]] || wants=\$S4M_SYSTEMD/timers.target.wants
        [[ -d \$wants && -L \$wants/\$name ]] && s4m_trusted \"\$wants\" || return 1
        resolved=\$(readlink --canonicalize-existing -- \"\$wants/\$name\") && [[ \$resolved == \"\$S4M_SYSTEMD/\$name\" ]] || return 1
        s4m_sync \"\$wants\" \"\$S4M_SYSTEMD\" \"\$S4M_SYSTEMD/\$name\" || return 1
    done
    s4w_start && s4m_systemctl start \"\$S4W_TIMER\" && s4w_units && s4w_live || return 1
    temporary=\$(mktemp -- \"\$S4M_STATE/web-ready.XXXXXX\") || return 1
    if ! s4w_identity > \"\$temporary\" || ! chmod 0600 -- \"\$temporary\" ||
        ! s4m_atomic \"\$S4M_STATE/web.ready\" \"\$temporary\" 0600; then
        rm -f -- \"\$temporary\"
        return 1
    fi
    rm -f -- \"\$temporary\" && s4w_verify
}

s4w_apply() {
    local name loaded
    s4w_assets && s4w_packages || return 1
    for name in \"\$S4W_SERVER\" \"\$S4W_SERVICE\" \"\$S4W_TIMER\"; do
        if [[ -e \$S4M_SYSTEMD/\$name || -L \$S4M_SYSTEMD/\$name ]]; then
            [[ -f \$S4M_SYSTEMD/\$name ]] && s4m_trusted \"\$S4M_SYSTEMD/\$name\" || return 1
        fi
    done
    if [[ -e \$S4M_STATE/web.ready || -L \$S4M_STATE/web.ready ]]; then
        [[ -f \$S4M_STATE/web.ready ]] && s4m_trusted \"\$S4M_STATE/web.ready\" &&
            rm -f -- \"\$S4M_STATE/web.ready\" || return 1
    fi
    s4m_sync \"\$S4M_STATE\" || return 1
    for name in \"\$S4W_TIMER\" \"\$S4W_SERVICE\"; do
        loaded=\$(s4m_systemctl show --property=LoadState --value \"\$name\") || return 1
        if [[ \$loaded == loaded ]]; then
            s4m_systemctl stop \"\$name\" && s4m_property \"\$name\" ActiveState inactive || return 1
        elif [[ \$loaded != not-found ]]; then return 1; fi
    done
    if s4w_configure && s4w_publish; then return 0; fi
    s4w_stop || return 1
    return 1
}

s4w_repair() {
    [[ ! -e \$S4M_STATE/bootstrap/pending && ! -L \$S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    if s4w_ready && s4w_packages; then
        if s4w_live; then return 0; fi
        if s4w_configure && s4w_start && s4w_live; then return 0; fi
    fi
    s4w_stop || return 75
    return 75
}
" > "$S4B_STAGE/"lib/web/common.sh || return 1
    printf '%s' "#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77
# shellcheck source=Web/common.sh
. /usr/local/lib/debian13s4/web/common.sh
s4w_repair
" > "$S4B_STAGE/"lib/web/repair.sh || return 1
    printf '%s' "[Unit]
Description=Existing private-HTTPS gateway nginx ingress
After=local-fs.target network.target
RequiresMountsFor=/usr/local/lib/debian13s4 /etc/debian13s4 /etc/debian13s4-web /etc/ssl
ConditionPathExists=!/var/lib/debian13s4/bootstrap/pending
StartLimitIntervalSec=0

[Service]
Type=exec
User=root
Group=root
ExecStartPre=/usr/bin/python3 -I -B /usr/local/lib/debian13s4/web/live.py --check
ExecStart=/usr/sbin/nginx -e stderr -c /etc/debian13s4-web/nginx.conf -p /etc/debian13s4-web/ -g 'daemon off;'
UMask=0077
RuntimeDirectory=debian13s4-web
RuntimeDirectoryMode=0755
StandardInput=null
StandardOutput=journal
StandardError=journal
TimeoutStartSec=120s
TimeoutStopSec=120s
KillSignal=SIGQUIT
KillMode=control-group
Restart=on-failure
RestartSec=30s
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/run/debian13s4-web
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_READ_SEARCH CAP_KILL

[Install]
WantedBy=multi-user.target
" > "$S4B_STAGE/"lib/web/debian13s4-web-server.service || return 1
    printf '%s' "[Unit]
Description=Check and restore existing TLS/nginx ingress startup inputs
After=local-fs.target
RequiresMountsFor=/usr/local/lib/debian13s4 /var/lib/debian13s4 /etc/debian13s4 /etc/debian13s4-web
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/debian13s4/web/repair.sh
User=root
Group=root
UMask=0077
StandardInput=null
StandardOutput=journal
StandardError=journal
# At most84 controls*11 +11 plain policies*11 +3 native policies*66
# +4 upstream policies*16 +3 server actions*121 +60 local seconds=1730.
# ExecStartPre's check is INCLUDED in the server start's121, not charged twice.
# This remains below unchanged1750 and phase1800; no old predicate is removed.
# Finite honest SOURCE accounting, not stalled IO/native/hard-progress proof.
TimeoutStartSec=1750s
TimeoutStopSec=30s
KillMode=control-group
Restart=on-failure
RestartSec=1min
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectClock=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
" > "$S4B_STAGE/"lib/web/debian13s4-web.service || return 1
    printf '%s' "[Unit]
Description=Periodic existing TLS/nginx input-generation check

[Timer]
OnBootSec=2min
OnUnitInactiveSec=5min
AccuracySec=15s
Persistent=yes
Unit=debian13s4-web.service

[Install]
WantedBy=timers.target
" > "$S4B_STAGE/"lib/web/debian13s4-web.timer || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Web/common.sh
. /usr/local/lib/debian13s4/web/common.sh
s4w_apply
" > "$S4B_STAGE/"lib/tasks/web/apply.sh || return 1
    printf '%s' "#!/bin/bash
# shellcheck source=Web/common.sh
. /usr/local/lib/debian13s4/web/common.sh
s4w_verify
" > "$S4B_STAGE/"lib/tasks/web/verify.sh || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Observe complete protected, preinstalled four-app release file intentions.

No binary is executed, installed, adopted or authenticated. Matching public
hashes and repeated filesystem facts are SOURCE correspondence only, not a
signed publisher/release, loaded memory, ABI, service or readiness certificate.
\"\"\"
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_release_reader',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_release_reader',
        Path(__file__).resolve().parents[1] / 'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL, Pending = BASE.KERNEL, BASE.Pending
INPUT = Path('/etc/debian13s4/application-releases.json')
RELEASE_ROOT = Path('/opt/debian13s4-apps')
APPLICATIONS = ('mk8.sava', 'mk8.drava', 'mk8.dns', 'mk8.email')
SERVICES = ('application', 'gateway')
MAX_INPUT = 262145
MAX_OUTPUT = 1048577
MAX_FILES = 256
MAX_DIRECTORIES = 256
MAX_TREE_ITEMS = 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
ATTEMPT_SECONDS = 60


def relative(value):
    if (type(value) is not str or not 1 <= len(value) <= 160 or
        re.fullmatch(r'[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64}){0,7}', value) is None or
        any(part in ('.', '..') for part in value.split('/'))):
        raise Pending('unsupported canonical relative release path')
    return value


def sha(value):
    if (type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None or
        value == '0' * 64):
        raise Pending('unsupported release SHA256 spelling')
    return value


def generation(entries, files):
    return hashlib.sha256(BASE.canonical({'entry_points': entries, 'files': files})).hexdigest()


def checked(value):
    KERNEL.known(value, {'schema', 'applications'}, {'schema', 'applications'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported application release schema')
    KERNEL.known(value['applications'], set(APPLICATIONS), set(APPLICATIONS))
    total = 0
    for app in APPLICATIONS:
        row = value['applications'][app]
        fields = {'generation', 'directory', 'entry_points', 'files'}
        KERNEL.known(row, fields, fields)
        marker = sha(row['generation'])
        if type(row['directory']) is not str or row['directory'] != str(RELEASE_ROOT / app / marker):
            raise Pending('release requires its explicit product/generation directory')
        KERNEL.known(row['entry_points'], set(SERVICES), set(SERVICES))
        entries = [relative(row['entry_points'][role]) for role in SERVICES]
        if entries[0] == entries[1]:
            raise Pending('application and gateway entry points must differ')
        files = row['files']
        if type(files) is not dict or not 2 <= len(files) <= MAX_FILES:
            raise Pending('release requires a complete bounded file inventory')
        for name, item in files.items():
            relative(name)
            KERNEL.known(item, {'bytes', 'mode', 'sha256'}, {'bytes', 'mode', 'sha256'})
            if type(item['mode']) is not str or item['mode'] not in ('0644', '0755'):
                raise Pending('unsupported release file mode')
            total += KERNEL.uint(item['bytes'], MAX_FILE_BYTES)
            sha(item['sha256'])
        if total > MAX_TOTAL_BYTES:
            raise Pending('whole release inventory byte capacity exceeded')
        for name in entries:
            if name not in files or files[name]['mode'] != '0755' or files[name]['bytes'] == 0:
                raise Pending('release entry requires a declared nonempty executable')
        if generation(row['entry_points'], files) != marker:
            raise Pending('release generation does not bind the complete declared inventory')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite release JSON')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected application release input') from error
    if raw != BASE.canonical(value):
        raise Pending('release input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def protected_directory(path, end):
    BASE.fence(end)
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise Pending('noncanonical release directory')
    path.relative_to(BASE.TRUST_ROOT)
    current = path
    while True:
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != BASE.TRUSTED_UID or
            info.st_mode & 0o022):
            raise Pending('unprotected release directory or ancestry')
        if current == BASE.TRUST_ROOT:
            break
        current = current.parent
    return path.lstat()


def tree(directory, end):
    \"\"\"Fresh bounded whole tree, retaining directory identities, never content cache.\"\"\"
    stack = [(Path(directory), '')]
    directories, files, device, items = {}, set(), None, 0
    while stack:
        BASE.fence(end)
        path, name = stack.pop()
        before = protected_directory(path, end)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != BASE.TRUSTED_UID or
            stat.S_IMODE(before.st_mode) != 0o755 or
            device is not None and before.st_dev != device):
            raise Pending('release tree requires protected same-device 0755 directories')
        device = before.st_dev
        directories[name or '.'] = list(KERNEL.signature(before))
        if len(directories) > MAX_DIRECTORIES:
            raise Pending('release directory count exceeds its bound')
        with os.scandir(path) as entries:
            for entry in entries:
                BASE.fence(end)
                items += 1
                if items > MAX_TREE_ITEMS:
                    raise Pending('release tree exceeds its entry bound')
                child = entry.name if not name else name + '/' + entry.name
                relative(child)
                fact = entry.stat(follow_symlinks=False)
                if fact.st_dev != device:
                    raise Pending('release tree crosses a device boundary')
                if stat.S_ISDIR(fact.st_mode):
                    stack.append((path / entry.name, child))
                elif stat.S_ISREG(fact.st_mode):
                    files.add(child)
                    if len(files) > MAX_FILES:
                        raise Pending('release tree exceeds its file count')
                else:
                    raise Pending('release tree contains a link or unsupported object')
        if KERNEL.signature(path.lstat()) != KERNEL.signature(before):
            raise Pending('release directory changed during enumeration')
    return {'directories': directories, 'files': sorted(files)}


def observe(row, end):
    directory = Path(row['directory'])
    before = tree(directory, end)
    expected_directories = {'.'}
    for name in row['files']:
        expected_directories.update(str(parent) for parent in Path(name).parents if str(parent) != '.')
    if set(before['files']) != set(row['files']) or set(before['directories']) != expected_directories:
        raise Pending('complete release tree differs from declared files or parents')
    sources = {}
    for name in sorted(row['files']):
        item = row['files'][name]
        raw, source = BASE.read_protected(directory / name, item['bytes'], False, end)
        identity = source['identity']
        if (len(raw) != item['bytes'] or source['sha256'] != item['sha256'] or
            stat.S_IMODE(identity[2]) != int(item['mode'], 8) or identity[0] != before['directories']['.'][0]):
            raise Pending('protected release file bytes, mode or device differs')
        sources[name] = source
    if tree(directory, end) != before:
        raise Pending('complete release tree changed during file reads')
    return {'generation': row['generation'], 'directory': str(directory),
        'entry_points': {role: str(directory / row['entry_points'][role]) for role in SERVICES},
        'directories': before['directories'], 'files': sources}


def prepare(deadline=None):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited release window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing release caller namespace')
    settings = configuration(end)
    observed = {app: observe(settings['value']['applications'][app], end) for app in APPLICATIONS}
    payload = BASE.canonical({'schema': 1, 'profile': 'four-app-complete-release-files-v1',
        'state': 'protected-preinstalled-release-source-only', 'namespace': context,
        'configuration': settings, 'applications': observed})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete release receipt exceeds its output bound')
    if configuration(end) != settings:
        raise Pending('protected release intentions changed')
    for app in APPLICATIONS:
        if observe(settings['value']['applications'][app], end) != observed[app]:
            raise Pending('protected release files or identities changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('release caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('release admission accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('release admission requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete release receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: ' + str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/releases.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Bind protected release files to explicit existing local account intentions.

These repeated file observations do not authenticate NSS/PAM, effective process
credentials, group privileges, IPC, publisher provenance or running services.
No accounts, directories, units or processes are created or changed.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_identity_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
INPUT = Path('/etc/debian13s4/application-identities.json')
PASSWD, GROUP = Path('/etc/passwd'), Path('/etc/group')
MAX_INPUT = 8192
MAX_INVENTORY = 262144
MAX_ROWS = 4096
MAX_OUTPUT = 2097153
ATTEMPT_SECONDS = 130


def name(value):
    if (type(value) is not str or
        re.fullmatch(r'[a-z][a-z0-9_]{0,30}', value) is None or value == 'root'):
        raise Pending('unsupported explicit application account or group name')
    return value


def checked(value):
    KERNEL.known(value, {'schema', 'applications'}, {'schema', 'applications'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported application identity schema')
    KERNEL.known(value['applications'], set(RELEASE.APPLICATIONS), set(RELEASE.APPLICATIONS))
    names = set()
    for app in RELEASE.APPLICATIONS:
        row = value['applications'][app]
        fields = {'application_user', 'gateway_user', 'shared_groups'}
        KERNEL.known(row, fields, fields)
        shared = row['shared_groups']
        if type(shared) is not list or len(shared) > 8:
            raise Pending('explicit shared groups require a bounded list, possibly empty')
        for entry in [row['application_user'], row['gateway_user'], *shared]:
            entry = name(entry)
            if entry in names:
                raise Pending('application roles and shared groups must have distinct names')
            names.add(entry)
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite identity input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected application identity input') from error
    if raw != BASE.canonical(value):
        raise Pending('identity input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def records(raw, columns):
    if (type(raw) is not bytes or not raw or len(raw) > MAX_INVENTORY or
        not raw.endswith(b'\\n') or any(c != 10 and not 32 <= c <= 126 for c in raw)):
        raise Pending('account inventories require bounded printable ASCII LF records')
    lines = raw[:-1].decode('ascii').split('\\n')
    if len(lines) > MAX_ROWS:
        raise Pending('account inventory exceeds its row bound')
    rows = {}
    for line in lines:
        fields = line.split(':')
        if (len(fields) != columns or
            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in rows):
            raise Pending('malformed or duplicate account inventory record')
        rows[fields[0]] = fields
    return rows


def numeric(text):
    if re.fullmatch(r'0|[1-9][0-9]{0,9}', text) is None:
        raise Pending('noncanonical account inventory number')
    return KERNEL.uint(int(text), 0x7fffffff)


def accounts(passwd, group, settings):
    settings = checked(settings)
    users, groups = records(passwd, 7), records(group, 4)
    primary, uids, gids, memberships = {}, set(), set(), {}
    for account, row in users.items():
        uid, gid = numeric(row[2]), numeric(row[3])
        if uid in uids:
            raise Pending('ambiguous application account UID')
        uids.add(uid); primary[account] = (uid, gid)
    for group_name, row in groups.items():
        gid = numeric(row[2]); members = row[3].split(',') if row[3] else []
        if (gid in gids or len(members) != len(set(members)) or
            any(member not in users for member in members)):
            raise Pending('ambiguous application group identity or membership')
        gids.add(gid); memberships[group_name] = (gid, set(members))
    result = {}
    for app in RELEASE.APPLICATIONS:
        intended = settings['applications'][app]
        pair = {intended['application_user'], intended['gateway_user']}
        roles, shared = {}, {}
        for role in RELEASE.SERVICES:
            account = intended[role+'_user']
            if account not in users or account not in memberships:
                raise Pending('application service account or named primary group is missing')
            row = users[account]; uid, gid = primary[account]
            if (not 100 <= uid <= 999 or not 100 <= gid <= 999 or
                row[1] not in ('x', '!', '*') or
                row[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
                memberships[account][0] != gid or memberships[account][1] - {account} or
                any(other != account and other_gid == gid for other, (_, other_gid) in primary.items())):
                raise Pending('application requires a dedicated nonlogin system account and primary group')
            allowed = {account, *intended['shared_groups']}
            if any(account in members and group_name not in allowed
                   for group_name, (_, members) in memberships.items()):
                raise Pending('application account has undeclared supplementary membership')
            roles[role] = {'name': account, 'uid': uid, 'primary_group': account,
                'primary_gid': gid, 'shell': row[6]}
        for group_name in intended['shared_groups']:
            if group_name not in memberships:
                raise Pending('declared application shared group is missing')
            gid, members = memberships[group_name]
            if (not 100 <= gid <= 999 or members != pair or
                any(primary_gid == gid for _, primary_gid in primary.values())):
                raise Pending('shared group requires only the explicit supplementary role pair')
            shared[group_name] = gid
        result[app] = {'roles': roles, 'shared_groups': shared}
    return result


def release_bytes(end):
    BASE.fence(end)
    raw = RELEASE.prepare(deadline=end)
    if type(raw) is not bytes or len(raw) > RELEASE.MAX_OUTPUT:
        raise Pending('unsupported complete release receipt bytes')
    BASE.fence(end)
    return raw


def prepare(deadline=None):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application identity window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application identity namespace')
    settings = configuration(end)
    passwd, user_source = BASE.read_protected(PASSWD, MAX_INVENTORY, False, end)
    group, group_source = BASE.read_protected(GROUP, MAX_INVENTORY, False, end)
    selected = accounts(passwd, group, settings['value'])
    raw_release = release_bytes(end)
    release = json.loads(raw_release, object_pairs_hook=KERNEL.unique_object)
    if (KERNEL.uint(release['namespace'], 0xffffffffffffffff) != context or
        raw_release != BASE.canonical(release)):
        raise Pending('complete protected release namespace or canonical bytes differ')
    bindings = {}
    for app in RELEASE.APPLICATIONS:
        bindings[app] = {role: {**selected[app]['roles'][role],
            'shared_groups': selected[app]['shared_groups'],
            'entry_point': release['applications'][app]['entry_points'][role]}
            for role in RELEASE.SERVICES}
    payload = BASE.canonical({'schema': 1, 'profile': 'four-app-release-account-intention-v1',
        'state': 'protected-application-execution-identity-source-only', 'namespace': context,
        'configuration': settings, 'passwd_source': user_source, 'group_source': group_source,
        'releases': release, 'release_sha256': hashlib.sha256(raw_release).hexdigest(),
        'execution_bindings': bindings})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete execution identity receipt exceeds its output bound')
    if configuration(end) != settings:
        raise Pending('protected execution account intentions changed')
    for path, raw, source in ((PASSWD, passwd, user_source), (GROUP, group, group_source)):
        after, after_source = BASE.read_protected(path, MAX_INVENTORY, False, end)
        if after != raw or after_source != source:
            raise Pending('complete application account or group inventory changed')
    if release_bytes(end) != raw_release:
        raise Pending('complete protected application releases changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application execution identity namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application identities accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application identities require binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete identity receipt publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/identities.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Join protected release/account FILE intentions with the existing DNS profile.

No unit, account, binary, signed zone, process or socket is installed, adopted,
executed or authenticated. This preprovisioned replica SOURCE join supplies no
catalog, publisher, enrollment, native ownership, enforcement or readiness proof.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_profile',
    Path(__file__).resolve().parents[1]/'DNS/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_dns_service_profile',
        Path(__file__).resolve().parents[1]/'dns/prepare.py')
DNS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DNS)
BASE, KERNEL, Pending = IDENTITIES.BASE, IDENTITIES.KERNEL, IDENTITIES.Pending
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 290
PROFILE_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'user_source', 'group_source', 'accounts', 'plan', 'unit_sha256'}
IDENTITY_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'passwd_source', 'group_source', 'releases', 'release_sha256', 'execution_bindings'}


def prepared_bytes(module, end):
    if module is not IDENTITIES and module is not DNS:
        raise Pending('unsupported DNS service dependency')
    BASE.fence(end)
    try:
        raw = (module.prepare(deadline=end) if module is IDENTITIES else
            module.prepare(deadline=end, scope=module.KERNEL.namespace))
    except (IDENTITIES.Pending, DNS.Pending) as error:
        raise Pending('protected DNS service dependency refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete service dependency bytes')
    BASE.fence(end)
    return raw


def prepared(module, end, context):
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite dependency JSON')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid service dependency JSON') from error
    fields, profile, state = ((IDENTITY_FIELDS, 'four-app-release-account-intention-v1',
        'protected-application-execution-identity-source-only') if module is IDENTITIES else
        (PROFILE_FIELDS, 'mk8-dns-preprovisioned-static-replica-intention-v1', 'dns-service-intention-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != BASE.canonical(value)):
        raise Pending('service dependency schema, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def bindings(identities, service):
    \"\"\"Cross-component correspondence; reported facts are not authentication.\"\"\"
    for left, right in (('passwd_source', 'user_source'), ('group_source', 'group_source')):
        if BASE.canonical(identities[left]) != BASE.canonical(service[right]):
            raise Pending('DNS and application identities observed different account sources')
    settings = DNS.checked(service['configuration']['value'])
    KERNEL.known(identities['execution_bindings'], set(IDENTITIES.RELEASE.APPLICATIONS),
        set(IDENTITIES.RELEASE.APPLICATIONS))
    roles = identities['execution_bindings']['mk8.dns']
    KERNEL.known(roles, {'application', 'gateway'}, {'application', 'gateway'})
    KERNEL.known(service['accounts'], {'users', 'ipc_group'}, {'users', 'ipc_group'})
    pair = {settings['application_user'], settings['gateway_user']}
    KERNEL.known(service['accounts']['users'], pair, pair)
    ipc = service['accounts']['ipc_group']
    KERNEL.known(ipc, {'name', 'gid'}, {'name', 'gid'})
    if ipc['name'] != settings['ipc_group']:
        raise Pending('DNS IPC intention differs from its selected group')
    shared = {ipc['name']: KERNEL.uint(ipc['gid'], 0x7fffffff)}
    for role in ('application', 'gateway'):
        row = roles[role]
        fields = {'name', 'uid', 'primary_group', 'primary_gid', 'shell', 'shared_groups', 'entry_point'}
        KERNEL.known(row, fields, fields)
        if (not 100 <= KERNEL.uint(row['uid'], 0x7fffffff) <= 999 or
            not 100 <= KERNEL.uint(row['primary_gid'], 0x7fffffff) <= 999):
            raise Pending('unsupported admitted DNS role numeric identity')
        account = settings[role+'_user']
        reported = service['accounts']['users'][account]
        expected = {'uid': row['uid'], 'primary_gid': row['primary_gid'], 'shell': row['shell']}
        if (row['name'] != account or row['primary_group'] != account or
            row['entry_point'] != settings[role+'_binary'] or
            BASE.canonical(row['shared_groups']) != BASE.canonical(shared) or
            BASE.canonical(reported) != BASE.canonical(expected)):
            raise Pending('DNS unit role, executable or account/group facts differ from admitted release identities')
    plan = DNS.render(settings)
    hashes = {unit: hashlib.sha256(text.encode('ascii')).hexdigest() for unit, text in plan['units'].items()}
    if (BASE.canonical(service['plan']) != BASE.canonical(plan) or
        BASE.canonical(service['unit_sha256']) != BASE.canonical(hashes)):
        raise Pending('complete DNS unit intentions differ from the real profile renderer')
    result = {}
    for unit, argv in plan['argv'].items():
        role = 'application' if unit == DNS.APP_UNIT else 'gateway'
        row = roles[role]
        if argv[0] != row['entry_point']:
            raise Pending('DNS unit invocation differs from the admitted role entry')
        result[unit] = {'role': role, 'user': row['name'], 'uid': row['uid'],
            'account_primary_gid': row['primary_gid'], 'unit_group': ipc['name'],
            'unit_gid': ipc['gid'], 'entry_point': argv[0]}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited DNS service preparation window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing DNS service caller namespace')
    identity_raw, identities = prepared(IDENTITIES, end, context)
    dns_raw, service = prepared(DNS, end, context)
    selected = bindings(identities, service)
    payload = BASE.canonical({'schema': 1, 'profile': 'protected-dns-release-service-intention-v1',
        'state': 'protected-dns-release-service-intention-only', 'namespace': context,
        'identities': identities, 'dns_service': service, 'unit_bindings': selected,
        'identity_sha256': hashlib.sha256(identity_raw).hexdigest(),
        'dns_service_sha256': hashlib.sha256(dns_raw).hexdigest()})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete DNS release/service intention exceeds its output bound')
    if prepared_bytes(IDENTITIES, end) != identity_raw:
        raise Pending('complete protected release/account identities changed')
    if prepared_bytes(DNS, end) != dns_raw:
        raise Pending('complete protected DNS service intentions changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('DNS release/service caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('DNS service preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('DNS service preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete DNS service intention publication')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/dns_service.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Join protected application-role FILE intentions to local-peer PG intentions.

Only the selected DNS and Email application roles are joined. This does not
authenticate NSS/PAM, grant Gateway database access, validate application
configuration/ABI, enroll services, connect, execute SQL or authorize retry.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_pg_application_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
PG = IDENTITIES.BASE
KERNEL, Pending = PG.KERNEL, PG.Pending
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 290
IDENTITY_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'passwd_source', 'group_source', 'releases', 'release_sha256', 'execution_bindings'}
PG_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration',
    'account_source', 'accounts', 'plan'}


def prepared_bytes(module, end):
    \"\"\"Owned real preparations only; every complete return is bounded first.\"\"\"
    PG.fence(end)
    raw = (PG.prepare(deadline=end, scope=KERNEL.namespace) if module is PG else
           IDENTITIES.prepare(deadline=end))
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported whole application/PG preparation bytes')
    PG.fence(end)
    return raw


def prepared(module, end, context):
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite preparation')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid application/PG preparation JSON') from error
    fields, profile, state = ((PG_FIELDS, 'postgresql17-local-peer-new-cluster-intention-v1',
        'local-peer-provisioning-intention-only') if module is PG else
        (IDENTITY_FIELDS, 'four-app-release-account-intention-v1',
         'protected-application-execution-identity-source-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != PG.canonical(value)):
        raise Pending('application/PG preparation schema, scope or canonical bytes differ')
    PG.fence(end)
    return raw, value


def bindings(identities, postgres):
    \"\"\"Reported correspondence only; public hashes do not authenticate origin.\"\"\"
    if PG.canonical(identities['passwd_source']) != PG.canonical(postgres['account_source']):
        raise Pending('application and PostgreSQL account source observations differ')
    settings = PG.checked(postgres['configuration']['value'])
    plan = PG.render(settings)
    if PG.canonical(postgres['plan']) != PG.canonical(plan):
        raise Pending('complete PostgreSQL intention differs from the real renderer')
    KERNEL.known(identities['execution_bindings'], set(IDENTITIES.RELEASE.APPLICATIONS),
        set(IDENTITIES.RELEASE.APPLICATIONS))
    KERNEL.known(postgres['accounts'], set(PG.APPLICATIONS), set(PG.APPLICATIONS))
    result = {}
    for app in PG.APPLICATIONS:
        pair = identities['execution_bindings'][app]
        KERNEL.known(pair, {'application', 'gateway'}, {'application', 'gateway'})
        role = pair['application']
        fields = {'name', 'uid', 'primary_group', 'primary_gid', 'shell', 'shared_groups', 'entry_point'}
        KERNEL.known(role, fields, fields)
        selected = settings['applications'][app]
        expected = {'name': role['name'], 'uid': role['uid'], 'gid': role['primary_gid'], 'shell': role['shell']}
        if (role['name'] != selected['role'] or role['primary_group'] != selected['role'] or
            not 100 <= KERNEL.uint(role['uid'], 0x7fffffff) <= 999 or
            not 100 <= KERNEL.uint(role['primary_gid'], 0x7fffffff) <= 999 or
            role['shell'] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
            PG.canonical(postgres['accounts'][app]) != PG.canonical(expected) or
            role['entry_point'] != identities['releases']['applications'][app]['entry_points']['application']):
            raise Pending('PostgreSQL peer role differs from the admitted application execution identity')
        result[app] = {'execution_role': 'application', 'user': role['name'],
            'uid': role['uid'], 'primary_gid': role['primary_gid'], 'shell': role['shell'],
            'entry_point': role['entry_point'], 'database': selected['database'],
            'connection_limit': selected['connection_limit'],
            'connection_intention': plan['connections'][app]}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application/PG join window')
        end = min(end, deadline)
    PG.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application/PG caller namespace')
    identity_raw, identities = prepared(IDENTITIES, end, context)
    pg_raw, postgres = prepared(PG, end, context)
    selected = bindings(identities, postgres)
    payload = PG.canonical({'schema': 1, 'profile': 'application-postgresql-peer-role-files-v1',
        'state': 'protected-application-postgresql-role-intention-only', 'namespace': context,
        'identities': identities, 'postgresql': postgres, 'role_bindings': selected,
        'identity_sha256': hashlib.sha256(identity_raw).hexdigest(),
        'postgresql_sha256': hashlib.sha256(pg_raw).hexdigest()})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole application/PG join exceeds its output bound')
    if prepared_bytes(IDENTITIES, end) != identity_raw:
        raise Pending('complete protected application execution identities changed')
    if prepared_bytes(PG, end) != pg_raw:
        raise Pending('complete protected PostgreSQL intentions changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application/PG caller namespace changed')
    PG.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application/PG preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application/PG preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete application/PG intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/postgresql_identity.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Observe paired Sava transport/policy files and private key SOURCE material.

Only selected fields and whole-file correspondence are admitted. This does not
validate every CLR option, listener, credential delivery, storage, account power,
native RPC authentication or service launch. Secret values are never returned.
\"\"\"
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_sava_identities',
    Path(__file__).resolve().with_name('identities.py'))
IDENTITIES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITIES)
BASE, KERNEL, Pending = IDENTITIES.BASE, IDENTITIES.KERNEL, IDENTITIES.Pending
INPUT = Path('/etc/debian13s4/sava-transport.json')
SETTINGS_ROOT = Path('/etc/debian13s4-sava')
MAX_INPUT = 8192
MAX_SETTINGS = 1048576
MAX_KEY_FILE = 4096
MAX_NODES = 16384
MAX_OUTPUT = 4194305
ATTEMPT_SECONDS = 280
FILES = ('application_settings', 'gateway_settings', 'access_key')
TRANSPORT_FIELDS = {'Endpoint', 'AccessKeyFile', 'MaximumControlFrameBytes', 'ConnectTimeout', 'RequestTimeout'}
POLICY_FIELDS = {'DataPath', 'DefaultAccount', 'Accounts', 'DataEncryptionKeys',
    'AccountCapabilities', 'ObjectReplicationPolicies', 'AllowAnonymousPublicAccess',
    'MaximumRequestBodyBytes', 'BearerAuthentication'}


def material(text):
    if type(text) is not str or not 44 <= len(text) <= 684:
        raise Pending('unsupported bounded base64 key spelling')
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeError) as error:
        raise Pending('invalid canonical base64 key') from error
    if not 32 <= len(raw) <= 512 or not any(raw) or base64.b64encode(raw).decode('ascii') != text:
        raise Pending('key requires canonical nonzero 32..512 byte material')
    return raw


def duration(value, maximum):
    if type(value) is not str or re.fullmatch(r'[0-9]{2}:[0-5][0-9]:[0-5][0-9]', value) is None:
        raise Pending('explicit transport duration requires canonical HH:MM:SS')
    h, m, s = map(int, value.split(':')); seconds = h*3600+m*60+s
    if not 1 <= seconds <= maximum:
        raise Pending('transport duration exceeds its supported source bound')
    return seconds


def endpoint(value):
    match = re.fullmatch(r'http://(127\\.0\\.0\\.1|\\[::1\\]):([1-9][0-9]{0,4})/internal/application', value) if type(value) is str else None
    if match is None or not 1024 <= int(match[2]) <= 65535 or int(match[2]) == 5432:
        raise Pending('this profile requires an explicit canonical loopback HTTP RPC endpoint')
    return {'address': '::1' if match[1] == '[::1]' else match[1], 'port': int(match[2]),
        'path': '/internal/application', 'scheme': 'http'}


def checked(value):
    KERNEL.known(value, {'schema', *FILES}, {'schema', *FILES})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Sava transport source schema')
    selected = set()
    for field in FILES:
        text = value[field]
        if type(text) is not str or not 1 <= len(text) <= 240 or os.path.normpath(text) != text:
            raise Pending('unsupported explicit protected Sava settings path')
        try:
            name = str(Path(text).relative_to(SETTINGS_ROOT))
        except ValueError as error:
            raise Pending('Sava inputs must be explicit descendants of the product settings directory') from error
        IDENTITIES.RELEASE.relative(name)
        if not name.endswith('.key' if field == 'access_key' else '.json') or text in selected:
            raise Pending('Sava settings/key paths require distinct named files')
        selected.add(text)
    return json.loads(BASE.canonical(value))


def structural(value):
    \"\"\"Finite JSON structure only; not the complete CLR configuration validator.\"\"\"
    stack = [(value, 0)]; count = 0
    while stack:
        item, depth = stack.pop(); count += 1
        if count > MAX_NODES or depth > 32:
            raise Pending('Sava settings exceed their structural bound')
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or not 1 <= len(key) <= 128 or any(not 32 <= ord(c) <= 126 for c in key):
                    raise Pending('unsupported settings property spelling')
                stack.append((child, depth+1))
        elif type(item) is list:
            stack.extend((child, depth+1) for child in item)
        elif type(item) is str:
            if len(item) > 65536 or any(not 32 <= ord(c) <= 126 for c in item):
                raise Pending('unsupported settings string')
        elif type(item) is int:
            if not -(2**63) <= item <= 2**63-1: raise Pending('settings integer exceeds signed64 source range')
        elif type(item) is float:
            if not math.isfinite(item): raise Pending('nonfinite Sava settings number')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported settings value')


def document(path, limit, end):
    raw, source = BASE.read_protected(path, limit, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite Sava JSON')))
        structural(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Sava JSON') from error
    if type(value) is not dict or raw != BASE.canonical(value):
        raise Pending('Sava input requires canonical ASCII JSON object plus LF')
    return raw, value, source


def settings(value, key_path):
    if not {'Sava', 'ApplicationTransport'} <= set(value):
        raise Pending('both selected Sava sections must be explicit')
    transport, policy = value['ApplicationTransport'], value['Sava']
    KERNEL.known(transport, TRANSPORT_FIELDS, TRANSPORT_FIELDS)
    listener = endpoint(transport['Endpoint'])
    if transport['AccessKeyFile'] != key_path or type(transport['AccessKeyFile']) is not str:
        raise Pending('transport must reference the declared protected key file')
    if not 4096 <= KERNEL.uint(transport['MaximumControlFrameBytes'], 64*1024*1024) <= 64*1024*1024:
        raise Pending('unsupported explicit control frame capacity')
    duration(transport['ConnectTimeout'], 60); duration(transport['RequestTimeout'], 3600)
    if type(policy) is not dict or not POLICY_FIELDS <= set(policy):
        raise Pending('selected Sava policy fields must be explicit')
    data = policy['DataPath']
    if (type(data) is not str or not 6 <= len(data) <= 240 or
        re.fullmatch(r'/(srv|var/lib)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', data) is None or
        any(part in ('.', '..') for part in data.split('/')[1:])):
        raise Pending('storage requires an explicit canonical supported directory intention')
    accounts = policy['Accounts']
    if type(accounts) is not dict or not 1 <= len(accounts) <= 64:
        raise Pending('Sava policy requires explicit bounded account material')
    for account, key in accounts.items():
        if re.fullmatch(r'[a-z0-9]{3,24}', account) is None: raise Pending('unsupported storage account name')
        material(key)
    if type(policy['DefaultAccount']) is not str or policy['DefaultAccount'] not in accounts:
        raise Pending('default storage account must explicitly identify declared material')
    encryption = policy['DataEncryptionKeys']
    if type(encryption) is not dict or set(encryption) != set(accounts):
        raise Pending('each account requires explicit data encryption material, without fallback')
    for key in encryption.values(): material(key)
    capabilities = policy['AccountCapabilities']
    if type(capabilities) is not dict or set(capabilities) != set(accounts) or any(type(row) is not dict for row in capabilities.values()):
        raise Pending('each account requires an explicit capability object')
    if type(policy['ObjectReplicationPolicies']) is not list or len(policy['ObjectReplicationPolicies']) > 64:
        raise Pending('unsupported explicit replication policy list')
    if type(policy['AllowAnonymousPublicAccess']) is not bool or policy['AllowAnonymousPublicAccess']:
        raise Pending('this source profile refuses anonymous public access')
    if not 1 <= KERNEL.uint(policy['MaximumRequestBodyBytes'], 5_000*1024*1024):
        raise Pending('unsupported explicit request body capacity')
    bearer = policy['BearerAuthentication']
    if type(bearer) is not dict or type(bearer.get('Enabled')) is not bool:
        raise Pending('bearer enablement must be explicit; native option validation remains required')
    return listener


def observe(end):
    descriptor_raw, descriptor, descriptor_source = document(INPUT, MAX_INPUT, end)
    descriptor = checked(descriptor)
    app_raw, app, app_source = document(Path(descriptor['application_settings']), MAX_SETTINGS, end)
    gateway_raw, gateway, gateway_source = document(Path(descriptor['gateway_settings']), MAX_SETTINGS, end)
    listener = settings(app, descriptor['access_key']); settings(gateway, descriptor['access_key'])
    if (BASE.canonical(app['Sava']) != BASE.canonical(gateway['Sava']) or
        BASE.canonical(app['ApplicationTransport']) != BASE.canonical(gateway['ApplicationTransport'])):
        raise Pending('whole selected Sava policy or transport sections differ between hosts')
    key_raw, key_source = BASE.read_protected(Path(descriptor['access_key']), MAX_KEY_FILE, True, end)
    try:
        key = material(key_raw[:-1].decode('ascii'))
    except UnicodeError as error:
        raise Pending('invalid protected RPC key encoding') from error
    if key_raw != base64.b64encode(key)+b'\\n':
        raise Pending('protected RPC key requires canonical base64 plus exact LF')
    record = {'configuration_source': descriptor_source, 'application_source': app_source,
        'gateway_source': gateway_source, 'access_key_source': key_source,
        'rpc': listener, 'control_frame_bytes': app['ApplicationTransport']['MaximumControlFrameBytes'],
        'connect_seconds': duration(app['ApplicationTransport']['ConnectTimeout'], 60),
        'request_seconds': duration(app['ApplicationTransport']['RequestTimeout'], 3600),
        'policy_sha256': hashlib.sha256(BASE.canonical(app['Sava'])).hexdigest(),
        'transport_sha256': hashlib.sha256(BASE.canonical(app['ApplicationTransport'])).hexdigest(),
        'key_bytes': len(key), 'key_material_sha256': hashlib.sha256(key).hexdigest(),
        'storage_directory_intention': app['Sava']['DataPath']}
    # Private comparison buffers stay in this preparation; never serialize them.
    return record, (descriptor_raw, app_raw, gateway_raw, key_raw)


def identity_bytes(end):
    BASE.fence(end)
    raw = IDENTITIES.prepare(deadline=end)
    if type(raw) is not bytes or len(raw) > IDENTITIES.MAX_OUTPUT:
        raise Pending('unsupported whole protected release/account receipt')
    BASE.fence(end)
    return raw


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Sava preparation window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Sava caller namespace')
    identities = identity_bytes(end)
    identity = json.loads(identities, object_pairs_hook=KERNEL.unique_object)
    if KERNEL.uint(identity['namespace'], 0xffffffffffffffff) != context:
        raise Pending('Sava release/account namespace differs')
    observed, private = observe(end)
    payload = BASE.canonical({'schema': 1, 'profile': 'sava-paired-transport-policy-files-v1',
        'state': 'sava-split-transport-policy-source-only', 'namespace': context,
        'identities': identity, 'identity_sha256': hashlib.sha256(identities).hexdigest(),
        'settings': observed})
    if len(payload) > MAX_OUTPUT: raise Pending('Sava source receipt exceeds its complete output bound')
    after, after_private = observe(end)
    if after != observed or after_private != private: raise Pending('whole Sava settings/key file observations changed')
    if identity_bytes(end) != identities: raise Pending('complete release/account identities changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Sava caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Sava source preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('Sava source preparation requires binary stdout')
        payload = prepare(); count = sink.write(payload)
        if type(count) is not int or count != len(payload): raise Pending('incomplete Sava receipt publication')
        sink.flush(); return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr); return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/sava_transport.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Bind selected Sava Gateway HTTPS FILE intentions to real nginx intentions.

This checks a narrow explicit Kestrel JSON/PEM profile and repeated protected
bytes. It neither runs CLR/TLS nor authenticates certificates, loaded listeners,
service-readable credentials, release ownership or application readiness.
\"\"\"
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys


def owned(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
SAVA = owned('debian13s4_sava_ingress_transport', Path(__file__).resolve().with_name('sava_transport.py'))
WEB_PATH = ROOT/'Web/prepare.py'
if not WEB_PATH.is_file():
    WEB_PATH = ROOT/'web/prepare.py'
WEB = owned('debian13s4_sava_ingress_web', WEB_PATH)
BASE, KERNEL, Pending = SAVA.BASE, SAVA.KERNEL, SAVA.Pending
MAX_OUTPUT = 8388609
ATTEMPT_SECONDS = 600
SAVA_FIELDS = {'schema', 'profile', 'state', 'namespace', 'identities', 'identity_sha256', 'settings'}
WEB_FIELDS = {'schema', 'profile', 'state', 'namespace', 'configuration', 'materials', 'nginx', 'nginx_sha256'}


def finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise Pending('nonfinite ingress correspondence number')
    return value


def prepared(module, end, context):
    if module is not SAVA and module is not WEB:
        raise Pending('unsupported owned Sava ingress dependency')
    BASE.fence(end)
    try:
        raw = (SAVA.prepare(deadline=end) if module is SAVA else
            WEB.prepare(deadline=end, scope=WEB.KERNEL.namespace))
    except (SAVA.Pending, WEB.Pending) as error:
        raise Pending('Sava ingress dependency refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete Sava ingress dependency bytes')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_float=finite, parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite dependency')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid Sava ingress dependency JSON') from error
    fields, profile, state = ((SAVA_FIELDS, 'sava-paired-transport-policy-files-v1',
        'sava-split-transport-policy-source-only') if module is SAVA else
        (WEB_FIELDS, 'nginx-private-https-three-gateway-intention-v1', 'ingress-configuration-intention-only'))
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
        raise Pending('Sava ingress dependency schema, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def material_path(value):
    path = WEB.material_path(value)
    try:
        name = str(Path(path).relative_to(SAVA.SETTINGS_ROOT))
    except ValueError as error:
        raise Pending('Gateway TLS files must be explicit product settings descendants') from error
    SAVA.IDENTITIES.RELEASE.relative(name)
    if not name.endswith('.pem'):
        raise Pending('Gateway TLS material requires explicit PEM files')
    return path


def listener(gateway, ingress, rpc):
    \"\"\"Selected file syntax/correspondence, not the native Kestrel validator.\"\"\"
    port = KERNEL.uint(ingress['upstream_port'], 65535)
    if port < 1024 or port == 5432:
        raise Pending('unsupported explicit Gateway ingress port')
    KERNEL.known(gateway, {'Sava', 'ApplicationTransport', 'Kestrel'},
        {'Sava', 'ApplicationTransport', 'Kestrel'})
    kestrel = gateway['Kestrel']
    KERNEL.known(kestrel, {'Endpoints'}, {'Endpoints'})
    KERNEL.known(kestrel['Endpoints'], {'Private'}, {'Private'})
    selected = kestrel['Endpoints']['Private']
    KERNEL.known(selected, {'Url', 'Protocols', 'Certificate'}, {'Url', 'Protocols', 'Certificate'})
    certificate = selected['Certificate']
    KERNEL.known(certificate, {'Path', 'KeyPath', 'Password'}, {'Path', 'KeyPath', 'Password'})
    if (type(selected['Url']) is not str or
        selected['Url'] != 'https://127.0.0.1:'+str(port) or
        type(selected['Protocols']) is not str or selected['Protocols'] != 'Http1' or
        type(certificate['Password']) is not str or certificate['Password'] != ''):
        raise Pending('Gateway requires one explicit loopback HTTPS/HTTP1 unencrypted PEM intention')
    public, private = material_path(certificate['Path']), material_path(certificate['KeyPath'])
    if public == private or private == ingress['upstream_ca'] or port == KERNEL.uint(rpc['port'], 65535):
        raise Pending('Gateway TLS material or RPC/listener ports conflict')
    return {'address': '127.0.0.1', 'port': port, 'scheme': 'https',
        'protocol': 'Http1', 'certificate': public, 'private_key': private,
        'server_name_intention': ingress['upstream_name']}


def observe(sava, web, end):
    descriptor_raw, descriptor, descriptor_source = SAVA.document(SAVA.INPUT, SAVA.MAX_INPUT, end)
    descriptor = SAVA.checked(descriptor)
    gateway_raw, gateway, gateway_source = SAVA.document(
        Path(descriptor['gateway_settings']), SAVA.MAX_SETTINGS, end)
    settings = sava['settings']
    if (BASE.canonical(descriptor_source) != BASE.canonical(settings['configuration_source']) or
        BASE.canonical(gateway_source) != BASE.canonical(settings['gateway_source'])):
        raise Pending('Gateway files differ from the complete owned Sava preparation')
    rpc = SAVA.settings(gateway, descriptor['access_key'])
    if (BASE.canonical(rpc) != BASE.canonical(settings['rpc']) or
        hashlib.sha256(BASE.canonical(gateway['Sava'])).hexdigest() != settings['policy_sha256'] or
        hashlib.sha256(BASE.canonical(gateway['ApplicationTransport'])).hexdigest() != settings['transport_sha256']):
        raise Pending('whole Gateway policy/transport differ from owned Sava preparation')
    try:
        config = WEB.checked(web['configuration']['value'])
        nginx = WEB.render(config)
        ingress = config['applications']['mk8.sava']
        selected = listener(gateway, ingress, rpc)
    except (SAVA.Pending, WEB.Pending) as error:
        raise Pending('Sava listener or real ingress renderer refused') from error
    if (type(web['nginx']) is not str or web['nginx'] != nginx or
        web['nginx_sha256'] != hashlib.sha256(nginx.encode('ascii')).hexdigest()):
        raise Pending('whole ingress intention differs from the real renderer')
    body = gateway['Sava']['MaximumRequestBodyBytes']
    if type(body) is not int or ingress['body_bytes'] > body:
        raise Pending('public ingress body intention exceeds selected Sava policy')
    key = selected['private_key']
    public_files = {row[field] for row in config['applications'].values()
        for field in ('certificate', 'upstream_ca')}
    if key in public_files or key == descriptor['access_key']:
        raise Pending('Gateway private key is reused as public or RPC material')
    certificate_raw, certificate_source = BASE.read_protected(
        Path(selected['certificate']), WEB.MAX_PEM, False, end)
    private_raw, private_source = BASE.read_protected(Path(key), WEB.MAX_PEM, True, end)
    try:
        certificate_blocks = WEB.pem(certificate_raw, False)
        private_blocks = WEB.pem(private_raw, True)
    except WEB.Pending as error:
        raise Pending('Gateway TLS material grammar refused') from error
    row = web['materials'][ingress['upstream_ca']]
    KERNEL.known(row, {'source', 'pem_blocks', 'kind'}, {'source', 'pem_blocks', 'kind'})
    if row['kind'] != 'certificate':
        raise Pending('ingress CA must remain reported public material')
    record = {'configuration_source': descriptor_source, 'gateway_source': gateway_source,
        'listener': selected, 'certificate_source': certificate_source,
        'private_key_source': private_source, 'certificate_blocks': certificate_blocks,
        'private_key_blocks': private_blocks, 'upstream_ca': row,
        'ingress_body_bytes': ingress['body_bytes'], 'policy_body_bytes': body}
    # Secret whole-file/key bytes stay private and are compared after encoding.
    return record, (descriptor_raw, gateway_raw, certificate_raw, private_raw)


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited Sava ingress window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing Sava ingress namespace')
    sava_raw, sava = prepared(SAVA, end, context)
    web_raw, web = prepared(WEB, end, context)
    observed, private = observe(sava, web, end)
    payload = BASE.canonical({'schema': 1, 'profile': 'sava-gateway-nginx-file-correspondence-v1',
        'state': 'protected-sava-gateway-ingress-source-only', 'namespace': context,
        'sava': sava, 'ingress': web, 'sava_sha256': hashlib.sha256(sava_raw).hexdigest(),
        'ingress_sha256': hashlib.sha256(web_raw).hexdigest(), 'gateway': observed})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole Sava ingress correspondence exceeds its output bound')
    if prepared(SAVA, end, context)[0] != sava_raw or prepared(WEB, end, context)[0] != web_raw:
        raise Pending('complete owned Sava or ingress preparation changed')
    after, after_private = observe(sava, web, end)
    if after != observed or after_private != private:
        raise Pending('whole Gateway settings or TLS material changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Sava ingress namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('Sava ingress correspondence accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('Sava ingress correspondence requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete Sava ingress output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/sava_ingress.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare Sava service and credential-delivery intentions from protected files.

This command renders units; it never writes units, creates storage, delivers
credentials or starts an application. Native systemd/.NET interpretation,
publisher identity, effective credentials and readiness remain unverified.
\"\"\"
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_sava_service_ingress',
    Path(__file__).resolve().with_name('sava_ingress.py'))
INGRESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INGRESS)
SPEC = importlib.util.spec_from_file_location('debian13s4_sava_private_directory',
    Path(__file__).resolve().with_name('private_directory.py'))
STORAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STORAGE)
SAVA = INGRESS.SAVA
BASE, KERNEL, Pending = SAVA.BASE, SAVA.KERNEL, SAVA.Pending
ATTEMPT_SECONDS = 1220
MAX_OUTPUT = 131072
# Deliberately below systemd 257's aggregate 1 MiB credential limit.
MAX_CREDENTIAL_BYTES = 1_000_000
UNITS = {role: 'debian13s4-sava-'+role+'.service' for role in ('application', 'gateway')}
PROFILE = 'sava-systemd-credential-service-intentions-v1'
STATE = 'protected-sava-service-intention-only'
CREDENTIAL_DIRECTORY = '\${CREDENTIALS_DIRECTORY}'


def path(value):
    \"\"\"A literal systemd operand, never a specifier or shell expression.\"\"\"
    if (type(value) is not str or not 1 < len(value) <= 512 or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value) is None or
        os.path.normpath(value) != value or any(p in ('.', '..') for p in value.split('/'))):
        raise Pending('unsupported literal Sava service path')
    return value


def configuration_keys(value):
    \"\"\"Reject ambiguous .NET key paths without claiming full CLR validation.\"\"\"
    stack = [value]
    while stack:
        row = stack.pop()
        if type(row) is dict:
            names = set()
            for key, child in row.items():
                folded = key.casefold()
                if ':' in key or folded in names:
                    raise Pending('ambiguous case-insensitive or flattened configuration key')
                names.add(folded)
                stack.append(child)
        elif type(row) is list:
            stack.extend(row)


def prerequisite(end, context):
    BASE.fence(end)
    try:
        raw = INGRESS.prepare(deadline=end)
    except INGRESS.Pending as error:
        raise Pending('Sava ingress preparation refused: '+str(error)) from error
    if type(raw) is not bytes or not raw or len(raw) > INGRESS.MAX_OUTPUT:
        raise Pending('unsupported complete Sava ingress receipt')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite ingress receipt')))
        fields = {'schema', 'profile', 'state', 'namespace', 'sava', 'sava_sha256',
                  'ingress', 'ingress_sha256', 'gateway'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'sava-gateway-nginx-file-correspondence-v1' or
            value['state'] != 'protected-sava-gateway-ingress-source-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
            raw != BASE.canonical(value)):
            raise Pending('Sava ingress profile, namespace or canonical bytes differ')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Sava ingress receipt') from error
    BASE.fence(end)
    return raw, value


def application_files(ingress, end):
    \"\"\"Read the two real settings files; retain private bytes only locally.\"\"\"
    settings = ingress['sava']['settings']
    private, values = [], {}
    for role in UNITS:
        source = settings[role+'_source']
        raw, value, actual = SAVA.document(Path(path(source['path'])), SAVA.MAX_SETTINGS, end)
        if BASE.canonical(actual) != BASE.canonical(source):
            raise Pending('Sava settings differ from the complete ingress observation')
        configuration_keys(value)
        if role == 'application':
            KERNEL.known(value, {'Sava', 'ApplicationTransport'}, {'Sava', 'ApplicationTransport'})
        SAVA.settings(value, settings['access_key_source']['path'])
        if (hashlib.sha256(BASE.canonical(value['Sava'])).hexdigest() != settings['policy_sha256'] or
            hashlib.sha256(BASE.canonical(value['ApplicationTransport'])).hexdigest() != settings['transport_sha256']):
            raise Pending('Sava policy or transport differs from its protected source')
        private.append(raw)
        values[role] = value
    return values, tuple(private)


def credential(name, source):
    filename = path(source['path'])
    size = KERNEL.uint(source['identity'][5], MAX_CREDENTIAL_BYTES)
    if size == 0:
        raise Pending('empty Sava service credential')
    return {'id': name, 'source': source, 'bytes': size,
            'load_directive': name+':'+filename}


def unit(role, binding, directory, data, credentials):
    account = SAVA.IDENTITIES.name(binding['name'])
    group = SAVA.IDENTITIES.name(binding['primary_group'])
    for field in ('uid', 'primary_gid'):
        if not 100 <= KERNEL.uint(binding[field], 999):
            raise Pending('Sava service requires a dedicated system identity')
    entry = path(binding['entry_point'])
    directory, data = path(directory), path(data)
    if not entry.startswith(directory+'/'):
        raise Pending('Sava service entry is outside its admitted release')
    # systemd expands only these fixed credential references. env -i removes
    # inherited configuration, profiler, loader and startup-hook variables.
    environment = ['PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8',
                   'HOME=/nonexistent', 'TMPDIR=/tmp', 'DOTNET_NOLOGO=1',
                   'DOTNET_ENVIRONMENT=Production', 'ASPNETCORE_ENVIRONMENT=Production']
    command = ['/usr/bin/env', '-i', *environment, entry,
               '--contentRoot', CREDENTIAL_DIRECTORY, '--environment', 'Production',
               '--ApplicationTransport:AccessKeyFile='+CREDENTIAL_DIRECTORY+'/rpc.key']
    if role == 'gateway':
        command += ['--Kestrel:Endpoints:Private:Certificate:Path='+CREDENTIAL_DIRECTORY+'/certificate.pem',
                    '--Kestrel:Endpoints:Private:Certificate:KeyPath='+CREDENTIAL_DIRECTORY+'/private-key.pem']
    lines = ['[Unit]', 'Description=Protected Sava '+role+' service intention',
             'After=network-online.target', 'Wants=network-online.target',
             'RequiresMountsFor='+directory+' '+data]
    if role == 'gateway':
        lines += ['Requires='+UNITS['application'], 'After='+UNITS['application']]
    lines += ['[Service]', 'Type=exec', 'User='+account, 'Group='+group,
              'WorkingDirectory='+directory, 'UMask=0077', 'Restart=no',
              'TimeoutStartSec=30s', 'TimeoutStopSec=120s', 'KillMode=control-group',
              'SendSIGKILL=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
              'AmbientCapabilities=', 'PrivateTmp=yes', 'PrivateDevices=yes',
              'ProtectSystem=strict', 'ProtectHome=yes', 'ProtectKernelTunables=yes',
              'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
              'RestrictSUIDSGID=yes', 'LockPersonality=yes',
              'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
              ('ReadWritePaths=' if role == 'application' else 'InaccessiblePaths=')+data,
              'StandardInput=null', 'StandardOutput=journal', 'StandardError=journal']
    lines += ['LoadCredential='+row['load_directive'] for row in credentials]
    lines += ['ExecStart='+' '.join(command)]
    text = '\\n'.join(lines)+'\\n'
    return {'name': UNITS[role], 'identity': binding, 'argv': command,
            'credentials': credentials, 'unit': text,
            'unit_sha256': hashlib.sha256(text.encode('ascii')).hexdigest()}


def render(ingress):
    sava, gateway = ingress['sava'], ingress['gateway']
    settings = sava['settings']
    identity = sava['identities']
    bindings = identity['execution_bindings']['mk8.sava']
    if bindings['application']['uid'] == bindings['gateway']['uid']:
        raise Pending('Sava Application and Gateway identities must remain distinct')
    release = identity['releases']['applications']['mk8.sava']
    data = settings['storage_directory_intention']
    result = {}
    for role in UNITS:
        credentials = [credential('appsettings.json', settings[role+'_source']),
                       credential('rpc.key', settings['access_key_source'])]
        if role == 'gateway':
            credentials += [credential('certificate.pem', gateway['certificate_source']),
                            credential('private-key.pem', gateway['private_key_source'])]
        total = sum(row['bytes'] for row in credentials)
        if total > MAX_CREDENTIAL_BYTES:
            raise Pending('combined Sava unit credentials exceed their bounded capacity')
        result[role] = unit(role, bindings[role], release['directory'], data, credentials)
        result[role]['credential_bytes'] = total
    return {'units': result, 'release_generation': release['generation'],
            'release_sha256': hashlib.sha256(BASE.canonical(identity['releases'])).hexdigest(),
            'identity_sha256': hashlib.sha256(BASE.canonical(identity)).hexdigest(),
            'required_storage': {'path': data, 'owner_uid': bindings['application']['uid'],
                'owner_gid': bindings['application']['primary_gid'], 'mode': '0700',
                'observed': False, 'created': False},
            'rpc_listener_intention': settings['rpc'],
            'gateway_listener_intention': gateway['listener']}


def storage_observation(plan, end, context):
    required = plan['required_storage']
    shared = plan['units']['application']['identity']['shared_groups']
    BASE.fence(end)
    try:
        raw = STORAGE.observe(Path(required['path']), required['owner_uid'], required['owner_gid'],
                              list(shared.values()), deadline=end)
    except (STORAGE.Pending, OSError) as error:
        raise Pending('Sava private storage directory refused: '+str(error)) from error
    if type(raw) is not bytes or not raw or len(raw) > STORAGE.MAX_OUTPUT:
        raise Pending('unsupported private storage observation bytes')
    value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
    if (type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or
        value.get('state') != STORAGE.STATE or KERNEL.uint(value.get('namespace'), 0xffffffffffffffff) != context or
        value.get('path') != required['path'] or type(value.get('owner_uid')) is not int or
        value['owner_uid'] != required['owner_uid'] or type(value.get('owner_gid')) is not int or
        value['owner_gid'] != required['owner_gid'] or raw != BASE.canonical(value)):
        raise Pending('private storage observation differs from the selected Sava identity')
    BASE.fence(end)
    return raw, value


def prepare(deadline=None, require_storage=False):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited Sava service window')
        end = min(end, deadline)
    BASE.fence(end)
    if type(require_storage) is not bool:
        raise Pending('storage admission selection must be a Boolean')
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing Sava service namespace')
    raw, ingress = prerequisite(end, context)
    _, private = application_files(ingress, end)
    plan = render(ingress)
    storage = None
    if require_storage:
        storage, observation = storage_observation(plan, end, context)
        plan['required_storage'].update(observed=True, observation=observation,
            observation_sha256=hashlib.sha256(storage).hexdigest())
    payload = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE,
        'namespace': context, 'ingress_sha256': hashlib.sha256(raw).hexdigest(),
        'plan': plan})
    if len(payload) > MAX_OUTPUT:
        raise Pending('complete Sava service intention exceeds its output bound')
    after, after_value = prerequisite(end, context)
    if after != raw:
        raise Pending('complete Sava ingress, settings or identity preparation changed')
    _, after_private = application_files(after_value, end)
    if after_private != private:
        raise Pending('Sava settings bytes changed after service encoding')
    if require_storage and storage_observation(plan, end, context)[0] != storage:
        raise Pending('Sava private storage observation changed after service encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Sava service namespace changed')
    BASE.fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', choices=tuple(UNITS), help='emit only the selected unit text')
    parser.add_argument('--require-storage', action='store_true',
                        help='also require the declared existing private data directory')
    args = parser.parse_args(argv)
    try:
        raw = prepare(require_storage=args.require_storage)
        if args.unit:
            raw = json.loads(raw)['plan']['units'][args.unit]['unit'].encode('ascii')
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete Sava service intention output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/sava_service.py || return 1
    printf '%s' "\"\"\"Read-only admission of an existing application-owned private directory.

This observes POSIX file metadata for explicitly supplied numeric identities.
It does not authenticate NSS credentials, inspect data contents, acquire a
service lease, test writes, reserve capacity or prove mount/physical durability.
\"\"\"
import importlib.util
import os
from pathlib import Path
import re
import stat

SPEC = importlib.util.spec_from_file_location('debian13s4_directory_reader',
    Path(__file__).resolve().parents[1]/'PostgreSQL/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_directory_reader',
        Path(__file__).resolve().parents[1]/'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL, Pending = BASE.KERNEL, BASE.Pending
ATTEMPT_SECONDS = 10
MAX_OUTPUT = 32768
STATE = 'private-application-directory-file-observation-only'


class CleanupFailure(Pending):
    \"\"\"Keep a body refusal and its separate descriptor cleanup failure.\"\"\"
    def __init__(self, cause, close_error):
        super().__init__('private directory observation and descriptor close both failed')
        self.cause = cause
        self.close_error = close_error


def identity(info):
    # Directory contents may change: this is ownership/path identity, not an
    # inventory or a snapshot of the application's stored data.
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def searchable(info, uid, groups):
    permission = 0o100 if info.st_uid == uid else 0o010 if info.st_gid in groups else 0o001
    return bool(info.st_mode & permission)


def ancestry(path, uid, groups, end):
    try:
        relative = path.relative_to(BASE.TRUST_ROOT)
    except ValueError as error:
        raise Pending('private application directory is outside the trusted root') from error
    if not relative.parts:
        raise Pending('application data cannot be the trusted ancestry root')
    current = BASE.TRUST_ROOT
    result = {}
    for part in ('', *relative.parts[:-1]):
        if part:
            current /= part
        BASE.fence(end)
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != BASE.TRUSTED_UID or
            info.st_mode & 0o022):
            raise Pending('private application data requires protected root-owned ancestry')
        if not searchable(info, uid, groups):
            raise Pending('application identity lacks an ancestry search permission')
        result[str(current)] = identity(info)
    return result


def leaf(info, uid, gid):
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or
        info.st_uid != uid or info.st_gid != gid):
        raise Pending('application data requires its declared UID/GID and directory mode 0700')
    return identity(info)


def observe(path, uid, gid, supplementary_groups=(), deadline=None):
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid inherited private directory window')
    end = min(start+ATTEMPT_SECONDS, deadline) if deadline is not None else start+ATTEMPT_SECONDS
    BASE.fence(end)
    if (type(path) is not type(BASE.TRUST_ROOT) or not path.is_absolute() or
        not 1 < len(str(path)) <= 512 or os.path.normpath(str(path)) != str(path) or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', str(path)) is None or
        any(part in ('.', '..') for part in path.parts)):
        raise Pending('unsupported canonical private directory path')
    if (type(uid) is not int or not 1 <= uid <= 0x7fffffff or
        type(gid) is not int or not 1 <= gid <= 0x7fffffff or
        type(supplementary_groups) not in (tuple, list) or len(supplementary_groups) > 8):
        raise Pending('unsupported explicit private directory identity')
    groups = {gid}
    for group in supplementary_groups:
        if type(group) is not int or not 1 <= group <= 0x7fffffff or group in groups:
            raise Pending('unsupported or duplicate supplementary group')
        groups.add(group)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing private directory namespace')
    parents = ancestry(path, uid, groups, end)
    before = leaf(path.lstat(), uid, gid)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    error = close_error = None
    try:
        if leaf(os.fstat(descriptor), uid, gid) != before:
            raise Pending('private directory descriptor differs from its path')
        payload = BASE.canonical({'schema': 1, 'state': STATE, 'namespace': context,
            'path': str(path), 'owner_uid': uid, 'owner_gid': gid,
            'supplementary_groups': sorted(groups-{gid}), 'identity': before,
            'ancestry': parents, 'contents_inspected': False, 'write_tested': False})
        if len(payload) > MAX_OUTPUT:
            raise Pending('private directory observation exceeds its output bound')
        if (leaf(os.fstat(descriptor), uid, gid) != before or
            leaf(path.lstat(), uid, gid) != before or ancestry(path, uid, groups, end) != parents):
            raise Pending('private directory or ancestry changed after encoding')
        if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
            raise Pending('private directory namespace changed')
        BASE.fence(end)
    except BaseException as caught:
        error = caught
    finally:
        closing, descriptor = descriptor, None
        try:
            os.close(closing)
        except OSError as caught:
            close_error = caught
    if error is not None:
        if close_error is not None:
            raise CleanupFailure(error, close_error) from error
        raise error
    if close_error is not None:
        raise Pending('private directory close did not complete successfully') from close_error
    BASE.fence(end)
    return payload
" > "$S4B_STAGE/"lib/applications/private_directory.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare Email Worker file bindings and credential/service intentions only.

No account, database, credential, service or application is changed. The retained
Worker performs schema/restore-queue work on startup; rendering this plan does not
authorize that work or establish full CLR configuration or native readiness.
\"\"\"
import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_email_worker_pg',
    Path(__file__).resolve().with_name('postgresql_identity.py'))
JOIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOIN)
BASE, KERNEL, Pending = JOIN.PG, JOIN.KERNEL, JOIN.Pending
INPUT = Path('/etc/debian13s4/email-worker.json')
SETTINGS_ROOT = Path('/etc/debian13s4-email')
MAX_INPUT, MAX_SETTINGS, MAX_SECRET = 8192, 524288, 131072
MAX_OUTPUT, MAX_CREDENTIAL_BYTES, ATTEMPT_SECONDS = 131072, 1_000_000, 600
PROFILE = 'email-worker-credential-service-intentions-v1'
STATE = 'protected-email-worker-service-intention-only'
UNIT = 'debian13s4-email-application.service'
SECTIONS = {'Database', 'Smtp', 'Imap', 'Pop3', 'Sieve', 'Jmap', 'Dav', 'OAuth',
    'Mfa', 'Tls', 'Dkim', 'Security', 'Filtering', 'Queue', 'Limits', 'General',
    'Admin', 'Messaging', 'ObjectStorage'}
REQUIRED = {'Database', 'Smtp', 'OAuth', 'Mfa', 'Dkim', 'Limits', 'Messaging', 'ObjectStorage'}


def literal(value):
    if (type(value) is not str or not 1 < len(value) <= 512 or
        re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value) is None or
        os.path.normpath(value) != value or any(p in ('.', '..') for p in value.split('/'))):
        raise Pending('unsupported literal Email file/service operand')
    return value


def structure(value):
    \"\"\"Bounded unambiguous JSON, not a replacement for EnvironmentConfig.Validate.\"\"\"
    stack = [(value, 0)]; count = 0
    while stack:
        item, depth = stack.pop(); count += 1
        if depth > 32 or count > 16384:
            raise Pending('Email configuration exceeds its structural bound')
        if type(item) is dict:
            seen = set()
            for key, child in item.items():
                if (not 1 <= len(key) <= 128 or any(not 32 <= ord(c) <= 126 for c in key)
                    or ':' in key or key.casefold() in seen):
                    raise Pending('ambiguous Email configuration property')
                seen.add(key.casefold()); stack.append((child, depth+1))
        elif type(item) is list:
            stack.extend((child, depth+1) for child in item)
        elif type(item) is str:
            if len(item) > 65536 or any(not 32 <= ord(c) <= 126 for c in item):
                raise Pending('unsupported Email configuration string')
        elif type(item) is int:
            if not -(2**63) <= item < 2**63: raise Pending('Email integer exceeds signed64')
        elif type(item) is float:
            if not math.isfinite(item): raise Pending('nonfinite Email number')
        elif item is not None and type(item) is not bool:
            raise Pending('unsupported Email configuration value')


def document(path, limit, end):
    raw, source = BASE.read_protected(path, limit, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite Email JSON')))
        structure(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Email JSON') from error
    if type(value) is not dict or raw != BASE.canonical(value):
        raise Pending('Email input requires canonical ASCII JSON object plus LF')
    return raw, value, source


def descriptor(value):
    KERNEL.known(value, {'schema', 'settings', 'credentials'}, {'schema', 'settings', 'credentials'})
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Email Worker descriptor schema')
    sources = value['credentials']
    if type(sources) is not dict or not 3 <= len(sources) <= 14:
        raise Pending('Email Worker requires explicit bounded credential sources')
    for name in sources:
        if re.fullmatch(r'[a-z][a-z0-9.-]{0,63}', name) is None or name == 'environment.json':
            raise Pending('unsupported Email credential name')
    paths = [value['settings'], *sources.values()]
    for filename in paths:
        literal(filename)
        if not filename.startswith(str(SETTINGS_ROOT)+'/'):
            raise Pending('Email inputs must be descendants of the product settings directory')
    if len(set(paths)) != len(paths) or str(INPUT) in paths:
        raise Pending('Email descriptor/settings/credential sources must be distinct')
    return value


def flag(row, name):
    value = row.get(name)
    if type(value) is not bool: raise Pending('Email feature selections must be explicit Booleans')
    return value


def secret_reference(row, field, credential, kind, expected, required=True):
    if row.get(field, '') != '' or type(row.get(field, '')) is not str:
        raise Pending('Email secrets must use separate credential files')
    filename = row.get(field+'File', '')
    if required:
        if filename != credential: raise Pending('Email secret must use its fixed credential leaf')
        expected[credential] = kind
    elif filename not in ('', None):
        raise Pending('disabled Email feature still references secret material')


def transport_configuration(value, peer):
    \"\"\"Selected shared database/messaging/object-store file intentions.\"\"\"
    KERNEL.known(value, SECTIONS, REQUIRED)
    if any(type(row) is not dict for row in value.values()):
        raise Pending('Email configuration sections must be objects')
    db, msg, objects = (value[name] for name in ('Database', 'Messaging', 'ObjectStorage'))
    KERNEL.known(db, {'Host', 'Port', 'Name', 'Username', 'Password', 'PasswordFile'},
                    {'Host', 'Port', 'Name', 'Username', 'Password', 'PasswordFile'})
    if (db['Host'] != BASE.SOCKET_DIRECTORY or type(db['Port']) is not int or db['Port'] != 5432
        or db['Name'] != peer['database'] or db['Username'] != peer['user']):
        raise Pending('Email database differs from its selected role/database file intention')
    expected = {}
    secret_reference(db, 'Password', 'database.password', 'password', expected)
    msg_fields = {'Enabled', 'EncryptionKeyId', 'EncryptionKey', 'EncryptionKeyFile', 'DecryptionKeys',
        'MaxPayloadBytes', 'InlinePayloadThresholdBytes', 'LeaseSeconds', 'NotificationFallbackSeconds', 'WorkerId'}
    KERNEL.known(msg, msg_fields, msg_fields)
    if not flag(msg, 'Enabled'): raise Pending('Email transport requires distributed messaging')
    identifier = r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}'
    if type(msg['EncryptionKeyId']) is not str or re.fullmatch(identifier, msg['EncryptionKeyId']) is None:
        raise Pending('unsupported Email messaging encryption key identifier')
    if (type(msg['WorkerId']) is not str or
        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}', msg['WorkerId']) is None):
        raise Pending('Email transport requires an explicit bounded identity, without machine-name fallback')
    secret_reference(msg, 'EncryptionKey', 'messaging.key', 'key32', expected)
    previous = msg['DecryptionKeys']; ids = {msg['EncryptionKeyId']}
    if type(previous) is not list or len(previous) > 8: raise Pending('too many Email decryption keys')
    for number, row in enumerate(previous):
        KERNEL.known(row, {'Id', 'Key', 'KeyFile'}, {'Id', 'Key', 'KeyFile'})
        if type(row['Id']) is not str or re.fullmatch(identifier, row['Id']) is None or row['Id'] in ids:
            raise Pending('Email messaging key identifiers must be distinct')
        ids.add(row['Id']); secret_reference(row, 'Key', f'messaging.decrypt-{number}.key', 'key32', expected)
    message_bytes = KERNEL.uint(value['Limits'].get('MaxMessageSizeBytes'), 1_073_741_824)
    payload = KERNEL.uint(msg['MaxPayloadBytes'], 1_073_741_824)
    if message_bytes < 65536 or payload < (4*message_bytes+2)//3+1048576:
        raise Pending('Email messaging capacity cannot hold the declared message envelope')
    KERNEL.uint(msg['InlinePayloadThresholdBytes'], min(1048576, payload))
    for field, minimum, maximum in (('LeaseSeconds', 5, 3600), ('NotificationFallbackSeconds', 1, 300)):
        if KERNEL.uint(msg[field], maximum) < minimum: raise Pending('unsupported Email messaging interval')
    object_fields = {'Provider', 'ConnectionString', 'ConnectionStringFile', 'ContainerName', 'ObjectPrefix', 'CreateContainerIfMissing'}
    KERNEL.known(objects, object_fields, object_fields)
    if objects['Provider'] != 'azure-blob' or flag(objects, 'CreateContainerIfMissing'):
        raise Pending('Email transport profile requires preprovisioned azure-blob object storage')
    container = objects['ContainerName']
    if (type(container) is not str or re.fullmatch(r'[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', container) is None
        or '--' in container): raise Pending('unsupported Email object container name')
    prefix = objects['ObjectPrefix']
    if type(prefix) is not str or len(prefix) > 512 or prefix.startswith('/') or '//' in prefix or '\\0' in prefix:
        raise Pending('unsupported Email object prefix')
    secret_reference(objects, 'ConnectionString', 'objects.connection', 'connection', expected)
    return expected


def configuration(value, peer):
    \"\"\"Check selected Worker fields and every supported credential reference.\"\"\"
    expected = transport_configuration(value, peer)
    oauth, mfa, dkim = (value[name] for name in ('OAuth', 'Mfa', 'Dkim'))
    enabled = flag(oauth, 'EnableOAuth'); oidc = flag(oauth, 'EnableOpenIdConnect')
    if oidc and not enabled: raise Pending('Email OpenID Connect requires OAuth')
    secret_reference(oauth, 'SigningKey', 'oauth-signing.pem', 'pem', expected, oidc)
    totp = flag(mfa, 'EnableTotp')
    if totp and not enabled: raise Pending('Email TOTP requires OAuth')
    secret_reference(mfa, 'EncryptionKey', 'mfa.key', 'key32', expected, totp)
    if flag(dkim, 'EnableSigning'):
        if dkim.get('PrivateKeyPath') != 'dkim.pem': raise Pending('Email DKIM requires its credential leaf')
        expected['dkim.pem'] = 'pem'
    elif dkim.get('PrivateKeyPath', '') not in ('', None):
        raise Pending('disabled DKIM still references a private key')
    return expected


def secret_bytes(raw, kind):
    \"\"\"Syntax checks only; no entropy, Azure, ASN.1, RSA or native authentication.\"\"\"
    try:
        text = raw.decode('ascii').rstrip('\\r\\n')
        if not text or text.casefold() == 'change_me': raise ValueError('missing material')
        if kind == 'key32':
            decoded = base64.b64decode(text, validate=True)
            if len(decoded) != 32 or not any(decoded) or base64.b64encode(decoded).decode('ascii') != text:
                raise ValueError('invalid 256-bit material')
        elif kind == 'pem':
            if not re.fullmatch(r'-----BEGIN ((?:RSA )?PRIVATE KEY)-----\\n[A-Za-z0-9+/=\\r\\n]+\\n-----END \\1-----', text):
                raise ValueError('unsupported private PEM spelling')
        elif not 16 <= len(text) <= 8192 or any(not 33 <= ord(c) <= 126 for c in text):
            raise ValueError('unsupported secret spelling')
    except (ValueError, UnicodeError) as error:
        raise Pending('Email credential material does not meet its bounded syntax') from error


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = JOIN.prepare(deadline=end)
    except JOIN.Pending as error: raise Pending('Email Application/PG prerequisite refused') from error
    if type(raw) is not bytes or not raw or len(raw) > JOIN.MAX_OUTPUT:
        raise Pending('unsupported complete Email Application/PG preparation')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'identities', 'postgresql',
                  'role_bindings', 'identity_sha256', 'postgresql_sha256'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'application-postgresql-peer-role-files-v1' or
            value['state'] != 'protected-application-postgresql-role-intention-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value) or
            BASE.canonical(value['role_bindings']) != BASE.canonical(JOIN.bindings(value['identities'], value['postgresql']))):
            raise Pending('Email Application/PG source correspondence differs')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Email Application/PG preparation') from error
    BASE.fence(end)
    return raw, value


def observe(peer, end):
    descriptor_raw, value, descriptor_source = document(INPUT, MAX_INPUT, end)
    value = descriptor(value)
    settings_raw, settings, settings_source = document(Path(value['settings']), MAX_SETTINGS, end)
    expected = configuration(settings, peer)
    if set(value['credentials']) != set(expected): raise Pending('Email credential sources differ from the complete selected references')
    credentials = [{'id': 'environment.json', 'source': settings_source, 'bytes': len(settings_raw)}]
    private = [descriptor_raw, settings_raw]
    for name, kind in sorted(expected.items()):
        raw, source = BASE.read_protected(Path(value['credentials'][name]), MAX_SECRET, True, end)
        secret_bytes(raw, kind); private.append(raw)
        credentials.append({'id': name, 'source': source, 'bytes': len(raw)})
    if sum(row['bytes'] for row in credentials) > MAX_CREDENTIAL_BYTES:
        raise Pending('combined Email unit credentials exceed their bounded capacity')
    return {'descriptor_source': descriptor_source, 'credentials': credentials,
            'worker_id': settings['Messaging']['WorkerId'], 'container': settings['ObjectStorage']['ContainerName']}, tuple(private)


def render(joined, inputs):
    role = joined['role_bindings']['mk8.email']
    release = joined['identities']['releases']['applications']['mk8.email']
    binding = joined['identities']['execution_bindings']['mk8.email']['application']
    directory, entry = literal(release['directory']), literal(role['entry_point'])
    if not entry.startswith(directory+'/'): raise Pending('Email Worker entry is outside its admitted release')
    environment = ['PATH=/usr/bin:/usr/sbin', 'LANG=C.UTF-8', 'LC_ALL=C.UTF-8', 'HOME=/nonexistent',
                   'TMPDIR=/tmp', 'DOTNET_NOLOGO=1', 'DOTNET_ENVIRONMENT=Production',
                   'MK8EMAIL_CONFIG_FILE=\${CREDENTIALS_DIRECTORY}/environment.json']
    commands = {mode: ['/usr/bin/env', '-i', *environment, entry, '--'+mode] for mode in ('serve', 'prepare', 'drain')}
    lines = ['[Unit]', 'Description=Protected Email Application Worker intention',
        'After=network-online.target debian13s4-postgresql-server.service', 'Wants=network-online.target',
        'RequiresMountsFor='+directory+' '+BASE.SOCKET_DIRECTORY, '[Service]', 'Type=exec',
        'User='+JOIN.IDENTITIES.name(role['user']), 'Group='+JOIN.IDENTITIES.name(binding['primary_group']),
        'WorkingDirectory=%d', 'UMask=0077', 'Restart=no', 'TimeoutStartSec=30s', 'TimeoutStopSec=120s',
        'KillMode=control-group', 'SendSIGKILL=yes', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=',
        'AmbientCapabilities=', 'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectSystem=strict',
        'ProtectHome=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
        'RestrictSUIDSGID=yes', 'LockPersonality=yes', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'StandardInput=null', 'StandardOutput=journal', 'StandardError=journal']
    lines += ['LoadCredential='+row['id']+':'+literal(row['source']['path']) for row in inputs['credentials']]
    lines += ['ExecStart='+' '.join(commands['serve'])]
    unit = '\\n'.join(lines)+'\\n'
    return {'unit_name': UNIT, 'unit': unit, 'unit_sha256': hashlib.sha256(unit.encode('ascii')).hexdigest(),
        'commands': commands, 'application_identity': binding, 'release_generation': release['generation'],
        'release_sha256': hashlib.sha256(BASE.canonical(joined['identities']['releases'])).hexdigest(),
        'identity_sha256': hashlib.sha256(BASE.canonical(joined['identities'])).hexdigest(),
        'database_intention': role['connection_intention'], 'inputs': inputs,
        'startup_database_mutations': True, 'full_native_configuration_validated': False}


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Email Worker window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Email Worker namespace')
    child_raw, joined = prerequisite(end, context)
    inputs, private = observe(joined['role_bindings']['mk8.email'], end)
    plan = render(joined, inputs)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
                          'application_pg_sha256': hashlib.sha256(child_raw).hexdigest(), 'plan': plan})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Email Worker intention exceeds its output bound')
    after, value = prerequisite(end, context)
    if after != child_raw: raise Pending('complete Email Application/PG preparation changed')
    after_inputs, after_private = observe(value['role_bindings']['mk8.email'], end)
    if BASE.canonical(inputs) != BASE.canonical(after_inputs) or private != after_private:
        raise Pending('Email settings or credential observations changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Email Worker namespace changed')
    BASE.fence(end)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', action='store_true', help='emit the Worker service intention text')
    args = parser.parse_args(argv)
    try:
        raw = prepare()
        if args.unit: raw = json.loads(raw)['plan']['unit'].encode('ascii')
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Email Worker intention output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/email_worker.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare partial Email Gateway/Worker configuration correspondence.

This reads existing protected files only. Gateway database authorization is
absent from the current local-peer plan, so no runnable unit is emitted. Native
configuration, cryptography, credentials, listeners and health remain unverified.
\"\"\"
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys


def owned(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).resolve().parents[1]
EMAIL = owned('debian13s4_email_gateway_worker', Path(__file__).resolve().with_name('email_worker.py'))
WEB_PATH = ROOT/'Web/prepare.py'
if not WEB_PATH.is_file(): WEB_PATH = ROOT/'web/prepare.py'
WEB = owned('debian13s4_email_gateway_web', WEB_PATH)
BASE, KERNEL, Pending = EMAIL.BASE, EMAIL.KERNEL, EMAIL.Pending
INPUT = Path('/etc/debian13s4/email-gateway.json')
MAX_INPUT, MAX_OUTPUT, ATTEMPT_SECONDS = 8192, 262144, 650
PROFILE = 'email-gateway-worker-file-correspondence-v1'
STATE = 'protected-email-gateway-file-correspondence-only'


def descriptor(value):
    fields = {'schema', 'settings', 'https_settings', 'credentials', 'state_directory'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported Email Gateway descriptor schema')
    credentials = value['credentials']
    if type(credentials) is not dict or not 5 <= len(credentials) <= 13:
        raise Pending('Email Gateway requires bounded explicit credential sources')
    paths = [value['settings'], value['https_settings'], *credentials.values()]
    for name in paths:
        if not EMAIL.literal(name).startswith(str(EMAIL.SETTINGS_ROOT)+'/'):
            raise Pending('Email Gateway files must be product settings descendants')
    if len(set(paths)) != len(paths) or set(paths) & {str(INPUT), str(EMAIL.INPUT)}:
        raise Pending('Email Gateway descriptor/settings/credential paths must remain distinct')
    state = EMAIL.literal(value['state_directory'])
    if not state.startswith(('/var/lib/debian13s4-email/', '/srv/debian13s4-email/')):
        raise Pending('Email Gateway state requires an explicit product directory intention')
    return value


def web_prepared(end, context):
    BASE.fence(end)
    try:
        raw = WEB.prepare(deadline=end, scope=WEB.KERNEL.namespace)
    except WEB.Pending as error:
        raise Pending('Email ingress preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > WEB.MAX_OUTPUT:
        raise Pending('unsupported complete Email ingress receipt')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'materials', 'nginx', 'nginx_sha256'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'nginx-private-https-three-gateway-intention-v1' or
            value['state'] != 'ingress-configuration-intention-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
            raise Pending('Email ingress profile, context or canonical bytes differ')
        nginx = WEB.render(value['configuration']['value'])
        if value['nginx'] != nginx or value['nginx_sha256'] != hashlib.sha256(nginx.encode('ascii')).hexdigest():
            raise Pending('Email ingress differs from the complete real renderer')
    except WEB.Pending as error:
        raise Pending('Email ingress renderer refused') from error
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Email ingress receipt') from error
    BASE.fence(end)
    return raw, value


def public_options(row, private):
    return {name: value for name, value in row.items() if name not in private}


def configuration(value, worker, role, ingress, state):
    \"\"\"A private HTTPS/JMAP-only profile; no extra mail TCP listeners selected.\"\"\"
    required = EMAIL.REQUIRED | {'Imap', 'Pop3', 'Sieve', 'Jmap', 'Dav', 'Tls', 'Admin'}
    KERNEL.known(value, EMAIL.SECTIONS, required)
    expected = EMAIL.transport_configuration(value, {'user': role['name'], 'database': worker['Database']['Name']})
    if value['Database']['Username'] == worker['Database']['Username']:
        raise Pending('Email Gateway must not borrow the Application database identity')
    for section, ignored in (
        ('Messaging', {'WorkerId'}), ('ObjectStorage', set()), ('Limits', set()),
        ('OAuth', {'SigningKey', 'SigningKeyFile'}), ('Mfa', {'EncryptionKey', 'EncryptionKeyFile'}),
        ('Dkim', {'PrivateKeyPath'})):
        if BASE.canonical(public_options(value[section], ignored)) != BASE.canonical(public_options(worker[section], ignored)):
            raise Pending('Email Gateway and Worker '+section+' intentions differ')
    if value['Messaging']['WorkerId'] == worker['Messaging']['WorkerId']:
        raise Pending('Email Gateway and Worker require distinct explicit process identifiers')
    for section, names in (('OAuth', ('SigningKey', 'SigningKeyFile')),
                           ('Mfa', ('EncryptionKey', 'EncryptionKeyFile')),
                           ('Dkim', ('PrivateKeyPath',))):
        if any(value[section].get(name, '') != '' for name in names):
            raise Pending('Worker-only signing/MFA material must not enter Gateway inputs')
    for section, names in (
        ('Smtp', ('EnableSmtp', 'EnableSubmission', 'EnableImplicitTls', 'EnableStartTls', 'RequireTls', 'AllowRelay')),
        ('Imap', ('EnableImap', 'EnableImplicitTls')),
        ('Pop3', ('EnablePop3', 'EnableImplicitTls', 'EnableStartTls')),
        ('Sieve', ('EnableManageSieve', 'EnableStartTls')),
        ('Dav', ('EnableDav',))):
        if any(EMAIL.flag(value[section], name) for name in names):
            raise Pending('Email Gateway profile selects private HTTPS/JMAP only')
    if value['Smtp'].get('ListenAddress') != '127.0.0.1' or value['Smtp'].get('Hostname') != worker['Smtp']['Hostname']:
        raise Pending('Email SMTP source identity or explicit loopback intention differs')
    KERNEL.known(value['Tls'], {'CertificatePath', 'CertificateKeyPath'}, set())
    if any(value['Tls'].get(name, '') != '' for name in ('CertificatePath', 'CertificateKeyPath')):
        raise Pending('disabled mail TCP listeners must not reference separate TLS material')
    jmap = value['Jmap']
    if (not EMAIL.flag(jmap, 'EnableJmap') or type(jmap.get('Port')) is not int or
        jmap['Port'] != ingress['upstream_port'] or jmap.get('PublicBaseUrl') != 'https://'+ingress['hostname']):
        raise Pending('Email JMAP listener/public URL differ from the ingress intention')
    for name, minimum, maximum in (('MaxUploadSizeBytes', 1048576, 1073741824),
                                  ('MaxRequestSizeBytes', 65536, 104857600)):
        if KERNEL.uint(jmap.get(name), maximum) < minimum:
            raise Pending('unsupported Email JMAP body bound')
    body = max(65536, jmap['MaxUploadSizeBytes'], jmap['MaxRequestSizeBytes'])
    if ingress['body_bytes'] > body:
        raise Pending('Email ingress body exceeds the selected Gateway body intention')
    for name in ('EnableOAuth', 'EnableOpenIdConnect'):
        EMAIL.flag(value['OAuth'], name)
    if value['OAuth']['EnableOAuth'] and value['OAuth'].get('PublicBaseUrl') != 'https://'+ingress['hostname']:
        raise Pending('Email OAuth public URL differs from ingress')
    admin = value['Admin']
    fields = {'AllowedNetworks', 'DataProtectionKeyPath', 'AuditLogPath', 'HealthStatusPath', 'SessionMinutes'}
    KERNEL.known(admin, fields, fields)
    if KERNEL.uint(admin['SessionMinutes'], 480) < 5:
        raise Pending('unsupported Email admin session bound')
    networks = admin['AllowedNetworks']
    if type(networks) is not list or not 1 <= len(networks) <= 32:
        raise Pending('Email admin networks must be explicit and bounded')
    try:
        if any(type(net) is not str or str(ipaddress.ip_network(net, strict=True)) != net for net in networks):
            raise ValueError('noncanonical network')
    except ValueError as error:
        raise Pending('unsupported explicit Email admin network') from error
    if len(set(networks)) != len(networks): raise Pending('duplicate Email admin network')
    for name, leaf in (('DataProtectionKeyPath', 'data-protection'), ('AuditLogPath', 'audit.jsonl'), ('HealthStatusPath', 'health.json')):
        if admin[name] != state+'/'+leaf: raise Pending('Email admin paths differ from explicit Gateway state')
    return expected, {'body_bytes': body, 'admin_networks': networks,
                      'admin_session_minutes': admin['SessionMinutes']}


def https(value, ingress):
    KERNEL.known(value, {'Kestrel'}, {'Kestrel'})
    KERNEL.known(value['Kestrel'], {'Endpoints'}, {'Endpoints'})
    endpoints = value['Kestrel']['Endpoints']
    KERNEL.known(endpoints, {'Private'}, {'Private'})
    endpoint = endpoints['Private']
    KERNEL.known(endpoint, {'Url', 'Protocols', 'Certificate'}, {'Url', 'Protocols', 'Certificate'})
    certificate = endpoint['Certificate']
    KERNEL.known(certificate, {'Path', 'KeyPath', 'Password'}, {'Path', 'KeyPath', 'Password'})
    if (endpoint['Url'] != 'https://127.0.0.1:'+str(ingress['upstream_port']) or endpoint['Protocols'] != 'Http1' or
        certificate != {'Path': 'certificate.pem', 'KeyPath': 'private-key.pem', 'Password': ''}):
        raise Pending('Email HTTPS requires one loopback HTTP1 listener and fixed credential leaves')
    return {'address': '127.0.0.1', 'port': ingress['upstream_port'], 'scheme': 'https',
            'protocol': 'Http1', 'server_name_intention': ingress['upstream_name']}


def observe(joined, web, end):
    worker_inputs, worker_private = EMAIL.observe(joined['role_bindings']['mk8.email'], end)
    worker = json.loads(worker_private[1])
    descriptor_raw, inputs, descriptor_source = EMAIL.document(INPUT, MAX_INPUT, end)
    inputs = descriptor(inputs)
    settings_raw, settings, settings_source = EMAIL.document(Path(inputs['settings']), EMAIL.MAX_SETTINGS, end)
    https_raw, https_settings, https_source = EMAIL.document(Path(inputs['https_settings']), EMAIL.MAX_SETTINGS, end)
    role = joined['identities']['execution_bindings']['mk8.email']['gateway']
    ingress = web['configuration']['value']['applications']['mk8.email']
    expected, options = configuration(settings, worker, role, ingress, inputs['state_directory'])
    listener = https(https_settings, ingress)
    expected.update({'certificate.pem': 'certificate', 'private-key.pem': 'private-key'})
    if set(inputs['credentials']) != set(expected):
        raise Pending('Email Gateway credential sources differ from selected references')
    worker_sources = {row['id']: row['source'] for row in worker_inputs['credentials']}
    forbidden = {worker_sources[name]['path'] for name in worker_sources
                 if name in ('environment.json', 'database.password', 'oauth-signing.pem', 'mfa.key', 'dkim.pem')}
    public_files = {row[field] for row in web['configuration']['value']['applications'].values()
                    for field in ('certificate', 'upstream_ca')}
    credentials = [{'id': 'environment.json', 'source': settings_source, 'bytes': len(settings_raw)},
                   {'id': 'appsettings.json', 'source': https_source, 'bytes': len(https_raw)}]
    private = [descriptor_raw, settings_raw, https_raw]
    for name, kind in sorted(expected.items()):
        filename = inputs['credentials'][name]
        if filename in forbidden or kind != 'certificate' and filename in public_files:
            raise Pending('Email Gateway reuses Worker-private or public ingress material')
        raw, source = BASE.read_protected(Path(filename), EMAIL.MAX_SECRET, True, end)
        if kind in ('certificate', 'private-key'):
            try: WEB.pem(raw, kind == 'private-key')
            except WEB.Pending as error: raise Pending('Email Gateway PEM grammar refused') from error
        else:
            EMAIL.secret_bytes(raw, kind)
        if name == 'objects.connection' or name.startswith('messaging.'):
            if source['sha256'] != worker_sources[name]['sha256']:
                raise Pending('Email Gateway and Worker shared transport material bytes differ')
        credentials.append({'id': name, 'source': source, 'bytes': len(raw)})
        private.append(raw)
    if sum(row['bytes'] for row in credentials) > EMAIL.MAX_CREDENTIAL_BYTES:
        raise Pending('combined Email Gateway credentials exceed their bounded capacity')
    record = {'configuration_source': descriptor_source, 'credentials': credentials,
        'gateway_identity': role, 'listener': listener, 'presentation': options,
        'required_state': {'path': inputs['state_directory'], 'owner_uid': role['uid'],
            'owner_gid': role['primary_gid'], 'mode': '0700', 'observed': False, 'created': False},
        'database': {'host': settings['Database']['Host'], 'port': 5432, 'name': settings['Database']['Name'],
            'user': role['name'], 'authorized_by_current_local_peer_plan': False},
        'unit_available': False, 'full_native_configuration_validated': False,
        'worker_files': worker_inputs}
    return record, tuple(private)+worker_private


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Email Gateway window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Email Gateway namespace')
    joined_raw, joined = EMAIL.prerequisite(end, context)
    web_raw, web = web_prepared(end, context)
    gateway, private = observe(joined, web, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'application_pg_sha256': hashlib.sha256(joined_raw).hexdigest(),
        'identity_sha256': hashlib.sha256(BASE.canonical(joined['identities'])).hexdigest(),
        'release_sha256': hashlib.sha256(BASE.canonical(joined['identities']['releases'])).hexdigest(),
        'ingress_sha256': hashlib.sha256(web_raw).hexdigest(), 'gateway': gateway})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Email Gateway observation exceeds its output bound')
    if EMAIL.prerequisite(end, context)[0] != joined_raw or web_prepared(end, context)[0] != web_raw:
        raise Pending('complete Email identity/PG or ingress preparation changed')
    after, after_private = observe(joined, web, end)
    if BASE.canonical(after) != BASE.canonical(gateway) or after_private != private:
        raise Pending('Email Gateway or Worker protected files changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Email Gateway namespace changed')
    BASE.fence(end)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        raw = prepare()
        count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Email Gateway output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/email_gateway.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Compose known protected application FILE prerequisites, never app readiness.

Four-role release/account files, selected DNS unit and PG role intentions, and
selected Sava policy/key files are checked. Drava/Email runtime settings, native
credentials, runnable binaries, health, enrollment and installation stay open.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def owned(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DNS = owned('debian13s4_application_dns_files', 'dns_service.py')
PG = owned('debian13s4_application_pg_files', 'postgresql_identity.py')
SAVA = owned('debian13s4_application_sava_files', 'sava_transport.py')
BASE, KERNEL, Pending = DNS.BASE, DNS.KERNEL, DNS.Pending
MAX_OUTPUT = 16777217
ATTEMPT_SECONDS = 1760
CHILDREN = (
    ('dns', DNS, {'schema', 'profile', 'state', 'namespace', 'identities', 'dns_service',
        'unit_bindings', 'identity_sha256', 'dns_service_sha256'},
     'protected-dns-release-service-intention-v1', 'protected-dns-release-service-intention-only'),
    ('postgresql', PG, {'schema', 'profile', 'state', 'namespace', 'identities', 'postgresql',
        'role_bindings', 'identity_sha256', 'postgresql_sha256'},
     'application-postgresql-peer-role-files-v1', 'protected-application-postgresql-role-intention-only'),
    ('sava', SAVA, {'schema', 'profile', 'state', 'namespace', 'identities', 'identity_sha256', 'settings'},
     'sava-paired-transport-policy-files-v1', 'sava-split-transport-policy-source-only'))


def prepared_bytes(module, end):
    BASE.fence(end)
    try:
        raw = module.prepare(deadline=end)
    except module.Pending as error:
        raise Pending('application file prerequisite refused') from error
    if type(raw) is not bytes or len(raw) > module.MAX_OUTPUT:
        raise Pending('unsupported complete application file prerequisite bytes')
    BASE.fence(end)
    return raw


def prepared(child, end, context):
    tag, module, fields, profile, state = child
    raw = prepared_bytes(module, end)
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite prerequisite')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid application file prerequisite JSON') from error
    KERNEL.known(value, fields, fields)
    identity = value['identities']
    KERNEL.known(identity, DNS.IDENTITY_FIELDS, DNS.IDENTITY_FIELDS)
    if (type(value['schema']) is not int or value['schema'] != 1 or
        value['profile'] != profile or value['state'] != state or
        KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        type(identity['schema']) is not int or identity['schema'] != 1 or
        identity['profile'] != 'four-app-release-account-intention-v1' or
        identity['state'] != 'protected-application-execution-identity-source-only' or
        KERNEL.uint(identity['namespace'], 0xffffffffffffffff) != context or
        value['identity_sha256'] != hashlib.sha256(BASE.canonical(identity)).hexdigest() or
        raw != BASE.canonical(value)):
        raise Pending('application file prerequisite schema, identity, scope or canonical bytes differ')
    BASE.fence(end)
    return raw, value


def correspondence(values):
    \"\"\"Whole reported identity correspondence, not native provenance or access.\"\"\"
    identity = BASE.canonical(values['dns']['identities'])
    if any(BASE.canonical(values[tag]['identities']) != identity for tag in ('postgresql', 'sava')):
        raise Pending('complete application release/account prerequisites differ')
    dns = values['dns']; pg = values['postgresql']
    try:
        dns_roles = DNS.bindings(dns['identities'], dns['dns_service'])
        pg_roles = PG.bindings(pg['identities'], pg['postgresql'])
    except (DNS.Pending, PG.Pending, DNS.DNS.Pending) as error:
        raise Pending('application role prerequisite refused') from error
    if (BASE.canonical(dns['unit_bindings']) != BASE.canonical(dns_roles) or
        BASE.canonical(pg['role_bindings']) != BASE.canonical(pg_roles)):
        raise Pending('whole DNS or PostgreSQL role correspondence differs from its real renderer')
    unit, peer = dns['unit_bindings'][DNS.DNS.APP_UNIT], pg['role_bindings']['mk8.dns']
    left = {'user': unit['user'], 'uid': unit['uid'], 'primary_gid': unit['account_primary_gid'], 'entry_point': unit['entry_point']}
    right = {key: peer[key] for key in left}
    if BASE.canonical(left) != BASE.canonical(right):
        raise Pending('DNS application unit identity differs from the reserved PostgreSQL role intention')
    return {'dns_application_identity': left, 'dns_unit_group': unit['unit_group'],
        'dns_unit_gid': unit['unit_gid'], 'identity_sha256': hashlib.sha256(identity).hexdigest()}


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited application prerequisite window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing application prerequisite namespace')
    original, values = {}, {}
    for child in CHILDREN:
        raw, value = prepared(child, end, context)
        original[child[0]], values[child[0]] = raw, value
    joined = correspondence(values)
    payload = BASE.canonical({'schema': 1, 'profile': 'application-file-prerequisites-v1',
        'state': 'application-file-prerequisites-source-only', 'namespace': context,
        'components': values, 'component_sha256': {tag: hashlib.sha256(raw).hexdigest() for tag, raw in original.items()},
        'correspondence': joined})
    if len(payload) > MAX_OUTPUT:
        raise Pending('whole application file prerequisites exceed their output bound')
    for tag, module, _, _, _ in CHILDREN:
        if prepared_bytes(module, end) != original[tag]:
            raise Pending('complete application file prerequisite changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('application prerequisite namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('application file prerequisites accept no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('application file prerequisites require binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete application prerequisite output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/prepare.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Read protected application inputs and report their source correspondence.

No service is installed or started. The report covers sequential file
observations, not executable validity, native credentials or application health.
Run with an isolated interpreter: python3 -I -B applications/preflight.py.
\"\"\"
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
import time


CHECKS = {
    'releases': ('releases.py', 'four-app-complete-release-files-v1',
                 'protected-preinstalled-release-source-only'),
    'linux-images': ('linux_images.py', 'four-app-linux-elf64-entry-structure-v1',
                     'protected-linux-entry-structure-source-only'),
    'linux-linkage': ('linux_linkage.py', 'four-app-elf-dynamic-dependency-files-v1',
                      'protected-linux-linkage-declarations-source-only'),
    'managed-runtime': ('managed_runtime.py', 'four-app-dotnet10-framework-metadata-v1',
                        'protected-managed-runtime-metadata-source-only'),
    'managed-images': ('managed_images.py', 'four-app-pe-cli-entry-structure-v1',
                       'protected-managed-entry-structure-source-only'),
    'managed-assets': ('managed_assets.py', 'four-app-selected-dependency-file-correspondence-v1',
                       'protected-managed-dependency-files-source-only'),
    'identities': ('identities.py', 'four-app-release-account-intention-v1',
                   'protected-application-execution-identity-source-only'),
    'dns': ('dns_service.py', 'protected-dns-release-service-intention-v1',
            'protected-dns-release-service-intention-only'),
    'postgresql': ('postgresql_identity.py', 'application-postgresql-peer-role-files-v1',
                   'protected-application-postgresql-role-intention-only'),
    'sava': ('sava_transport.py', 'sava-paired-transport-policy-files-v1',
             'sava-split-transport-policy-source-only'),
    'ingress': ('sava_ingress.py', 'sava-gateway-nginx-file-correspondence-v1',
                'protected-sava-gateway-ingress-source-only'),
    'sava-service': ('sava_service.py', 'sava-systemd-credential-service-intentions-v1',
                     'protected-sava-service-intention-only'),
    'email-worker': ('email_worker.py', 'email-worker-credential-service-intentions-v1',
                     'protected-email-worker-service-intention-only'),
    'email-gateway': ('email_gateway.py', 'email-gateway-worker-file-correspondence-v1',
                      'protected-email-gateway-file-correspondence-only'),
    'prerequisites': ('prepare.py', 'application-file-prerequisites-v1',
                      'application-file-prerequisites-source-only'),
}
GROUPS = {
    'all': ('prerequisites', 'ingress'),
    'service-plans': ('linux-images', 'managed-runtime', 'sava-service', 'email-worker'),
    'release-files': ('linux-images', 'managed-images', 'managed-assets'),
}
ATTEMPT_SECONDS = 2400
MAX_OUTPUT = 65536
LIMITATIONS = (
    'Application binaries, framework compatibility and native credentials are unverified.',
    'Runtime settings, service health and complete four-application integration remain unverified.',
    'Sequential file observations do not prove continuous identity or reserve network ports.',
)


class Pending(ValueError):
    \"\"\"A requested input check or its cross-component correspondence refused.\"\"\"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\\n').encode('ascii')


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def fence(end):
    if now() >= end:
        raise Pending('application preflight window expired')


def owned(check):
    spec = importlib.util.spec_from_file_location('debian13s4_preflight_'+check,
        Path(__file__).resolve().with_name(CHECKS[check][0]))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Pending('duplicate prerequisite property')
        value[key] = item
    return value


def finite(text):
    value = float(text)
    if not math.isfinite(value):
        raise Pending('nonfinite prerequisite number')
    return value


def observe(check, module, end, namespace):
    fence(end)
    try:
        raw = module.prepare(deadline=end)
    except (module.Pending, OSError) as error:
        raise Pending(check+': protected inputs refused: '+str(error)) from error
    if type(raw) is not bytes or not raw or len(raw) > module.MAX_OUTPUT:
        raise Pending(check+': unsupported prerequisite bytes')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_float=finite,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite prerequisite')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending(check+': invalid prerequisite JSON') from error
    if (type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or
        value.get('profile') != CHECKS[check][1] or value.get('state') != CHECKS[check][2] or
        type(value.get('namespace')) is not int or value['namespace'] != namespace or
        raw != canonical(value)):
        raise Pending(check+': prerequisite profile, context or canonical bytes differ')
    fence(end)
    return raw, value


def listener_plan(prerequisites, ingress):
    \"\"\"Refuse collisions among the selected TCP listener intentions, not sockets.\"\"\"
    if canonical(prerequisites['components']['sava']) != canonical(ingress['sava']):
        raise Pending('Sava release, account or settings observations differ between checks')
    claims = []
    web = ingress['ingress']['configuration']['value']['applications']
    for app, row in sorted(web.items()):
        claims.append({'owner': app+' HTTPS gateway', 'address': '127.0.0.1',
                       'port': row['upstream_port'], 'transport': 'tcp'})
    rpc = ingress['sava']['settings']['rpc']
    claims.append({'owner': 'mk8.sava Application RPC', 'address': rpc['address'],
                   'port': rpc['port'], 'transport': 'tcp'})
    dns = prerequisites['components']['dns']['dns_service']['plan']['listeners']
    for row in dns:
        claims.append({'owner': row['unit']+' health', 'address': row['health_address'],
                       'port': row['health_port'], 'transport': 'tcp'})
    occupied = {}
    for row in claims:
        if (row['address'] not in ('127.0.0.1', '::1') or
            type(row['port']) is not int or not 1024 <= row['port'] <= 65535 or row['port'] == 5432):
            raise Pending('unsupported loopback listener intention')
        key = row['address'], row['port'], row['transport']
        if key in occupied:
            raise Pending(f\"listener conflict at {key[0]}:{key[1]}: {occupied[key]} and {row['owner']}\")
        occupied[key] = row['owner']
    return claims


def digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None or value == '0'*64:
        raise Pending('unsupported complete source commitment')
    return value


def service_plan_correspondence(values):
    \"\"\"Join observed files and three unit intentions, not installed services.\"\"\"
    try:
        image, runtime = values['linux-images'], values['managed-runtime']
        sava, email = values['sava-service']['plan'], values['email-worker']['plan']
        releases = [digest(row['release_sha256']) for row in (image, runtime, sava, email)]
        if len(set(releases)) != 1:
            raise Pending('complete release observations differ between image, runtime and service plans')
        identities = [digest(row['identity_sha256']) for row in (sava, email)]
        if identities[0] != identities[1]:
            raise Pending('complete identity observations differ between service plans')
        if canonical(image['configuration']) != canonical(runtime['image_configuration']):
            raise Pending('Linux target configuration observations differ between image and runtime checks')
        units = []
        for name, row in [(sava['units'][role]['name'], sava['units'][role])
                          for role in ('application', 'gateway')] + [(email['unit_name'], email)]:
            if (type(name) is not str or re.fullmatch('debian13s4-[a-z-]+\\\\.service', name) is None or
                type(row['unit']) is not str or not row['unit'] or
                hashlib.sha256(row['unit'].encode('ascii')).hexdigest() != digest(row['unit_sha256'])):
                raise Pending('unit intention text or its commitment differs')
            units.append({'name': name, 'sha256': row['unit_sha256']})
        if len({row['name'] for row in units}) != len(units):
            raise Pending('service intentions claim the same unit name')
        return {'release_sha256': releases[0], 'identity_sha256': identities[0],
                'units': units, 'complete_four_application_service_plan': False}
    except (KeyError, TypeError, UnicodeError) as error:
        raise Pending('incomplete service-plan correspondence') from error


def release_file_correspondence(values):
    \"\"\"Join native entries, managed entries and selected assets of one release.\"\"\"
    try:
        native, managed, assets = (values[tag] for tag in GROUPS['release-files'])
        releases = [digest(row['release_sha256']) for row in (native, managed, assets)]
        if len(set(releases)) != 1:
            raise Pending('complete release observations differ between file checks')
        runtime = digest(managed['runtime_sha256'])
        if runtime != digest(assets['runtime_sha256']):
            raise Pending('complete runtime metadata observations differ between file checks')
        configuration = canonical(native['configuration'])
        if any(canonical(row['image_configuration']) != configuration for row in (managed, assets)):
            raise Pending('Linux target configuration observations differ between file checks')
        architecture = native['configuration']['value']['architecture']
        if architecture not in ('x86_64', 'aarch64'):
            raise Pending('unsupported release-file target architecture')
        applications = ('mk8.dns', 'mk8.drava', 'mk8.email', 'mk8.sava')
        if any(set(row['applications']) != set(applications) for row in (native, managed, assets)):
            raise Pending('release file checks must cover all four applications')
        entries = []
        for app in applications:
            if any(set(row['applications'][app]) != {'application', 'gateway'} for row in (native, managed, assets)):
                raise Pending('release file checks must cover both application roles')
            for role in ('application', 'gateway'):
                executable = native['applications'][app][role]
                assembly = managed['applications'][app][role]['source']
                selected = assets['applications'][app][role]['assets']
                if (type(executable['source']['path']) is not str or
                    assembly['path'] != executable['source']['path']+'.dll' or
                    executable['image']['architecture'] != architecture):
                    raise Pending('native and managed entry paths or architecture differ')
                if type(selected) is not list or not 1 <= len(selected) <= 256:
                    raise Pending('unsupported selected release dependency assets')
                matches = [row['source'] for row in selected if row['kind'] == 'runtime' and
                           row['source']['path'] == assembly['path']]
                if len(matches) != 1 or canonical(matches[0]) != canonical(assembly):
                    raise Pending('managed entry and selected dependency file observations differ')
                entries.append({'application': app, 'role': role,
                    'native_sha256': digest(executable['source']['sha256']),
                    'assembly_sha256': digest(assembly['sha256']), 'selected_assets': len(selected)})
        return {'release_sha256': releases[0], 'runtime_sha256': runtime,
                'architecture': architecture, 'entries': entries,
                'runtime_compatibility_verified': False, 'publisher_authenticated': False}
    except (KeyError, TypeError, UnicodeError) as error:
        raise Pending('incomplete release-file correspondence') from error


def prepare(check='all', deadline=None):
    if type(check) is not str or check not in (*CHECKS, *GROUPS):
        raise Pending('unknown application preflight check')
    start = now()
    if deadline is not None and (type(deadline) not in (int, float) or
                                not math.isfinite(deadline) or deadline <= start):
        raise Pending('invalid inherited preflight deadline')
    end = min(start+ATTEMPT_SECONDS, deadline) if deadline is not None else start+ATTEMPT_SECONDS
    selected = GROUPS.get(check, (check,))
    values, summaries, modules = {}, {}, []
    namespace = None
    for tag in selected:
        fence(end)
        module = owned(tag)
        context = module.KERNEL.uint(module.KERNEL.namespace(), 0xffffffffffffffff)
        if context == 0 or namespace is not None and context != namespace:
            raise Pending(tag+': namespace unavailable or changed')
        namespace = context
        raw, value = observe(tag, module, end, namespace)
        modules.append(module)
        values[tag] = value
        summaries[tag] = {'state': value['state'], 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()}
    listeners = listener_plan(values['prerequisites'], values['ingress']) if check == 'all' else []
    report = {'schema': 1, 'state': 'application-preflight-source-only',
        'requested': check, 'namespace': namespace, 'checks': summaries,
        'listener_intentions': listeners, 'limitations': list(LIMITATIONS)}
    if check == 'service-plans':
        report['service_plan_correspondence'] = service_plan_correspondence(values)
    if check == 'release-files':
        report['release_file_correspondence'] = release_file_correspondence(values)
    payload = canonical(report)
    if len(payload) > MAX_OUTPUT:
        raise Pending('preflight report exceeds its bound')
    for module in modules:
        if module.KERNEL.uint(module.KERNEL.namespace(), 0xffffffffffffffff) != namespace:
            raise Pending('preflight namespace changed')
    fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', choices=(*CHECKS, *GROUPS), default='all')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    args = parser.parse_args(argv)
    try:
        raw = prepare(args.check)
        if args.format == 'text':
            value = json.loads(raw)
            lines = ['Protected application file checks completed: '+', '.join(value['checks'])+'.',
                     'Scope: source inputs only; application readiness remains unverified.']
            lines.extend(f\"{row['owner']}: {row['address']}:{row['port']} ({row['transport']} intention)\"
                         for row in value['listener_intentions'])
            if 'service_plan_correspondence' in value:
                lines.append('Matching release and identity observations for unit intentions: '+
                    ', '.join(row['name'] for row in value['service_plan_correspondence']['units'])+'.')
            if 'release_file_correspondence' in value:
                files = value['release_file_correspondence']
                lines.append('Matching native entries, managed entries and dependency files: '+
                    str(len(files['entries']))+' entries for '+files['architecture']+'.')
            lines.extend(value['limitations'])
            raw = ('\\n'.join(lines)+'\\n').encode('ascii')
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete preflight output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/preflight.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Describe a protected release tree without copying, installing or executing it.

The resulting declaration proposes its generation directory. The operator must
publish the same bytes separately before releases.py can admit that directory.
Public hashes identify bytes; they do not authenticate a publisher or CLR/ABI.
\"\"\"
import argparse
import importlib.util
from pathlib import Path
import stat
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_manifest_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
MAX_OUTPUT = RELEASE.MAX_OUTPUT


def prepare(application, directory, application_entry, gateway_entry, deadline=None):
    if type(application) is not str or application not in RELEASE.APPLICATIONS:
        raise Pending('select one supported application explicitly')
    if type(directory) is not type(BASE.TRUST_ROOT):
        raise Pending('release inventory requires an explicit absolute directory')
    entries = {'application': RELEASE.relative(application_entry), 'gateway': RELEASE.relative(gateway_entry)}
    if application_entry == gateway_entry:
        raise Pending('application and gateway entry points must differ')
    start = KERNEL.now()
    if deadline is not None and (not KERNEL.finite_deadline(deadline) or deadline <= start):
        raise Pending('invalid release inventory deadline')
    end = min(start+RELEASE.ATTEMPT_SECONDS, deadline) if deadline is not None else start+RELEASE.ATTEMPT_SECONDS
    BASE.fence(end)
    namespace = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not namespace:
        raise Pending('missing release inventory namespace')
    before = RELEASE.tree(directory, end)
    if not 2 <= len(before['files']) <= RELEASE.MAX_FILES or not set(entries.values()) <= set(before['files']):
        raise Pending('both entry points must occur in the complete release inventory')
    expected_directories = {'.'}
    facts, total = {}, 0
    for name in before['files']:
        BASE.fence(end)
        expected_directories.update(str(p) for p in Path(name).parents if str(p) != '.')
        info = (directory/name).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != BASE.TRUSTED_UID or
            info.st_dev != before['directories']['.'][0] or stat.S_IMODE(info.st_mode) not in (0o644, 0o755) or
            not 0 <= info.st_size <= RELEASE.MAX_FILE_BYTES):
            raise Pending('unsupported release file owner, type, link, mode, device or size')
        total += info.st_size
        if total > RELEASE.MAX_TOTAL_BYTES:
            raise Pending('release inventory exceeds its total byte bound')
        facts[name] = info
    if set(before['directories']) != expected_directories:
        raise Pending('release tree contains undeclared empty directories')
    for entry in entries.values():
        if stat.S_IMODE(facts[entry].st_mode) != 0o755 or facts[entry].st_size == 0:
            raise Pending('release entry points require nonempty executable files')
    files, sources = {}, {}
    for name, info in facts.items():
        raw, source = BASE.read_protected(directory/name, info.st_size, False, end)
        if source['identity'] != list(KERNEL.signature(info)):
            raise Pending('release file changed after inventory')
        files[name] = {'bytes': len(raw), 'mode': format(stat.S_IMODE(info.st_mode), '04o'), 'sha256': source['sha256']}
        sources[name] = source
    if RELEASE.tree(directory, end) != before:
        raise Pending('release inventory changed during file reads')
    generation = RELEASE.generation(entries, files)
    declaration = {'generation': generation, 'directory': str(RELEASE.RELEASE_ROOT/application/generation),
                   'entry_points': entries, 'files': files}
    payload = BASE.canonical({'schema': 1, 'state': 'release-manifest-proposal-only',
        'application': application, 'namespace': namespace, 'source_directory': str(directory),
        'declaration': declaration, 'observed_sources': sources, 'observed_directories': before['directories']})
    if len(payload) > MAX_OUTPUT:
        raise Pending('release inventory proposal exceeds its output bound')
    # Reuse the complete production admission reader for the final observation.
    # Its directory is the actual staging tree, not the proposed destination.
    actual = dict(declaration, directory=str(directory))
    after = RELEASE.observe(actual, end)
    if after['files'] != sources or after['directories'] != before['directories']:
        raise Pending('release inventory changed after proposal encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != namespace:
        raise Pending('release inventory namespace changed')
    BASE.fence(end)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', choices=RELEASE.APPLICATIONS, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--application-entry', required=True)
    parser.add_argument('--gateway-entry', required=True)
    args = parser.parse_args(argv)
    try:
        raw = prepare(args.application, args.directory, args.application_entry, args.gateway_entry)
        sink = sys.stdout.buffer
        count = sink.write(raw)
        if type(count) is not int or count != len(raw):
            raise Pending('incomplete release proposal output')
        sink.flush()
        return 0
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/release_manifest.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Inspect protected Linux entry images without loading or executing them.

This is a bounded ELF64 header/segment profile, not a complete ELF, CLR, linker,
publisher or ABI verifier. The target architecture and interpreter are explicit
protected inputs, not inferred from the machine running this tool.
\"\"\"
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_linux_image_releases',
    Path(__file__).resolve().with_name('releases.py'))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
BASE, KERNEL, Pending = RELEASE.BASE, RELEASE.KERNEL, RELEASE.Pending
INPUT = Path('/etc/debian13s4/application-images.json')
MACHINES = {'x86_64': 62, 'aarch64': 183}
MAX_INPUT, MAX_OUTPUT, ATTEMPT_SECONDS = 4096, 262145, 150
MAX_PROGRAM_HEADERS, MAX_SECTION_HEADERS, MAX_MAPPED_BYTES = 128, 4096, 1 << 30
PROFILE = 'four-app-linux-elf64-entry-structure-v1'
STATE = 'protected-linux-entry-structure-source-only'
ELF_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
PROGRAM_HEADER = struct.Struct('<IIQQQQQQ')
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK = 1, 2, 3, 0x6474e551


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite image configuration')))
        fields = {'schema', 'architecture', 'interpreter'}
        KERNEL.known(value, fields, fields)
        if type(value['schema']) is not int or value['schema'] != 1 or value['architecture'] not in MACHINES:
            raise Pending('unsupported explicit Linux image profile')
        interpreter = value['interpreter']
        if interpreter is not None and (type(interpreter) is not str or len(interpreter) > 240 or
            re.fullmatch(r'/(?:usr/)?lib(?:64)?/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', interpreter) is None or
            os.path.normpath(interpreter) != interpreter or any(p in ('.', '..') for p in interpreter.split('/'))):
            raise Pending('interpreter must be an explicit canonical library path or null')
        if raw != BASE.canonical(value): raise Pending('image configuration must be canonical ASCII JSON plus LF')
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise Pending('invalid protected Linux image configuration') from error
    return {'value': value, 'source': source}


def interval(offset, size, limit, description):
    # Python arithmetic does not wrap; subtraction also expresses the serialized
    # unsigned range check without relying on a machine-sized addition.
    if offset > limit or size > limit-offset:
        raise Pending(description+' exceeds its bounded image/range')


def inspect(raw, architecture, interpreter):
    if type(raw) is not bytes or not ELF_HEADER.size <= len(raw) <= RELEASE.MAX_FILE_BYTES:
        raise Pending('ELF entry requires bounded immutable whole bytes')
    if type(architecture) is not str or architecture not in MACHINES:
        raise Pending('unsupported explicit ELF architecture')
    fields = ELF_HEADER.unpack_from(raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shnames = fields
    if (ident[:7] != b'\\x7fELF\\x02\\x01\\x01' or ident[7] not in (0, 3) or any(ident[8:]) or
        kind not in (2, 3) or machine != MACHINES[architecture] or version != 1 or flags != 0 or
        ehsize != ELF_HEADER.size or phsize != PROGRAM_HEADER.size or not 1 <= phnum <= MAX_PROGRAM_HEADERS or
        phoff < ELF_HEADER.size or entry == 0):
        raise Pending('unsupported ELF64 little-endian executable header or architecture')
    interval(phoff, phnum*phsize, len(raw), 'program header table')
    if shoff == 0:
        if shnum != 0 or shnames != 0: raise Pending('section table is absent but counts are present')
    else:
        if shoff < ELF_HEADER.size or shsize != 64 or not 1 <= shnum <= MAX_SECTION_HEADERS or shnames >= shnum:
            raise Pending('unsupported bounded section table header')
        interval(shoff, shnum*shsize, len(raw), 'section header table')
    loads, segments, interpreters, stacks = [], [], [], []
    mapped = 0; dynamic = 0
    for index in range(phnum):
        tag, permissions, offset, address, physical, size, memory, alignment = PROGRAM_HEADER.unpack_from(raw, phoff+index*phsize)
        interval(offset, size, len(raw), 'segment file data')
        interval(address, memory, (1 << 64)-1, 'segment virtual range')
        if permissions & ~7 or alignment > MAX_MAPPED_BYTES or alignment > 1 and alignment & (alignment-1):
            raise Pending('unsupported segment flags or alignment')
        if tag == PT_LOAD:
            if size > memory or memory > MAX_MAPPED_BYTES or alignment > 1 and address % alignment != offset % alignment:
                raise Pending('invalid load segment size or congruence')
            if permissions & 3 == 3 or not permissions & 4:
                raise Pending('load segment must be readable and cannot request write plus execute')
            if loads and address < loads[-1]['address']+loads[-1]['memory_bytes']:
                raise Pending('load segments overlap or are not ordered')
            mapped += memory
            if mapped > MAX_MAPPED_BYTES: raise Pending('total load segment memory exceeds its profile bound')
            loads.append({'address': address, 'file_offset': offset, 'file_bytes': size,
                          'memory_bytes': memory, 'flags': permissions, 'alignment': alignment})
        elif tag == PT_INTERP:
            if loads or interpreters or not 2 <= size <= 241:
                raise Pending('interpreter must occur once before load segments')
            data = raw[offset:offset+size]
            try: text = data[:-1].decode('ascii')
            except UnicodeError as error: raise Pending('invalid interpreter encoding') from error
            if data[-1:] != b'\\0' or b'\\0' in data[:-1]: raise Pending('interpreter must have one final NUL')
            interpreters.append(text)
        elif tag == PT_GNU_STACK:
            if stacks or permissions & 1: raise Pending('an explicit single nonexecutable stack declaration is required')
            stacks.append(permissions)
        elif tag == PT_DYNAMIC:
            dynamic += 1
        elif tag == 5:
            raise Pending('reserved PT_SHLIB segment is unsupported')
        segments.append(tag)
    if not loads or not any(row['flags'] & 1 and row['address'] <= entry < row['address']+row['file_bytes'] for row in loads):
        raise Pending('ELF entry must fall inside a file-backed executable load segment')
    if len(stacks) != 1 or interpreters != ([] if interpreter is None else [interpreter]):
        raise Pending('ELF stack/interpreter differs from the explicit Linux profile')
    if dynamic > 1 or interpreters and dynamic != 1:
        raise Pending('dynamic executable requires one dynamic segment')
    return {'format': 'ELF64-LSB', 'architecture': architecture, 'elf_type': kind,
            'entry_address': entry, 'interpreter': interpreter, 'program_headers': len(segments),
            'section_headers': shnum, 'declared_mapped_bytes': mapped,
            'nonexecutable_stack_declared': True, 'loads': loads}


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = RELEASE.prepare(deadline=end)
    except RELEASE.Pending as error: raise Pending('complete protected release preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > RELEASE.MAX_OUTPUT:
        raise Pending('unsupported complete release observation')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'applications'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or
            value['profile'] != 'four-app-complete-release-files-v1' or
            value['state'] != 'protected-preinstalled-release-source-only' or
            KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or raw != BASE.canonical(value)):
            raise Pending('release observation profile or context differs')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete release observation') from error
    BASE.fence(end)
    return raw, value


def entries(releases, settings, end):
    result = {}
    for app in RELEASE.APPLICATIONS:
        observed = releases['applications'][app]
        declared = releases['configuration']['value']['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            relative = declared['entry_points'][role]
            filename = Path(declared['directory'])/relative
            if observed['entry_points'][role] != str(filename): raise Pending('admitted release entry path differs')
            raw, source = BASE.read_protected(filename, declared['files'][relative]['bytes'], False, end)
            if BASE.canonical(source) != BASE.canonical(observed['files'][relative]):
                raise Pending('whole ELF entry differs from its complete protected release')
            result[app][role] = {'source': source, 'image': inspect(raw, settings['architecture'], settings['interpreter'])}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Linux image window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing Linux image namespace')
    settings = configuration(end)
    child_raw, releases = prerequisite(end, context)
    images = entries(releases, settings['value'], end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'configuration': settings, 'release_sha256': hashlib.sha256(child_raw).hexdigest(), 'applications': images})
    if len(raw) > MAX_OUTPUT: raise Pending('complete Linux entry report exceeds its output bound')
    if configuration(end) != settings: raise Pending('Linux image profile changed')
    after, observed = prerequisite(end, context)
    if after != child_raw or entries(observed, settings['value'], end) != images:
        raise Pending('complete releases or entry images changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('Linux image namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Linux image inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Linux image report output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/linux_images.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Read bounded ELF dynamic dependency declarations without invoking a loader.

This optional file profile rejects embedded RPATH/RUNPATH, audit/filter hooks
and declared text relocations. It does not resolve dependencies or verify the
remaining dynamic tags, relocations, symbols, loader environment or ABI.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_linux_linkage_images',
    Path(__file__).resolve().with_name('linux_images.py'))
IMAGE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(IMAGE)
BASE, KERNEL, Pending = IMAGE.BASE, IMAGE.KERNEL, IMAGE.Pending
PROFILE = 'four-app-elf-dynamic-dependency-files-v1'
STATE = 'protected-linux-linkage-declarations-source-only'
ATTEMPT_SECONDS, MAX_OUTPUT = 2 * IMAGE.ATTEMPT_SECONDS + 30, 262145
MAX_DYNAMIC, MAX_STRINGS, MAX_NEEDED = 4096, 1048576, 64
DYNAMIC = struct.Struct('<qQ')
# Standard RPATH, TEXTREL and RUNPATH; GNU audit/dependency-audit and
# auxiliary/filter objects can also introduce distinct loader behavior.
FORBIDDEN = {15, 22, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff}


def mapped(image, address, size):
    matches = []
    for row in image['loads']:
        offset = address-row['address']
        extent = min(row['file_bytes'], row['memory_bytes'])
        if 0 <= offset <= extent and size <= extent-offset:
            matches.append(row['file_offset']+offset)
    if len(matches) != 1:
        raise Pending('dynamic data must fit one unambiguous file-backed load range')
    return matches[0]


def library_name(strings, offset):
    if not 0 < offset < len(strings):
        raise Pending('dependency string offset is outside the declared table')
    end = strings.find(b'\\0', offset, min(len(strings), offset+256))
    if end == -1:
        raise Pending('dependency name lacks a bounded terminator')
    try:
        name = strings[offset:end].decode('ascii')
    except UnicodeError as error:
        raise Pending('dependency name is not ASCII') from error
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,254}', name) is None:
        raise Pending('dependency names must be nonempty basenames without paths or substitutions')
    return name


def inspect(raw, architecture, interpreter):
    image = IMAGE.inspect(raw, architecture, interpreter)
    header = IMAGE.ELF_HEADER.unpack_from(raw)
    dynamic = []
    for index in range(header[10]):
        row = IMAGE.PROGRAM_HEADER.unpack_from(raw, header[5]+index*header[9])
        if row[0] == IMAGE.PT_DYNAMIC:
            dynamic.append(row)
    if not dynamic:
        return {'dynamic_segment': False, 'needed': [], 'soname': None,
                'uninterpreted_tags': [], 'dependency_resolution_verified': False,
                'relocations_verified': False, 'loader_environment_verified': False}
    if len(dynamic) != 1:
        raise Pending('dynamic declarations require one segment')
    _, _, offset, address, _, size, memory, _ = dynamic[0]
    if (size == 0 or size % DYNAMIC.size or size > MAX_DYNAMIC*DYNAMIC.size or
        memory < size or mapped(image, address, size) != offset):
        raise Pending('dynamic table extent or file mapping differs')
    entries, terminated = [], False
    for position in range(offset, offset+size, DYNAMIC.size):
        tag, value = DYNAMIC.unpack_from(raw, position)
        if terminated:
            if tag != 0 or value != 0:
                raise Pending('dynamic padding after termination must be zero')
            continue
        if tag == 0:
            if value != 0: raise Pending('dynamic terminator must have zero value')
            terminated = True
        else:
            if not 0 < tag <= 0x7fffffff:
                raise Pending('unsupported dynamic tag range')
            if tag in FORBIDDEN or tag == 30 and value & 4:
                raise Pending('embedded loader path/hook or text-relocation declaration refused')
            entries.append((tag, value))
    if not terminated:
        raise Pending('dynamic table lacks its terminator')
    singleton = {}
    for tag in (5, 10, 14, 30):
        values = [value for kind, value in entries if kind == tag]
        if len(values) > 1:
            raise Pending('duplicate dynamic string/flag declaration')
        if values: singleton[tag] = values[0]
    if 5 not in singleton or 10 not in singleton or not 1 <= singleton[10] <= MAX_STRINGS:
        raise Pending('dynamic declarations require a bounded explicit string table')
    start = mapped(image, singleton[5], singleton[10]); stop = start+singleton[10]
    if start < offset+size and offset < stop:
        raise Pending('dynamic table and its strings overlap')
    strings = raw[start:stop]
    if strings[:1] != b'\\0' or strings[-1:] != b'\\0':
        raise Pending('dynamic string table requires leading and trailing NUL')
    offsets = [value for tag, value in entries if tag == 1]
    if len(offsets) > MAX_NEEDED:
        raise Pending('dependency names exceed their count bound')
    needed = [library_name(strings, value) for value in offsets]
    if len(set(needed)) != len(needed):
        raise Pending('dependency names are duplicate or exceed their count bound')
    soname = library_name(strings, singleton[14]) if 14 in singleton else None
    return {'dynamic_segment': True, 'dynamic_entries': len(entries),
            'string_table_bytes': len(strings), 'needed': needed, 'soname': soname,
            'uninterpreted_tags': sorted({tag for tag, _ in entries}-{1, 5, 10, 14}),
            'dependency_resolution_verified': False, 'relocations_verified': False,
            'loader_environment_verified': False}


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = IMAGE.prepare(deadline=end)
    except IMAGE.Pending as error: raise Pending('complete Linux image preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > IMAGE.MAX_OUTPUT:
        raise Pending('unsupported complete Linux image receipt')
    try:
        value = json.loads(raw, object_pairs_hook=KERNEL.unique_object)
        fields = {'schema', 'profile', 'state', 'namespace', 'configuration', 'release_sha256', 'applications'}
        KERNEL.known(value, fields, fields)
        if (type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != IMAGE.PROFILE or
            value['state'] != IMAGE.STATE or KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
            raw != BASE.canonical(value)):
            raise Pending('Linux image receipt profile/context/canonical bytes differ')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid complete Linux image receipt') from error
    BASE.fence(end)
    return raw, value


def observations(images, end):
    settings = images['configuration']['value']
    result = {}
    for app in IMAGE.RELEASE.APPLICATIONS:
        result[app] = {}
        for role in IMAGE.RELEASE.SERVICES:
            expected = images['applications'][app][role]['source']
            raw, source = BASE.read_protected(Path(expected['path']), IMAGE.RELEASE.MAX_FILE_BYTES, False, end)
            if BASE.canonical(source) != BASE.canonical(expected):
                raise Pending('Linux dependency entry differs from the complete image observation')
            BASE.fence(end)
            result[app][role] = {'source': source,
                'linkage': inspect(raw, settings['architecture'], settings['interpreter'])}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited Linux linkage window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing Linux linkage namespace')
    original, images = prerequisite(end, context)
    observed = observations(images, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'image_sha256': hashlib.sha256(original).hexdigest(), 'release_sha256': images['release_sha256'],
        'configuration': images['configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('Linux linkage report exceeds its output bound')
    after, final = prerequisite(end, context)
    if after != original or BASE.canonical(observations(final, end)) != BASE.canonical(observed):
        raise Pending('complete Linux image or linkage observations changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('Linux linkage namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('Linux linkage inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete Linux linkage output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/linux_linkage.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Check conventional framework-dependent .NET10 release metadata as files.

No dotnet, loader, package query, assembly or application is executed. Companion
names are this explicit profile's convention, not decoded apphost bindings.
\"\"\"
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_managed_image_profile',
    Path(__file__).resolve().with_name('linux_images.py'))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
RELEASE, BASE, KERNEL, Pending = IMAGE.RELEASE, IMAGE.BASE, IMAGE.KERNEL, IMAGE.Pending
MAX_JSON, MAX_OUTPUT, ATTEMPT_SECONDS = 1048576, 262145, 150
PROFILE = 'four-app-dotnet10-framework-metadata-v1'
STATE = 'protected-managed-runtime-metadata-source-only'
FRAMEWORKS = {'Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'}
BOOL_PROPERTIES = {'System.GC.Server', 'System.GC.Concurrent', 'System.Runtime.TieredCompilation',
    'System.Runtime.TieredPGO', 'System.Globalization.Invariant', 'System.Globalization.PredefinedCulturesOnly',
    'System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault', 'System.Diagnostics.Tracing.EventSource.IsSupported'}
FALSE_PROPERTIES = {'System.Reflection.Metadata.MetadataUpdater.IsSupported',
                    'System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization'}


def decoded(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON:
        raise Pending('managed metadata requires bounded immutable whole bytes')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite managed metadata')))
        stack = [(value, 0)]; nodes = 0
        while stack:
            item, depth = stack.pop(); nodes += 1
            if nodes > 65536 or depth > 24: raise Pending('managed metadata exceeds its structural bound')
            if type(item) is dict:
                for key, child in item.items():
                    if len(key) > 512 or any(ord(c) < 32 for c in key): raise Pending('invalid managed metadata key')
                    stack.append((child, depth+1))
            elif type(item) is list: stack.extend((child, depth+1) for child in item)
            elif type(item) is str:
                if len(item) > 8192 or any(ord(c) < 32 for c in item): raise Pending('invalid managed metadata string')
            elif type(item) is int:
                if not -(2**63) <= item < 2**63: raise Pending('managed metadata integer exceeds signed64')
            elif type(item) is float and not math.isfinite(item): raise Pending('nonfinite managed metadata')
        if type(value) is not dict: raise Pending('managed metadata requires a JSON object')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid strict managed metadata JSON') from error
    # SDK whitespace/order is retained verbatim in the protected source hash.
    return value


def runtime(value):
    KERNEL.known(value, {'runtimeOptions'}, {'runtimeOptions'})
    options = value['runtimeOptions']
    KERNEL.known(options, {'tfm', 'framework', 'frameworks', 'rollForward', 'applyPatches', 'configProperties'},
                         {'tfm', 'rollForward'})
    if (options['tfm'] != 'net10.0' or options['rollForward'] != 'LatestPatch' or
        'applyPatches' in options and options['applyPatches'] is not True):
        raise Pending('managed profile requires net10.0 with explicit LatestPatch and enabled patch selection')
    if ('framework' in options) == ('frameworks' in options):
        raise Pending('managed profile requires exactly one framework declaration form')
    rows = [options['framework']] if 'framework' in options else options['frameworks']
    if type(rows) is not list or not 1 <= len(rows) <= 2: raise Pending('unsupported framework count')
    result = {}
    for row in rows:
        KERNEL.known(row, {'name', 'version', 'rollForward', 'applyPatches'}, {'name', 'version'})
        name, version = row['name'], row['version']
        if (type(name) is not str or name not in FRAMEWORKS or name in result or type(version) is not str or
            re.fullmatch(r'10\\.0\\.(?:0|[1-9][0-9]{0,3})', version) is None or
            row.get('rollForward', 'LatestPatch') != 'LatestPatch' or
            'applyPatches' in row and row['applyPatches'] is not True):
            raise Pending('unsupported, repeated or conflicting managed framework reference')
        result[name] = version
    if 'Microsoft.NETCore.App' not in result: raise Pending('the core framework must be explicit')
    properties = options.get('configProperties', {})
    if type(properties) is not dict or set(properties)-BOOL_PROPERTIES-FALSE_PROPERTIES:
        raise Pending('unsupported runtime property; this profile has no probing/startup-hook overrides')
    for name, setting in properties.items():
        if type(setting) is not bool or name in FALSE_PROPERTIES and setting:
            raise Pending('runtime property has an unsupported value')
    return {'tfm': 'net10.0', 'roll_forward': 'LatestPatch', 'frameworks': result, 'properties': properties}


def dependencies(value, architecture):
    if type(architecture) is not str or architecture not in ('x86_64', 'aarch64'):
        raise Pending('dependency metadata requires an explicit supported architecture')
    KERNEL.known(value, {'runtimeTarget', 'compilationOptions', 'targets', 'libraries'},
                         {'runtimeTarget', 'targets', 'libraries'})
    target = value['runtimeTarget']
    KERNEL.known(target, {'name', 'signature'}, {'name'})
    rid = {'x86_64': 'linux-x64', 'aarch64': 'linux-arm64'}[architecture]
    portable = '.NETCoreApp,Version=v10.0'
    name = target['name']
    if type(name) is not str or name not in (portable, portable+'/'+rid):
        raise Pending('dependency target differs from net10.0 and the explicit Linux architecture')
    if 'signature' in target and type(target['signature']) is not str: raise Pending('invalid dependency signature spelling')
    targets, libraries = value['targets'], value['libraries']
    if (type(targets) is not dict or not 1 <= len(targets) <= 2 or name not in targets or
        set(targets)-{portable, portable+'/'+rid} or type(libraries) is not dict or not 1 <= len(libraries) <= 4096):
        raise Pending('unsupported bounded dependency target/library tables')
    for group in targets.values():
        if type(group) is not dict or not 1 <= len(group) <= 4096 or set(group)-set(libraries):
            raise Pending('dependency target entries require corresponding library records')
        if any(type(row) is not dict for row in group.values()): raise Pending('dependency target entries must be objects')
    if any(type(row) is not dict for row in libraries.values()): raise Pending('dependency library records must be objects')
    if 'compilationOptions' in value and type(value['compilationOptions']) is not dict:
        raise Pending('dependency compilation metadata must be an object')
    return {'runtime_target': name, 'libraries': len(libraries), 'selected_target_libraries': len(targets[name])}


def metadata(releases, architecture, end):
    result = {}
    for app in RELEASE.APPLICATIONS:
        declared = releases['configuration']['value']['applications'][app]
        observed = releases['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            entry = declared['entry_points'][role]
            if entry+'.runtimeconfig.dev.json' in declared['files']:
                raise Pending('development probing metadata is outside this runtime profile')
            sources, parsed = {}, {}
            for label, suffix in (('assembly', '.dll'), ('runtime', '.runtimeconfig.json'), ('dependencies', '.deps.json')):
                name = entry+suffix
                if (name not in declared['files'] or declared['files'][name]['mode'] != '0644' or
                    declared['files'][name]['bytes'] == 0):
                    raise Pending('managed entry requires explicit nonempty 0644 assembly/runtime/dependency companions')
                source = observed['files'][name]
                sources[label] = source
                if label == 'assembly': continue  # Whole release preparation already reads these opaque bytes.
                raw, actual = BASE.read_protected(Path(declared['directory'])/name, MAX_JSON, False, end)
                if BASE.canonical(actual) != BASE.canonical(source): raise Pending('managed metadata differs from the protected release')
                value = decoded(raw)
                parsed[label] = runtime(value) if label == 'runtime' else dependencies(value, architecture)
                BASE.fence(end)
            result[app][role] = {'sources': sources, **parsed}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited managed metadata window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if context == 0: raise Pending('missing managed metadata namespace')
    settings = IMAGE.configuration(end)
    child_raw, releases = IMAGE.prerequisite(end, context)
    values = metadata(releases, settings['value']['architecture'], end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'image_configuration': settings, 'release_sha256': hashlib.sha256(child_raw).hexdigest(), 'applications': values})
    if len(raw) > MAX_OUTPUT: raise Pending('managed metadata report exceeds its output bound')
    if IMAGE.configuration(end) != settings: raise Pending('explicit target architecture changed')
    after, observed = IMAGE.prerequisite(end, context)
    if after != child_raw or metadata(observed, settings['value']['architecture'], end) != values:
        raise Pending('complete releases or managed metadata changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('managed metadata namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('managed metadata inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete managed metadata output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/managed_runtime.py || return 1
    printf '%s' "\"\"\"Bounded PE/CLI entry structure; never load, verify IL, or authenticate code.

The selected profile is optimized ECMA metadata in an IL-only, framework-
dependent executable assembly. ReadyToRun, mixed/native entry points, deltas,
portable PDB metadata and uncommon table extensions are outside this profile.
\"\"\"
import hashlib
import struct

MAX_BYTES = 64 * 1024 * 1024
MAX_METADATA = 16 * 1024 * 1024
MAX_ROWS = 1048576
MAX_CODE = 1048576


class Pending(ValueError):
    pass


def span(start, size, limit):
    if start < 0 or size < 0 or start > limit or size > limit-start:
        raise Pending('PE/CLI range exceeds its containing bytes')
    return start+size


def number(raw, start, size):
    span(start, size, len(raw))
    return int.from_bytes(raw[start:start+size], 'little')


def unpack(raw, start, pattern):
    span(start, struct.calcsize('<'+pattern), len(raw))
    return struct.unpack_from('<'+pattern, raw, start)


def disjoint(ranges):
    last = 0
    for start, end in sorted(ranges):
        if start < last: raise Pending('overlapping PE/CLI ranges')
        last = end


def heap_string(heap, index):
    if not 0 < index < len(heap): raise Pending('missing managed metadata string')
    end = heap.find(b'\\0', index, min(len(heap), index+513))
    if end == -1: raise Pending('unbounded managed metadata string')
    try: value = heap[index:end].decode('utf-8')
    except UnicodeError as error: raise Pending('invalid managed metadata UTF-8') from error
    if not value or any(ord(c) < 32 for c in value): raise Pending('invalid managed metadata name')
    return value


def heap_blob(heap, index):
    if not 0 < index < len(heap): raise Pending('missing managed signature blob')
    lead = heap[index]
    if lead < 0x80:
        size, width = lead, 1
    elif lead < 0xc0:
        span(index, 2, len(heap)); size, width = ((lead & 0x3f) << 8) | heap[index+1], 2
        if size < 0x80: raise Pending('nonminimal managed blob length')
    elif lead < 0xe0:
        span(index, 4, len(heap)); size, width = int.from_bytes(heap[index:index+4], 'big') & 0x1fffffff, 4
        if size < 0x4000: raise Pending('nonminimal managed blob length')
    else: raise Pending('invalid managed blob length')
    if not 1 <= size <= 4096: raise Pending('managed entry signature exceeds its bound')
    end = span(index+width, size, len(heap))
    return heap[index+width:end]


def tables(raw, heaps, token):
    reserved, major, minor, flags, one, present, sorted_mask = unpack(raw, 0, 'IBBBBQQ')
    excluded = (3, 5, 7, 19, 22, 30, 31, 33, 34, 36, 37)
    if (reserved != 0 or (major, minor, one) != (2, 0, 1) or flags & ~7 or
        present >> 45 or sorted_mask >> 45 or any(present & (1 << n) for n in excluded)):
        raise Pending('unsupported optimized managed table profile')
    rows, position = [0]*45, 24
    for table in range(45):
        if present & (1 << table):
            rows[table] = number(raw, position, 4); position += 4
            if not 1 <= rows[table] <= MAX_ROWS: raise Pending('unsupported managed table row count')
    if sum(rows) > MAX_ROWS or rows[0] != 1 or rows[32] != 1 or not rows[2] or not rows[6]:
        raise Pending('managed entry requires bounded module/type/method/assembly tables')
    widths = [4 if flags & (1 << bit) else 2 for bit in range(3)]
    strings, guids, blobs = widths
    for heap, width in zip(('#Strings', '#GUID', '#Blob'), widths):
        if width == 2 and len(heaps[heap]) > 65535: raise Pending('managed heap exceeds its index width')
    def index(table): return 2 if rows[table] < 65536 else 4
    def coded(bits, *targets): return 2 if max(rows[n] for n in targets) < (1 << (16-bits)) else 4
    type_ref = coded(2, 2, 1, 27); method_ref = coded(1, 6, 10)
    implementation = coded(2, 38, 35, 39)
    sizes = {
        0: 2+strings+3*guids, 1: coded(2, 0, 26, 35, 1)+2*strings,
        2: 4+2*strings+type_ref+index(4)+index(6), 4: 2+strings+blobs,
        6: 8+strings+blobs+index(8), 8: 4+strings, 9: index(2)+type_ref,
        10: coded(3, 2, 1, 26, 6, 27)+strings+blobs, 11: 2+coded(2, 4, 8, 23)+blobs,
        12: coded(5, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)+coded(3, 6, 10)+blobs,
        13: coded(1, 4, 8)+blobs, 14: 2+coded(2, 2, 6, 32)+blobs,
        15: 6+index(2), 16: 4+index(4), 17: blobs, 18: index(2)+index(20),
        20: 2+strings+type_ref, 21: index(2)+index(23), 23: 2+strings+blobs,
        24: 2+index(6)+coded(1, 20, 23), 25: index(2)+2*method_ref,
        26: strings, 27: blobs, 28: 2+coded(1, 4, 6)+strings+index(26),
        29: 4+index(4), 32: 16+blobs+2*strings, 35: 12+2*blobs+2*strings,
        38: 4+strings+blobs, 39: 8+2*strings+implementation,
        40: 8+strings+implementation, 41: 2*index(2),
        42: 4+coded(1, 2, 6)+strings, 43: method_ref+blobs, 44: index(42)+type_ref,
    }
    offsets = {}
    for table, count in enumerate(rows):
        if count:
            offsets[table] = position
            position = span(position, sizes[table]*count, len(raw))
    if len(raw)-position > 4 or any(raw[position:]): raise Pending('unexpected managed table suffix')
    if token >> 24 != 6 or not 1 <= (token & 0xffffff) <= rows[6]:
        raise Pending('managed entry must reference an existing MethodDef row')
    module = offsets[0]
    heap_string(heaps['#Strings'], number(raw, module+2, strings))
    mvid = number(raw, module+2+strings, guids)
    if not 1 <= mvid <= len(heaps['#GUID'])//16: raise Pending('missing managed module MVID')
    assembly = offsets[32]
    assembly_name = heap_string(heaps['#Strings'], number(raw, assembly+16+blobs, strings))
    method = offsets[6]+((token & 0xffffff)-1)*sizes[6]
    rva, implementation_flags, attributes = unpack(raw, method, 'IHH')
    if not attributes & 0x10 or attributes & (0x400 | 0x2000) or implementation_flags & ~0x3e8:
        raise Pending('managed entry must be a static managed IL method')
    method_name = heap_string(heaps['#Strings'], number(raw, method+8, strings))
    signature = heap_blob(heaps['#Blob'], number(raw, method+8+strings, blobs))
    if signature not in (b'\\0\\0\\x01', b'\\0\\0\\x08', b'\\0\\0\\x09',
                         b'\\0\\x01\\x01\\x1d\\x0e', b'\\0\\x01\\x08\\x1d\\x0e', b'\\0\\x01\\x09\\x1d\\x0e'):
        raise Pending('unsupported plain managed entry signature')
    parameter = number(raw, method+8+strings+blobs, index(8))
    if not 1 <= parameter <= rows[8]+1: raise Pending('managed entry parameter-list index is out of range')
    return {'rows': {str(n): count for n, count in enumerate(rows) if count},
            'entry_token': token, 'entry_rva': rva, 'entry_name': method_name,
            'assembly_name': assembly_name, 'signature_hex': signature.hex()}


def metadata(raw, token):
    signature, major, minor, reserved, size = unpack(raw, 0, 'IHHII')
    if signature != 0x424a5342 or (major, minor, reserved) != (1, 1, 0) or not 4 <= size <= 256 or size % 4:
        raise Pending('unsupported CLI metadata root')
    position = span(16, size, len(raw)); version = raw[16:position]
    if version.rstrip(b'\\0') != b'v4.0.30319' or version[-1] != 0:
        raise Pending('unsupported managed metadata version')
    flags, count = unpack(raw, position, 'HH'); position += 4
    if flags or not 4 <= count <= 5: raise Pending('unsupported managed stream inventory')
    streams = {}
    for _ in range(count):
        offset, size = unpack(raw, position, 'II'); position += 8
        end = raw.find(b'\\0', position, min(len(raw), position+32))
        if end == -1: raise Pending('unterminated managed stream name')
        try: name = raw[position:end].decode('ascii')
        except UnicodeError as error: raise Pending('invalid managed stream name') from error
        aligned = (end+4) & ~3
        span(end, aligned-end, len(raw))
        if any(raw[end:aligned]) or name not in ('#~', '#Strings', '#GUID', '#Blob', '#US') or name in streams or offset % 4:
            raise Pending('ambiguous or unsupported managed stream')
        streams[name] = offset, span(offset, size, len(raw)); position = aligned
    if not {'#~', '#Strings', '#GUID', '#Blob'} <= streams.keys(): raise Pending('missing managed metadata streams')
    ranges = [(0, position), *streams.values()]; disjoint(ranges)
    heaps = {name: raw[start:end] for name, (start, end) in streams.items()}
    for name in ('#Strings', '#Blob', '#US'):
        if name in heaps and (not heaps[name] or heaps[name][0] != 0): raise Pending('managed heap lacks its reserved zero')
    if not heaps['#GUID'] or len(heaps['#GUID']) % 16: raise Pending('invalid managed GUID heap extent')
    result = tables(heaps['#~'], heaps, token)
    return result | {'streams': {name: {'offset': start, 'bytes': end-start} for name, (start, end) in streams.items()},
                     'metadata_sha256': hashlib.sha256(raw).hexdigest()}


def inspect(raw, architecture):
    if type(raw) is not bytes or not 512 <= len(raw) <= MAX_BYTES or architecture not in ('x86_64', 'aarch64'):
        raise Pending('unsupported managed image bytes or architecture')
    if raw[:2] != b'MZ': raise Pending('missing managed PE DOS signature')
    pe = number(raw, 60, 4)
    if pe < 64 or pe % 4 or raw[pe:pe+4] != b'PE\\0\\0': raise Pending('missing managed PE signature')
    machine, count, _, symbol_pointer, symbols, optional_size, characteristics = unpack(raw, pe+4, 'HHIIIHH')
    if not 1 <= count <= 16 or symbol_pointer or symbols or not characteristics & 2:
        raise Pending('unsupported managed COFF image inventory')
    optional = pe+24; magic = number(raw, optional, 2)
    if (machine, magic, optional_size) not in ((0x14c, 0x10b, 224),
        (0x8664 if architecture == 'x86_64' else 0xaa64, 0x20b, 240)):
        raise Pending('managed PE machine/header differs from the explicit target')
    table = span(optional, optional_size, len(raw)); span(table, 40*count, len(raw))
    section_alignment, file_alignment = unpack(raw, optional+32, 'II')
    image_size, headers = unpack(raw, optional+56, 'II')
    if (not 512 <= file_alignment <= 65536 or file_alignment & (file_alignment-1) or
        not file_alignment <= section_alignment <= 65536 or section_alignment & (section_alignment-1) or
        not 0 < image_size <= (1 << 30) or image_size % section_alignment or
        headers < table+40*count or headers > len(raw) or headers % file_alignment):
        raise Pending('unsupported managed PE alignment or image extent')
    sections, file_ranges, virtual_ranges = [], [(0, headers)], []
    for index in range(count):
        offset = table+40*index
        virtual_size, rva, size, pointer = unpack(raw, offset+8, 'IIII')
        flags = number(raw, offset+36, 4)
        extent = max(size, virtual_size)
        if (not virtual_size or rva < headers or rva % section_alignment or
            rva+extent > image_size or size % file_alignment or
            size and (pointer < headers or pointer % file_alignment) or
            not size and pointer or flags & 0x80000000 and flags & 0x20000000):
            raise Pending('unsupported managed PE section range or permissions')
        if size: file_ranges.append((pointer, span(pointer, size, len(raw))))
        virtual_ranges.append((rva, rva+extent)); sections.append((rva, min(size, virtual_size), pointer))
    disjoint(file_ranges); disjoint(virtual_ranges)
    def mapped(rva, size):
        if not rva or not size: raise Pending('missing managed mapped range')
        matches = [pointer+rva-start for start, extent, pointer in sections if start <= rva and rva+size <= start+extent]
        if len(matches) != 1: raise Pending('managed RVA does not map to one whole file-backed section')
        return matches[0]
    directory = optional+(96 if magic == 0x10b else 112)
    if number(raw, directory-4, 4) != 16: raise Pending('unsupported managed PE directory inventory')
    cli_rva, cli_size = unpack(raw, directory+14*8, 'II')
    if cli_size != 72: raise Pending('unsupported CLI header size')
    cli = mapped(cli_rva, cli_size)
    size, major, minor, metadata_rva, metadata_size, flags, token = unpack(raw, cli, 'IHHIIII')
    if size != 72 or (major, minor) != (2, 5) or not flags & 1 or flags & ~0x10009:
        raise Pending('managed profile requires an IL-only executable CLI header')
    for index in range(6):
        rva, size = unpack(raw, cli+24+index*8, 'II')
        if bool(rva) != bool(size) or index >= 2 and (rva or size):
            raise Pending('native/mixed/ReadyToRun CLI directories are outside this profile')
        if rva: mapped(rva, size)
        if index == 1 and flags & 8 and not size: raise Pending('reported strong name has no signature range')
    if not 1 <= metadata_size <= MAX_METADATA: raise Pending('managed metadata exceeds its bounded capacity')
    start = mapped(metadata_rva, metadata_size)
    disjoint(((cli, cli+72), (start, start+metadata_size)))
    result = metadata(raw[start:start+metadata_size], token)
    body = mapped(result['entry_rva'], 1); first = raw[body]
    if first & 3 == 2:
        header, code_size, extra = 1, first >> 2, False
    elif first & 3 == 3:
        header_flags, _, code_size, locals_token = unpack(raw, body, 'HHII')
        header = (header_flags >> 12)*4; extra = bool(header_flags & 8)
        if body % 4 or header != 12 or header_flags & 0xfff & ~0x1b or locals_token and (
            locals_token >> 24 != 17 or not 1 <= (locals_token & 0xffffff) <= result['rows'].get('17', 0)):
            raise Pending('unsupported fat managed entry body header')
    else: raise Pending('missing managed entry IL body header')
    if not 1 <= code_size <= MAX_CODE: raise Pending('managed entry code extent exceeds its bound')
    mapped(result['entry_rva'], header+code_size)
    disjoint(((body, body+header+code_size), (cli, cli+72), (start, start+metadata_size)))
    return {'machine': machine, 'pe_magic': magic, 'sections': count, 'cli_flags': flags,
            'metadata': result, 'entry_code_bytes': code_size,
            'entry_extra_sections_unverified': extra, 'il_validated': False,
            'native_compatibility_validated': False, 'publisher_authenticated': False}
" > "$S4B_STAGE/"lib/applications/cli_image.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Observe protected PE/CLI entry structure alongside complete .NET metadata.

No CLR, apphost, assembly, native parser or application is executed. This is a
selected structural profile, not IL verification, dependency resolution,
publisher authentication, native compatibility or readiness.
\"\"\"
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().with_name(leaf))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


RUNTIME = module('debian13s4_managed_images_runtime', 'managed_runtime.py')
CLI = module('debian13s4_managed_images_cli', 'cli_image.py')
BASE, KERNEL, Pending = RUNTIME.BASE, RUNTIME.KERNEL, RUNTIME.Pending
PROFILE = 'four-app-pe-cli-entry-structure-v1'
STATE = 'protected-managed-entry-structure-source-only'
ATTEMPT_SECONDS, MAX_OUTPUT = 350, 262145


def prerequisite(end, context):
    BASE.fence(end)
    try: raw = RUNTIME.prepare(deadline=end)
    except RUNTIME.Pending as error: raise Pending('managed runtime preparation refused') from error
    if type(raw) is not bytes or not raw or len(raw) > RUNTIME.MAX_OUTPUT:
        raise Pending('unsupported complete managed runtime receipt')
    value = RUNTIME.decoded(raw)
    fields = {'schema', 'profile', 'state', 'namespace', 'image_configuration', 'release_sha256', 'applications'}
    KERNEL.known(value, fields, fields)
    if (type(value['schema']) is not int or value['schema'] != 1 or value['profile'] != RUNTIME.PROFILE or
        value['state'] != RUNTIME.STATE or KERNEL.uint(value['namespace'], 0xffffffffffffffff) != context or
        raw != BASE.canonical(value)):
        raise Pending('managed runtime receipt profile/context/canonical bytes differ')
    BASE.fence(end)
    return raw, value


def images(runtime, end):
    architecture = runtime['image_configuration']['value']['architecture']
    result = {}
    KERNEL.known(runtime['applications'], set(RUNTIME.RELEASE.APPLICATIONS), set(RUNTIME.RELEASE.APPLICATIONS))
    for app in RUNTIME.RELEASE.APPLICATIONS:
        roles = runtime['applications'][app]
        KERNEL.known(roles, set(RUNTIME.RELEASE.SERVICES), set(RUNTIME.RELEASE.SERVICES))
        result[app] = {}
        for role in RUNTIME.RELEASE.SERVICES:
            expected = roles[role]['sources']['assembly']
            raw, source = BASE.read_protected(Path(expected['path']), CLI.MAX_BYTES, False, end)
            if BASE.canonical(source) != BASE.canonical(expected):
                raise Pending('managed entry bytes differ from the complete release observation')
            BASE.fence(end)
            try: image = CLI.inspect(raw, architecture)
            except CLI.Pending as error: raise Pending('managed entry structure refused: '+app+' '+role) from error
            BASE.fence(end)
            result[app][role] = {'source': source, 'structure': image}
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited managed entry window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing managed entry namespace')
    original, runtime = prerequisite(end, context)
    observed = images(runtime, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'runtime_sha256': hashlib.sha256(original).hexdigest(), 'release_sha256': runtime['release_sha256'],
        'image_configuration': runtime['image_configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('managed entry report exceeds its output bound')
    after, value = prerequisite(end, context)
    if after != original or BASE.canonical(images(value, end)) != BASE.canonical(observed):
        raise Pending('complete managed runtime or entry observations changed')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context:
        raise Pending('managed entry namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('managed entry inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete managed entry output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/managed_images.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Bind already-selected .NET dependency assets to protected release files.

This is a closed app-directory file profile, not host probing, RID fallback,
framework resolution, native dependency resolution, signature or ABI validation.
No CLR, package, application, socket or process entry occurs here.
\"\"\"
import base64
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_managed_assets_runtime',
    Path(__file__).resolve().with_name('managed_runtime.py'))
RUNTIME = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(RUNTIME)
RELEASE, BASE, KERNEL, Pending = RUNTIME.RELEASE, RUNTIME.BASE, RUNTIME.KERNEL, RUNTIME.Pending
PROFILE = 'four-app-selected-dependency-file-correspondence-v1'
STATE = 'protected-managed-dependency-files-source-only'
ATTEMPT_SECONDS = 2 * (RUNTIME.ATTEMPT_SECONDS + RELEASE.ATTEMPT_SECONDS) + 10
MAX_OUTPUT, MAX_ASSETS = 1048577, 256


def library_name(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) is None:
        raise Pending('unsupported dependency library name')
    return value


def version(value):
    if type(value) is not str or re.fullmatch(r'[0-9][A-Za-z0-9_.+-]{0,95}', value) is None:
        raise Pending('dependency requires an explicit bounded version')
    return value


def library(value):
    if type(value) is not str or value.count('/') != 1:
        raise Pending('dependency library key requires name/version')
    name, release = value.split('/')
    return library_name(name), version(release)


def library_record(value):
    KERNEL.known(value, {'type', 'serviceable', 'sha512', 'path', 'hashPath'}, {'type', 'serviceable', 'sha512'})
    if value['type'] not in ('project', 'package', 'reference') or type(value['serviceable']) is not bool:
        raise Pending('unsupported selected dependency library record')
    digest = value['sha512']
    if type(digest) is not str or len(digest) > 88: raise Pending('unsupported dependency hash declaration')
    if digest:
        try: data = base64.b64decode(digest, validate=True)
        except ValueError as error: raise Pending('invalid dependency hash declaration') from error
        if len(data) != 64 or base64.b64encode(data).decode('ascii') != digest:
            raise Pending('dependency hash declaration is not canonical SHA512-sized data')
    for name in ('path', 'hashPath'):
        if name in value: RELEASE.relative(value[name])


def asset_path(kind, name, value):
    RELEASE.relative(name)
    fields = {'assemblyVersion', 'fileVersion'} | ({'locale'} if kind == 'resources' else set())
    KERNEL.known(value, fields, {'locale'} if kind == 'resources' else set())
    for key in ('assemblyVersion', 'fileVersion'):
        if key in value:
            text = value[key]
            if (type(text) is not str or re.fullmatch(r'[0-9]{1,5}(?:\\.[0-9]{1,5}){1,3}', text) is None or
                any(int(part) > 65535 for part in text.split('.'))):
                raise Pending('unsupported reported dependency asset version')
    pieces = name.split('/')
    if pieces[-1] == '_._': raise Pending('dependency placeholders are outside the selected file profile')
    if kind == 'resources':
        locale = value['locale']
        if (type(locale) is not str or re.fullmatch(r'[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,4}', locale) is None or
            len(pieces) < 2 or pieces[-2] != locale):
            raise Pending('resource path and explicit locale differ')
        return locale+'/'+pieces[-1]
    return pieces[-1]


def bind(value, architecture, entry, declared, observed):
    \"\"\"Correspondence within the owned whole release; no external probing.\"\"\"
    summary = RUNTIME.dependencies(value, architecture)
    target = summary['runtime_target']
    if set(value['targets']) != {target} or set(value['targets'][target]) != set(value['libraries']):
        raise Pending('dependency file requires one complete already-selected target')
    RELEASE.relative(entry)
    parent = Path(entry).parent
    assets, destinations, entry_count = [], set(), 0
    group = value['targets'][target]
    for key, row in sorted(group.items()):
        library(key); library_record(value['libraries'][key])
        KERNEL.known(row, {'dependencies', 'runtime', 'native', 'resources'}, set())
        dependencies = row.get('dependencies', {})
        if type(dependencies) is not dict or len(dependencies) > 4096:
            raise Pending('unsupported selected dependency references')
        for name, release in dependencies.items():
            reference = library_name(name)+'/'+version(release)
            if reference not in group: raise Pending('dependency reference is absent from the selected library table')
        for kind in ('runtime', 'native', 'resources'):
            table = row.get(kind, {})
            if type(table) is not dict or len(table) > MAX_ASSETS:
                raise Pending('dependency asset inventory exceeds its bound')
            for name, facts in sorted(table.items()):
                relative = str(parent/asset_path(kind, name, facts))
                RELEASE.relative(relative)
                if relative in destinations: raise Pending('dependency assets collide at one published file')
                destinations.add(relative)
                if relative not in declared['files'] or relative not in observed['files']:
                    raise Pending('selected dependency asset is absent from the whole release: '+relative)
                item, source = declared['files'][relative], observed['files'][relative]
                if (item['bytes'] == 0 or item['mode'] not in (('0644', '0755') if kind == 'native' else ('0644',)) or
                    source['sha256'] != item['sha256'] or source['identity'][5] != item['bytes'] or
                    source['path'] != str(Path(declared['directory'])/relative)):
                    raise Pending('dependency asset differs from its nonempty protected file declaration')
                assets.append({'library': key, 'kind': kind, 'declared_path': name,
                               'release_path': relative, 'source': source})
                if kind == 'runtime' and relative == entry+'.dll': entry_count += 1
                if len(assets) > MAX_ASSETS: raise Pending('selected dependency assets exceed their combined bound')
    if entry_count != 1:
        raise Pending('dependency target must include the declared entry assembly exactly once')
    return {'runtime_target': target, 'libraries': len(group), 'assets': assets,
            'framework_resolution_verified': False, 'loader_resolution_verified': False,
            'package_hashes_verified': False}


def prerequisites(end, context):
    BASE.fence(end)
    try: runtime_raw = RUNTIME.prepare(deadline=end)
    except RUNTIME.Pending as error: raise Pending('complete managed runtime preparation refused') from error
    if type(runtime_raw) is not bytes or not runtime_raw or len(runtime_raw) > RUNTIME.MAX_OUTPUT:
        raise Pending('unsupported managed runtime receipt')
    runtime = RUNTIME.decoded(runtime_raw)
    fields = {'schema', 'profile', 'state', 'namespace', 'image_configuration', 'release_sha256', 'applications'}
    KERNEL.known(runtime, fields, fields)
    if (type(runtime['schema']) is not int or runtime['schema'] != 1 or runtime['profile'] != RUNTIME.PROFILE or
        runtime['state'] != RUNTIME.STATE or KERNEL.uint(runtime['namespace'], 0xffffffffffffffff) != context or
        runtime_raw != BASE.canonical(runtime)):
        raise Pending('managed runtime profile, context or canonical receipt differs')
    release_raw, release = RUNTIME.IMAGE.prerequisite(end, context)
    if hashlib.sha256(release_raw).hexdigest() != runtime['release_sha256']:
        raise Pending('managed runtime and whole release observations differ')
    BASE.fence(end)
    return runtime_raw, runtime, release_raw, release


def observations(runtime, release, end):
    result = {}
    architecture = runtime['image_configuration']['value']['architecture']
    for app in RELEASE.APPLICATIONS:
        declared, observed = release['configuration']['value']['applications'][app], release['applications'][app]
        result[app] = {}
        for role in RELEASE.SERVICES:
            entry = declared['entry_points'][role]; expected = runtime['applications'][app][role]['sources']['dependencies']
            raw, source = BASE.read_protected(Path(declared['directory'])/(entry+'.deps.json'), RUNTIME.MAX_JSON, False, end)
            if BASE.canonical(source) != BASE.canonical(expected): raise Pending('selected dependency file observation changed')
            BASE.fence(end)
            value = bind(RUNTIME.decoded(raw), architecture, entry, declared, observed)
            result[app][role] = {'dependencies': source, **value}
            BASE.fence(end)
    return result


def prepare(deadline=None):
    end = KERNEL.now()+ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline): raise Pending('invalid inherited dependency file window')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff)
    if not context: raise Pending('missing dependency file namespace')
    runtime_raw, runtime, release_raw, release = prerequisites(end, context)
    observed = observations(runtime, release, end)
    raw = BASE.canonical({'schema': 1, 'profile': PROFILE, 'state': STATE, 'namespace': context,
        'runtime_sha256': hashlib.sha256(runtime_raw).hexdigest(), 'release_sha256': hashlib.sha256(release_raw).hexdigest(),
        'image_configuration': runtime['image_configuration'], 'applications': observed})
    if len(raw) > MAX_OUTPUT: raise Pending('dependency file report exceeds its bound')
    final_runtime_raw, final_runtime, final_release_raw, final_release = prerequisites(end, context)
    if (final_runtime_raw != runtime_raw or final_release_raw != release_raw or
        BASE.canonical(observations(final_runtime, final_release, end)) != BASE.canonical(observed)):
        raise Pending('managed runtime, release or dependency observations changed after encoding')
    if KERNEL.uint(KERNEL.namespace(), 0xffffffffffffffff) != context: raise Pending('dependency file namespace changed')
    BASE.fence(end)
    return raw


def main():
    try:
        if len(sys.argv) != 1: raise Pending('dependency file inspection accepts no overrides')
        raw = prepare(); count = sys.stdout.buffer.write(raw)
        if type(count) is not int or count != len(raw): raise Pending('incomplete dependency file output')
        sys.stdout.buffer.flush()
        return 0
    except (Pending, OSError, ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/applications/managed_assets.py || return 1
    printf '%s' "#!/usr/bin/python3
\"\"\"Prepare PARTIAL preprovisioned mk8.dns replica service intentions only.

No binaries, accounts, snapshots, directories, units or network are installed,
published, started or queried. Binary paths and zone IDs are explicit caller
intentions, not checked releases or usable signed catalogs. The existing
application must have provisioned active signed snapshots; this profile has
no controller, publication, TSIG, transfer, signing or renewal authority.
\"\"\"

import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

SPEC = importlib.util.spec_from_file_location('debian13s4_dns_inputs',
    Path(__file__).resolve().parents[1] / 'PostgreSQL/prepare.py')
if not Path(SPEC.origin).is_file():
    SPEC = importlib.util.spec_from_file_location('debian13s4_dns_inputs',
        Path(__file__).resolve().parents[1] / 'postgresql/prepare.py')
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
KERNEL = BASE.KERNEL
Pending = BASE.Pending
INPUT = Path('/etc/debian13s4/dns.json')
PASSWD = Path('/etc/passwd')
GROUP = Path('/etc/group')
MAX_INPUT = 8192
MAX_INVENTORY = 262144
MAX_OUTPUT = 65537
ATTEMPT_SECONDS = 10
SOCKET = '/run/debian13s4-dns/query.sock'
STATE = '/var/lib/debian13s4-dns'
APP_UNIT = 'debian13s4-dns-application.service'
# Product CLI fields and supported capacity bounds, not deployment defaults.
BUDGETS = {'udp-response-rate': (1, 1000000), 'udp-response-burst': (1, 1000000),
    'udp-byte-rate': (1, 1000000000), 'udp-byte-burst': (512, 1000000000),
    'udp-global-response-rate': (1, 1000000), 'udp-global-response-burst': (1, 1000000),
    'udp-global-byte-rate': (1, 1000000000), 'udp-global-byte-burst': (512, 1000000000),
    'udp-prefix-limit': (1, 65536)}
NAME = re.compile(r'[a-z][a-z0-9_]{0,30}\\Z')


def name(value):
    if type(value) is not str or NAME.fullmatch(value) is None or value == 'root':
        raise Pending('unsupported explicit DNS service identity')
    return value


def binary_path(value):
    if (type(value) is not str or not 6 <= len(value) <= 240 or
        re.fullmatch(r'/opt/[A-Za-z0-9_./-]+', value) is None or
        any(part in ('', '.', '..') for part in value.split('/')[1:]) or
        os.path.normpath(value) != value):
        raise Pending('unsupported explicit DNS binary path')
    return value


def address(value):
    if type(value) is not str or '%' in value:
        raise Pending('DNS bind address requires a literal without a scope alias')
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise Pending('invalid DNS bind address') from error
    if (str(parsed) != value or parsed.is_unspecified or parsed.is_multicast or
        parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or
        parsed.version == 4 and int(parsed) < 0x01000000 or
        parsed.version == 6 and (parsed.ipv4_mapped is not None or parsed.is_site_local)):
        raise Pending('unsupported explicit unicast DNS bind address')
    return parsed.version


def checked(value):
    fields = {'schema', 'application_user', 'gateway_user', 'ipc_group',
        'application_binary', 'gateway_binary', 'node', 'zones', 'listeners', 'budgets'}
    KERNEL.known(value, fields, fields)
    if type(value['schema']) is not int or value['schema'] != 1:
        raise Pending('unsupported DNS intention schema')
    identities = [name(value[k]) for k in ('application_user', 'gateway_user', 'ipc_group')]
    if len(set(identities)) != 3:
        raise Pending('DNS service accounts and IPC group must be distinct')
    binaries = [binary_path(value[k]) for k in ('application_binary', 'gateway_binary')]
    if binaries[0] == binaries[1]:
        raise Pending('DNS application and gateway binaries must be distinct')
    if (type(value['node']) is not str or
        re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value['node']) is None):
        raise Pending('unsupported explicit DNS node')
    zones = value['zones']
    if (type(zones) is not list or not 1 <= len(zones) <= 64 or
        any(type(z) is not str or re.fullmatch(r'[0-9a-f]{32}', z) is None or
            z == '0'*32 for z in zones) or len(set(zones)) != len(zones)):
        raise Pending('DNS requires distinct nonempty canonical zone IDs')
    listeners = value['listeners']
    if type(listeners) is not list or not 1 <= len(listeners) <= 2:
        raise Pending('DNS requires one or two explicit family listeners')
    families, health = set(), set()
    for row in listeners:
        KERNEL.known(row, {'address', 'health_port'}, {'address', 'health_port'})
        family = address(row['address']); port = row['health_port']
        if type(port) is not int or not 1024 <= port <= 65535 or port == 5432:
            raise Pending('unsupported explicit DNS loopback health port')
        if family in families or port in health:
            raise Pending('DNS listeners share a family or health port')
        families.add(family); health.add(port)
    KERNEL.known(value['budgets'], set(BUDGETS), set(BUDGETS))
    for field, (minimum, maximum) in BUDGETS.items():
        number = value['budgets'][field]
        if type(number) is not int or not minimum <= number <= maximum:
            raise Pending('unsupported explicit DNS response budget')
    return json.loads(BASE.canonical(value))


def configuration(end):
    raw, source = BASE.read_protected(INPUT, MAX_INPUT, True, end)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=KERNEL.unique_object,
            parse_constant=lambda text: (_ for _ in ()).throw(Pending('nonfinite DNS input')))
        value = checked(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Pending('invalid DNS JSON input') from error
    if raw != BASE.canonical(value):
        raise Pending('DNS input requires canonical ASCII JSON plus LF')
    return {'value': value, 'source': source}


def records(raw, columns):
    if type(raw) is not bytes or len(raw) > MAX_INVENTORY:
        raise Pending('unsupported DNS account inventory bytes')
    if (not raw.endswith(b'\\n') or
        any(c != 10 and not 32 <= c <= 126 for c in raw)):
        raise Pending('DNS inventory requires printable ASCII and exact LF records')
    lines = raw[:-1].decode('ascii').split('\\n')
    if len(lines) > 4096:
        raise Pending('DNS account inventory exceeds its row bound')
    rows = {}
    for line in lines:
        fields = line.split(':')
        if (len(fields) != columns or
            re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}', fields[0]) is None or
            fields[0] in rows):
            raise Pending('malformed or duplicate DNS account inventory')
        rows[fields[0]] = fields
    return rows


def numeric(text):
    if re.fullmatch(r'0|[1-9][0-9]{0,9}', text) is None:
        raise Pending('noncanonical DNS inventory numeric identity')
    return KERNEL.uint(int(text), 0x7fffffff)


def accounts(passwd, group, settings):
    settings = checked(settings)
    users = records(passwd, 7); groups = records(group, 4)
    primary, uids, gids, membership = {}, set(), set(), {}
    for account, row in users.items():
        uid, gid = numeric(row[2]), numeric(row[3])
        if uid in uids:
            raise Pending('ambiguous DNS account UID')
        uids.add(uid); primary[account] = (uid, gid)
    for group_name, row in groups.items():
        gid = numeric(row[2]); members = row[3].split(',') if row[3] else []
        if (gid in gids or len(members) != len(set(members)) or
            any(member not in users for member in members)):
            raise Pending('ambiguous DNS group identity or membership')
        gids.add(gid); membership[group_name] = (gid, set(members))
    selected = [settings['application_user'], settings['gateway_user']]
    result = {}
    for account in selected:
        if account not in users or account not in groups:
            raise Pending('DNS service account or dedicated primary group is missing')
        row = users[account]; uid, gid = primary[account]
        if (not 100 <= uid <= 999 or gid == 0 or row[1] not in ('x', '!', '*') or
            row[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false') or
            membership[account][0] != gid or membership[account][1] - {account} or
            any(other != account and other_gid == gid for other, (_, other_gid) in primary.items())):
            raise Pending('DNS requires dedicated nonlogin system accounts')
        result[account] = {'uid': uid, 'primary_gid': gid, 'shell': row[6]}
    ipc = settings['ipc_group']
    if (ipc not in membership or membership[ipc][0] == 0 or
        membership[ipc][1] != set(selected) or
        any(gid == membership[ipc][0] for _, gid in primary.values())):
        raise Pending('DNS IPC group must contain only the two explicit supplementary members')
    for group_name, (_, members) in membership.items():
        for account in selected:
            if account in members and group_name not in (account, ipc):
                raise Pending('DNS service account has unsupported supplementary membership')
    return {'users': result, 'ipc_group': {'name': ipc, 'gid': membership[ipc][0]}}


def render(settings):
    settings = checked(settings)
    shared = ('Type=exec\\nRestart=no\\nUMask=0077\\nNoNewPrivileges=yes\\n'
        'ProtectSystem=strict\\nProtectHome=yes\\nPrivateTmp=yes\\n'
        'RestrictSUIDSGID=yes\\nLockPersonality=yes\\n'
        'KillMode=control-group\\nTimeoutStartSec=30\\nTimeoutStopSec=30\\n'
        'StandardOutput=journal\\nStandardError=journal\\n')
    app_argv = [settings['application_binary'], '--socket', SOCKET, '--state', STATE,
        '--node', settings['node'], '--role', 'authoritative-replica',
        '--zones', ','.join(settings['zones'])]
    for field in BUDGETS:
        app_argv.extend(('--'+field, str(settings['budgets'][field])))
    application = ('[Unit]\\nDescription=Private mk8.dns preprovisioned replica\\n'
        '[Service]\\n' + shared + f\"User={settings['application_user']}\\n\"
        f\"Group={settings['ipc_group']}\\nWorkingDirectory={Path(settings['application_binary']).parent}\\n\"
        'RuntimeDirectory=debian13s4-dns\\nRuntimeDirectoryMode=0710\\n'
        'RuntimeDirectoryPreserve=yes\\n'
        f'ReadWritePaths={STATE} /run/debian13s4-dns\\n'
        'RestrictAddressFamilies=AF_UNIX\\nCapabilityBoundingSet=\\nAmbientCapabilities=\\n'
        'ExecStart='+' '.join(app_argv)+'\\n[Install]\\nWantedBy=multi-user.target\\n')
    units = {APP_UNIT: application}; argv = {APP_UNIT: app_argv}; listeners = []
    for row in settings['listeners']:
        family = address(row['address'])
        unit = f'debian13s4-dns-gateway{family}.service'
        command = [settings['gateway_binary'], '--socket', SOCKET, '--role', 'query',
            '--health-port', str(row['health_port']), '--dns-address', row['address'], '--dns-port', '53']
        units[unit] = ('[Unit]\\nDescription=Public mk8.dns query gateway\\n'
            f'Requires={APP_UNIT}\\nAfter={APP_UNIT} network-online.target\\n'
            'Wants=network-online.target\\n[Service]\\n'+shared+
            f\"User={settings['gateway_user']}\\nGroup={settings['ipc_group']}\\n\"
            f\"WorkingDirectory={Path(settings['gateway_binary']).parent}\\n\"
            f'InaccessiblePaths={STATE}\\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\\n'
            'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\\nAmbientCapabilities=CAP_NET_BIND_SERVICE\\n'
            'ExecStart='+' '.join(command)+'\\n[Install]\\nWantedBy=multi-user.target\\n')
        argv[unit] = command
        listeners.append({'unit': unit, 'address': row['address'], 'port': 53,
            'transports': ['udp', 'tcp'], 'health_address': '127.0.0.1',
            'health_port': row['health_port']})
    return {'units': units, 'argv': argv, 'listeners': listeners,
        'ipc': {'socket': SOCKET, 'directory_mode': '0710', 'socket_mode': '0660'},
        'state_directory': STATE}


def prepare(deadline=None, scope=KERNEL.namespace):
    end = KERNEL.now() + ATTEMPT_SECONDS
    if deadline is not None:
        if not KERNEL.finite_deadline(deadline):
            raise Pending('invalid inherited DNS deadline')
        end = min(end, deadline)
    BASE.fence(end)
    context = KERNEL.uint(scope(), 0xffffffffffffffff)
    if context == 0:
        raise Pending('missing DNS caller namespace')
    settings = configuration(end)
    passwd, user_source = BASE.read_protected(PASSWD, MAX_INVENTORY, False, end)
    group, group_source = BASE.read_protected(GROUP, MAX_INVENTORY, False, end)
    selected = accounts(passwd, group, settings['value'])
    plan = render(settings['value'])
    record = {'schema': 1, 'profile': 'mk8-dns-preprovisioned-static-replica-intention-v1',
        'state': 'dns-service-intention-only', 'namespace': context, 'configuration': settings,
        'user_source': user_source, 'group_source': group_source, 'accounts': selected,
        'plan': plan, 'unit_sha256': {k: hashlib.sha256(v.encode('ascii')).hexdigest()
            for k, v in plan['units'].items()}}
    payload = BASE.canonical(record)
    if len(payload) > MAX_OUTPUT:
        raise Pending('DNS service intention exceeds its complete output bound')
    if configuration(end) != settings:
        raise Pending('DNS input changed during preparation')
    for path, raw, source in ((PASSWD, passwd, user_source), (GROUP, group, group_source)):
        after, after_source = BASE.read_protected(path, MAX_INVENTORY, False, end)
        if after != raw or after_source != source:
            raise Pending('DNS account or group inventory changed')
    if KERNEL.uint(scope(), 0xffffffffffffffff) != context:
        raise Pending('DNS caller namespace changed')
    BASE.fence(end)
    return payload


def main():
    try:
        if len(sys.argv) != 1:
            raise Pending('DNS preparation accepts no overrides')
        sink = sys.stdout.buffer
        if not callable(getattr(sink, 'write', None)) or not callable(getattr(sink, 'flush', None)):
            raise Pending('DNS preparation requires binary stdout')
        payload = prepare()
        count = sink.write(payload)
        if type(count) is not int or count != len(payload):
            raise Pending('incomplete DNS intention publication')
        sink.flush()
    except (Pending, OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError) as error:
        print('Pending: '+str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == '__main__':
    sys.exit(main())
" > "$S4B_STAGE/"lib/dns/prepare.py || return 1
    printf '%s' "5e8f9686488c77aa03d05b36c874090e7cc6ed9795c70e28944e8b8f7fe41936  lib/repair.sh
0532281d04de4d830a60f3490467f5feff9f0ec018dce6974114da2d76b583ba  lib/tasks.list
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
79bfcfbfa9e7077835f997599d981baa41e2611631e0c72285a5bda39f7c9a27  lib/firewall/kernel.py
8be3551e55ba629d5b428d4b4eb790633e62f389a280c622e9a017992b7fbdb1  lib/ssh/common.sh
d5aa5c2cdbd5d586a096ce135d6041606173aafdc28b694b953512552cf6dab1  lib/ssh/policy.py
c695a6f939cef5eb0dec883b04722c71095877f7e0c06f9a76161b6672f35bdf  lib/ssh/repair.sh
1bb3285e71f2461e8159bd93ba240fae1b89d03cfcf832f811d0d8b411bac735  lib/ssh/debian13s4-admin-ssh.service
37346a701711ae61f025720ce4360cc5b8de008fce611ce077c43c1181302b59  lib/ssh/debian13s4-ssh.service
7554b9365ae78d6a59c1bc1dc1eedfa14a07f5f64aabc79a45f540862a12233d  lib/ssh/debian13s4-ssh.timer
22ebcfa9fc38e455077130d400e76433948740c8e80c1475bf8224891813a1b9  lib/tasks/ssh/apply.sh
3e0d51509cf31af2188db77617d6e06ace86350c51b57425b5c066e76059f19e  lib/tasks/ssh/verify.sh
897c27a540ac4d6156651942ef03ba0090aee160a11abeb5264f5beb7db64e9c  lib/postgresql/prepare.py
fb1df98101a5e50fb34b6a5702e3b0113b2d088887a0d34d668b6f365f9eace6  lib/postgresql/live.py
e73ce455f1cb8c5aeb8cc73b77dce4cffe6bdd95d30bd2480bf44da16ca5f944  lib/postgresql/access.py
075d1757636bc1a2d75809c8bc999be8e8907b02043fa38f1150eb916eef801f  lib/postgresql/backup.py
59e81c10f8f8b05a096bd97b582fd7daabb6335ce9e3e517cc5733b6e0f911bd  lib/postgresql/archive_stage.py
256db3afefc72bb7d2adf3def8b48e451e4198c47a4657fa97daa0a266bf25d6  lib/postgresql/archive_inspection.py
23d8a0698e34fb967fbfba28df2a7ef2cbcd363d2bb02b5631cf8072d870cf01  lib/postgresql/dump_stream.py
cbf37f48fee0adada2758944e1fd03a437f363989895fbb96e5ada49dcfce28c  lib/postgresql/selected_stage.py
e4c34d38e289799664836e4c7697b5ad19d115b14d3d76ca30f3d94daa33b49f  lib/postgresql/selected_inspection.py
8ee33451c466e42e7509008d5181098f78bf462c18011a64ab7d5cf29af6083e  lib/postgresql/selected_uncertainty.py
844e7b6eac0d47bfdf312bd017983f6d66a572645845ecc18b0d8eb08ee57251  lib/postgresql/stage_manifest.py
ca965202b25b70f463d0a6c3d7b48ba245382274f520710f0c2fe57e14824aab  lib/postgresql/backup_attempt.py
f231c41d5a7361fad8e4b1fa18d3c78ae2ab505c4b72de798c135edeac25d740  lib/postgresql/backup_lifecycle.py
d99a4520415f43297fb0f1d85430b6593cc82b23b3d80161ca894bb289d89aa4  lib/postgresql/private_storage.py
3c5e2277f334d6e69ed31aed79cdeee1f776b76d1f4440184a3e7b0f6c737d61  lib/postgresql/backup_status.py
9035ef9a499f25e4bd1029b7c346a9d173ed3bd468fa9870b0132eb8a6e110d0  lib/postgresql/backup_run.py
a3ae727aea741fd1e6eefd24b0e1ceb49ac8ba6200d0f29d6bf112e189337efb  lib/postgresql/attempt_failure.py
369af8f804c8cc5381eebdae6884acd092f7e89931e1f7e3a8d555c323a0ad78  lib/postgresql/common.sh
8970d97756f23f5a59e3ea3b13e251226883ebb35563746369befd626db30d42  lib/postgresql/repair.sh
53d2380f5858b0674e27357e702913e6026370733c97884d837463180db68d5e  lib/postgresql/debian13s4-postgresql-server.service
4c4cdbfdee71006a46eb89c7b878c303eca2bd71fc0b5937335b7d035c70f628  lib/postgresql/debian13s4-postgresql.service
3854f90c81bdee439875ef75d3e2189097d43286c036cbeda0b88c9e1bf45b98  lib/postgresql/debian13s4-postgresql.timer
b09b6b1a5ff3e4c162a2d6bae7a47a1bc39dd804d88bf3f9ecdb56ed5f4b5ba5  lib/tasks/postgresql/apply.sh
71c562845f4f9d7130ac675d4912ce7ae3459b74050d1b90f22e64a25fa36f84  lib/tasks/postgresql/verify.sh
f648899b4a9f33e7dbcfb4267bb50b35d6e75f89c6568ba3d00353e5274091c6  lib/web/prepare.py
90fd1681fc2858eb7525ca0753a7d6b34854c2b43d95dd17577cf2a0d8983649  lib/web/live.py
61e514726ac9214b7eee710b762c262c66d6f9beb23f2b889efce544d44914e2  lib/web/upstream.py
bddf21d0cedecc46afb05bf6e610cbb88d1cb4432b67aeb09898f737200ac283  lib/web/common.sh
1293c7fded0b7f3d157042c6b1dabbbc457721f8d1da0a7963a006dbb045f29d  lib/web/repair.sh
b2c8beec9d2427ac3f8c1efad7650aa2feab9ae99e193876663a237a3904a328  lib/web/debian13s4-web-server.service
ffa012329dc6b82cccec126e69037be879261e231bab9872d50f3767b1120de2  lib/web/debian13s4-web.service
fc7dcf7ec6f4650b2cb178e4a9f9954b863f68f12b84c2d88846b3f7a0229e87  lib/web/debian13s4-web.timer
20c8c90e83399178ba14f7cdef4f8cd22cc3f8aa0529482b03909dd1ae011cd4  lib/tasks/web/apply.sh
051d3643b9f3d3c54109344adf1003a602bbd28d3b14c0c9b2c1afa01907dc88  lib/tasks/web/verify.sh
2d395f1e7d369127f638749148ea5325b1d5e046ad55ca5cba3372b37c76e30e  lib/applications/releases.py
ba5b74a1977287ea168574c2021e638966f400a5bc3f47e255c144a4e59d4073  lib/applications/identities.py
89137179e6c4353bfd2d1bdc6f05bd74163a4549aa4ca500c2467e396a9bc2ab  lib/applications/dns_service.py
f5e10597f7bb35cb04ca76ee75c0ec2aed5910698fe256e523f6e2e91f23d561  lib/applications/postgresql_identity.py
adead23bd4503d3525e3a5cce0bf46de28f7c46b7e3dba9c362f53a1a46042fc  lib/applications/sava_transport.py
d3a9632c7e3e3bb8e42a060d2c9c0ccbc01deade8d9d4f2a1b7d80754217e226  lib/applications/sava_ingress.py
f4f9ef7d0a58d4a62f320f069df3b8246aa5f96d7b0873d3c7b47fcf6e8df0d2  lib/applications/sava_service.py
e146268fc4e5f727d730135c3875282149c807079d989eb63f7e30da8d457c0d  lib/applications/private_directory.py
0ef1b8e9e6258d3492353bb1fcddce322e165c8c24b930c71522c8480ab19528  lib/applications/email_worker.py
fffc4daf3a061c6223fc6ffb52125ea62b8bdef1ec9d0ebfd05b15b64474d8ed  lib/applications/email_gateway.py
4668dcff64153729aa7dd09cdba6583adb9044f22e42bb8f230894339955d2b4  lib/applications/prepare.py
f32f97656c45d3b675bbd238e08bb12820f494757ca1887f5b78c8458df7b0b2  lib/applications/preflight.py
1de119181721839e120647eaf34023d5879602ab1b7b9793e32750c0f65a43e7  lib/applications/release_manifest.py
ba6972cd98dfe8761ea62d77f542ade67741d794f9b967c5bd84bd973e22913d  lib/applications/linux_images.py
f0e90295b042249e23c3f0f6c20673c0d0ca098cad77c039c0f681d26893064f  lib/applications/linux_linkage.py
9f0009b9cdf5436649268b9b99dddbef78ce16092e48f554798fbab91c5aedb1  lib/applications/managed_runtime.py
6e2221da7775202b8f485966c16ad270c799cbe0a216a1142619c11e975e6952  lib/applications/cli_image.py
07f5d29181a12228fb2846509c2efd6c41fa138057bcbda721efc9de5c409c9d  lib/applications/managed_images.py
998cf9331a7979f4e24f9b8239efebcb44eddf1df42c49e300eafb592cfaff80  lib/applications/managed_assets.py
472655d786dcbce62247771243c6c856a49ea7dbed9abcad80d7aee3c7915093  lib/dns/prepare.py
" > "$S4B_STAGE/files.sha256" || return 1
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -Eeuo pipefail
    PATH=$S4B_PATH
    export PATH
    umask 077
    s4b_main "$@"
fi
