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
    debian13s4-network.timer debian13s4-network.service)
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
