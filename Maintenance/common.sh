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
# Match the shipped one-hour oneshot. Restart slices leave 2100 seconds for
# package work and 300 seconds for final controls; they never grow with a queue.
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
