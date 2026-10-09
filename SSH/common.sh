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
