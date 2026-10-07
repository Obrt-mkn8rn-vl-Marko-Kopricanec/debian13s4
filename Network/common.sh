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
