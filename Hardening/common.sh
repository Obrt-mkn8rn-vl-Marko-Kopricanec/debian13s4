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
