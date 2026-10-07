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
