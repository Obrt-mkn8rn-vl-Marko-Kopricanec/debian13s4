#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
S4G_LIBRARY=/usr/local/lib/debian13s4/postgresql
S4G_CONFIG=/etc/debian13s4-postgresql
S4G_SERVER=debian13s4-postgresql-server.service
S4G_SERVICE=debian13s4-postgresql.service
S4G_TIMER=debian13s4-postgresql.timer
S4G_LOADED_GENERATION=''
S4G_FILES=(prepare.py live.py common.sh repair.sh debian13s4-postgresql-server.service
    debian13s4-postgresql.service debian13s4-postgresql.timer)

s4g_policy() (
    local descriptor=$S4M_REPAIR_FD
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 15s env -i PATH="$S4M_PATH" LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B "$S4G_LIBRARY/live.py" "$@"
)

s4g_action() (
    local descriptor=$S4M_REPAIR_FD action=$1
    trap - EXIT
    [[ $action == stop || $action == start ]] || return 1
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 120s env -i PATH="$S4M_PATH" LANG=C LC_ALL=C \
        systemctl "$action" "$S4G_SERVER"
)

s4g_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    for name in "${S4G_FILES[@]}"; do
        [[ -f $S4G_LIBRARY/$name ]] && s4m_trusted "$S4G_LIBRARY/$name" || return 1
    done
    [[ -x $S4G_LIBRARY/repair.sh ]] && s4m_trusted "$S4M_LIBRARY/common.sh" &&
        s4m_trusted "${S4G_LIBRARY%/*}/firewall/kernel.py"
}

s4g_identity() {
    local name digest
    for name in "${S4G_FILES[@]}"; do
        digest=$(sha256sum -- "$S4G_LIBRARY/$name") || return 1
        printf '%s postgresql/%s\n' "${digest%% *}" "$name" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py; do
        digest=$(sha256sum -- "${S4G_LIBRARY%/*}/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
}

s4g_packages() (
    # This supported join requires pre-installed packages and pre-provisioned
    # enrolled data. It never invokes APT or vendor cluster-creation scripts.
    s4m_load_packages || return 1
    S4P_PACKAGES=(postgresql-17 postgresql-client-17)
    s4p_query() {
        s4m_control dpkg-query --show --showformat="\${Status}\n" -- "$1"
    }
    s4p_dpkg() {
        [[ $# == 1 && $1 == --audit ]] || return 1
        s4m_control dpkg --audit
    }
    s4p_verify
)

s4g_stop() {
    local loaded marker=$S4M_STATE/postgresql.loaded
    loaded=$(s4m_systemctl show --property=LoadState --value "$S4G_SERVER") || return 1
    if [[ $loaded == loaded ]]; then
        s4g_action stop && s4m_property "$S4G_SERVER" ActiveState inactive &&
            s4m_property "$S4G_SERVER" MainPID 0 || return 1
    elif [[ $loaded != not-found ]]; then
        return 1
    fi
    if [[ -e $marker || -L $marker ]]; then
        [[ -f $marker ]] && s4m_trusted "$marker" && rm -f -- "$marker" || return 1
        s4m_sync "$S4M_STATE" || return 1
    fi
}

s4g_configure() {
    local name temporary
    # Stop/confirm inactive before any startup-input replacement. Prestart
    # positively checks enrolled existing stopped data, not just disk syntax.
    s4g_stop && s4g_policy --prestart || return 1
    if [[ -e $S4G_CONFIG || -L $S4G_CONFIG ]]; then
        [[ -d $S4G_CONFIG ]] && s4m_trusted "$S4G_CONFIG" || return 1
    else
        s4m_trusted "${S4G_CONFIG%/*}" && mkdir -m 0755 -- "$S4G_CONFIG" || return 1
    fi
    for name in postgresql.conf pg_hba.conf pg_ident.conf; do
        temporary=$(mktemp -- "$S4M_STATE/postgresql-config.XXXXXX") || return 1
        if ! s4g_policy --file "$name" > "$temporary" || ! chmod 0600 -- "$temporary" ||
            ! s4m_atomic "$S4G_CONFIG/$name" "$temporary" 0644; then
            rm -f -- "$temporary"
            return 1
        fi
        rm -f -- "$temporary" || return 1
    done
}

s4g_generation() {
    local rows key value active='' pid='' invocation=''
    rows=$(s4m_systemctl show --property=ActiveState --property=MainPID \
        --property=InvocationID "$S4G_SERVER") || return 1
    [[ ${#rows} -le 512 ]] || return 1
    while IFS='=' read -r key value; do
        case $key in
            ActiveState) [[ -z $active && $value == active ]] || return 1; active=$value ;;
            MainPID)
                [[ -z $pid && $value =~ ^[1-9][0-9]{0,9}$ ]] &&
                    (( 10#$value <= 2147483647 )) || return 1; pid=$value ;;
            InvocationID)
                [[ -z $invocation && $value =~ ^[0-9a-f]{32}$ &&
                    $value != 00000000000000000000000000000000 ]] || return 1; invocation=$value ;;
            *) return 1 ;;
        esac
    done <<< "$rows"
    [[ $active == active && -n $pid && -n $invocation ]] || return 1
    printf 'instance %s %s\n' "$pid" "$invocation" && s4g_identity && s4g_policy --identity
}

s4g_loaded() {
    local marker=$S4M_STATE/postgresql.loaded mode size links actual expected
    [[ -f $marker ]] && s4m_trusted "$marker" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- "$marker") || return 1
    [[ $mode == 600 && $links == 1 && $size =~ ^[1-9][0-9]{0,4}$ ]] &&
        (( 10#$size <= 24576 )) || return 1
    expected=$(s4g_generation) && actual=$(cat -- "$marker") && [[ $expected == "$actual" ]] || return 1
    S4G_LOADED_GENERATION=$expected
}

s4g_live() {
    local before
    s4g_loaded || return 1
    before=$S4G_LOADED_GENERATION
    s4g_policy --check && s4g_loaded && [[ $before == "$S4G_LOADED_GENERATION" ]]
}

s4g_start() {
    local before after generation temporary
    s4m_property "$S4G_SERVER" ActiveState inactive && s4m_property "$S4G_SERVER" MainPID 0 || return 1
    before=$(s4g_identity && s4g_policy --identity) && s4g_action start &&
        s4g_policy --check && after=$(s4g_identity && s4g_policy --identity) && [[ $before == "$after" ]] || return 1
    generation=$(s4g_generation) && [[ ${generation#*$'\n'} == "$before" ]] || return 1
    temporary=$(mktemp -- "$S4M_STATE/postgresql-loaded.XXXXXX") || return 1
    if ! printf '%s\n' "$generation" > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/postgresql.loaded" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4g_loaded
}

s4g_units() {
    local name
    for name in "$S4G_SERVER" "$S4G_SERVICE" "$S4G_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4G_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" &&
            s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4G_SERVER" && s4m_enabled "$S4G_TIMER" && s4m_property "$S4G_TIMER" ActiveState active
}

s4g_ready() {
    local actual expected mode size links
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/postgresql.ready ]] && s4m_trusted "$S4M_STATE/postgresql.ready" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- "$S4M_STATE/postgresql.ready") || return 1
    [[ $mode == 600 && $links == 1 && $size =~ ^[1-9][0-9]{0,3}$ ]] &&
        (( 10#$size <= 4096 )) || return 1
    s4g_assets && s4g_units || return 1
    expected=$(s4g_identity) && actual=$(cat -- "$S4M_STATE/postgresql.ready") && [[ $expected == "$actual" ]]
}

s4g_verify() {
    s4g_ready && s4g_packages && s4g_live
}

s4g_publish() {
    local name wants resolved temporary
    for name in "$S4G_SERVER" "$S4G_SERVICE" "$S4G_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$name" "$S4G_LIBRARY/$name" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for name in "$S4G_SERVER" "$S4G_TIMER"; do
        s4m_systemctl enable "$name" && s4m_enabled "$name" || return 1
        wants=$S4M_SYSTEMD/multi-user.target.wants
        [[ $name != "$S4G_TIMER" ]] || wants=$S4M_SYSTEMD/timers.target.wants
        [[ -d $wants && -L $wants/$name ]] && s4m_trusted "$wants" || return 1
        resolved=$(readlink --canonicalize-existing -- "$wants/$name") && [[ $resolved == "$S4M_SYSTEMD/$name" ]] || return 1
        s4m_sync "$wants" "$S4M_SYSTEMD" "$S4M_SYSTEMD/$name" || return 1
    done
    s4g_start && s4m_systemctl start "$S4G_TIMER" && s4g_units && s4g_live || return 1
    temporary=$(mktemp -- "$S4M_STATE/postgresql-ready.XXXXXX") || return 1
    if ! s4g_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/postgresql.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4g_verify
}

s4g_apply() {
    local name loaded
    s4g_assets && s4g_packages || return 1
    for name in "$S4G_SERVER" "$S4G_SERVICE" "$S4G_TIMER"; do
        if [[ -e $S4M_SYSTEMD/$name || -L $S4M_SYSTEMD/$name ]]; then
            [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" || return 1
        fi
    done
    if [[ -e $S4M_STATE/postgresql.ready || -L $S4M_STATE/postgresql.ready ]]; then
        [[ -f $S4M_STATE/postgresql.ready ]] && s4m_trusted "$S4M_STATE/postgresql.ready" &&
            rm -f -- "$S4M_STATE/postgresql.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for name in "$S4G_TIMER" "$S4G_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$name") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$name" && s4m_property "$name" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then return 1; fi
    done
    if s4g_configure && s4g_publish; then return 0; fi
    s4g_stop || return 1
    return 1
}

s4g_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    if s4g_ready && s4g_packages; then
        if s4g_live; then return 0; fi
        if s4g_configure && s4g_start && s4g_live; then return 0; fi
    fi
    s4g_stop || return 75
    return 75
}
