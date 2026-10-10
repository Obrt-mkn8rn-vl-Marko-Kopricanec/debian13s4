#!/bin/bash

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
S4W_LIBRARY=/usr/local/lib/debian13s4/web
S4W_CONFIG=/etc/debian13s4-web
S4W_SERVER=debian13s4-web-server.service
S4W_SERVICE=debian13s4-web.service
S4W_TIMER=debian13s4-web.timer
S4W_LOADED_GENERATION=''
S4W_FILES=(prepare.py live.py common.sh repair.sh debian13s4-web-server.service
    debian13s4-web.service debian13s4-web.timer)

s4w_policy() (
    local descriptor=$S4M_REPAIR_FD seconds=10
    [[ ${1-} != --check && ${1-} != --live ]] || seconds=65
    trap - EXIT
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s "${seconds}s" env -i PATH="$S4M_PATH" LANG=C LC_ALL=C \
        /usr/bin/python3 -I -B "$S4W_LIBRARY/live.py" "$@"
)

s4w_action() (
    local descriptor=$S4M_REPAIR_FD action=$1
    trap - EXIT
    [[ $action == stop || $action == start ]] || return 1
    [[ -z $descriptor ]] || exec {descriptor}>&-
    timeout --signal=TERM --kill-after=1s 120s env -i PATH="$S4M_PATH" LANG=C LC_ALL=C \
        systemctl "$action" "$S4W_SERVER"
)

s4w_assets() {
    local name
    [[ -d $S4M_STATE && -d $S4M_SYSTEMD ]] &&
        s4m_trusted "$S4M_STATE" && s4m_trusted "$S4M_SYSTEMD" || return 1
    for name in "${S4W_FILES[@]}"; do
        [[ -f $S4W_LIBRARY/$name ]] && s4m_trusted "$S4W_LIBRARY/$name" || return 1
    done
    [[ -x $S4W_LIBRARY/repair.sh ]] && s4m_trusted "$S4M_LIBRARY/common.sh" &&
        s4m_trusted "${S4W_LIBRARY%/*}/firewall/kernel.py" &&
        s4m_trusted "${S4W_LIBRARY%/*}/postgresql/prepare.py"
}

s4w_identity() {
    local name digest
    for name in "${S4W_FILES[@]}"; do
        digest=$(sha256sum -- "$S4W_LIBRARY/$name") || return 1
        printf '%s web/%s\n' "${digest%% *}" "$name" || return 1
    done
    for name in maintenance/common.sh firewall/kernel.py postgresql/prepare.py; do
        digest=$(sha256sum -- "${S4W_LIBRARY%/*}/$name") || return 1
        printf '%s %s\n' "${digest%% *}" "$name" || return 1
    done
}

s4w_packages() (
    # This supported join requires pre-installed nginx/crypto packages, existing private TLS
    # inputs and an inactive vendor nginx service. It never invokes APT.
    s4m_load_packages || return 1
    S4P_PACKAGES=(nginx nginx-common openssl ca-certificates)
    s4p_query() {
        s4m_control dpkg-query --show --showformat="\${Status}\n" -- "$1"
    }
    s4p_dpkg() {
        [[ $# == 1 && $1 == --audit ]] || return 1
        s4m_control dpkg --audit
    }
    s4p_verify
)

s4w_stop() {
    local loaded marker=$S4M_STATE/web.loaded
    loaded=$(s4m_systemctl show --property=LoadState --value "$S4W_SERVER") || return 1
    if [[ $loaded == loaded ]]; then
        s4w_action stop && s4m_property "$S4W_SERVER" ActiveState inactive &&
            s4m_property "$S4W_SERVER" MainPID 0 || return 1
    elif [[ $loaded != not-found ]]; then
        return 1
    fi
    if [[ -e $marker || -L $marker ]]; then
        [[ -f $marker ]] && s4m_trusted "$marker" && rm -f -- "$marker" || return 1
        s4m_sync "$S4M_STATE" || return 1
    fi
}

s4w_vendor_inactive() {
    local loaded
    loaded=$(s4m_systemctl show --property=LoadState --value nginx.service) || return 1
    if [[ $loaded == loaded || $loaded == masked ]]; then
        s4m_property nginx.service ActiveState inactive && s4m_property nginx.service MainPID 0
    else
        [[ $loaded == not-found ]]
    fi
}

s4w_configure() {
    local temporary
    # No foreign/vendor stop or adoption. Only our own server is stopped,
    # and inactivity is confirmed BEFORE replacing any startup configuration.
    s4w_vendor_inactive && s4w_stop || return 1
    if [[ -e $S4W_CONFIG || -L $S4W_CONFIG ]]; then
        [[ -d $S4W_CONFIG ]] && s4m_trusted "$S4W_CONFIG" || return 1
    else
        s4m_trusted "${S4W_CONFIG%/*}" && mkdir -m 0755 -- "$S4W_CONFIG" || return 1
    fi
    temporary=$(mktemp -- "$S4M_STATE/web-config.XXXXXX") || return 1
    if ! s4w_policy --file > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4W_CONFIG/nginx.conf" "$temporary" 0644; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4w_policy --identity > /dev/null
}

s4w_generation() {
    local rows key value active='' pid='' invocation=''
    rows=$(s4m_systemctl show --property=ActiveState --property=MainPID \
        --property=InvocationID "$S4W_SERVER") || return 1
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
    printf 'instance %s %s\n' "$pid" "$invocation" && s4w_identity && s4w_policy --identity
}

s4w_loaded() {
    local marker=$S4M_STATE/web.loaded mode size links actual expected
    [[ -f $marker ]] && s4m_trusted "$marker" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- "$marker") || return 1
    [[ $mode == 600 && $links == 1 && $size =~ ^[1-9][0-9]{0,4}$ ]] &&
        (( 10#$size <= 24576 )) || return 1
    expected=$(s4w_generation) && actual=$(cat -- "$marker") && [[ $expected == "$actual" ]] || return 1
    S4W_LOADED_GENERATION=$expected
}

s4w_live() {
    local before pid
    s4w_loaded || return 1
    before=$S4W_LOADED_GENERATION
    pid=${before%%$'\n'*}; pid=${pid#instance }; pid=${pid%% *}
    s4w_vendor_inactive && s4w_policy --live "$pid" && s4w_loaded && [[ $before == "$S4W_LOADED_GENERATION" ]]
}

s4w_start() {
    local before after generation temporary pid
    s4m_property "$S4W_SERVER" ActiveState inactive && s4m_property "$S4W_SERVER" MainPID 0 || return 1
    s4w_vendor_inactive || return 1
    before=$(s4w_identity && s4w_policy --identity) && s4w_action start &&
        after=$(s4w_identity && s4w_policy --identity) && [[ $before == "$after" ]] || return 1
    generation=$(s4w_generation) && [[ ${generation#*$'\n'} == "$before" ]] || return 1
    pid=${generation%%$'\n'*}; pid=${pid#instance }; pid=${pid%% *}
    s4w_policy --live "$pid" && [[ $(s4w_generation) == "$generation" ]] || return 1
    temporary=$(mktemp -- "$S4M_STATE/web-loaded.XXXXXX") || return 1
    if ! printf '%s\n' "$generation" > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/web.loaded" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4w_loaded
}

s4w_units() {
    local name
    for name in "$S4W_SERVER" "$S4W_SERVICE" "$S4W_TIMER"; do
        [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" &&
            cmp --silent -- "$S4W_LIBRARY/$name" "$S4M_SYSTEMD/$name" || return 1
        s4m_property "$name" FragmentPath "$S4M_SYSTEMD/$name" &&
            s4m_property "$name" DropInPaths '' || return 1
    done
    s4m_enabled "$S4W_SERVER" && s4m_enabled "$S4W_TIMER" && s4m_property "$S4W_TIMER" ActiveState active
}

s4w_ready() {
    local actual expected mode size links
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending &&
        -f $S4M_STATE/web.ready ]] && s4m_trusted "$S4M_STATE/web.ready" || return 1
    read -r mode size links < <(stat --format='%a %s %h' -- "$S4M_STATE/web.ready") || return 1
    [[ $mode == 600 && $links == 1 && $size =~ ^[1-9][0-9]{0,3}$ ]] &&
        (( 10#$size <= 4096 )) || return 1
    s4w_assets && s4w_units || return 1
    expected=$(s4w_identity) && actual=$(cat -- "$S4M_STATE/web.ready") && [[ $expected == "$actual" ]]
}

s4w_verify() {
    s4w_ready && s4w_packages && s4w_live
}

s4w_publish() {
    local name wants resolved temporary
    for name in "$S4W_SERVER" "$S4W_SERVICE" "$S4W_TIMER"; do
        s4m_atomic "$S4M_SYSTEMD/$name" "$S4W_LIBRARY/$name" || return 1
    done
    s4m_systemctl daemon-reload || return 1
    for name in "$S4W_SERVER" "$S4W_TIMER"; do
        s4m_systemctl enable "$name" && s4m_enabled "$name" || return 1
        wants=$S4M_SYSTEMD/multi-user.target.wants
        [[ $name != "$S4W_TIMER" ]] || wants=$S4M_SYSTEMD/timers.target.wants
        [[ -d $wants && -L $wants/$name ]] && s4m_trusted "$wants" || return 1
        resolved=$(readlink --canonicalize-existing -- "$wants/$name") && [[ $resolved == "$S4M_SYSTEMD/$name" ]] || return 1
        s4m_sync "$wants" "$S4M_SYSTEMD" "$S4M_SYSTEMD/$name" || return 1
    done
    s4w_start && s4m_systemctl start "$S4W_TIMER" && s4w_units && s4w_live || return 1
    temporary=$(mktemp -- "$S4M_STATE/web-ready.XXXXXX") || return 1
    if ! s4w_identity > "$temporary" || ! chmod 0600 -- "$temporary" ||
        ! s4m_atomic "$S4M_STATE/web.ready" "$temporary" 0600; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" && s4w_verify
}

s4w_apply() {
    local name loaded
    s4w_assets && s4w_packages || return 1
    for name in "$S4W_SERVER" "$S4W_SERVICE" "$S4W_TIMER"; do
        if [[ -e $S4M_SYSTEMD/$name || -L $S4M_SYSTEMD/$name ]]; then
            [[ -f $S4M_SYSTEMD/$name ]] && s4m_trusted "$S4M_SYSTEMD/$name" || return 1
        fi
    done
    if [[ -e $S4M_STATE/web.ready || -L $S4M_STATE/web.ready ]]; then
        [[ -f $S4M_STATE/web.ready ]] && s4m_trusted "$S4M_STATE/web.ready" &&
            rm -f -- "$S4M_STATE/web.ready" || return 1
    fi
    s4m_sync "$S4M_STATE" || return 1
    for name in "$S4W_TIMER" "$S4W_SERVICE"; do
        loaded=$(s4m_systemctl show --property=LoadState --value "$name") || return 1
        if [[ $loaded == loaded ]]; then
            s4m_systemctl stop "$name" && s4m_property "$name" ActiveState inactive || return 1
        elif [[ $loaded != not-found ]]; then return 1; fi
    done
    if s4w_configure && s4w_publish; then return 0; fi
    s4w_stop || return 1
    return 1
}

s4w_repair() {
    [[ ! -e $S4M_STATE/bootstrap/pending && ! -L $S4M_STATE/bootstrap/pending ]] || return 75
    s4m_lock || return 75
    trap s4m_unlock EXIT
    if s4w_ready && s4w_packages; then
        if s4w_live; then return 0; fi
        if s4w_configure && s4w_start && s4w_live; then return 0; fi
    fi
    s4w_stop || return 75
    return 75
}
