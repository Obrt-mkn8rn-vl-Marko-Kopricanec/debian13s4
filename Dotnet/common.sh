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
S4D_FILES=(common.sh update.sh policy.conf preferences sources.sources
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
    # Explicit installation also repairs an accidentally removed runtime.
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
    s4m_update
)
