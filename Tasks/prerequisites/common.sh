#!/bin/bash

S4P_PACKAGES=(ca-certificates debian-archive-keyring curl gpgv nftables
    apparmor apparmor-utils unattended-upgrades needrestart)
S4P_TASK_DIR=/usr/local/lib/debian13s4/tasks/prerequisites
S4P_APT_DIR=/var/lib/apt/debian13s4

s4p_prepare() {
    local path ancestor owner mode
    for path in /var/lib/apt "$S4P_APT_DIR" "$S4P_APT_DIR/lists"; do
        ancestor=${path%/*}
        while :; do
            [[ -d $ancestor && ! -L $ancestor ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- "$ancestor") || return 1
            [[ $owner == 0 ]] && (( (8#$mode & 8#022) == 0 )) || return 1
            [[ $ancestor == / ]] && break
            ancestor=${ancestor%/*}
            [[ -n $ancestor ]] || ancestor=/
        done
        if [[ -e $path || -L $path ]]; then
            [[ -d $path && ! -L $path ]] || return 1
            read -r owner mode < <(stat --format='%u %a' -- "$path") || return 1
            [[ $owner == 0 ]] && (( (8#$mode & 8#022) == 0 )) || return 1
        fi
        install -d -o root -g root -m 0755 -- "$path" || return 1
    done
}

s4p_apt() {
    apt-get \
        -o "Dir::Etc::sourcelist=$S4P_TASK_DIR/debian.sources" \
        -o Dir::Etc::sourceparts=- \
        -o "Dir::State::lists=$S4P_APT_DIR/lists" \
        -o APT::Update::Error-Mode=any \
        -o Acquire::Retries=2 \
        -o Acquire::http::Timeout=30 \
        -o Acquire::https::Timeout=30 \
        -o Acquire::Check-Date=true \
        -o Acquire::Check-Valid-Until=true \
        -o Acquire::AllowInsecureRepositories=false \
        -o Acquire::AllowDowngradeToInsecureRepositories=false \
        -o APT::Get::AllowUnauthenticated=false \
        -o APT::Get::allow-downgrades=false \
        -o APT::Get::allow-change-held-packages=false \
        -o APT::Get::allow-remove-essential=false \
        -o DPkg::Lock::Timeout=60 \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        --assume-yes --no-remove --no-install-recommends "$@"
}

s4p_dpkg() {
    dpkg "$@"
}

s4p_query() {
    dpkg-query --show --showformat='${Status}\n' -- "$1"
}

s4p_verify() {
    local package status audit
    for package in "${S4P_PACKAGES[@]}"; do
        status=$(s4p_query "$package") || return 1
        [[ $status == 'install ok installed' ]] || return 1
    done
    audit=$(s4p_dpkg --audit) || return 1
    [[ -z $audit ]]
}

s4p_apply() {
    # A partial index refresh must never be mistaken for a usable online run.
    # Authentication and normal dpkg/APT locks remain enabled on every retry.
    s4p_apt update || return 1
    if ! s4p_dpkg --force-confdef --force-confold --configure --pending; then
        s4p_apt --fix-broken install || return 1
        s4p_dpkg --force-confdef --force-confold --configure --pending || return 1
    fi
    s4p_apt install "${S4P_PACKAGES[@]}"
}
