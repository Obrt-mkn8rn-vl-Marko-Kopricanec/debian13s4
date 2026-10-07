#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4m_apply
