#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none \
    NEEDRESTART_MODE=l UCF_FORCE_CONFFOLD=1 s4d_apply
