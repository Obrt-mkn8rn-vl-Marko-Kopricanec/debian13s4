#!/bin/bash
set -Eeuo pipefail
umask 077

# shellcheck source=Tasks/prerequisites/common.sh
. /usr/local/lib/debian13s4/tasks/prerequisites/common.sh

# Reuse a protected dedicated index directory even after forced termination.
# APT's list lock and a successful authenticated refresh gate installation;
# _apt can traverse the path and retains its normal download sandbox.
s4p_prepare
export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_MODE=l
s4p_apply
