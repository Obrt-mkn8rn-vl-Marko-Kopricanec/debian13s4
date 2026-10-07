#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Retention/common.sh
. /usr/local/lib/debian13s4/retention/common.sh
s4r_repair
