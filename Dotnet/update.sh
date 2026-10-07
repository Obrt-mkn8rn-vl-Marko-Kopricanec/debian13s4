#!/bin/bash -p
set -Eeuo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
(( EUID == 0 )) || exit 77

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_update
