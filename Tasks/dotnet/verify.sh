#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Dotnet/common.sh
. /usr/local/lib/debian13s4/dotnet/common.sh
s4d_verify
