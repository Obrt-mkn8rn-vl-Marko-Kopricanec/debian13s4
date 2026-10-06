#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Tasks/prerequisites/common.sh
. /usr/local/lib/debian13s4/tasks/prerequisites/common.sh
s4p_verify
