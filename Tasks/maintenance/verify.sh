#!/bin/bash
set -Eeuo pipefail

# shellcheck source=Maintenance/common.sh
. /usr/local/lib/debian13s4/maintenance/common.sh
s4m_load_packages
s4m_verify
