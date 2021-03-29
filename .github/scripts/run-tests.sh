#!/usr/bin/env bash
set -euo pipefail
TYPE=$1
if [ "${COLLECT_LOGS}" = "true" ]; then
    function print_logs {
        cat "${IBP_ANSIBLE_LOG_FILENAME}"
    }
    IBP_ANSIBLE_LOG_FILENAME=$(mktemp)
    export IBP_ANSIBLE_LOG_FILENAME
    trap print_logs EXIT
fi
.github/scripts/setup-tests.sh
".github/scripts/run-${TYPE}-tests.sh"