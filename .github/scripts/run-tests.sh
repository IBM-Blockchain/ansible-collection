#!/usr/bin/env bash
set -euo pipefail
TYPE=$1
TARGET=$2
if [ "${COLLECT_LOGS}" = "true" ]; then
    IBP_ANSIBLE_LOG_FILENAME=${TYPE}-${TARGET}.log
    export IBP_ANSIBLE_LOG_FILENAME
    echo "${IBP_ANSIBLE_LOG_FILENAME}" > /tmp/ibp-ansible-log-filename.txt
fi
.github/scripts/setup-tests.sh
".github/scripts/run-${TYPE}-tests.sh"