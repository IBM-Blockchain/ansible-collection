#!/usr/bin/env bash
set -euo pipefail
TYPE=$1
.github/scripts/setup-tests.sh
".github/scripts/run-${TYPE}-tests.sh"