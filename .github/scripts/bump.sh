#!/usr/bin/env bash
set -euo pipefail
CURRENT_VERSION=$(yq -r .version galaxy.yml)
cat <<EOF | python > /tmp/version.txt
import semantic_version
v = semantic_version.Version('${CURRENT_VERSION}')
v = v.next_patch()
print(str(v))
EOF
NEXT_VERSION=$(cat /tmp/version.txt)
SED="sed"
if [ "$(uname)" == "Darwin" ]; then
    SED="gsed"
fi
${SED} -i "s|^version:.*|version: ${NEXT_VERSION}|" galaxy.yml