#
# SPDX-License-Identifier: Apache-2.0
#

default:
    @just --list

# Local ansible-galalxy build and install
local:
    ansible-galaxy collection build -f
    ansible-galaxy collection install $(ls -1 | grep ibm-blockchain_platform) -f

# Lint the codebase
lint:
    #!/bin/bash
    set -ex -o pipefail

    flake8 .
    ansible-lint
    shellcheck tutorial/*.sh
    yamllint .

docker:
    docker build -t fabric-ansible .

# Build the documentation
docs:
    #!/bin/bash
    set -ex -o pipefail

    cd docs
    make clean
    make all

toolcheck:
    #!/bin/bash
    set -e -o pipefail

    confirm() {
        if ! command -v $1 &> /dev/null
        then
            echo "$1 could not be found"
            exit
        fi
    }

    confirm "shellcheck"
    confirm "yamllint"

