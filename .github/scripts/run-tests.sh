#!/usr/bin/env bash
set -euo pipefail
TYPE=$1
TARGET=$2
IBP_ANSIBLE_LOG_FILENAME=/tmp/${TYPE}-${TARGET}.log
export IBP_ANSIBLE_LOG_FILENAME
echo "${IBP_ANSIBLE_LOG_FILENAME}" >/tmp/ibp-ansible-log-filename.txt

#
pushd tutorial
function cleanup {
    ./join_network.sh destroy
}
trap cleanup EXIT
./build_network.sh build
./join_network.sh join
./deploy_smart_contract.sh
trap - EXIT
./join_network.sh destroy
