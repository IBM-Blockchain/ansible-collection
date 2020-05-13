#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
function usage {
    echo "Usage: deploy_smart_contract.sh" 1>&2
    exit 1
}
while getopts ":" OPT; do
    case ${OPT} in
        \?)
            usage
            ;;
    esac
done
set -x
ansible-playbook 18-install-chaincode.yml --extra-vars "@org1-vars.yml"
ansible-playbook 19-install-chaincode.yml --extra-vars "@org2-vars.yml"
ansible-playbook 20-instantiate-chaincode.yml --extra-vars "@org1-vars.yml"
set +x