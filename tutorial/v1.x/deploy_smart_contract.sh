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
ansible-playbook 18-install-chaincode.yml
ansible-playbook 19-install-chaincode.yml
ansible-playbook 20-instantiate-chaincode.yml
ansible-playbook 21-register-application.yml
ansible-playbook 22-register-application.yml
set +x