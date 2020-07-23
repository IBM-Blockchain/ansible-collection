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
ansible-playbook 19-install-and-approve-chaincode.yml
ansible-playbook 20-install-and-approve-chaincode.yml
ansible-playbook 21-commit-chaincode.yml
ansible-playbook 22-register-application.yml
ansible-playbook 23-register-application.yml
set +x