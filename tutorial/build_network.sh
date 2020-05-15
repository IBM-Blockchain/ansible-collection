#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
IMPORT_EXPORT_REQUIRED=0
function usage {
    echo "Usage: build_network.sh [-i] [build|destroy]" 1>&2
    exit 1
}
while getopts ":i" OPT; do
    case ${OPT} in
        i)
            IMPORT_EXPORT_REQUIRED=1
            ;;
        \?)
            usage
            ;;
    esac
done
COMMAND=${@:$OPTIND:1}
if [ "${COMMAND}" = "build" ]; then
    set -x
    ansible-playbook 01-create-ordering-organization-components.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 02-create-endorsing-organization-components.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    if [ "${IMPORT_EXPORT_REQUIRED}" = "1" ]; then
        ansible-playbook 03-export-organization.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
        ansible-playbook 04-import-organization.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
    fi
    ansible-playbook 05-add-organization-to-consortium.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
    if [ "${IMPORT_EXPORT_REQUIRED}" = "1" ]; then
        ansible-playbook 06-export-ordering-service.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
        ansible-playbook 07-import-ordering-service.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    fi
    ansible-playbook 08-create-channel.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 09-join-peer-to-channel.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 10-add-anchor-peer-to-channel.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    set +x
elif [ "${COMMAND}" = "destroy" ]; then
    set -x
    ansible-playbook 97-delete-endorsing-organization-components.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 99-delete-ordering-organization-components.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
    set +x
else
    usage
fi