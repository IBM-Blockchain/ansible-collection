#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
IMPORT_EXPORT_REQUIRED=0
function usage {
    echo "Usage: join_network.sh [-i] [join|destroy]" 1>&2
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
if [ "${COMMAND}" = "join" ]; then
    set -x
    ansible-playbook 11-create-endorsing-organization-components.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
    if [ "${IMPORT_EXPORT_REQUIRED}" = "1" ]; then
        ansible-playbook 12-export-organization.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
        ansible-playbook 13-import-organization.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    fi
    ansible-playbook 14-add-organization-to-channel.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    if [ "${IMPORT_EXPORT_REQUIRED}" = "1" ]; then
        ansible-playbook 15-import-ordering-service.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
    fi
    ansible-playbook 16-join-peer-to-channel.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 17-add-anchor-peer-to-channel.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
    set +x
elif [ "${COMMAND}" = "destroy" ]; then
    set -x
    ansible-playbook 97-delete-endorsing-organization-components.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 98-delete-endorsing-organization-components.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"
    ansible-playbook 99-delete-ordering-organization-components.yml --extra-vars "@ordering-org-vars.yml" --extra-vars "@common-vars.yml"
    set +x
else
    usage
fi