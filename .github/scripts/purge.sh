#!/usr/bin/env bash
set -euo pipefail
if [ "${API_AUTHTYPE}" = "basic" ]; then
    curl -f -k -XDELETE -u "${API_KEY}:${API_SECRET}" "${API_ENDPOINT}/ak/api/v3/kubernetes/components/purge"
elif [ "${API_AUTHTYPE}" = "ibmcloud" ]; then
    ACCESS_TOKEN=$(curl -XPOST -d "apikey=${API_KEY}" -d grant_type=urn:ibm:params:oauth:grant-type:apikey https://iam.cloud.ibm.com/identity/token | jq -r .access_token)
    curl -f -XDELETE -H "Authorization: Bearer ${ACCESS_TOKEN}" "${API_ENDPOINT}/ak/api/v3/kubernetes/components/purge"
fi
