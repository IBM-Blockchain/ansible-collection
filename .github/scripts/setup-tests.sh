#!/usr/bin/env bash
set -euo pipefail
curl -sSL https://github.com/hyperledger/fabric/releases/download/v2.2.1/hyperledger-fabric-linux-amd64-2.2.1.tar.gz | sudo tar xzf - -C /usr/local
curl -sL https://ibm.biz/idt-installer | bash
ibmcloud config --check-version=false
ibmcloud version
ibmcloud plugin list
curl -sSL https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-4.5/openshift-client-linux.tar.gz | sudo tar xzf - -C /usr/local/bin
ibmcloud login --apikey "${IBM_CLOUD_API_KEY}" -c "${IBM_CLOUD_ACCOUNT}" -r "${IBM_CLOUD_REGION}"
ibmcloud oc cluster config -c "${IBM_CLOUD_OPENSHIFT_CLUSTER_ID}"
oc login -u apikey -p "${IBM_CLOUD_API_KEY}"