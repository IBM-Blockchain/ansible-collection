#!/usr/bin/env bash
set -euo pipefail
cd ~/.ansible/collections/ansible_collections/ibm/blockchain_platform
TEST_RUN_ID=$(dd if=/dev/urandom bs=4096 count=1 2>/dev/null | shasum | awk '{print $1}')
SHORT_TEST_RUN_ID=$(echo "${TEST_RUN_ID}" | awk '{print substr($1,1,8)}')
yq -yi ".api_endpoint=\"${API_ENDPOINT}\"" tests/integration/integration_config.yml
yq -yi ".api_authtype=\"${API_AUTHTYPE}\"" tests/integration/integration_config.yml
yq -yi ".api_key=\"${API_KEY}\"" tests/integration/integration_config.yml
yq -yi ".api_secret=\"${API_SECRET}\"" tests/integration/integration_config.yml
yq -yi ".api_timeout=300" tests/integration/integration_config.yml
yq -yi ".k8s_namespace=\"${K8S_NAMESPACE}\"" tests/integration/integration_config.yml
yq -yi ".test_run_id=\"${TEST_RUN_ID}\"" tests/integration/integration_config.yml
yq -yi ".short_test_run_id=\"${SHORT_TEST_RUN_ID}\"" tests/integration/integration_config.yml
yq -yi ".wait_timeout=1800" tests/integration/integration_config.yml