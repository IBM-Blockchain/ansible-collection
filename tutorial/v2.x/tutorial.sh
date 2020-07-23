#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
#
set -ex
ansible-playbook 01-create-ordering-organization-components.yml
ansible-playbook 02-create-endorsing-organization-components.yml
ansible-playbook 03-export-organization.yml
ansible-playbook 04-import-organization.yml
ansible-playbook 05-enable-capabilities.yml
ansible-playbook 06-add-organization-to-consortium.yml
ansible-playbook 07-export-ordering-service.yml
ansible-playbook 08-import-ordering-service.yml
ansible-playbook 09-create-channel.yml
ansible-playbook 10-join-peer-to-channel.yml
ansible-playbook 11-add-anchor-peer-to-channel.yml
ansible-playbook 12-create-endorsing-organization-components.yml
ansible-playbook 13-export-organization.yml
ansible-playbook 14-import-organization.yml
ansible-playbook 15-add-organization-to-channel.yml
ansible-playbook 16-import-ordering-service.yml
ansible-playbook 17-join-peer-to-channel.yml
ansible-playbook 18-add-anchor-peer-to-channel.yml
ansible-playbook 19-install-and-approve-chaincode.yml
ansible-playbook 20-install-and-approve-chaincode.yml
ansible-playbook 21-commit-chaincode.yml
ansible-playbook 22-register-application.yml
ansible-playbook 23-register-application.yml
ansible-playbook 97-delete-endorsing-organization-components.yml --extra-vars '{"import_export_used":true}'
ansible-playbook 98-delete-endorsing-organization-components.yml --extra-vars '{"import_export_used":true}'
ansible-playbook 99-delete-ordering-organization-components.yml --extra-vars '{"import_export_used":true}'
