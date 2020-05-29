#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
#
set -ex
ansible-playbook 01-create-ordering-organization-components.yml
ansible-playbook 02-create-endorsing-organization-components.yml
ansible-playbook 03-export-organization.yml
ansible-playbook 04-import-organization.yml
ansible-playbook 05-add-organization-to-consortium.yml
ansible-playbook 06-export-ordering-service.yml
ansible-playbook 07-import-ordering-service.yml
ansible-playbook 08-create-channel.yml
ansible-playbook 09-join-peer-to-channel.yml
ansible-playbook 10-add-anchor-peer-to-channel.yml
ansible-playbook 11-create-endorsing-organization-components.yml
ansible-playbook 12-export-organization.yml
ansible-playbook 13-import-organization.yml
ansible-playbook 14-add-organization-to-channel.yml
ansible-playbook 15-import-ordering-service.yml
ansible-playbook 16-join-peer-to-channel.yml
ansible-playbook 17-add-anchor-peer-to-channel.yml
ansible-playbook 18-install-chaincode.yml
ansible-playbook 19-install-chaincode.yml
ansible-playbook 20-instantiate-chaincode.yml
ansible-playbook 21-register-application.yml
ansible-playbook 22-register-application.yml
ansible-playbook 97-delete-endorsing-organization-components.yml --extra-vars '{"import_export_used":true}'
ansible-playbook 98-delete-endorsing-organization-components.yml --extra-vars '{"import_export_used":true}'
ansible-playbook 99-delete-ordering-organization-components.yml --extra-vars '{"import_export_used":true}'
