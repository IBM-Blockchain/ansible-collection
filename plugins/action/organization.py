#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ibm.blockchain_platform.plugins.module_utils.blockchain_platform import BlockchainPlatform
from ansible_collections.ibm.blockchain_platform.plugins.module_utils.dict_utils import copy_dict, merge_dicts, equal_dicts, diff_dicts
from ansible.errors import AnsibleActionFail
from ansible.module_utils.urls import open_url
from ansible.plugins.action import ActionBase

import json
import time
import urllib.parse

class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        changed = False

        # Log in to the IBP console.
        api_endpoint = self._task.args['api_endpoint']
        api_authtype = self._task.args['api_authtype']
        api_key = self._task.args['api_key']
        api_secret = self._task.args.get('api_secret', None)
        api_timeout = self._task.args.get('api_timeout', 60)
        self.ibp = ibp = BlockchainPlatform(api_endpoint, api_timeout)
        ibp.login(api_authtype, api_key, api_secret)

        # Determine whether or not the organization exists.
        name = self._task.args['name']
        organization = ibp.get_component_by_display_name(name)

        # Extract the organization configuration.
        state = self._task.args.get('state', 'present')
        msp_id = self._task.args.get('msp_id', None)
        root_certs = self._task.args.get('root_certs', list())
        intermediate_certs = self._task.args.get('intermediate_certs', list())
        admins = self._task.args.get('admins', list())
        revocation_list = self._task.args.get('revocation_list', list())
        tls_root_certs = self._task.args.get('tls_root_certs', list())
        tls_intermediate_certs = self._task.args.get('tls_intermediate_certs', list())
        fabric_node_ous = self._task.args.get('fabric_node_ous', None)

        # Get any certificates from the certificate authority, if specified.
        certificate_authority_certs = self._get_from_certificate_authority()

        # If the organization does not exist, but should - create it.
        if organization is None and state == 'present':
            new_organization = {
                'display_name': name,
                'msp_id': msp_id,
                'root_certs': root_certs,
                'intermediate_certs': intermediate_certs,
                'admins': admins,
                'revocation_list': revocation_list,
                'tls_root_certs': tls_root_certs,
                'tls_intermediate_certs': tls_intermediate_certs,
                'fabric_node_ous': {
                    'enable': True,
                    'admin_ou_identifier': {
                        'organizational_unit_identifier': 'admin'
                    },
                    'client_ou_identifier': {
                        'organizational_unit_identifier': 'client'
                    },
                    'peer_ou_identifier': {
                        'organizational_unit_identifier': 'peer'
                    },
                    'orderer_ou_identifier': {
                        'organizational_unit_identifier': 'orderer'
                    }
                }
            }
            if fabric_node_ous is not None:
                merge_dicts(new_organization['fabric_node_ous'], fabric_node_ous)
            if certificate_authority_certs is not None:
                merge_dicts(new_organization, certificate_authority_certs)
            organization = ibp.create_organization(new_organization)
            changed = True

        # If the organization does exist, but should not - delete it.
        elif organization is not None and state == 'absent':
            ibp.delete_organization(organization['id'])
            return {
                'changed': True
            }

        # If the organization does not exist, and should not, nothing to do.
        elif organization is None and state == 'absent':
            return {
                'changed': False
            }

        # If the organization does exist, and should - update it if necessary.
        elif state == 'present':

            # Update the configuration.
            new_organization = copy_dict(organization)
            merge_dicts(new_organization, {
                'display_name': name,
                'msp_id': msp_id,
                'root_certs': root_certs,
                'intermediate_certs': intermediate_certs,
                'admins': admins,
                'revocation_list': revocation_list,
                'tls_root_certs': tls_root_certs,
                'tls_intermediate_certs': tls_intermediate_certs,
                'fabric_node_ous': {
                    'enable': True,
                    'admin_ou_identifier': {
                        'organizational_unit_identifier': 'admin'
                    },
                    'client_ou_identifier': {
                        'organizational_unit_identifier': 'client'
                    },
                    'peer_ou_identifier': {
                        'organizational_unit_identifier': 'peer'
                    },
                    'orderer_ou_identifier': {
                        'organizational_unit_identifier': 'orderer'
                    }
                }
            })
            if fabric_node_ous is not None:
                merge_dicts(new_organization['fabric_node_ous'], fabric_node_ous)
            if certificate_authority_certs is not None:
                merge_dicts(new_organization, certificate_authority_certs)

            # Now we can generate a diff and make sure any differences are valid for an update.
            diff = diff_dicts(organization, new_organization)
            if 'msp_id' in diff:
                raise AnsibleActionFail(f'msp_id cannot be updated; must delete organization and try again')

            if not equal_dicts(new_organization, organization):
                peer = ibp.update_organization(organization['id'], new_organization)
                changed = True

        # Extract organization information.
        result = ibp.extract_organization_info(organization)
        result['changed'] = changed
        return result

    def _get_from_certificate_authority(self):

        # Get the certificate authority.
        if 'certificate_authority' not in self._task.args:
            return None
        certificate_authority = self._get_certificate_authority()

        # Get the certificate authority information.
        response = open_url(f'{certificate_authority["api_url"]}/cainfo?ca={certificate_authority["ca_name"]}', None, None, method='GET', validate_certs=False)
        cainfo = json.load(response)
        response = open_url(f'{certificate_authority["api_url"]}/cainfo?ca={certificate_authority["tlsca_name"]}', None, None, method='GET', validate_certs=False)
        tlscainfo = json.load(response)

        # Return the certificate authority information.
        return {
            'root_certs': [
                cainfo['result']['CAChain']
            ],
            'tls_root_certs': [
                tlscainfo['result']['CAChain']
            ]
        }

    def _get_certificate_authority(self):

        # If the certificate authority is a dictionary, then we assume that
        # it contains all of the required keys/values.
        certificate_authority = self._task.args['certificate_authority']
        if isinstance(certificate_authority, dict):
            return certificate_authority

        # Otherwise, it is the display name of a certificate authority that
        # we need to look up.
        component = self.ibp.get_component_by_display_name(certificate_authority)
        if component is None:
            raise AnsibleActionFail(f'The certificate authority {certificate_authority} does not exist')
        return self.ibp.extract_ca_info(component)