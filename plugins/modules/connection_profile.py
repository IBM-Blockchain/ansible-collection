#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import equal_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console, get_organization_by_module, get_certificate_authority_by_module, get_peers_by_module

from ansible.module_utils._text import to_native

import base64
import json
import os

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: connection_profile
short_description: Manage a connection profile for a Hyperledger Fabric network
description:
    - Create, update, or delete a connection profile for a Hyperledger Fabric network by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    api_endpoint:
        description:
            - The URL for the IBM Blockchain Platform console.
        type: str
    api_authtype:
        description:
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication.
              You must provide a valid API key using I(api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication.
              You must provide both a valid API key using I(api_key) and API secret using I(api_secret).
        type: str
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: integer
        default: 60
    api_token_endpoint:
        description:
            - The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.
            - Only required when I(api_authtype) is C(ibmcloud), and you are using IBM internal staging servers for testing.
        type: str
        default: https://iam.cloud.ibm.com/identity/token
    state:
        description:
            - C(absent) - If a connection profile exists at the specified path, it will be removed.
            - C(present) - Asserts that a connection profile exists at the specified path. If no
              connection profile exists, a connection profile will be created. If a connection profile
              exists, but does not match the specfied configuration, then the connection profile will
              be updated, if it can be. If it cannot be updated, it will be removed and re-created
              with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    name:
        description:
            - The name of this connection profile.
        type: str
    path:
        description:
            - The path to the JSON file where the connection profile will be stored.
    organization:
        description:
            - The organization for this connection profile.
    certificate_authority:
        description:
            - The certificate authority to reference in this connection profile.
            - You can pass a string, which is the display names of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
        type: list
        elements: raw
    peers:
        description:
            - The peers to reference in this connection profile.
            - You can pass strings, which are the display names of peers registered
              with the IBM Blockchain Platform console.
            - You can also pass dictionaries, which must match the result format of one of the
              M(peer_info) or M(peer) modules.
        type: list
        elements: raw
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
{}
'''


def main():

    # Create the module.
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str'),
        path=dict(type='str', required=True),
        organization=dict(type='raw'),
        certificate_authority=dict(type='raw'),
        peers=dict(type='list', elements='raw', default=list())
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['name', 'organization', 'peers'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the connection profile exists.
        path = module.params['path']
        path_exists = os.path.isfile(path)

        # If the connection profile should not exist, handle that now.
        state = module.params['state']
        if state == 'absent' and path_exists:
            os.remove(path)
            return module.exit_json(changed=True)
        elif state == 'absent':
            return module.exit_json(changed=False)

        # Get the organization, certificate authority and peers.
        organization = get_organization_by_module(console, module)
        if module.params['certificate_authority']:
            certificate_authority = get_certificate_authority_by_module(console, module)
        peers = get_peers_by_module(console, module)

        # Build the connection profile.
        certificate_authority_names = list()
        certificate_authorities_dict = dict()
        peer_names = list()
        peers_dict = dict()
        if certificate_authority is not None:
            certificate_authority_names.append(certificate_authority.name)
            certificate_authorities_dict[certificate_authority.name] = {
                'url': certificate_authority.api_url,
                'caName': certificate_authority.ca_name,
                'tlsCACerts': {
                    'pem': base64.b64decode(certificate_authority.pem).decode('utf8')
                }
            }
        for peer in peers:
            peer_names.append(peer.name)
            peers_dict[peer.name] = {
                'url': peer.api_url,
                'tlsCACerts': {
                    'pem': base64.b64decode(peer.pem).decode('utf8')
                }
            }
        connection_profile = {
            'name': module.params['name'],
            'version': '1.0',
            'client': {
                'organization': organization.name,
                'connection': {
                    'timeout': {
                        'peer': {
                            'endorser': 300
                        },
                        'orderer': 300
                    }
                }
            },
            'organizations': {
                organization.name: {
                    'mspid': organization.msp_id,
                    'peers': peer_names,
                    'certificateAuthorities': certificate_authority_names
                }
            },
            'certificateAuthorities': certificate_authorities_dict,
            'peers': peers_dict
        }

        # Now, either create or update the connection profile.
        changed = False
        if state == 'present' and not path_exists:

            # Create the connection profile.
            with open(path, 'w') as file:
                json.dump(connection_profile, file, indent=4)
            changed = True

        elif state == 'present' and path_exists:

            # Load the existing connection profile.
            with open(path, 'r') as file:
                existing_connection_profile = json.load(file)

            # Compare the two connection profiles, and update it if it has changed.
            if not equal_dicts(existing_connection_profile, connection_profile):
                with open(path, 'w') as file:
                    json.dump(connection_profile, file, indent=4)
                changed = True

        # Return the connection profile.
        module.exit_json(changed=changed, connection_profile=connection_profile)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
