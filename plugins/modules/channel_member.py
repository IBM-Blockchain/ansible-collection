#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.channel_utils import get_highest_capability
from ..module_utils.dict_utils import equal_dicts, merge_dicts, copy_dict
from ..module_utils.module import BlockchainModule
from ..module_utils.msp_utils import organization_to_msp
from ..module_utils.proto_utils import proto_to_json, json_to_proto
from ..module_utils.utils import get_console, get_organization_by_module, get_peers_by_module

from ansible.module_utils._text import to_native

import json
import urllib

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_member
short_description: Manage a member for a Hyperledger Fabric channel
description:
    - Add, update, and remove members for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    api_endpoint:
        description:
            - The URL for the IBM Blockchain Platform console.
        type: str
        required: true
    api_authtype:
        description:
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication.
              You must provide a valid API key using I(api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication.
              You must provide both a valid API key using I(api_key) and API secret using I(api_secret).
        type: str
        required: true
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
        required: true
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: int
        default: 60
    api_token_endpoint:
        description:
            - The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.
            - Only required when I(api_authtype) is C(ibmcloud), and you are using IBM internal staging servers for testing.
        type: str
        default: https://iam.cloud.ibm.com/identity/token
    state:
        description:
            - C(absent) - An organization matching the specified name will be removed from the channel.
            - C(present) - Asserts that an organization matching the specified name and configuration exists
              in the channel. If no organization matches the specified name, the organization will be added
              to the channel. If an organization matches the specified name but the configuration does not
              match, then the organization in the channel will be updated.
        type: str
        default: present
        choices:
            - absent
            - present
    path:
        description:
            - Path to current the channel configuration file.
            - This file can be fetched by using the M(channel_config) module.
            - This file will be updated in place. You will need to keep a copy of the original file for computing the configuration
              update.
        type: str
        required: true
    organization:
        description:
            - The organization to add, update, or remove from the channel.
            - You can pass a string, which is the display name of an organization registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(organization_info) or M(organization[]) modules.
        type: raw
        required: true
    anchor_peers:
        description:
            - The anchor peers for this organization in this channel.
            - You can pass strings, which are the names of peers that are
              registered with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one
              of the M(peer_info) or M(peer) modules.
        type: list
        elements: raw
    policies:
        description:
            - The set of policies for the channel member. The keys are the policy
              names, and the values are the policies.
            - You can pass strings, which are paths to JSON files containing policies
              in the Hyperledger Fabric format (common.Policy).
            - You can also pass a dict, which must correspond to a parsed policy in the
              Hyperledger Fabric format (common.Policy).
            - Default policies are provided for the Admins, Writers, Readers, and Endorsement
              policies. You only need to provide policies if you want to override these default
              policies, or add additional policies.
        type: dict
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Add the organization to the channel
  ibm.blockchain_platform.channel_member:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    organization: Org2
    path: channel_config.bin

- name: Update the organization in the channel with anchor peers
  ibm.blockchain_platform.channel_member:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    organization: Org2
    path: channel_config.bin
    anchor_peers:
      - Org2 Peer

- name: Remove the organization from the channel
  ibm.blockchain_platform.channel_member:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    organization: Org2
    path: channel_config.bin
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
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic'], required=True),
        api_key=dict(type='str', no_log=True, required=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        path=dict(type='str', required=True),
        organization=dict(type='raw', required=True),
        anchor_peers=dict(type='list', elements='raw', default=list()),
        policies=dict(type='dict', default=dict())
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the organization and the target path.
        path = module.params['path']
        organization = get_organization_by_module(console, module)

        # Build the anchor peer values.
        anchor_peers = get_peers_by_module(console, module, 'anchor_peers')
        if len(anchor_peers) > 0:
            anchor_peers_value = dict(
                mod_policy='Admins',
                value=dict(
                    anchor_peers=list()
                )
            )
            for anchor_peer in anchor_peers:
                api_url_split = urllib.parse.urlsplit(anchor_peer.api_url)
                anchor_peers_value['value']['anchor_peers'].append(dict(
                    host=api_url_split.hostname,
                    port=api_url_split.port
                ))
        else:
            anchor_peers_value = None

        # Get the policies.
        policies = module.params['policies']
        actual_policies = dict()
        for policyName, policy in policies.items():
            if isinstance(policy, str):
                with open(policy, 'r') as file:
                    actual_policies[policyName] = json.load(file)
            elif isinstance(policy, dict):
                actual_policies[policyName] = policy
            else:
                raise Exception(f'The policy {policyName} is invalid')

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())

        # Determine the capabilities for this channel.
        highest_capability = get_highest_capability(config_json['channel_group'])
        endorsement_policy_required = False
        if highest_capability is not None and highest_capability >= 'V2_0':
            endorsement_policy_required = True

        # Check to see if the channel member exists.
        application_groups = config_json['channel_group']['groups']['Application']['groups']
        msp = application_groups.get(organization.msp_id, None)

        # Handle the desired state appropriately.
        state = module.params['state']
        if state == 'present' and msp is None:

            # Add the channel member.
            msp = organization_to_msp(organization, endorsement_policy_required, actual_policies)
            if anchor_peers_value is not None:
                msp['values']['AnchorPeers'] = anchor_peers_value
            application_groups[organization.msp_id] = msp

        elif state == 'present' and msp is not None:

            # Update the channel member.
            new_msp = organization_to_msp(organization, endorsement_policy_required, actual_policies)
            if anchor_peers_value is not None:
                new_msp['values']['AnchorPeers'] = anchor_peers_value
            updated_msp = copy_dict(msp)
            merge_dicts(updated_msp, new_msp)
            if equal_dicts(msp, updated_msp):
                return module.exit_json(changed=False)
            application_groups[organization.msp_id] = updated_msp

        elif state == 'absent' and msp is None:

            # Nothing to do.
            return module.exit_json(changed=False)

        elif state == 'absent' and msp is not None:

            # Delete the channel member.
            del application_groups[organization.msp_id]

        # Save the config.
        config_proto = json_to_proto('common.Config', config_json)
        with open(path, 'wb') as file:
            file.write(config_proto)
        module.exit_json(changed=True)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
