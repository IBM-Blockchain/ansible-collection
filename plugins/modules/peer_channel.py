#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.proto_utils import proto_to_json
from ..module_utils.utils import get_console, get_identity_by_module, get_peer_by_module

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: peer_channel
short_description: Manage the list of channels joined by a Hyperledger Fabric peer
description:
    - Join a Hyperledger Fabric peer to a channel by using the IBM Blockchain Platform.
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
    operation:
        description:
            - C(join) - Join the specified I(peer) to the channel with the genesis block specified in I(path).
        type: str
    peer:
        description:
            - The peer to join to the channel.
            - You can pass a string, which is the display name of a peer registered
              with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one of the
              M(peer_info) or M(peer) modules.
        type: raw
    identity:
        description:
            - The identity to use when interacting with the peer.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
        type: raw
    msp_id:
        description:
            - The MSP ID to use for interacting with the peer.
        type: str
    path:
        description:
            - The path to the file where the channel genesis block is stored.
        type: str
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
'''


def join(module):

    # Log in to the IBP console.
    console = get_console(module)

    # Get the peer.
    peer = get_peer_by_module(console, module)

    # Get the identity.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']

    # Get the channel and target path.
    path = module.params['path']

    # Connect to the peer.
    with peer.connect(identity, msp_id) as connection:

        # Get the list of channels the peer has joined.
        channels = connection.list_channels()

        # Load the block to determine what channel it is for.
        with open(path, 'rb') as file:
            block_json = proto_to_json('common.Block', file.read())
        name = block_json['data']['data'][0]['payload']['header']['channel_header']['channel_id']

        # Determine if we've joined the channel.
        joined_channel = name in channels
        if joined_channel:
            return module.exit_json(changed=False)

        # Join the channel.
        connection.join_channel(path)
        module.exit_json(changed=True)


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str'),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic']),
        api_key=dict(type='str'),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        operation=dict(type='str', required=True, choices=['join']),
        peer=dict(type='raw'),
        identity=dict(type='raw'),
        msp_id=dict(type='str'),
        path=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('operation', 'join', ['api_endpoint', 'api_authtype', 'api_key', 'peer', 'identity', 'msp_id', 'path']),
    ]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:
        operation = module.params['operation']
        if operation == 'join':
            join(module)
        else:
            raise Exception(f'Invalid operation {operation}')

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
