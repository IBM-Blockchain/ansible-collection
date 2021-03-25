#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.proto_utils import proto_to_json
from ..module_utils.utils import (get_console, get_identity_by_module,
                                  get_peer_by_module, resolve_identity)

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
            - C(absent) - If the peer has joined the channel with the specified name, then an error will be thrown,
              as it is not possible for a peer to leave a channel.
            - C(present) - Asserts that the peer has joined the channel with the specified name. If the peer has not
              joined the channel with the specified name, then the peer will be joined to the channel using the specified
              configuration block.
        type: str
        default: present
        choices:
            - absent
            - present
    peer:
        description:
            - The peer to join to the channel.
            - You can pass a string, which is the display name of a peer registered
              with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one of the
              M(peer_info) or M(peer) modules.
        type: raw
        required: true
    identity:
        description:
            - The identity to use when interacting with the peer.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
        type: raw
        required: true
    msp_id:
        description:
            - The MSP ID to use for interacting with the peer.
        type: str
        required: true
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for digital signatures."
            - Only required if the identity specified in I(identity) was enrolled using an HSM.
        type: dict
        suboptions:
            pkcs11library:
                description:
                    - "The PKCS #11 library that should be used for digital signatures."
                type: str
            label:
                description:
                    - The HSM label that should be used for digital signatures.
                type: str
            pin:
                description:
                    - The HSM pin that should be used for digital signatures.
                type: str
    name:
        description:
            - The name of the channel.
            - Only required when I(state) is C(absent).
        type: str
    path:
        description:
            - The path to the file where the channel genesis block is stored.
            - Only required when I(state) is C(present).
        type: str
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Join the peer to the channel
  ibm.blockchain_platform.peer_channel:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    path: channel_genesis_block.bin

- name: Ensure the peer is not joined to the channel
  ibm.blockchain_platform.peer_channel:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    name: channel1
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
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        operation=dict(type='str', required=False, choices=['join']),
        peer=dict(type='raw', required=True),
        identity=dict(type='raw', required=True),
        msp_id=dict(type='str', required=True),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        name=dict(type='str'),
        path=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['path']),
        ('state', 'absent', ['name'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the peer.
        peer = get_peer_by_module(console, module)

        # Get the identity.
        identity = get_identity_by_module(module)
        msp_id = module.params['msp_id']
        hsm = module.params['hsm']
        identity = resolve_identity(console, module, identity, msp_id)

        # Connect to the peer.
        with peer.connect(identity, msp_id, hsm) as connection:

            # Get the list of channels the peer has joined.
            channels = connection.list_channels()

            # Get the channel and target path.
            name = module.params['name']
            path = module.params['path']

            # Load the block to determine what channel it is for.
            if not name:
                with open(path, 'rb') as file:
                    block_json = proto_to_json('common.Block', file.read())
                name = block_json['data']['data'][0]['payload']['header']['channel_header']['channel_id']

            # Determine if the channel exists.
            channel_exists = name in channels

            # Act depending on the desired state.
            state = module.params['state']
            if state == 'absent' and channel_exists:

                # The peer has joined the channel, but we can't remove it yet.
                raise Exception(f'cannot unjoin peer from channel {name}')

            elif state == 'absent':

                # The peer has not joined the channel, nothing to do.
                return module.exit_json(changed=False)

            elif state == 'present' and not channel_exists:

                # The peer hasn't joined the channel, so join it.
                connection.join_channel(path)
                return module.exit_json(changed=True)

            else:

                # The peer has joined the channel, nothing to do.
                return module.exit_json(changed=False)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
