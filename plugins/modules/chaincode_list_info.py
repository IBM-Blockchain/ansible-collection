#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import (get_console, get_identity_by_module,
                                  get_peer_by_module, resolve_identity)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: chaincode_list_info
short_description: Get information about all installed and committed chaincodes on a Hyperledger Fabric channel
description:
    - Get inofrmation on a chaincode definition on a Hyperledger Fabric channel
author: Mark Edwards
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
    peer:
        description:
            - The peer to use to manage the committed chaincode definition.
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
    channel:
        description:
            - The name of the channel.
        type: str
        required: true
'''

EXAMPLES = '''
- name: Show information on 'Org1 Peer' chaincodes
  ibm.blockchain_platform.committed_chaincode:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    channel: mychannel


'''

RETURN = '''
---
committed_chaincode:
    description:
        - The committed chaincode definition.
    type: dict
    returned: when I(state) is C(present)
    contains:
        installed_chaincodes:
            description:
                - list of installed chaincodes on the peer
            type: array
        committed_chaincodes:
            description:
                - List of committed chaincode definitions
            type: array
'''


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str',
                          required=True,
                          choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(
            type='str', default='https://iam.cloud.ibm.com/identity/token'),
        peer=dict(type='raw', required=True),
        identity=dict(type='raw', required=True),
        msp_id=dict(type='str', required=True),
        hsm=dict(type='dict',
                 options=dict(pkcs11library=dict(type='str', required=True),
                              label=dict(type='str',
                                         required=True,
                                         no_log=True),
                              pin=dict(type='str', required=True,
                                       no_log=True))),
        # organizations=dict(type='list', elements='raw'),
        channel=dict(type='str', required=True),
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
    ]
    mutually_exclusive = [['endorsement_policy_ref', 'endorsement_policy']]
    module = BlockchainModule(min_fabric_version='2.1.1',
                              argument_spec=argument_spec,
                              supports_check_mode=True,
                              required_if=required_if,
                              mutually_exclusive=mutually_exclusive)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the peer, identity, and MSP ID.
        peer = get_peer_by_module(console, module)
        identity = get_identity_by_module(module)
        msp_id = module.params['msp_id']
        hsm = module.params['hsm']
        identity = resolve_identity(console, module, identity, msp_id)

        # Extract the chaincode information.
        channel = module.params['channel']

        # Check if this chaincode is already committed on the channel.
        with peer.connect(module, identity, msp_id, hsm) as peer_connection:
            committed_chaincodes = peer_connection.query_committed_chaincodes(
                channel)
            installed_chaincodes = peer_connection.list_installed_chaincodes_newlc(
            )

            module.json_log({
                'msg': 'got the commited chaincodes',
                'chaincodes': committed_chaincodes
            })
            module.json_log({
                'msg': 'got the installed (newlc) chaincodes',
                'chaincodes': installed_chaincodes
            })

        # Return the committed chaincode.
        return module.exit_json(committed_chaincodes=committed_chaincodes,
                                installed_chaincodes=installed_chaincodes)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
