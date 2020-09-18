#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.file_utils import get_temp_file, equal_files
from ..module_utils.module import BlockchainModule
from ..module_utils.ordering_services import OrderingService
from ..module_utils.utils import get_console, get_identity_by_module, get_ordering_service_by_module, get_ordering_service_nodes_by_module, resolve_identity

from ansible.module_utils.basic import _load_params, env_fallback
from ansible.module_utils._text import to_native

import os
import shutil

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_block
short_description: Fetch blocks for a Hyperledger Fabric channel
description:
    - Fetch blocks for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
    operation:
        description:
            - C(fetch) - Fetch the target block to the specified I(path).
        type: str
        required: true
    ordering_service:
        description:
            - The ordering service to use to manage the channel.
            - You can pass a string, which is the cluster name of a ordering service registered
              with the IBM Blockchain Platform console.
            - You can also pass a list, which must match the result format of one of the
              M(ordering_service_info) or M(ordering_service) modules.
            - Only required when I(operation) is C(fetch).
            - Cannot be specified with I(ordering_service_nodes).
        type: raw
        required: true
    ordering_service_nodes:
        description:
            - The ordering service nodes to use to manage the channel.
            - You can pass strings, which are the names of ordering service nodes that are
              registered with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one
              of the M(ordering_service_node_info) or M(ordering_service_node) modules.
            - Only required when I(operation) is C(fetch).
            - Cannot be specified with I(ordering_service).
        type: raw
    identity:
        description:
            - The identity to use when interacting with the ordering service or for signing
              channel configuration update transactions.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
        type: raw
        required: true
    msp_id:
        description:
            - The MSP ID to use for interacting with the ordering service or for signing
              channel configuration update transactions.
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
        type: str
        required: true
    target:
        description:
            - The target block to fetch.
            - Can be the number of the block to fetch, or one of C(newest), C(oldest) or C(config).
        type: str
        required: true
    path:
        description:
            - The path to the file where the channel configuration or the channel configuration
              update transaction will be stored.
        type: str
        required: true
    tls_handshake_time_shift:
        type: str
        description:
            - The amount of time to shift backwards for certificate expiration checks during TLS handshakes with the ordering service endpoint.
            - Only use this option if the ordering service TLS certificates have expired.
            - The value must be a duration, for example I(30m), I(24h), or I(6h30m).
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Fetch the genesis block for the channel
  ibm.blockchain_platform.channel_block:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    operation: fetch
    ordering_service: Ordering Service
    identity: Org1 Admin.json
    msp_id: Org1MSP
    name: mychannel
    target: "0"
    path: channel_genesis_block.bin
'''

RETURN = '''
---
path:
    description:
        - The path to the file where the channel block is stored.
    type: str
    returned: always
'''


def fetch(module):

    # Log in to the IBP console.
    console = get_console(module)

    # Get the ordering service.
    ordering_service_specified = module.params['ordering_service'] is not None
    if ordering_service_specified:
        ordering_service = get_ordering_service_by_module(console, module)
    else:
        ordering_service_nodes = get_ordering_service_nodes_by_module(console, module)
        ordering_service = OrderingService(ordering_service_nodes)
    tls_handshake_time_shift = module.params['tls_handshake_time_shift']

    # Get the identity.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']
    hsm = module.params['hsm']
    identity = resolve_identity(console, module, identity, msp_id)

    # Get the channel and target path.
    name = module.params['name']
    path = module.params['path']
    target = module.params['target']

    # Create a temporary file to hold the block.
    block_proto_path = get_temp_file()
    try:

        # Fetch the block.
        with ordering_service.connect(identity, msp_id, hsm, tls_handshake_time_shift) as connection:
            connection.fetch(name, target, block_proto_path)

        # Compare and copy if needed.
        if os.path.exists(path):
            changed = not equal_files(path, block_proto_path)
            if changed:
                shutil.copyfile(block_proto_path, path)
            module.exit_json(changed=changed, path=path)
        else:
            shutil.copyfile(block_proto_path, path)
            module.exit_json(changed=True, path=path)

    # Ensure the temporary file is cleaned up.
    finally:
        os.remove(block_proto_path)


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str'),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        operation=dict(type='str', required=True, choices=['fetch']),
        ordering_service=dict(type='raw'),
        ordering_service_nodes=dict(type='list', elements='raw'),
        tls_handshake_time_shift=dict(type='str', fallback=(env_fallback, ['IBP_TLS_HANDSHAKE_TIME_SHIFT'])),
        identity=dict(type='raw'),
        msp_id=dict(type='str'),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        name=dict(type='str'),
        path=dict(type='str'),
        target=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('operation', 'fetch', ['api_endpoint', 'api_authtype', 'api_key', 'identity', 'msp_id', 'name', 'path', 'target']),
    ]
    # Ansible doesn't allow us to say "require one of X and Y only if condition A is true",
    # so we need to handle this ourselves by seeing what was passed in.
    actual_params = _load_params()
    if actual_params.get('operation', None) in ['fetch']:
        required_one_of = [
            ['ordering_service', 'ordering_service_nodes']
        ]
    else:
        required_one_of = []
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if, required_one_of=required_one_of)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:
        operation = module.params['operation']
        if operation == 'fetch':
            fetch(module)
        else:
            raise Exception(f'Invalid operation {operation}')

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
