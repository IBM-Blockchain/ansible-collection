#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.file_utils import get_temp_file, equal_files
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console, get_identity_by_module, get_ordering_service_by_module

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
            - C(fetch) - Fetch the target block to the specified I(path).
        type: str
    ordering_service:
        description:
            - The ordering service to use to manage the channel.
            - You can pass a string, which is the cluster name of a ordering service registered
              with the IBM Blockchain Platform console.
            - You can also pass a list, which must match the result format of one of the
              M(ordering_service_info) or M(ordering_service) modules.
            - Only required when I(operation) is C(fetch) or C(apply_update).
        type: raw
    identity:
        description:
            - The identity to use when interacting with the ordering service or for signing
              channel configuration update transactions.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
            - Only required when I(operation) is C(fetch), C(sign_update), or C(apply_update).
        type: raw
    msp_id:
        description:
            - The MSP ID to use for interacting with the ordering service or for signing
              channel configuration update transactions.
            - Only required when I(operation) is C(fetch), C(sign), or C(apply_update).
        type: str
    name:
        description:
            - The name of the channel.
        type: str
    target:
        description:
            - The target block to fetch.
            - Can be the number of the block to fetch, or one of C(newest), C(oldest) or C(config).
        type: str
    path:
        description:
            - The path to the file where the channel configuration or the channel configuration
              update transaction will be stored.
        type: str
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
path:
    description:
        - The path to the file where the channel block is stored.
    type: str
'''


def fetch(module):

    # Log in to the IBP console.
    console = get_console(module)

    # Get the ordering service.
    ordering_service = get_ordering_service_by_module(console, module)

    # Get the identity.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']

    # Get the channel and target path.
    name = module.params['name']
    path = module.params['path']
    target = module.params['target']

    # Create a temporary file to hold the block.
    block_proto_path = get_temp_file()
    try:

        # Fetch the block.
        with ordering_service.connect(identity, msp_id) as connection:
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
        api_key=dict(type='str'),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        operation=dict(type='str', required=True, choices=['create', 'fetch', 'compute_update', 'sign_update', 'apply_update']),
        ordering_service=dict(type='str'),
        identity=dict(type='raw'),
        msp_id=dict(type='str'),
        name=dict(type='str'),
        path=dict(type='str'),
        target=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('operation', 'fetch', ['api_endpoint', 'api_authtype', 'api_key', 'ordering_service', 'identity', 'msp_id', 'name', 'path', 'target']),
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

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
