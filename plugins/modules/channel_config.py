#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import diff_dicts
from ..module_utils.file_utils import get_temp_file
from ..module_utils.msp_utils import convert_identity_to_msp_path
from ..module_utils.proto_utils import proto_to_json, json_to_proto
from ..module_utils.utils import get_console, get_identity_by_module, get_ordering_service_by_module

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from subprocess import CalledProcessError

import json
import os
import shutil
import subprocess
import tempfile

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_config
short_description: Manage the configuration for a Hyperledger Fabric channel
description:
    - Fetch and update the configuration for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication. You must provide
              a valid API key using I(ibp_api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication. You must provide both a
              valid API key using I(ibp_api_key) and API secret using I(ibp_api_secret).
        type: str
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(ibp_api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: int
        default: 60
    operation:
        description:
            - C(fetch) - Fetch the current channel configuration to the specified I(path).
            - C(compute_update) - Compute a channel configuration update transaction using
              the original configuration at I(origin) and the updated configuration at
              I(updated).
            - C(sign_update) - Sign a channel configuration update transaction.
            - C(apply_update) - Apply a channel configuration update transaction.
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
    path:
        description:
            - The path to the file where the channel configuration or the channel configuration
              update transaction will be stored.
        type: str
    original:
        description:
            - The path to the file where the original channel configuration is stored.
            - Only required when I(operation) is C(compute_update).
        type: str
    updated:
        description:
            - The path to the file where the updated channel configuration is stored.
            - Only required when I(operation) is C(compute_update).
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
        - The path to the file where the channel configuration or the channel configuration
          update transaction is stored.
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

    # Create a temporary file to hold the block.
    block_proto_path = get_temp_file()
    try:

        # Fetch the block.
        with ordering_service.connect(identity, msp_id) as connection:
            connection.fetch(name, 'config', block_proto_path)

        # Convert it into JSON.
        with open(block_proto_path, 'rb') as file:
            block_json = proto_to_json('common.Block', file.read())

        # Extract the config.
        config_json = block_json['data']['data'][0]['payload']['data']['config']
        config_proto = json_to_proto('common.Config', config_json)

        # Compare and copy if needed.
        if os.path.exists(path):
            changed = False
            try:
                with open(path, 'rb') as file:
                    original_config_json = proto_to_json('common.Config', file.read())
                changed = diff_dicts(original_config_json, config_json)
            except:
                changed = True
            if changed:
                with open(path, 'wb') as file:
                    file.write(config_proto)
            module.exit_json(changed=changed, path=path)
        else:
            with open(path, 'wb') as file:
                file.write(config_proto)
            module.exit_json(changed=True, path=path)

    # Ensure the temporary file is cleaned up.
    finally:
        os.remove(block_proto_path)

def compute_update(module):

    # Get the channel and target path.
    name = module.params['name']
    path = module.params['path']
    original = module.params['original']
    updated = module.params['updated']

    # Create a temporary file to hold the block.
    config_update_proto_path = get_temp_file()
    try:

        # Run the command to compute the update
        try:
            process = subprocess.run([
                'configtxlator', 'compute_update', f'--channel_id={name}', f'--original={original}', f'--updated={updated}', f'--output={config_update_proto_path}'
            ], text=True, close_fds=True, check=True, capture_output=True)
        except CalledProcessError as e:
            if e.stderr.find('no differences detected') != -1:
                if os.path.exists(path):
                    os.remove(path)
                    return module.exit_json(changed=True, path=None)
                else:
                    return module.exit_json(changed=False, path=None)
            raise

        # Convert it into JSON.
        with open(config_update_proto_path, 'rb') as file:
            config_update_json = proto_to_json('common.ConfigUpdate', file.read())

        # Build the config envelope.
        config_update_envelope_json = dict(
            payload=dict(
                header=dict(
                    channel_header=dict(
                        channel_id=name,
                        type=2
                    )
                ),
                data=dict(
                    config_update=config_update_json
                )
            )
        )
        config_update_envelope_proto = json_to_proto('common.Envelope', config_update_envelope_json)

        # Compare and copy if needed.
        if os.path.exists(path):
            changed = False
            try:
                with open(path, 'rb') as file:
                    original_config_update_envelope_json = proto_to_json('common.Envelope', file.read())
                changed = diff_dicts(original_config_update_envelope_json, config_update_envelope_json)
            except:
                changed = True
            if changed:
                with open(path, 'wb') as file:
                    file.write(config_update_envelope_proto)
            module.exit_json(changed=changed, path=path)
        else:
            with open(path, 'wb') as file:
                file.write(config_update_envelope_proto)
            module.exit_json(changed=True, path=path)

    # Ensure the temporary file is cleaned up.
    finally:
        os.remove(config_update_proto_path)

def sign_update(module):

    # Get the channel and target path.
    name = module.params['name']
    path = module.params['path']

    # Get the identity and MSP ID.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']

    # Load in the existing config update file and see if we've already signed it.
    with open(path, 'rb') as file:
        config_update_envelope_json = proto_to_json('common.Envelope', file.read())
    signatures = config_update_envelope_json['payload']['data'].get('signatures', list())
    for signature in signatures:
        if msp_id == signature['signature_header']['creator']['mspid']:
            return module.exit_json(changed=False, path=path)

    # Need to sign it.
    msp_path = convert_identity_to_msp_path(identity)
    env = os.environ.copy()
    env['CORE_PEER_MSPCONFIGPATH'] = msp_path
    env['CORE_PEER_LOCALMSPID'] = msp_id
    subprocess.run([
        'peer', 'channel', 'signconfigtx', '-f', path
    ], env=env, text=True, close_fds=True, check=True, capture_output=True)
    module.exit_json(changed=True, path=path)

def apply_update(module):

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

    # Update the channel.
    with ordering_service.connect(identity, msp_id) as connection:
        connection.update(name, path)
    module.exit_json(changed=True)

def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str'),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic']),
        api_key=dict(type='str'),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        operation=dict(type='str', required=True, choices=['fetch', 'compute_update', 'sign_update', 'apply_update']),
        ordering_service=dict(type='str'),
        identity=dict(type='raw'),
        msp_id=dict(type='str'),
        name=dict(type='str'),
        path=dict(type='str'),
        original=dict(type='str'),
        updated=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('operation', 'fetch', ['api_endpoint', 'api_authtype', 'api_key', 'ordering_service', 'identity', 'msp_id', 'name', 'path']),
        ('operation', 'compute_update', ['name', 'path', 'original', 'updated']),
        ('operation', 'sign_update', ['identity', 'msp_id', 'name', 'path']),
        ('operation', 'apply_update', ['api_endpoint', 'api_authtype', 'api_key', 'ordering_service', 'identity', 'msp_id', 'name', 'path'])
    ]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:
        operation = module.params['operation']
        if operation == 'fetch':
            fetch(module)
        elif operation == 'compute_update':
            compute_update(module)
        elif operation == 'sign_update':
            sign_update(module)
        elif operation == 'apply_update':
            apply_update(module)
        else:
            raise Exception(f'Invalid operation {operation}')

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))

if __name__ == '__main__':
    main()