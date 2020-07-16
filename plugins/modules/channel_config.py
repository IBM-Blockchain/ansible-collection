#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import diff_dicts
from ..module_utils.fabric_utils import get_fabric_cfg_path
from ..module_utils.file_utils import get_temp_file
from ..module_utils.module import BlockchainModule
from ..module_utils.msp_utils import convert_identity_to_msp_path
from ..module_utils.proto_utils import proto_to_json, json_to_proto
from ..module_utils.utils import get_console, get_identity_by_module, get_ordering_service_by_module, get_organizations_by_module

from ansible.module_utils._text import to_native
from subprocess import CalledProcessError

import json
import os
import shutil
import subprocess

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
            - C(create) - Create a channel configuration update transaction for a new channel.
            - C(fetch) - Fetch the current channel configuration to the specified I(path).
            - C(compute_update) - Compute a channel configuration update transaction using
              the original configuration at I(origin) and the updated configuration at
              I(updated).
            - C(sign_update) - Sign a channel configuration update transaction.
            - C(apply_update) - Apply a channel configuration update transaction.
        type: str
        required: true
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
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for digital signatures."
            - Only required if the identity specified in I(identity) was enrolled using an HSM,
              and when I(operation) is C(fetch), C(sign), or C(apply_update).
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
    path:
        description:
            - The path to the file where the channel configuration or the channel configuration
              update transaction will be stored.
        type: str
        required: true
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
    organizations:
        description:
            - The list of organizations to add as members in the new channel.
            - The organizations must all be members of the consortium.
            - You can pass strings, which are the names of organizations that are
              registered with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one
              of the M(organization_info) or M(organization) modules.
            - Only required when I(operation) is C(create).
        type: list
        elements: raw
    policies:
        description:
            - The set of policies to add to the new channel. The keys are the policy
              names, and the values are the policies.
            - You can pass strings, which are paths to JSON files containing policies
              in the Hyperledger Fabric format (common.Policy).
            - You can also pass a dict, which must correspond to a parsed policy in the
              Hyperledger Fabric format (common.Policy).
            - You must provide at least an Admins, Writers, and Readers policy.
            - Only required when I(operation) is C(create).
        type: dict
    capabilities:
        description:
            - The capability levels for the new channel.
        type: dict
        suboptions:
            application:
                description:
                    - The application capability level for the new channel.
                    - The value must be a valid application capability level supported by Hyperledger Fabric,
                      and all peers that will join the new channel must support this application capability level.
                    - Example application capability levels include C(V1_4_2) and C(V2_0).
                type: str
                default: V1_4_2
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Create the configuration for a new channel
  ibm.blockchain_platform.channel_config:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    operation: create
    name: mychannel
    path: channel_config_update.bin
    organizations:
      - Org1
    policies:
      Admins: admins-policy.json
      Readers: readers-policy.json
      Writers: writers-policy.json

- name: Fetch the channel configuration
  ibm.blockchain_platform.channel_config:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ordering_service: Ordering Service
    identity: Org1 Admin.json
    msp_id: Org1MSP
    operation: fetch
    name: mychannel
    path: channel_config.bin

- name: Compute the configuration update for the channel
  ibm.blockchain_platform.channel_config:
    operation: compute_update
    name: mychannel
    original: original_channel_config.bin
    updated: updated_channel_config.bin
    path: channel_config_update.bin

- name: Sign the configuration update for the channel
  ibm.blockchain_platform.channel_config:
    operation: sign_update
    identity: Org1 Admin.json
    msp_id: Org1MSP
    name: mychannel
    path: channel_config_update.bin

- name: Apply the configuration update for the channel
  ibm.blockchain_platform.channel_config:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ordering_service: Ordering Service
    identity: Org1 Admin.json
    msp_id: Org1MSP
    operation: apply_update
    name: mychannel
    path: channel_config_update.bin
'''

RETURN = '''
---
path:
    description:
        - The path to the file where the channel configuration or the channel configuration
          update transaction is stored.
    type: str
    returned: always
'''


def create(module):

    # Log in to the IBP console.
    console = get_console(module)

    # Get the organizations.
    organizations = get_organizations_by_module(console, module)

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

    # Build the config update for a new channel.
    name = module.params['name']
    application_capability = module.params['capabilities']['application']
    config_update_json = dict(
        channel_id=name,
        read_set=dict(
            groups=dict(
                Application=dict(
                    groups=dict()
                )
            ),
            values=dict(
                Consortium=dict(
                    value=dict(
                        name='SampleConsortium'
                    )
                )
            )
        ),
        write_set=dict(
            groups=dict(
                Application=dict(
                    groups=dict(),
                    mod_policy='Admins',
                    policies=dict(),
                    values=dict(
                        Capabilities=dict(
                            mod_policy='Admins',
                            value=dict(
                                capabilities={
                                    application_capability: {}
                                }
                            )
                        )
                    ),
                    version=1
                )
            ),
            values=dict(
                Consortium=dict(
                    value=dict(
                        name='SampleConsortium'
                    )
                )
            )
        )
    )

    # Add the organizations to the config update.
    for organization in organizations:
        config_update_json['read_set']['groups']['Application']['groups'][organization.msp_id] = dict()
        config_update_json['write_set']['groups']['Application']['groups'][organization.msp_id] = dict()

    # Add the policies to the config update.
    for policyName, policy in actual_policies.items():
        config_update_json['write_set']['groups']['Application']['policies'][policyName] = dict(
            mod_policy='Admins',
            policy=policy
        )

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
    path = module.params['path']
    if os.path.exists(path):
        changed = False
        try:
            with open(path, 'rb') as file:
                original_config_update_envelope_json = proto_to_json('common.Envelope', file.read())
            changed = diff_dicts(original_config_update_envelope_json, config_update_envelope_json)
        except Exception:
            changed = True
        if changed:
            with open(path, 'wb') as file:
                file.write(config_update_envelope_proto)
        module.exit_json(changed=changed, path=path)
    else:
        with open(path, 'wb') as file:
            file.write(config_update_envelope_proto)
        module.exit_json(changed=True, path=path)


def fetch(module):

    # Log in to the IBP console.
    console = get_console(module)

    # Get the ordering service.
    ordering_service = get_ordering_service_by_module(console, module)

    # Get the identity.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']
    hsm = module.params['hsm']

    # Get the channel and target path.
    name = module.params['name']
    path = module.params['path']

    # Create a temporary file to hold the block.
    block_proto_path = get_temp_file()
    try:

        # Fetch the block.
        with ordering_service.connect(identity, msp_id, hsm) as connection:
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
            except Exception:
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
            subprocess.run([
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
            except Exception:
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
    path = module.params['path']

    # Get the identity and MSP ID.
    identity = get_identity_by_module(module)
    msp_id = module.params['msp_id']
    hsm = module.params['hsm']

    # Load in the existing config update file and see if we've already signed it.
    with open(path, 'rb') as file:
        config_update_envelope_json = proto_to_json('common.Envelope', file.read())
    signatures = config_update_envelope_json['payload']['data'].get('signatures', list())
    for signature in signatures:
        if msp_id == signature['signature_header']['creator']['mspid']:
            return module.exit_json(changed=False, path=path)

    # Need to sign it.
    msp_path = convert_identity_to_msp_path(identity)
    fabric_cfg_path = get_fabric_cfg_path()
    try:
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = msp_path
        env['CORE_PEER_LOCALMSPID'] = msp_id
        env['FABRIC_CFG_PATH'] = fabric_cfg_path
        if hsm:
            env['CORE_PEER_BCCSP_DEFAULT'] = 'PKCS11'
            env['CORE_PEER_BCCSP_PKCS11_LIBRARY'] = hsm['pkcs11library']
            env['CORE_PEER_BCCSP_PKCS11_LABEL'] = hsm['label']
            env['CORE_PEER_BCCSP_PKCS11_PIN'] = hsm['pin']
            env['CORE_PEER_BCCSP_PKCS11_HASH'] = 'SHA2'
            env['CORE_PEER_BCCSP_PKCS11_SECURITY'] = '256'
            env['CORE_PEER_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE'] = os.path.join(msp_path, 'keystore')
        subprocess.run([
            'peer', 'channel', 'signconfigtx', '-f', path
        ], env=env, text=True, close_fds=True, check=True, capture_output=True)
        module.exit_json(changed=True, path=path)
    finally:
        shutil.rmtree(msp_path)
        shutil.rmtree(fabric_cfg_path)


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
    hsm = module.params['hsm']
    with ordering_service.connect(identity, msp_id, hsm) as connection:
        connection.update(name, path)
    module.exit_json(changed=True)


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str'),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        operation=dict(type='str', required=True, choices=['create', 'fetch', 'compute_update', 'sign_update', 'apply_update']),
        ordering_service=dict(type='str'),
        identity=dict(type='raw'),
        msp_id=dict(type='str'),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        name=dict(type='str'),
        path=dict(type='str'),
        original=dict(type='str'),
        updated=dict(type='str'),
        organizations=dict(type='list', elements='raw'),
        policies=dict(type='dict'),
        capabilities=dict(type='dict', default=dict(), options=dict(
            application=dict(type='str', default='V1_4_2')
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('operation', 'create', ['api_endpoint', 'api_authtype', 'api_key', 'organizations', 'policies', 'name', 'path']),
        ('operation', 'fetch', ['api_endpoint', 'api_authtype', 'api_key', 'ordering_service', 'identity', 'msp_id', 'name', 'path']),
        ('operation', 'compute_update', ['name', 'path', 'original', 'updated']),
        ('operation', 'sign_update', ['identity', 'msp_id', 'name', 'path']),
        ('operation', 'apply_update', ['api_endpoint', 'api_authtype', 'api_key', 'ordering_service', 'identity', 'msp_id', 'name', 'path'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:
        operation = module.params['operation']
        if operation == 'create':
            create(module)
        elif operation == 'fetch':
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
