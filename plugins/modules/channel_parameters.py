#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import equal_dicts, copy_dict
from ..module_utils.module import BlockchainModule
from ..module_utils.proto_utils import proto_to_json, json_to_proto

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_parameters
short_description: Manage the parameters for a Hyperledger Fabric channel
description:
    - Specify the parameters for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    path:
        description:
            - Path to current the channel configuration file.
            - This file can be fetched by using the M(channel_config) module.
            - This file will be updated in place. You will need to keep a copy of the original file for computing the configuration
              update.
        type: str
        required: true
    batch_size:
        description:
            - The batch size parameters for the channel.
        type: dict
        suboptions:
            max_message_count:
                description:
                    - The maximum number of messages that should be present in a block for the channel.
                type: int
            absolute_max_bytes:
                description:
                    - The total size of all the messages in a block for the channel must not exceed this value.
                type: int
            preferred_max_bytes:
                description:
                    - The total size of all the messages in a block for the channel should not exceed this value.
                type: int
    batch_timeout:
        description:
            - The maximum time to wait before cutting a new block for the channel.
            - Example values include I(500ms), I(5m), or I(24h).
        type: str
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Set batch size channel parameters
  ibm.blockchain_platform.channel_parameters:
    path: channel_config.bin
    batch_size:
      max_message_count: 10000
      absolute_max_bytes: 10485760
      preferred_max_bytes: 5242880

- name: Set batch timeout channel parameter
  ibm.blockchain_platform.channel_parameters:
    path: channel_config.bin
    batch_timeout: 500ms
'''

RETURN = '''
---
{}
'''


def main():

    # Create the module.
    argument_spec = dict(
        path=dict(type='str', required=True),
        batch_size=dict(type='dict', options=dict(
            max_message_count=dict(type='int'),
            absolute_max_bytes=dict(type='int'),
            preferred_max_bytes=dict(type='int')
        )),
        batch_timeout=dict(type='str')
    )
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True)

    # Ensure all exceptions are caught.
    try:

        # Get the target path, policy name and capabilities.
        path = module.params['path']
        batch_size = module.params['batch_size']
        batch_timeout = module.params['batch_timeout']

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())
        original_config_json = copy_dict(config_json)

        # Handle the batch size.
        if batch_size:
            orderer_group = config_json['channel_group']['groups']['Orderer']
            orderer_values = orderer_group['values']
            orderer_batch_size_value = orderer_values['BatchSize']
            for key in batch_size:
                if batch_size[key]:
                    orderer_batch_size_value['value'][key] = batch_size[key]

        # Handle the batch timeout.
        if batch_timeout:
            orderer_group = config_json['channel_group']['groups']['Orderer']
            orderer_values = orderer_group['values']
            orderer_batch_timeout_value = orderer_values['BatchTimeout']
            orderer_batch_timeout_value['value']['timeout'] = batch_timeout

        # If nothing changed, get out now.
        if equal_dicts(original_config_json, config_json):
            return module.exit_json(changed=False)

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
