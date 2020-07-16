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
module: channel_capabilities
short_description: Manage the capabilities for a Hyperledger Fabric channel
description:
    - Specify the capability levels for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
    application:
        description:
            - The application capability level for the channel.
            - The value must be a valid application capability level supported by Hyperledger Fabric,
              and all peers in the channel being updated must support this application capability level.
            - Example application capability levels include C(V1_4_2) and C(V2_0).
        type: str
    channel:
        description:
            - The channel capability level.
            - The value must be a valid channel capability level supported by Hyperledger Fabric,
              and all peers and ordering service nodes in the channel being updated must support
              this channel capability level.
            - Example channel capability levels include C(V1_4_3) and C(V2_0).
        type: str
    orderer:
        description:
            - The orderer capability level for the channel.
            - The value must be a valid orderer capability level supported by Hyperledger Fabric,
              and all ordering service nodes in the channel being updated must support this orderer
              capability level.
            - Example orderer capability levels include C(V1_4_2) and C(V2_0).
        type: str
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Set application capability level for Hyperledger Fabric v1.4.x
  ibm.blockchain_platform.channel_capabilities:
    path: channel_config.bin
    application: V1_4_2

- name: Set channel capability level for Hyperledger Fabric v1.4.x
  ibm.blockchain_platform.channel_capabilities:
    path: channel_config.bin
    channel: V1_4_3

- name: Set orderer capability level for Hyperledger Fabric v1.4.x
  ibm.blockchain_platform.channel_capabilities:
    path: channel_config.bin
    orderer: V1_4_2

- name: Set all channel capability levels for Hyperledger Fabric v2.x
  ibm.blockchain_platform.channel_capabilities:
    path: channel_config.bin
    application: V2_0
    channel: V2_0
    orderer: V2_0
'''

RETURN = '''
---
{}
'''


def main():

    # Create the module.
    argument_spec = dict(
        path=dict(type='str', required=True),
        application=dict(type='str'),
        channel=dict(type='str'),
        orderer=dict(type='str')
    )
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True)

    # Ensure all exceptions are caught.
    try:

        # Get the target path, policy name and capabilities.
        path = module.params['path']
        application = module.params['application']
        channel = module.params['channel']
        orderer = module.params['orderer']

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())
        original_config_json = copy_dict(config_json)

        # Handle the application capability level.
        if application:
            application_group = config_json['channel_group']['groups']['Application']
            application_values = application_group['values']
            application_capabilities_value = application_values['Capabilities']
            application_capabilities_value['value']['capabilities'] = {
                application: {}
            }

        # Handle the channel capability level.
        if channel:
            channel_group = config_json['channel_group']
            channel_values = channel_group['values']
            channel_capabilities_value = channel_values['Capabilities']
            channel_capabilities_value['value']['capabilities'] = {
                channel: {}
            }

        # Handle the orderer capability level.
        if orderer:
            orderer_group = config_json['channel_group']['groups']['Orderer']
            orderer_values = orderer_group['values']
            orderer_capabilities_value = orderer_values['Capabilities']
            orderer_capabilities_value['value']['capabilities'] = {
                orderer: {}
            }

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
