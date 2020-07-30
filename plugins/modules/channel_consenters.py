#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import equal_dicts, copy_dict
from ..module_utils.module import BlockchainModule
from ..module_utils.proto_utils import proto_to_json, json_to_proto
from ..module_utils.utils import get_console, get_ordering_service_by_module, get_ordering_service_nodes_by_module

from ansible.module_utils._text import to_native

import urllib.parse

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_consenters
short_description: Manage the consenters for a Hyperledger Fabric channel
description:
    - Specify the consenters for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
    path:
        description:
            - Path to current the channel configuration file.
            - This file can be fetched by using the M(channel_config) module.
            - This file will be updated in place. You will need to keep a copy of the original file for computing the configuration
              update.
        type: str
        required: true
    ordering_service:
        description:
            - The ordering service to use as the consenters for this channel. All ordering service nodes
              in this ordering service will be used as the consenters for this channel.
            - You can pass a string, which is the cluster name of a ordering service registered
              with the IBM Blockchain Platform console.
            - You can also pass a list, which must match the result format of one of the
              M(ordering_service_info) or M(ordering_service) modules.
            - Cannot be specified with I(ordering_service_nodes).
        type: raw
    ordering_service_nodes:
        description:
            - The ordering service nodes to use as the consenters for this channel.
            - You can pass strings, which are the names of ordering service nodes that are
              registered with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one
              of the M(ordering_service_node_info) or M(ordering_service_node) modules.
            - Cannot be specified with I(ordering_service).
        type: list
        elements: raw
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Set channel consenters from ordering service
  ibm.blockchain_platform.channel_consenters:
    path: channel_config.bin
    ordering_service: Ordering Service

- name: Set channel consenters from ordering service nodes
  ibm.blockchain_platform.channel_consenters:
    path: channel_config.bin
    ordering_service_nodes:
      - Ordering Service_1
      - Ordering Service_2
      - Ordering Service_5
'''

RETURN = '''
---
{}
'''


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic'], required=True),
        api_key=dict(type='str', no_log=True, required=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        path=dict(type='str', required=True),
        ordering_service=dict(type='raw'),
        ordering_service_nodes=dict(type='list', elements='raw'),
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    required_one_of = [
        ['ordering_service', 'ordering_service_nodes']
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if, required_one_of=required_one_of)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the target path, ordering service and ordering service nodes.
        path = module.params['path']
        ordering_service_specified = module.params['ordering_service'] is not None

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())
        original_config_json = copy_dict(config_json)

        # Get the list of ordering service nodes.
        if ordering_service_specified:
            ordering_service = get_ordering_service_by_module(console, module)
            ordering_service_nodes = ordering_service.nodes
        else:
            ordering_service_nodes = get_ordering_service_nodes_by_module(console, module)

        # Build the expected list of consenters.
        expected_consenters = list()
        for ordering_service_node in ordering_service_nodes:
            parsed_api_url = urllib.parse.urlparse(ordering_service_node.api_url)
            host = parsed_api_url.hostname
            port = parsed_api_url.port or 443
            client_tls_cert = ordering_service_node.client_tls_cert or ordering_service_node.tls_cert
            server_tls_cert = ordering_service_node.server_tls_cert or ordering_service_node.tls_cert
            expected_consenters.append(dict(
                host=host,
                port=port,
                client_tls_cert=client_tls_cert,
                server_tls_cert=server_tls_cert,
            ))

        # Get the actual list of consenters.
        orderer_group = config_json['channel_group']['groups']['Orderer']
        orderer_values = orderer_group['values']
        orderer_consensus_type = orderer_values['ConsensusType']['value']
        orderer_consensus_type_type = orderer_consensus_type['type']
        if orderer_consensus_type_type != 'etcdraft':
            raise Exception(f'The channel uses an unsupported consensus type ${orderer_consensus_type_type}')
        actual_consenters = orderer_consensus_type['metadata']['consenters']

        # Compare the expected consenters to the actual consenters.
        # Look for a additional consenter or an update to an existing consenter.
        changed = False
        for expected_consenter in expected_consenters:
            actual_consenter = None
            for consenter in actual_consenters:
                if consenter['host'] == expected_consenter['host'] and consenter['port'] == expected_consenter['port']:
                    actual_consenter = consenter
                    break
            if actual_consenter is None:
                if changed:
                    raise Exception('Multiple changes to the consenters for the channel are required but cannot be made at the same time')
                actual_consenters.append(expected_consenter)
                changed = True
            else:
                if actual_consenter['client_tls_cert'] == expected_consenter['client_tls_cert'] and actual_consenter['server_tls_cert'] == expected_consenter['server_tls_cert']:
                    continue
                elif changed:
                    raise Exception('Multiple changes to the consenters for the channel are required but cannot be made at the same time')
                actual_consenter['client_tls_cert'] = expected_consenter['client_tls_cert']
                actual_consenter['server_tls_cert'] = expected_consenter['server_tls_cert']
                changed = True

        # Compare the actual consenters to the expected consenters.
        # Look for a consenter that has been removed.
        for idx, actual_consenter in enumerate(actual_consenters):
            expected_consenter = None
            for consenter in expected_consenters:
                if consenter['host'] == actual_consenter['host'] and consenter['port'] == actual_consenter['port']:
                    expected_consenter = consenter
                    break
            if expected_consenter is None:
                if changed:
                    raise Exception('Multiple changes to the consenters for the channel are required but cannot be made at the same time')
                del actual_consenters[idx]
                changed = True

        # Build the expected list of orderer addresses.
        expected_orderer_addresses = set()
        for ordering_service_node in ordering_service_nodes:
            parsed_api_url = urllib.parse.urlparse(ordering_service_node.api_url)
            host = parsed_api_url.hostname
            port = parsed_api_url.port or 443
            expected_orderer_addresses.add(f'{host}:{port}')

        # Get the actual list of orderer addresses.
        channel_group = config_json['channel_group']
        channel_values = channel_group['values']
        orderer_addresses_value = channel_values['OrdererAddresses']['value']
        orderer_addresses = orderer_addresses_value['addresses']
        actual_orderer_addresses = set(orderer_addresses)

        # Update the list of orderer addresses if required.
        if expected_orderer_addresses != actual_orderer_addresses:
            orderer_addresses_value['addresses'] = list(expected_orderer_addresses)

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
