#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console, get_ordering_service_node_by_name

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ordering_service_node_info
short_description: Get information about a Hyperledger Fabric ordering service node
description:
    - Get information about a Hyperledger Fabric ordering service node by using the IBM Blockchain Platform.
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
        type: int
        default: 60
    api_token_endpoint:
        description:
            - The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.
            - Only required when I(api_authtype) is C(ibmcloud), and you are using IBM internal staging servers for testing.
        type: str
        default: https://iam.cloud.ibm.com/identity/token
    name:
        description:
            - The name of the ordering service node.
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the ordering service node is available.
        type: int
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Get the ordering service node
  ibm.blockchain_platform.ordering_service_node_info:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Ordering Service Node_1
'''

RETURN = '''
---
exists:
    description:
        - True if the ordering service node exists, false otherwise.
    type: boolean
ordering_service_node:
    description:
        - The ordering service node.
    returned: if ordering service node exists
    type: dict
    contains:
        name:
            description:
                - The name of the ordering service node.
            type: str
            sample: Ordering Service_1
        api_url:
            description:
                - The URL for the API of the ordering service node.
            type: str
            sample: grpcs://orderingservice1-api.example.org:32000
        operations_url:
            description:
                - The URL for the operations service of the ordering service node.
            type: str
            sample: https://orderingservice1-operations.example.org:32000
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the ordering service node.
            type: str
            sample: https://orderingservice1-grpcwebproxy.example.org:32000
        msp_id:
            description:
                - The MSP ID of the ordering service node.
            type: str
            sample: OrdererOrgMSP
        pem:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_cert:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        location:
            description:
                - The location of the ordering service node.
            type: str
            sample: ibmcloud
        system_channel_id:
            description:
                - The name of the system channel for the ordering service node.
            type: str
            sample: testchainid
        client_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        server_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        cluster_id:
            description:
                - The unique ID of the ordering service cluster.
            type: str
            sample: abcdefgh
        cluster_name:
            description:
                - The name of the ordering service cluster.
            type: str
            sample: Ordering Service
'''


def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str', required=True),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the ordering service node exists.
        ordering_service_node = get_ordering_service_node_by_name(console, module.params['name'], fail_on_missing=False)

        # If it doesn't exist, return now.
        if ordering_service_node is None:
            return module.exit_json(exists=False)

        # Wait for the ordering service node to start.
        wait_timeout = module.params['wait_timeout']
        ordering_service_node.wait_for(wait_timeout)

        # Return peer information.
        module.exit_json(exists=True, ordering_service_node=ordering_service_node.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
