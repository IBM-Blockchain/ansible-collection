#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.utils import get_console, get_ordering_service_by_name

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ordering_service_info
short_description: Get information about a Hyperledger Fabric ordering service
description:
    - Get information about a Hyperledger Fabric ordering service by using the IBM Blockchain Platform.
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
        type: integer
        default: 60
    name:
        description:
            - The name of the ordering service.
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the ordering service is available.
        type: integer
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
exists:
    description:
        - True if the peer exists, false otherwise.
    type: boolean
ordering_service:
    description:
        - The ordering service, as a list of ordering service nodes.
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - The name of the ordering service node.
            type: str
        api_url:
            description:
                - The URL for the API of the ordering service node.
            type: str
        operations_url:
            description:
                - The URL for the operations service of the ordering service node.
            type: str
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the ordering service node.
            type: str
        msp_id:
            description:
                - The MSP ID of the ordering service node.
            type: str
        pem:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        tls_cert:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        location:
            description:
                - The location of the ordering service node.
            type: str
        system_channel_id:
            description:
                - The name of the system channel for the ordering service node.
            type: str
        client_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
        server_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
        cluster_id:
            description:
                - The unique ID of the ordering service cluster.
            type: str
        cluster_name:
            description:
                - The name of the ordering service cluster.
            type: str
'''

def main():

    # Create the module.
    argument_spec = dict(
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        name=dict(type='str', required=True),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the ordering service exists.
        ordering_service = get_ordering_service_by_name(console, module.params['name'], fail_on_missing=False)

        # If it doesn't exist, return now.
        if ordering_service is None:
            return module.exit_json(exists=False)

        # Wait for the peer to start.
        wait_timeout = module.params['wait_timeout']
        ordering_service.wait_for(wait_timeout)

        # Return peer information.
        module.exit_json(exists=True, ordering_service=ordering_service.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))

if __name__ == '__main__':
    main()