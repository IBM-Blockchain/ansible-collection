#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console, get_peer_by_name

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: peer_info
short_description: Get information about a Hyperledger Fabric peer
description:
    - Get information about a Hyperledger Fabric peer by using the IBM Blockchain Platform.
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
    name:
        description:
            - The name of the peer.
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the peer is available.
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
peer:
    description: The peer.
    type: dict
    contains:
        name:
            description:
                - The name of the peer.
            type: str
        api_url:
            description:
                - The URL for the API of the peer.
            type: str
        operations_url:
            description:
                - The URL for the operations service of the peer.
            type: str
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the peer.
            type: str
        msp_id:
            description:
                - The MSP ID of the peer.
            type: str
        pem:
            description:
                - The TLS certificate chain for the peer.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        tls_cert:
            description:
                - The TLS certificate chain for the peer.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        location:
            description:
                - The location of the peer.
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

        # Determine if the peer exists.
        peer = get_peer_by_name(console, module.params['name'], fail_on_missing=False)

        # If it doesn't exist, return now.
        if peer is None:
            return module.exit_json(exists=False)

        # Wait for the peer to start.
        wait_timeout = module.params['wait_timeout']
        peer.wait_for(wait_timeout)

        # Return peer information.
        module.exit_json(exists=True, peer=peer.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
