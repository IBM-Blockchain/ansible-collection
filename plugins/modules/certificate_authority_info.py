#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console, get_certificate_authority_by_name

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: certificate_authority_info
short_description: Get information about a Hyperledger Fabric certificate authority
description:
    - Get information about a Hyperledger Fabric certificate authority by using the IBM Blockchain Platform.
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
    name:
        description:
            - The name of the certificate authority.
        required: true
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the certificate authority is available.
        type: int
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Get certificate authority
  ibm.blockchain_platform.certificate_authority:
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 CA
'''

RETURN = '''
---
exists:
    description:
        - True if the certificate authority exists, false otherwise.
    returned: always
    type: boolean
certificate_authority:
    description:
        - The certificate authority.
    returned: if certificate authority exists
    type: dict
    contains:
        name:
            description:
                - The name of the certificate authority.
            type: str
            sample: Org1 CA
        api_url:
            description:
                - The URL for the API of the certificate authority.
            type: str
            sample: https://org1ca-api.example.org:32000
        operations_url:
            description:
                - The URL for the operations service of the certificate authority.
            type: str
            sample: https://org1ca-operations.example.org:32000
        ca_url:
            description:
                - The URL for the API of the certificate authority.
            type: str
            sample: https://org1ca-api.example.org:32000
        ca_name:
            description:
                - The certificate authority name to use for enrollment requests.
            type: str
            sample: ca
        tlsca_name:
            description:
                - The certificate authority name to use for TLS enrollment requests.
            type: str
            sample: tlsca
        location:
            description:
                - The location of the certificate authority.
            type: str
            sample: ibmcloud
        pem:
            description:
                - The TLS certificate chain for the certificate authority.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_cert:
            description:
                - The TLS certificate chain for the certificate authority.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
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

        # Determine if the certificate authority exists.
        certificate_authority = get_certificate_authority_by_name(console, module.params['name'], fail_on_missing=False)

        # If it doesn't exist, return now.
        if certificate_authority is None:
            return module.exit_json(exists=False)

        # Wait for the CA to start.
        wait_timeout = module.params['wait_timeout']
        certificate_authority.wait_for(wait_timeout)

        # Return certificate authority information.
        module.exit_json(exists=True, certificate_authority=certificate_authority.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
