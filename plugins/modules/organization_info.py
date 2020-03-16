#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.utils import get_console, get_organization_by_name

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: organization_info
short_description: Get information about a Hyperledger Fabric organization
description:
    - Get information about a Hyperledger Fabric organization by using the IBM Blockchain Platform.
    - A Hyperledger Fabric organziation is also known as a Membership Services Provider (MSP).
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
            - The name of the organization.
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
exists:
    description:
        - True if the organization exists, false otherwise.
    type: boolean
organization:
    description:
        - The organization.
    type: dict
    suboptions:
        name:
            description:
                - The name of the organization.
            type: str
        root_certs:
            description:
                - The list of root certificates for this organization.
                - Root certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        intermediate_certs:
            description:
                - The list of intermediate certificates for this organization.
                - Intermediate certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        admins:
            description:
                - The list of administrator certificates for this organization.
                - Administrator certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        revocation_list:
            description:
                - The list of revoked certificates for this organization.
                - Revoked certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        tls_root_certs:
            description:
                - The list of TLS root certificates for this organization.
                - TLS root certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        tls_intermediate_certs:
            description:
                - The list of TLS root certificates for this organization.
                - TLS intermediate certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
        fabric_node_ous:
            description:
                - Configuration specific to the identity classification.
            type: dict
            suboptions:
                enable:
                    description:
                        - True if identity classification is enabled for this organization, false otherwise.
                    default: true
                    type: boolean
                admin_ou_identifier:
                    description:
                        - Configuration specific to the admin identity classification.
                    type: dict
                    suboptions:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            default: admin
                client_ou_identifier:
                    description:
                        - Configuration specific to the client identity classification.
                    type: dict
                    suboptions:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            default: client
                peer_ou_identifier:
                    description:
                        - Configuration specific to the peer identity classification.
                    type: dict
                    suboptions:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            default: peer
                orderer_ou_identifier:
                    description:
                        - Configuration specific to the orderer identity classification.
                    type: dict
                    suboptions:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            default: orderer
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

        # Determine if the organization exists.
        organization = get_organization_by_name(console, module.params['name'], fail_on_missing=False)

        # If it doesn't exist, return now.
        if organization is None:
            return module.exit_json(exists=False)

        # Return organization information.
        module.exit_json(exists=True, organization=organization.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))

if __name__ == '__main__':
    main()