#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import copy_dict, equal_dicts, merge_dicts
from ..module_utils.organizations import Organization
from ..module_utils.utils import get_console

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: external_organization
short_description: Manage an external Hyperledger Fabric organization
description:
    - Import or remove an external Hyperledger Fabric organization by using the IBM Blockchain Platform.
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
    state:
        description:
            - C(absent) - An organization matching the specified name will be stopped and removed.
            - C(present) - Asserts that an organization matching the specified name and configuration exists.
              If no organization matches the specified name, an organization will be created.
              If an organization matches the specified name but the configuration does not match, then the
              organization will be updated, if it can be. If it cannot be updated, it will be removed and
              re-created with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    name:
        description:
            - The name of the external organization.
            - Only required when I(state) is C(absent).
        type: str
    organization:
        description:
            - The definition of the external organization
            - Only required when I(state) is C(present).
        type: dict
        suboptions:
            name:
                description:
                    - The name of the organization.
                type: str
            msp_id:
                description:
                    - The MSP ID for the organization.
                type: str
            certificate_authority:
                description:
                    - The certificate authority to use to build this organization.
                    - You can pass a string, which is the display name of a certificate authority registered
                      with the IBM Blockchain Platform console.
                    - You can also pass a dictionary, which must match the result format of one of the
                      M(certificate_authority_info) or M(certificate_authority) modules.
                type: raw
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

notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
organization:
    description:
        - The organization.
    type: dict
    contains:
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
            contains:
                enable:
                    description:
                        - True if identity classification is enabled for this organization, false otherwise.
                    default: true
                    type: boolean
                admin_ou_identifier:
                    description:
                        - Configuration specific to the admin identity classification.
                    type: dict
                    contains:
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
                    contains:
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
                    contains:
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
                    contains:
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
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str'),
        organization=dict(type='dict', options=dict(
            name=dict(type='str'),
            msp_id=dict(type='str'),
            root_certs=dict(type='list', elements='str', default=list()),
            intermediate_certs=dict(type='list', elements='str', default=list()),
            admins=dict(type='list', elements='str', default=list()),
            revocation_list=dict(type='list', elements='str', default=list()),
            tls_root_certs=dict(type='list', elements='str', default=list()),
            tls_intermediate_certs=dict(type='list', elements='str', default=list()),
            fabric_node_ous=dict(type='dict'),
            host_url=dict(type='str', default=None),
            type=dict(type='str')
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['organization']),
        ('state', 'absent', ['name'])
    ]
    mutually_exclusive = [
        ['name', 'organization']
    ]
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the organization exists.
        state = module.params['state']
        organization_definition = module.params['organization']
        name = module.params['name']
        if state == 'present':
            name = organization_definition['name']
        organization = console.get_component_by_display_name(name)
        organization_exists = organization is not None

        # If state is absent, then handle the removal now.
        if state == 'absent' and organization_exists:

            # The organization should not exist, so delete it.
            console.delete_organization(organization['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The organization should not exist and doesn't.
            return module.exit_json(changed=False)

        # Extract the expected organization configuration.
        expected_organization = dict(
            display_name=name,
            msp_id=organization_definition['msp_id'],
            root_certs=organization_definition['root_certs'],
            intermediate_certs=organization_definition['intermediate_certs'],
            admins=organization_definition['admins'],
            revocation_list=organization_definition['revocation_list'],
            tls_root_certs=organization_definition['tls_root_certs'],
            tls_intermediate_certs=organization_definition['tls_intermediate_certs'],
            fabric_node_ous=organization_definition['fabric_node_ous'],
            host_url=organization_definition['host_url']
        )

        # Handle appropriately based on state.
        changed = False
        if not organization_exists:

            # Create the organization.
            organization = console.create_organization(expected_organization)
            changed = True

        else:

            # Build the new organization, including any defaults.
            new_organization = copy_dict(organization)
            merge_dicts(new_organization, expected_organization)

            # If the organization has changed, apply the changes.
            organization_changed = not equal_dicts(organization, new_organization)
            if organization_changed:
                organization = console.update_organization(new_organization['id'], new_organization)
                changed = True

        # Return the organization.
        organization = Organization.from_json(console.extract_organization_info(organization))
        module.exit_json(changed=changed, organization=organization.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
