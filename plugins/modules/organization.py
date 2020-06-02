#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.cert_utils import split_ca_chain, equal_crls
from ..module_utils.dict_utils import copy_dict, diff_dicts, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.organizations import Organization
from ..module_utils.utils import get_console, get_certificate_authority_by_module, get_identity_by_module

from ansible.module_utils.urls import open_url
from ansible.module_utils._text import to_native

import json
import urllib

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: organization
short_description: Manage a Hyperledger Fabric organization
description:
    - Create, update, or delete a Hyperledger Fabric organization by using the IBM Blockchain Platform.
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
    registrar:
        description:
            - The identity to use when interacting with the certificate authority. If you want
              a CRL (Certificate Revocation List) generated from the certificate authority, you
              must supply an identity to use as the registrar.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
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
    organizational_unit_identifiers:
        description:
            - The list of organizational unit identifiers for this organization.
        type: list
        elements: dict
        suboptions:
            certificate:
                description:
                    - The root or intermediate certificate for this organizational unit identifier.
                    - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                type: str
            organizational_unit_identifier:
                description:
                    - The organizational unit (OU) identifier.
                type: str

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
        msp_id:
            description:
                - The MSP ID for the organization.
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
        organizational_unit_identifiers:
            description:
                - The list of organizational unit identifiers for this organization.
            type: list
            elements: dict
            contains:
                certificate:
                    description:
                        - The root or intermediate certificate for this organizational unit identifier.
                        - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                    type: str
                organizational_unit_identifier:
                    description:
                        - The organizational unit (OU) identifier.
                    type: str
'''


def get_from_certificate_authority(console, module):

    # Get the certificate authority.
    if module.params['certificate_authority'] is None:
        return None
    certificate_authority = get_certificate_authority_by_module(console, module)

    # Get the certificate authority information.
    url = urllib.parse.urljoin(certificate_authority.api_url, f'/cainfo?ca={certificate_authority.ca_name}')
    response = open_url(url, None, None, method='GET', validate_certs=False)
    cainfo = json.load(response)
    url = urllib.parse.urljoin(certificate_authority.api_url, f'/cainfo?ca={certificate_authority.tlsca_name}')
    response = open_url(f'{certificate_authority.api_url}/cainfo?ca={certificate_authority.tlsca_name}', None, None, method='GET', validate_certs=False)
    tlscainfo = json.load(response)

    # Split the certificate authority chains into root certificates and intermediate certificates.
    ca_chain = cainfo['result']['CAChain']
    (root_certs, intermediate_certs) = split_ca_chain(ca_chain)
    tlsca_chain = tlscainfo['result']['CAChain']
    (tls_root_certs, tls_intermediate_certs) = split_ca_chain(tlsca_chain)

    # Build the return information.
    result = {
        'root_certs': root_certs,
        'intermediate_certs': intermediate_certs,
        'tls_root_certs': tls_root_certs,
        'tls_intermediate_certs': tls_intermediate_certs
    }

    # Generate a revocation list if a registrar has been provided.
    if module.params['registrar']:
        registrar = get_identity_by_module(module, 'registrar')
        with certificate_authority.connect() as connection:
            revocation_list = connection.generate_crl(registrar)
            result['revocation_list'] = [revocation_list]

    # Return the information retrieved from the certificate authority.
    return result


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
        name=dict(type='str', required=True),
        msp_id=dict(type='str'),
        certificate_authority=dict(type='raw'),
        registrar=dict(type='raw'),
        root_certs=dict(type='list', elements='str', default=list()),
        intermediate_certs=dict(type='list', elements='str', default=list()),
        admins=dict(type='list', elements='str', default=list()),
        revocation_list=dict(type='list', elements='str', default=list()),
        tls_root_certs=dict(type='list', elements='str', default=list()),
        tls_intermediate_certs=dict(type='list', elements='str', default=list()),
        fabric_node_ous=dict(type='dict', default=dict(), options=dict(
            enable=dict(type='bool', default=True),
            admin_ou_identifier=dict(type='dict', default=dict(), options=dict(
                certificate=dict(type='str'),
                organizational_unit_identifier=dict(type='str', default='admin')
            )),
            client_ou_identifier=dict(type='dict', default=dict(), options=dict(
                certificate=dict(type='str'),
                organizational_unit_identifier=dict(type='str', default='client')
            )),
            peer_ou_identifier=dict(type='dict', default=dict(), options=dict(
                certificate=dict(type='str'),
                organizational_unit_identifier=dict(type='str', default='peer')
            )),
            orderer_ou_identifier=dict(type='dict', default=dict(), options=dict(
                certificate=dict(type='str'),
                organizational_unit_identifier=dict(type='str', default='orderer')
            ))
        )),
        organizational_unit_identifiers=dict(type='list', elements='dict', default=list(), options=dict(
            certificate=dict(type='str', required=True),
            organizational_unit_identifier=dict(type='str', required=True)
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['name', 'msp_id'])
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the organization exists.
        name = module.params['name']
        organization = console.get_component_by_display_name(name)
        organization_exists = organization is not None

        # Extract the organization configuration.
        expected_organization = dict(
            display_name=name,
            msp_id=module.params['msp_id'],
            root_certs=module.params['root_certs'],
            intermediate_certs=module.params['intermediate_certs'],
            admins=module.params['admins'],
            revocation_list=module.params['revocation_list'],
            tls_root_certs=module.params['tls_root_certs'],
            tls_intermediate_certs=module.params['tls_intermediate_certs'],
            fabric_node_ous=module.params['fabric_node_ous'],
            organizational_unit_identifiers=module.params['organizational_unit_identifiers'],
            host_url=console.get_host_url()
        )

        # Get any certificates from the certificate authority, if specified.
        certificate_authority_certs = get_from_certificate_authority(console, module)

        # Merge any certificate authority certificates.
        if certificate_authority_certs is not None:

            # Extend the root and intermediate certificate lists.
            expected_organization['root_certs'].extend(certificate_authority_certs['root_certs'])
            expected_organization['intermediate_certs'].extend(certificate_authority_certs['intermediate_certs'])
            expected_organization['tls_root_certs'].extend(certificate_authority_certs['tls_root_certs'])
            expected_organization['tls_intermediate_certs'].extend(certificate_authority_certs['tls_intermediate_certs'])

            # If a revocation list has been generated, extend that as well.
            if 'revocation_list' in certificate_authority_certs:
                expected_organization['revocation_list'].extend(certificate_authority_certs['revocation_list'])

            # Check to see if NodeOU support is enabled.
            node_ous_enabled = expected_organization['fabric_node_ous']['enable']
            if node_ous_enabled:

                # If using an intermediate certificate authority, use the intermediate certificate.
                # Otherwise, use the root certificate.
                if certificate_authority_certs['intermediate_certs']:
                    default_cert = certificate_authority_certs['intermediate_certs'][0]
                else:
                    default_cert = certificate_authority_certs['root_certs'][0]

                # Go through each OU, ensuring that the certificate field is set.
                for node_ou in ['admin', 'client', 'orderer', 'peer']:
                    node_ou_identifier = expected_organization['fabric_node_ous'][f'{node_ou}_ou_identifier']
                    if node_ou_identifier.get('certificate', None) is None:
                        node_ou_identifier['certificate'] = default_cert

        # Handle appropriately based on state.
        state = module.params['state']
        changed = False
        if state == 'present' and not organization_exists:

            # Create the organization.
            organization = console.create_organization(expected_organization)
            changed = True

        elif state == 'present' and organization_exists:

            # Build the new organization, including any defaults.
            new_organization = copy_dict(organization)
            merge_dicts(new_organization, expected_organization)

            # Check to see if any banned changes have been made.
            banned_changes = ['msp_id']
            diff = diff_dicts(organization, new_organization)
            for banned_change in banned_changes:
                if banned_change in diff:
                    raise Exception(f'{banned_change} cannot be changed from {organization[banned_change]} to {new_organization[banned_change]} for existing organization')

            # Check to see if the revocation list has actually changed (in terms of actual serial numbers).
            # We need to do this because the revocation list is generated every time.
            if 'revocation_list' in organization and 'revocation_list' in new_organization:
                if equal_crls(organization['revocation_list'], new_organization['revocation_list']):
                    new_organization['revocation_list'] = organization['revocation_list']

            # If the organization has changed, apply the changes.
            organization_changed = not equal_dicts(organization, new_organization)
            if organization_changed:
                organization = console.update_organization(new_organization['id'], new_organization)
                changed = True

        elif state == 'absent' and organization_exists:

            # The organization should not exist, so delete it.
            console.delete_organization(organization['id'])
            return module.exit_json(changed=True)

        else:

            # The organization should not exist and doesn't.
            return module.exit_json(changed=False)

        # Return the organization.
        organization = Organization.from_json(console.extract_organization_info(organization))
        module.exit_json(changed=changed, organization=organization.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
