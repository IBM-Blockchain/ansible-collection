#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.certificate_authorities import CertificateAuthority
from ..module_utils.dict_utils import copy_dict, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: external_certificate_authority
short_description: Manage an external Hyperledger Fabric certificate authority
description:
    - Import or remove an external Hyperledger Fabric certificate authority by using the IBM Blockchain Platform.
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
    state:
        description:
            - C(absent) - A certificate authority matching the specified name will be stopped and removed.
            - C(present) - Asserts that a certificate authority matching the specified name and configuration exists.
              If no certificate authority matches the specified name, a certificate authority will be created.
              If a certificate authority matches the specified name but the configuration does not match, then the
              certificate authority will be updated, if it can be. If it cannot be updated, it will be removed and
              re-created with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    name:
        description:
            - The name of the external certificate authority.
            - Only required when I(state) is C(absent).
        type: str
    certificate_authority:
        description:
            - The definition of the external certificate authority
            - Only required when I(state) is C(present).
        type: dict
        suboptions:
            name:
                description:
                    - The name of the certificate authority.
                type: str
            api_url:
                description:
                    - The URL for the API of the certificate authority.
                type: str
            operations_url:
                description:
                    - The URL for the operations service of the certificate authority.
                type: str
            ca_url:
                description:
                    - The URL for the API of the certificate authority.
                type: str
            ca_name:
                description:
                    - The certificate authority name to use for enrollment requests.
                type: str
            tlsca_name:
                description:
                    - The certificate authority name to use for TLS enrollment requests.
                type: str
            location:
                description:
                    - The location of the certificate authority.
                type: str
            pem:
                description:
                    - The TLS certificate chain for the certificate authority.
                    - The TLS certificate chain is returned as a base64 encoded PEM.
                type: str
            tls_cert:
                description:
                    - The TLS certificate chain for the certificate authority.
                    - The TLS certificate chain is returned as a base64 encoded PEM.
                type: str
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Import the certificate authority
  ibm.blockchain_platform.external_certificate_authority:
    status: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    certificate_authority: "{{ lookup('file', 'Org1 CA.json') }}"

- name: Remove the imported certificate authority
  ibm.blockchain_platform.external_certificate_authority:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 CA
'''

RETURN = '''
---
certificate_authority:
    description:
        - The certificate authority.
    returned: when I(state) is C(present)
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
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str'),
        certificate_authority=dict(type='dict', options=dict(
            name=dict(type='str'),
            api_url=dict(type='str'),
            operations_url=dict(type='str'),
            ca_url=dict(type='str'),
            ca_name=dict(type='str'),
            tlsca_name=dict(type='str'),
            location=dict(type='str'),
            pem=dict(type='str'),
            tls_cert=dict(type='str'),
            type=dict(type='str')
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['certificate_authority']),
        ('state', 'absent', ['name'])
    ]
    mutually_exclusive = [
        ['name', 'certificate_authority']
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the certificate authority exists.
        state = module.params['state']
        certificate_authority_definition = module.params['certificate_authority']
        name = module.params['name']
        if state == 'present':
            name = certificate_authority_definition['name']
        certificate_authority = console.get_component_by_display_name('fabric-ca', name, 'included')
        certificate_authority_exists = certificate_authority is not None
        module.json_log({
            'msg': 'got external certificate authority',
            'certificate_authority': certificate_authority,
            'certificate_authority_exists': certificate_authority_exists
        })

        # If the certificate authority exists, make sure it's an imported one and not
        # a real one - we don't want to delete it, which may lose data or orphan
        # the Kubernetes components.
        if certificate_authority_exists:
            has_deployment_attrs = False
            has_location = False
            if 'deployment_attrs_missing' not in certificate_authority:
                has_deployment_attrs = True
            elif certificate_authority.get('location', '-') != '-':
                has_location = True
            if has_deployment_attrs or has_location:
                raise Exception('Certificate authority exists and appears to be managed by this console, refusing to continue')

        # If state is absent, then handle the removal now.
        if state == 'absent' and certificate_authority_exists:

            # The certificate authority should not exist, so delete it.
            console.delete_ext_ca(certificate_authority['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The certificate authority should not exist and doesn't.
            return module.exit_json(changed=False)

        # Extract the expected certificate authority configuration.
        expected_certificate_authority = dict(
            display_name=name,
            api_url=certificate_authority_definition['api_url'],
            operations_url=certificate_authority_definition['operations_url'],
            ca_name=certificate_authority_definition['ca_name'],
            tlsca_name=certificate_authority_definition['tlsca_name'],
            tls_cert=certificate_authority_definition['tls_cert'] or certificate_authority_definition['pem'],
        )

        # Handle appropriately based on state.
        changed = False
        if not certificate_authority_exists:

            # Create the certificate authority.
            certificate_authority = console.create_ext_ca(expected_certificate_authority)
            changed = True

        else:

            # Build the new certificate authority, including any defaults.
            new_certificate_authority = copy_dict(certificate_authority)
            merge_dicts(new_certificate_authority, expected_certificate_authority)

            # If the certificate authority has changed, apply the changes.
            certificate_authority_changed = not equal_dicts(certificate_authority, new_certificate_authority)
            if certificate_authority_changed:
                module.json_log({
                    'msg': 'differences detected, updating external certificate authority',
                    'certificate_authority': certificate_authority,
                    'new_certificate_authority': new_certificate_authority
                })
                certificate_authority = console.update_ext_ca(new_certificate_authority['id'], new_certificate_authority)
                changed = True

        # Return the certificate authority.
        certificate_authority = CertificateAuthority.from_json(console.extract_ca_info(certificate_authority))
        module.exit_json(changed=changed, certificate_authority=certificate_authority.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
