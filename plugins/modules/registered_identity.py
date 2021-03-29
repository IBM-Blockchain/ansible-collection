#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.dict_utils import copy_dict, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import (get_certificate_authority_by_module,
                                  get_console, get_identity_by_module)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: registered_identity
short_description: Manage a registered Hyperledger Fabric identity
description:
    - Register, update, or revoke an Hyperledger Fabric identity by using the IBM Blockchain Platform.
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
            - C(absent) - If an identity is registered matching the specified enrollment ID, the identity will be removed.
              Note that this operation is unsupported by default and must be enabled by the certificate authority.
            - C(present) - Asserts that an identity matching the specified enrollment ID and configuration is registered.
              If no identity matches the specified enrollment ID, the identity will be created. If an identity matches
              the specified enrollment ID but the configuration does not match, then the identity will be updated, if it
              can be. If it cannot be updated, it will be removed and re-created with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    certificate_authority:
        description:
            - The certificate authority to use to register this identity.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
        type: raw
        required: true
    registrar:
        description:
            - The identity to use when interacting with the certificate authority.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
        type: raw
        required: true
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for digital signatures."
            - Only required if the identity specified in I(registrar) was enrolled using an HSM.
        type: dict
        suboptions:
            pkcs11library:
                description:
                    - "The PKCS #11 library that should be used for digital signatures."
                type: str
            label:
                description:
                    - The HSM label that should be used for digital signatures.
                type: str
            pin:
                description:
                    - The HSM pin that should be used for digital signatures.
                type: str
    enrollment_id:
        description:
            - The enrollment ID, or user name, of the identity to register on the certificate authority.
        type: str
        required: true
    enrollment_secret:
        description:
            - The enrollment secret, or password, of an identity to register on the certificate authority.
            - Only required when I(state) is C(present).
        type: str
    max_enrollments:
        description:
            - The maximum number of times that this identity can be enrolled.
        type: int
        default: -1
    type:
        description:
            - The type of this identity.
        type: str
        default: client
        choices:
            - admin
            - client
            - peer
            - orderer
    affiliation:
        description:
            - The affiliation of this identity.
        type: str
    attributes:
        description:
            - The attributes for this identity.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - The name of the attribute.
                type: str
            value:
                description:
                    - The value of the attribute.
                type: str
            ecert:
                description:
                    - Whether or not the attribute and its value will be in the enrollment certificate.
                type: bool
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Register a new identity
  ibm.blockchain_platform.registered_identity:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    certificate_authority: Org1 CA
    registrar: Org1 CA Admin.json
    enrollment_id: org1app
    enrollment_secret: org1apppw
    max_enrollments: 10
    type: client
    attributes:
      - name: "fabcar.admin"
        value: "true"

- name: Delete an existing identity
  ibm.blockchain_platform.registered_identity:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    certificate_authority: Org1 CA
    registrar: Org1 CA Admin.json
    enrollment_id: org1app
'''

RETURN = '''
---
registered_identity:
    description:
        - The registered identity.
    type: dict
    returned: when I(state) is C(present)
    contains:
        enrollment_id:
            description:
                - The enrollment ID, or user name, of the identity.
            type: str
            sample: org1admin
        enrollment_secret:
            description:
                - The enrollment secret, or password, of an identity.
            type: str
            sample: org1adminpw
        max_enrollments:
            description:
                - The maximum number of times that this identity can be enrolled.
            type: int
            sample: -1
        type:
            description:
                - The type of this identity.
            type: str
            sample: admin
        affiliation:
            description:
                - The affiliation of this identity.
            type: str
            sample: org1.department
        attributes:
            description:
                - The attributes for this identity.
            type: list
            elements: dict
            contains:
                name:
                    description:
                        - The name of the attribute.
                    type: str
                    sample: fabcar.admin
                value:
                    description:
                        - The value of the attribute.
                    type: str
                    sample: true
                ecert:
                    description:
                        - Whether or not the attribute and its value will be in the enrollment certificate.
                    type: bool
                    sample: true
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
        certificate_authority=dict(type='raw', required=True),
        registrar=dict(type='raw', required=True),
        enrollment_id=dict(type='str', required=True),
        enrollment_secret=dict(type='str', no_log=True),
        max_enrollments=dict(type='int', default=-1),
        type=dict(type='str', default='client', choices=['admin', 'client', 'peer', 'orderer']),
        affiliation=dict(type='str', default=''),
        attributes=dict(type='list', elements='dict', default=list(), options=dict(
            name=dict(type='str', required=True),
            value=dict(type='str', required=True),
            ecert=dict(type='bool', default=False)
        )),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the certificate authority and identity.
        certificate_authority = get_certificate_authority_by_module(console, module)
        registrar = get_identity_by_module(module, 'registrar')

        # Connect to the certificate authority.
        hsm = module.params['hsm']
        with certificate_authority.connect(module, hsm) as connection:

            # Determine if the identity is registered.
            enrollment_id = module.params['enrollment_id']
            identity_registered = connection.is_registered(registrar, enrollment_id)

            # If the identity should not be registered, handle that now.
            state = module.params['state']
            if state == 'absent' and identity_registered:

                # The identity should not be registered, delete it.
                connection.delete_registration(registrar, enrollment_id)
                return module.exit_json(changed=True)

            elif state == 'absent':

                # The identity should not be registered and isn't.
                return module.exit_json(changed=False)

            # Extract the expected registration
            enrollment_id = module.params['enrollment_id']
            enrollment_secret = module.params['enrollment_secret']
            max_enrollments = module.params['max_enrollments']
            type = module.params['type']
            affiliation = module.params['affiliation']
            attributes = module.params['attributes']

            # Either create or update the registration.
            changed = False
            if state == 'present' and not identity_registered:

                # Create the registration.
                enrollment_secret = connection.create_registration(registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attributes)
                changed = True

            elif state == 'present' and identity_registered:

                # Get the actual registration.
                actual_registration = connection.get_registration(registrar, enrollment_id)

                # Update the registration.
                new_registration = copy_dict(actual_registration)
                expected_registration = dict(
                    id=enrollment_id,
                    max_enrollments=max_enrollments,
                    type=type,
                    affiliation=affiliation
                )
                merge_dicts(new_registration, expected_registration)

                # If the registration has changed, apply the changes.
                registration_changed = not equal_dicts(actual_registration, new_registration)

                # If the registration has not changed, we now need to check the attributes.
                if not registration_changed:

                    # First, transform both lists into dictionaries, and compare those.
                    actual_attrs_as_dict = dict()
                    actual_attrs = actual_registration.get('attrs', None)
                    if actual_attrs:
                        for attr in actual_attrs:
                            name = attr['name']
                            value = attr['value']
                            actual_attrs_as_dict[name] = value
                    expected_attrs_as_dict = dict()
                    if attributes:
                        for attr in attributes:
                            name = attr['name']
                            value = attr['value']
                            expected_attrs_as_dict[name] = value
                    for default_attr_name in ['hf.EnrollmentID', 'hf.Type', 'hf.Affiliation']:
                        actual_attrs_as_dict.pop(default_attr_name, None)
                        expected_attrs_as_dict.pop(default_attr_name, None)
                    registration_changed = not equal_dicts(actual_attrs_as_dict, expected_attrs_as_dict)

                    # In order to delete any attributes, we must set their values to the empty string.
                    for name, value in actual_attrs_as_dict.items():
                        if name not in expected_attrs_as_dict:
                            attributes.append(dict(name=name, value=''))

                # Apply the changes if required.
                if registration_changed:
                    connection.update_registration(registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attributes)
                    changed = True

            # Return the registered identity.
            module.exit_json(changed=changed, registered_identity=dict(
                enrollment_id=enrollment_id,
                enrollment_secret=enrollment_secret,
                type=type,
                affiliation=affiliation,
                max_enrollments=max_enrollments,
                attributes=attributes
            ))

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
