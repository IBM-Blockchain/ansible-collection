#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import os.path
from datetime import datetime

from ansible.module_utils._text import to_native

from ..module_utils.certificate_authorities import \
    CertificateAuthorityException
from ..module_utils.enrolled_identities import EnrolledIdentity
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import (get_certificate_authority_by_module,
                                  get_console)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    # Missing dependencies are handled elsewhere.
    pass

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: enrolled_identity
short_description: Manage an enrolled Hyperledger Fabric identity
description:
    - Enroll, re-enroll, or delete an enrolled Hyperledger Fabric identity by using the IBM Blockchain Platform.
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
    certificate_authority:
        description:
            - The certificate authority to use to enroll this identity.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
            - Only required when I(state) is C(present).
        type: raw
    name:
        description:
            - The name of the enrolled identity.
            - Only required when I(state) is C(present).
        type: str
    enrollment_id:
        description:
            - The enrollment ID, or user name, of an identity registered on the certificate authority for this peer.
            - Only required when I(state) is C(present).
        type: str
    enrollment_secret:
        description:
            - The enrollment secret, or password, of an identity registered on the certificate authority for this peer.
            - Only required when I(state) is C(present).
        type: str
    path:
        description:
            - The path to the JSON file where the enrolled identity will be stored.
        required: true
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for generating and storing the private key."
        type: dict
        suboptions:
            pkcs11library:
                description:
                    - "The PKCS #11 library that should be used for generating and storing the private key."
                type: str
            label:
                description:
                    - The HSM label that should be used for generating and storing the private key.
                type: str
            pin:
                description:
                    - The HSM pin that should be used for generating and storing the private key.
                type: str
    tls:
        description:
            - True if the identity should be enrolled against the TLS certificate authority, false otherwise.
            - Cannot be specified at the same time as a PKCS #11 compliant HSM configuration.
        type: bool
        default: false
    hosts:
        description:
            - The list of host names to add to the certificate as X.509 Subject Alternative Names.
            - Can only be specified when enrolling the identity against the TLS certificate authority.
        type: list
        elements: str
    force_reenroll:
        description:
            - True if the identity should be re-enrolled, false otherwise.
            - If specified, then the identity will be re-enrolled every time that your playbook is run.
        type: bool
        default: false
    reenroll_before_expiry:
        description:
            - Use this option to automatically re-enroll the identity before the certificate expires.
            - Specified as the maximum time in seconds before the expiration of the certificate.
            - For example, to automatically re-enroll the identity when there are less than 30 days
              remaining before the certificate expires, set this option to C(2592000).
        type: int
        default: -1
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Enroll an identity
  ibm.blockchain_platform.enrolled_identity:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    certificate_authority: Org1 CA
    name: Org1 Admin
    enrollment_id: org1admin
    enrollment_secret: org1adminpw
    path: Org1 Admin.json

- name: Remove an enrolled identity
  ibm.blockchain_platform.enrolled_identity:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    path: Org1 Admin.json
'''

RETURN = '''
---
enrolled_identity:
    description:
        - The enrolled identity.
    type: dict
    returned: when I(state) is C(present)
    contains:
        name:
            description:
                - The name of the enrolled identity.
            type: str
            sample: Org1 Admin
        cert:
            description:
                - The base64 encoded certificate of the enrolled identity.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        private_key:
            description:
                - The base64 encoded private key of the enrolled identity.
            type: str
            sample: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0t...
        ca:
            description:
                - The base64 encoded CA certificate chain of the enrolled identity.
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
        certificate_authority=dict(type='raw'),
        name=dict(type='str'),
        enrollment_id=dict(type='str'),
        enrollment_secret=dict(type='str', no_log=True),
        path=dict(type='str', required=True),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        tls=dict(type='bool', default=False),
        hosts=dict(type='list', elements='str'),
        force_reenroll=dict(type='bool', default=False),
        reenroll_before_expiry=dict(type='int', default=-1)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['certificate_authority', 'name', 'enrollment_id', 'enrollment_secret'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Validate HSM requirements if HSM is specified.
    hsm = module.params['hsm']
    if hsm:
        module.check_for_missing_hsm_libs()

    # Reject HSM + TLS, or hosts without TLS.
    tls = module.params['tls']
    if hsm and tls:
        raise Exception('Cannot specify HSM configuration and enroll against TLS certificate authority')
    hosts = module.params['hosts']
    if hosts and not tls:
        raise Exception('Can only specify hosts when enrolling against TLS certificate authority')

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the identity exists.
        path = module.params['path']
        path_exists = os.path.isfile(path)

        # Handle appropriately based on state.
        state = module.params['state']
        if state == 'present' and not path_exists:

            # Enroll the identity.
            certificate_authority = get_certificate_authority_by_module(console, module)
            name = module.params['name']
            enrollment_id = module.params['enrollment_id']
            enrollment_secret = module.params['enrollment_secret']
            with certificate_authority.connect(module, hsm, tls) as connection:
                identity = connection.enroll(name, enrollment_id, enrollment_secret, hosts)
            with open(path, 'w') as file:
                json.dump(identity.to_json(), file, indent=4)
            module.exit_json(changed=True, enrolled_identity=identity.to_json())

        elif state == 'present' and path_exists:

            # Load the identity.
            with open(path, 'r') as file:
                identity = EnrolledIdentity.from_json(json.load(file))

            # Update it.
            name = module.params['name']
            new_identity = identity.clone()
            new_identity.name = name

            # The certificate may no longer be valid (revoked, expired, new certificate authority).
            # If this is the case, we want to try re-enrolling it.
            certificate_authority = get_certificate_authority_by_module(console, module)
            with certificate_authority.connect(module, hsm, tls) as connection:

                # Determine if the certificate is valid.
                enrollment_id = module.params['enrollment_id']
                enrollment_secret = module.params['enrollment_secret']
                certificate_valid = False
                try:
                    connection.get_certificates(new_identity, enrollment_id)
                    certificate_valid = True
                except CertificateAuthorityException as e:
                    if e.code == 71:
                        # This means that the user is authenticated (certificate is valid), but the user is not authorized to get certificates.
                        certificate_valid = True
                    elif e.code == 20:
                        # This means that the user is not authenticated (certificate is invalid).
                        pass
                    else:
                        # This is some other problem that we should not ignore.
                        raise

                # Are we going to re-enroll the certificate?
                reenroll_required = not certificate_valid
                force_reenroll = module.params['force_reenroll']
                if force_reenroll:
                    reenroll_required = True
                reenroll_before_expiry = module.params['reenroll_before_expiry']
                if reenroll_before_expiry > -1:
                    certificate = x509.load_pem_x509_certificate(new_identity.cert, default_backend())
                    remaining_period_delta = certificate.not_valid_after - datetime.utcnow()
                    remaining_period_secs = remaining_period_delta.total_seconds()
                    if remaining_period_secs < reenroll_before_expiry:
                        reenroll_required = True

                # If we need to re-enroll the certificate, do it now.
                if reenroll_required:
                    new_identity = connection.enroll(name, enrollment_id, enrollment_secret, hosts)

            # Check if it has changed.
            changed = not new_identity.equals(identity)
            if changed:
                with open(path, 'w') as file:
                    json.dump(new_identity.to_json(), file, indent=4)
            module.exit_json(changed=changed, enrolled_identity=new_identity.to_json())

        elif state == 'absent' and path_exists:

            # The enrolled identity should not exist, so delete it.
            os.remove(path)
            module.exit_json(changed=True)

        else:

            # The enrolled identity should not exist and doesn't.
            module.exit_json(changed=False)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
