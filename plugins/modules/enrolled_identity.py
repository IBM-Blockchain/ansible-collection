#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.enrolled_identities import EnrolledIdentity
from ..module_utils.utils import get_console, get_certificate_authority_by_module

from ansible.errors import AnsibleActionFail
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

import base64
import json
import os
import os.path

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
        type: int
        default: 60
    certificate_authority:
        description:
            - The certificate authority to use to enroll this identity.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
        type: raw
    name:
        description:
            - The name of the enrolled identity.
        type: str
    enrollment_id:
        description:
            - The enrollment ID, or user name, of an identity registered on the certificate authority for this peer.
        type: str
    enrollment_secret:
        description:
            - The enrollment secret, or password, of an identity registered on the certificate authority for this peer.
        type: str
    path:
        description:
            - The path to the JSON file where the enrolled identity will be stored.
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
name:
    description:
        - The name of the enrolled identity.
    type: str
cert:
    description:
        - The base64 encoded certificate of the enrolled identity.
    type: str
private_key:
    description:
        - The base64 encoded private key of the enrolled identity.
    type: str
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
        certificate_authority=dict(type='raw'),
        name=dict(type='str'),
        enrollment_id=dict(type='str'),
        enrollment_secret=dict(type='str'),
        path=dict(type='str', required=True)
    )
    required_if= [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['certificate_authority', 'name', 'enrollment_id', 'enrollment_secret'])
    ]
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

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
            with certificate_authority.connect() as connection:
                identity = connection.enroll(name, enrollment_id, enrollment_secret)
            with open(path, 'w') as file:
                json.dump(identity.to_json(), file, indent=4)
            module.exit_json(changed=True, **identity.to_json())

        elif state == 'present' and path_exists:

            # Load the identity.
            with open(path, 'r') as file:
                identity = EnrolledIdentity.from_json(json.load(file))

            # Update it.
            name = module.params['name']
            new_identity = identity.clone()
            new_identity.name = name

            # Check if it has changed.
            changed = not new_identity.equals(identity)
            if changed:
                with open(path, 'w') as file:
                    json.dump(new_identity.to_json(), file, indent=4)
            module.exit_json(changed=changed, **new_identity.to_json())

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