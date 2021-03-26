#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: console_user
short_description: Manage the list of users for an IBM Blockchain Platform console
description:
    - Add, update, and remove users for an instance of the IBM Blockchain Platform console.
    - This module works with the IBM Blockchain Platform software running in a Red Hat OpenShift
      or Kubernetes cluster. It does not work with the IBM Blockchain Platform managed service
      running in IBM Cloud; to manage the list of users in this environment, you must use IAM.
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
            - C(absent) - A user matching the specified email will be removed from the IBM Blockchain
              Platform console.
            - C(present) - Asserts that a user matching the specified email and configuration exists
              in the IBM Blockchain Platform console. If no user matches the specified email, the
              user will be added to the IBM Blockchain Platform console. If a user matches the specified
              email but the configuration does not match, then the user in the IBM Blockchain Platform
              console will be updated.
        type: str
        default: present
        choices:
            - absent
            - present
    email:
        description:
            - The email address of the user.
        type: str
    roles:
        description:
            - The roles for the user. A user must have one or more roles from the list of roles C(reader), C(writer), and C(manager).
            - If you specify C(manager), then the roles C(reader) and C(writer) will be automatically specified for you. If you specify
              C(writer), then the role C(reader) will be automatically specified for you.
        type: list
        elements: str
'''

EXAMPLES = '''
---
- name: Add a user with the manager role to the console
  ibm.blockchain_platform.console_user:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    email: alice@example.org
    roles:
      - manager

- name: Add a user with the writer role to the console
  ibm.blockchain_platform.console_user:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    email: bob@example.org
    roles:
      - writer

- name: Add a user with the reader role to the console
  ibm.blockchain_platform.console_user:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    email: charlie@example.org
    roles:
      - reader

- name: Remove the user from the console
  ibm.blockchain_platform.console_user:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    email: alice@example.org
'''

RETURN = '''
---
console_user:
    description:
        - The user.
    returned: when I(state) is C(present)
    type: dict
    contains:
        uuid:
            description:
                - The UUID of the user.
            type: str
            sample: 7ea7d413-d718-4138-9c25-3712fb5d7d0f
        email:
            description:
                - The email address of the user.
            type: str
            sample: alice@example.org
        roles:
            description:
                - The roles assigned to the user.
            type: list
            elements: str
            sample: manager
'''


def main():

    # Create the module.
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', choices=['ibmcloud', 'basic'], required=True),
        api_key=dict(type='str', no_log=True, required=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        email=dict(type='str', required=True),
        roles=dict(type='list', elements='str', choices=['manager', 'reader', 'writer'])
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['roles'])
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Throw an error if this module is used against SaaS.
        if console.is_saas():
            raise Exception('Cannot use this module with the IBM Blockchain Platform managed service running in IBM Cloud')

        # Determine if the specified user exists.
        email = module.params['email']
        user = console.get_user(email)
        user_exists = user is not None
        module.json_log({
            'msg': 'got console user',
            'user': user,
            'user_exists': user_exists
        })

        # If the user should not exist, handle that now.
        state = module.params['state']
        if state == 'absent' and user_exists:

            # Delete the user.
            console.delete_user(email)
            return module.exit_json(changed=True)

        elif state == 'absent':

            # Nothing to do.
            module.exit_json(changed=False)

        # Build the expected list of roles.
        roles = module.params['roles']
        if 'manager' in roles:
            roles.extend(['writer', 'reader'])
        elif 'writer' in roles:
            roles.append('reader')
        expected_roles = list(set(roles))

        # Now either create or update the user.
        changed = False
        if state == 'present' and not user_exists:

            # Create the user.
            user = console.create_user(email, expected_roles)
            changed = True

        else:

            # Determine the current list of roles.
            expected_role_set = set(expected_roles)
            actual_role_set = set(user['roles'])

            # Update the user if the roles have changed.
            diff = expected_role_set.symmetric_difference(actual_role_set)
            if diff:
                module.json_log({
                    'msg': 'differences detected, updating console user',
                    'expected_role_set': expected_role_set,
                    'actual_role_set': actual_role_set
                })
                user = console.update_user(email, expected_roles)
                changed = True

        # Return the user.
        module.exit_json(changed=changed, console_user=user)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
