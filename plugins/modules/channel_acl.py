#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.proto_utils import json_to_proto, proto_to_json

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_acl
short_description: Manage an ACL for a Hyperledger Fabric channel
description:
    - Add, update, and remove ACLs for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    state:
        description:
            - C(absent) - An ACL matching the specified name will be removed from the channel.
            - C(present) - Asserts that an ACL matching the specified name and policy exists
              in the channel. If no ACL matches the specified name, the ACL will be added
              to the channel. If an ACL matches the specified name but the policy does not
              match, then the ACL in the channel will be updated.
        type: str
        default: present
        choices:
            - absent
            - present
    path:
        description:
            - Path to current the channel configuration file.
            - This file can be fetched by using the M(channel_config) module.
            - This file will be updated in place. You will need to keep a copy of the original file for computing the configuration
              update.
        type: str
        required: true
    name:
        description:
            - The name of the ACL to add, update, or remove from the channel.
        type: str
        required: true
    policy:
        description:
            - The name of the policy used by the ACL.
        type: str
        required: true
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Add the ACL to the channel
  ibm.blockchain_platform.channel_acl:
    state: present
    name: lscc/ChaincodeExists
    policy: /Channel/Application/Admins
    path: channel_config.bin

- name: Remove the ACL from the channel
  ibm.blockchain_platform.channel_acl:
    state: absent
    name: lscc/ChaincodeExists
    path: channel_config.bin
'''

RETURN = '''
---
{}
'''


def main():

    # Create the module.
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        path=dict(type='str', required=True),
        name=dict(type='str', required=True),
        policy=dict(type='raw', required=True)
    )
    required_if = [
    ]
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Get the target path, ACL name and policy.
        path = module.params['path']
        name = module.params['name']
        policy = module.params['policy']

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())

        # Check to see if the channel ACL exists.
        application_values = config_json['channel_group']['groups']['Application']['values']
        acls_value = application_values.setdefault('ACLs', dict(
            mod_policy='Admins',
            value=dict(
                acls=dict()
            ),
            version=0
        ))
        value = acls_value.get('value', None)
        if value is None:
            value = acls_value['value'] = dict()
        acls = value.get('acls', None)
        if acls is None:
            acls = value['acls'] = dict()
        acl = acls.get(name, None)
        acl_exists = acl is not None

        # Handle the desired state appropriately.
        state = module.params['state']
        if state == 'present' and not acl_exists:

            # Add the channel ACL.
            acls[name] = dict(policy_ref=policy)

        elif state == 'present' and acl_exists:

            # Update the channel ACL.
            current_policy = acl['policy_ref']
            if current_policy == policy:
                return module.exit_json(changed=False)
            acls[name] = dict(policy_ref=policy)

        elif state == 'absent' and not acl_exists:

            # Nothing to do.
            return module.exit_json(changed=False)

        elif state == 'absent' and acl_exists:

            # Delete the channel ACL.
            del acls[name]

        # Save the config.
        config_proto = json_to_proto('common.Config', config_json)
        with open(path, 'wb') as file:
            file.write(config_proto)
        module.exit_json(changed=True)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
