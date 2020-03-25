#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import equal_dicts, merge_dicts, copy_dict
from ..module_utils.proto_utils import proto_to_json, json_to_proto

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

import json

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_policy
short_description: Manage a policy for a Hyperledger Fabric channel
description:
    - Add, update, and remove policies for a Hyperledger Fabric channel by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    state:
        description:
            - C(absent) - An policy matching the specified name will be removed from the channel.
            - C(present) - Asserts that an policy matching the specified name and configuration exists
              in the channel. If no policy matches the specified name, the policy will be added
              to the channel. If an policy matches the specified name but the configuration does not
              match, then the policy in the channel will be updated.
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
    name:
        description:
            - The name of the policy to add, update, or remove from the channel.
        type: str
    policy:
        description:
            - The policy to add, update, or remove from the channel.
            - You can pass a string, which is a path to a JSON file containing a [p;ocy]
              in the Hyperledger Fabric format (common.Policy).
            - You can also pass a dict, which must correspond to a parsed policy in the
              Hyperledger Fabric format (common.Policy).
        type: raw
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
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
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True, required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Get the target path, policy name and policy.
        path = module.params['path']
        name = module.params['name']
        policy = module.params['policy']
        if isinstance(policy, str):
            with open(policy, 'r') as file:
                policy = json.load(file)
        elif isinstance(policy, dict):
            pass
        else:
            raise Exception(f'The policy {name} is invalid')

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())

        # Check to see if the channel member exists.
        application_policies = config_json['channel_group']['groups']['Application']['policies']
        policy_wrapper = application_policies.get(name, None)

        # Handle the desired state appropriately.
        state = module.params['state']
        if state == 'present' and policy_wrapper is None:

            # Add the channel policy.
            application_policies[name] = dict(
                mod_policy='Admins',
                policy=policy
            )

        elif state == 'present' and policy_wrapper is not None:

            # Update the channel policy.
            updated_policy_wrapper = copy_dict(policy_wrapper)
            merge_dicts(updated_policy_wrapper['policy'], policy)
            if equal_dicts(policy_wrapper, updated_policy_wrapper):
                return module.exit_json(changed=False)
            application_policies[name] = updated_policy_wrapper

        elif state == 'absent' and policy_wrapper is None:

            # Nothing to do.
            return module.exit_json(changed=False)

        elif state == 'absent' and policy_wrapper is not None:

            # Delete the channel member.
            del application_policies[name]

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
