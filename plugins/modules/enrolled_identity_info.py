#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.enrolled_identities import EnrolledIdentity

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
module: enrolled_identity_info
short_description: Get information about an enrolled Hyperledger Fabric identity
description:
    - Get information about an enrolled Hyperledger Fabric identity by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    path:
        description:
            - The path to the JSON file where the enrolled identity is stored.
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
exists:
    description:
        - True if the enrolled identity exists, false otherwise.
    type: boolean
enrolled_identity:
    description:
        - The enrolled identity.
    type: dict
    contains:
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
        ca:
            description:
                - The base64 encoded CA certificate chain of the enrolled identity.
            type: str
'''

def main():

    # Create the module.
    argument_spec = dict(
        path=dict(type='str', required=True)
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    # Ensure all exceptions are caught.
    try:

        # Determine if the identity exists.
        path = module.params['path']
        path_exists = os.path.isfile(path)

        # If it doesn't exist, return now.
        if not path_exists:
            return module.exit_json(exists=False)

        # Return identity information.
        with open(path, 'r') as file:
            data = json.load(file)
        identity = EnrolledIdentity.from_json(data)
        module.exit_json(exists=True, enrolled_identity=identity.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))

if __name__ == '__main__':
    main()