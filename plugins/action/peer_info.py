#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ibm.blockchain_platform.plugins.module_utils.blockchain_platform import BlockchainPlatform
from ansible_collections.ibm.blockchain_platform.plugins.module_utils.dict_utils import copy_dict, merge_dicts, equal_dicts, diff_dicts
from ansible.errors import AnsibleActionFail
from ansible.module_utils.urls import open_url
from ansible.plugins.action import ActionBase

import json
import time
import urllib.parse

class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        changed = False

        # Log in to the IBP console.
        api_endpoint = self._task.args['api_endpoint']
        api_authtype = self._task.args['api_authtype']
        api_key = self._task.args['api_key']
        api_secret = self._task.args.get('api_secret', None)
        api_timeout = self._task.args.get('api_timeout', 60)
        ibp = BlockchainPlatform(api_endpoint, api_timeout)
        ibp.login(api_authtype, api_key, api_secret)

        # Determine whether or not the peer exists.
        display_name = self._task.args['display_name']
        peer = ibp.get_component_by_display_name(display_name, 'included')

        # If it doesn't exist, return now.
        if peer is None:
            return {
                'exists': False
            }

        # Wait for the CA to start.
        timeout = self._task.args.get('wait_timeout', 60)
        ibp.wait_for_peer(peer, timeout)

        # Extract peer information.
        result = ibp.extract_peer_info(peer)
        result['exists'] = True
        return result