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

        # Determine whether or not the CA exists.
        display_name = self._task.args['display_name']
        ca = ibp.get_component_by_display_name(display_name, 'included')

        # Extract the CA configuration.
        state = self._task.args.get('state', 'present')
        config_override = self._task.args.get('config_override', None)
        resources = self._task.args.get('resources', None)
        storage = self._task.args.get('storage', None)

        # If the CA does not exist, but should - create it.
        if ca is None and state == 'present':
            new_ca = {
                'display_name': display_name,
                'config_override': {

                },
                'resources': {
                    'ca': {
                        'requests': {
                            'cpu': '100m',
                            'memory': '200M'
                        }
                    }
                },
                'storage': {
                    'ca': {
                        'size': '20Gi'
                    }
                }
            }
            if config_override is not None:
                merge_dicts(new_ca['config_override'], config_override)
            if resources is not None:
                merge_dicts(new_ca['resources'], resources)
            if storage is not None:
                merge_dicts(new_ca['storage'], storage)
            ibp.create_ca(new_ca)
            changed = True

        # If the CA does exist, but should not - delete it.
        elif ca is not None and state == 'absent':
            ibp.delete_ca(ca['id'])
            return {
                'changed': True
            }

        # If the CA does not exist, and should not, nothing to do.
        elif ca is None and state == 'absent':
            return {
                'changed': False
            }

        # If the CA does exist, and should - update it if necessary.
        elif state == 'present':

            # Update the configuration.
            new_ca = copy_dict(ca)
            if config_override is not None:
                merge_dicts(new_ca['config_override'], config_override)
            if resources is not None:
                merge_dicts(new_ca['resources'], resources)
            if storage is not None:
                merge_dicts(new_ca['storage'], storage)

            # You can't change the registry after creation, but the remote names and secrets are redacted.
            # In order to diff properly, we need to redact the incoming secrets.
            identities = new_ca.get('config_override', dict()).get('ca', dict()).get('registry', dict()).get('identities', list())
            for identity in identities:
                if 'name' in identity:
                    identity['name'] = '[redacted]'
                if 'pass' in identity:
                    identity['pass'] = '[redacted]'
            identities = new_ca.get('config_override', dict()).get('tlsca', dict()).get('registry', dict()).get('identities', list())
            for identity in identities:
                if 'name' in identity:
                    identity['name'] = '[redacted]'
                if 'pass' in identity:
                    identity['pass'] = '[redacted]'

            # Now we can generate a diff and make sure any differences are valid for an update.
            diff = diff_dicts(ca, new_ca)
            if 'storage' in diff:
                raise AnsibleActionFail(f'storage cannot be updated; must delete CA and try again')
            if 'registry' in diff.get('config_override', dict()).get('ca', dict()):
                raise AnsibleActionFail(f'config_override.ca.registry cannot be updated; must delete CA and try again')
            if 'registry' in diff.get('config_override', dict()).get('tlsca', dict()):
                raise AnsibleActionFail(f'config_override.tlsca.registry cannot be updated; must delete CA and try again')

            if not equal_dicts(new_ca, ca):
                ibp.update_ca(ca['id'], new_ca)
                changed = True

        # Extract CA information.
        url = ca['api_url']
        parsed_url = urllib.parse.urlparse(url)
        protocol = parsed_url.scheme
        hostname = parsed_url.hostname
        port = parsed_url.port
        pem = None
        caname = ca['ca_name']
        tlscaname = ca['tlsca_name']

        # Wait for the CA to start.
        self._wait_for(url, 60)

        # Return CA information.
        return {
            'changed': changed,
            'protocol': protocol,
            'hostname': hostname,
            'port': port,
            'url': url,
            'pem': pem,
            'caname': caname,
            'tlscaname': tlscaname
        }

    def _wait_for(self, url, seconds):
        started = False
        for x in range(seconds):
            try:
                response = open_url(f'{url}/cainfo', None, None, method='GET', validate_certs=False)
                if response.code == 200:
                    cainfo = json.load(response)
                    if cainfo['result']['Version'] is not None:
                        started = True
                        break
            except:
                pass
            time.sleep(1)
        if not started:
            raise AnsibleActionFail(f'Certificate authority failed to start within {seconds} seconds')