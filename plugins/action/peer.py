#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.consoles import Console
from ..module_utils.dict_utils import copy_dict, merge_dicts, equal_dicts, diff_dicts

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
        self.console = console = Console(api_endpoint, api_timeout)
        console.login(api_authtype, api_key, api_secret)

        # Determine whether or not the peer exists.
        display_name = self._task.args['display_name']
        peer = console.get_component_by_display_name(display_name, 'included')

        # Extract the peer configuration.
        state = self._task.args.get('state', 'present')
        msp_id = self._task.args.get('msp_id', None)
        state_database = self._task.args.get('state_database', 'couchdb')
        config_override = self._task.args.get('config_override', None)
        resources = self._task.args.get('resources', None)
        storage = self._task.args.get('storage', None)

        # If the peer does not exist, but should - create it.
        if peer is None and state == 'present':
            config = self._get_config()

            new_peer = {
                'display_name': display_name,
                'msp_id': msp_id,
                'state_db': state_database,
                'config': config,
                'config_override': {

                },
                'resources': {
                    'peer': {
                        'requests': {
                            'cpu': '200m',
                            'memory': '1000M'
                        }
                    },
                    'proxy': {
                        'requests': {
                            'cpu': '100m',
                            'memory': '200M'
                        }
                    },
                    'couchdb': {
                        'requests': {
                            'cpu': '200m',
                            'memory': '400M'
                        }
                    },
                    'dind': {
                        'requests': {
                            'cpu': '1000m',
                            'memory': '1000M'
                        }
                    }
                },
                'storage': {
                    'peer': {
                        'size': '100Gi'
                    },
                    'couchdb': {
                        'size': '100Gi'
                    }
                }
            }
            if config_override is not None:
                merge_dicts(new_peer['config_override'], config_override)
            if resources is not None:
                merge_dicts(new_peer['resources'], resources)
            if storage is not None:
                merge_dicts(new_peer['storage'], storage)
            peer = console.create_peer(new_peer)
            changed = True

        # If the peer does exist, but should not - delete it.
        elif peer is not None and state == 'absent':
            console.delete_peer(peer['id'])
            return {
                'changed': True
            }

        # If the peer does not exist, and should not, nothing to do.
        elif peer is None and state == 'absent':
            return {
                'changed': False
            }

        # If the peer does exist, and should - update it if necessary.
        elif state == 'present':

            # Update the configuration.
            new_peer = copy_dict(peer)
            new_peer['msp_id'] = msp_id
            new_peer['state_db'] = state_database
            if config_override is not None:
                merge_dicts(new_peer['config_override'], config_override)
            if resources is not None:
                merge_dicts(new_peer['resources'], resources)
            if storage is not None:
                merge_dicts(new_peer['storage'], storage)

            # Now we can generate a diff and make sure any differences are valid for an update.
            diff = diff_dicts(peer, new_peer)
            if 'msp_id' in diff:
                raise AnsibleActionFail(f'msp_id cannot be updated; must delete peer and try again')
            elif 'state_db' in diff:
                raise AnsibleActionFail(f'state_database cannot be updated; must delete peer and try again')
            elif 'storage' in diff:
                raise AnsibleActionFail(f'storage cannot be updated; must delete peer and try again')

            if not equal_dicts(new_peer, peer):
                peer = console.update_peer(peer['id'], new_peer)
                changed = True

        # Wait for the peer to start.
        timeout = self._task.args.get('wait_timeout', 60)
        console.wait_for_peer(peer, timeout)

        # Extract peer information.
        result = console.extract_peer_info(peer)
        result['changed'] = changed
        return result

    def _get_config(self):

        # See if the user provided their own configuration.
        config = self._task.args.get('config', None)
        if config is not None:
            return config

        # Otherwise, provide an enrollment configuration.
        return {
            'enrollment': self._get_enrollment_config()
        }

    def _get_enrollment_config(self):

        # Get the enrollment configuration.
        return {
            'component': self._get_enrollment_component_config(),
            'tls': self._get_enrollment_tls_config(),
        }

    def _get_enrollment_component_config(self):

        # Get the enrollment configuration for the peers MSP.
        certificate_authority = self._get_certificate_authority()
        certificate_authority_url = urllib.parse.urlsplit(certificate_authority['api_url'])
        enrollment_id = self._task.args['enrollment_id']
        enrollment_secret = self._task.args['enrollment_secret']
        admin_certificates = self._task.args['admin_certificates']
        return {
            'cahost': certificate_authority_url.hostname,
            'caport': str(certificate_authority_url.port),
            'caname': certificate_authority['ca_name'],
            'catls': {
                'cacert': certificate_authority['tls_cert']
            },
            'enrollid': enrollment_id,
            'enrollsecret': enrollment_secret,
            'admincerts': admin_certificates
        }

    def _get_enrollment_tls_config(self):

        # Get the enrollment configuration for the peers TLS.
        certificate_authority = self._get_certificate_authority()
        certificate_authority_url = urllib.parse.urlsplit(certificate_authority['api_url'])
        enrollment_id = self._task.args['enrollment_id']
        enrollment_secret = self._task.args['enrollment_secret']
        return {
            'cahost': certificate_authority_url.hostname,
            'caport': str(certificate_authority_url.port),
            'caname': certificate_authority['tlsca_name'],
            'catls': {
                'cacert': certificate_authority['tls_cert']
            },
            'enrollid': enrollment_id,
            'enrollsecret': enrollment_secret
        }

    def _get_certificate_authority(self):

        # If the certificate authority is a dictionary, then we assume that
        # it contains all of the required keys/values.
        certificate_authority = self._task.args['certificate_authority']
        if isinstance(certificate_authority, dict):
            return certificate_authority

        # Otherwise, it is the display name of a certificate authority that
        # we need to look up.
        component = self.console.get_component_by_display_name(certificate_authority)
        if component is None:
            raise AnsibleActionFail(f'The certificate authority {certificate_authority} does not exist')
        return self.console.extract_ca_info(component)
