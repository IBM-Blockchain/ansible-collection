#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

# from plugins.module_utils.console_interface import ConsoleInterface

__metaclass__ = type

# import base64
import json
# import re
# import ssl
# import time
import urllib.parse
import q

# from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import open_url

SEMANTIC_VERSION_IMPORT_ERR = None
try:
    from semantic_version import SimpleSpec, Version
    HAS_SEMANTIC_VERSION = True
except ImportError as e:
    HAS_SEMANTIC_VERSION = False
    SEMANTIC_VERSION_IMPORT_ERR = e
    Version = object
    SimpleSpec = object
    pass


class LocalConsole:

    def __init__(self, module, api_endpoint, api_timeout, api_token_endpoint=None, retries=5):
        self.module = module
        self.api_endpoint = api_endpoint
        self.api_timeout = api_timeout
        self.api_token_endpoint = api_token_endpoint
        self.retries = retries
        self.authorization = None
        self.v1 = False
        self.logged_in = False

    def get_component_by_id(self, id):
        url = urllib.parse.urljoin(self.api_endpoint, f'./components/{id}')
        headers = {
            'Accepts': 'application/json'
        }
        response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
        component = json.load(response)
        self.module.json_log({'msg': 'got component by id', 'component': component})
        q(component)
        return component

    def get_component_by_display_name(self, component_type, display_name):
        components = self.get_all_components()
        for component in components:
            if component.get('display_name', None) == display_name and component.get('type', None) == component_type:
                return self.get_component_by_id(component['id'])
        return None

    def get_all_components(self):

        url = urllib.parse.urljoin(self.api_endpoint, './components')
        headers = {
            'Accepts': 'application/json'
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to get all components', 'url': url, 'attempt': attempt, 'api_timeout': self.api_timeout})
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                parsed_response = json.load(response)
                components = parsed_response
                self.module.json_log({'msg': 'got all components', 'components': components})
                return components
            except Exception as e:
                self.module.json_log({'msg': 'failed to get all components', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get all components', e)

    # No specific login implemented
    def login(self, api_authtype, api_key, api_secret):
        self.module.json_log({'msg': 'Local Fabric Connection'})

    def should_retry_error(self, error, attempt):
        return False

    def handle_error(self, message, error):
        if isinstance(error, urllib.error.HTTPError):
            str = error.read()
            try:
                str = json.loads(str)
            except Exception:
                pass
            raise Exception(f'{message}: HTTP status code {error.code}: {str}')
        else:
            raise Exception(f'{message}: {type(error).__name__}: {error}')

    def extract_peer_info(self, peer):
        return {
            'name': peer['display_name'],
            'api_url': peer['api_url'],
            'operations_url': peer['operations_url'],
            'grpcwp_url': peer['grpcwp_url'],
            'type': 'fabric-peer',
            'msp_id': peer['msp_id'],
            'pem': peer.get('tls_ca_root_cert', peer.get('pem', None)),
            'tls_ca_root_cert': peer.get('tls_ca_root_cert', peer.get('pem', None)),
            'tls_cert': peer.get('tls_cert', None),
            'location': peer['location']
        }