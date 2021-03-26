#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type


import base64
import json
import re
import ssl
import time
import urllib.parse

from ansible.module_utils.basic import missing_required_lib
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


class Console:

    def __init__(self, module, api_endpoint, api_timeout, api_token_endpoint, retries=5):
        self.module = module
        self.api_endpoint = api_endpoint
        self.api_timeout = api_timeout
        self.api_token_endpoint = api_token_endpoint
        self.retries = retries
        self.authorization = None
        self.v1 = False
        self.logged_in = False

    def login(self, api_authtype, api_key, api_secret):
        if api_authtype == 'ibmcloud':
            self._login_ibmcloud(api_key)
        elif api_authtype == 'basic':
            self._login_basic(api_key, api_secret)
        else:
            raise Exception(f'invalid authentication type "{api_authtype}" specified, valid values are "ibmcloud" and "basic"')
        try:
            self.logged_in = True
            return self._login_v2()
        except Exception:
            self.logged_in = False
            raise

    def _login_v2(self):
        try:
            self.v1 = False
            self.api_base_url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/')
            self.health = self.get_health()
            self.settings = self.get_settings()
        except Exception as e:
            if "HTTP status code 404" in str(e):
                return self._login_v1()
            raise Exception(f'Failed to access IBM Blockchain Platform console: {e}')

    def _login_v1(self):
        try:
            self.v1 = True
            self.api_base_url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v1/')
            self.health = self.get_health()
            self.settings = self.get_settings()
        except Exception as e:
            raise Exception(f'Failed to access IBM Blockchain Platform console: {e}')

    def _login_ibmcloud(self, api_key):
        data = urllib.parse.urlencode({
            'apikey': api_key,
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey'
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to log in to IBM Cloud', 'url': self.api_token_endpoint, 'attempt': attempt})
                auth_response = open_url(url=self.api_token_endpoint, method='POST', headers=headers, data=data, timeout=self.api_timeout)
                auth = json.load(auth_response)
                access_token = auth['access_token']
                self.authorization = f'Bearer {access_token}'
            except Exception as e:
                self.module.json_log({'msg': 'failed to log in to IBM Cloud', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                raise self.handle_error('Failed to log in to IBM Cloud', e)

    def _login_basic(self, api_key, api_secret):
        credentials = f'{api_key}:{api_secret}'
        self.authorization = f'Basic {base64.b64encode(credentials.encode("utf8")).decode("utf8")}'

    def _ensure_loggedin(self):
        if not self.logged_in:
            raise Exception('Not logged in')

    def get_health(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './health')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to get console health', 'url': url, 'attempt': attempt})
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                health = json.load(response)
                self.module.json_log({'msg': 'got console health', 'health': health})
                return health
            except Exception as e:
                self.module.json_log({'msg': 'failed to get console health', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get console health', e)

    def get_settings(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './settings')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to get console settings', 'url': url, 'attempt': attempt})
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                settings = json.load(response)
                self.module.json_log({'msg': 'got console settings', 'settings': settings})
                return settings
            except Exception as e:
                self.module.json_log({'msg': 'failed to get console settings', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get console settings', e)

    def get_all_components(self, deployment_attrs='omitted'):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components?deployment_attrs={deployment_attrs}&cache=skip')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to get all components', 'url': url, 'attempt': attempt})
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                parsed_response = json.load(response)
                components = parsed_response.get('components', list())
                self.module.json_log({'msg': 'got all components', 'components': components})
                return components
            except Exception as e:
                self.module.json_log({'msg': 'failed to get all components', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get all components', e)

    def get_component_by_id(self, id, deployment_attrs='omitted'):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/{id}?deployment_attrs={deployment_attrs}&cache=skip')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to get component by id', 'id': id, 'url': url, 'attempt': attempt})
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'got component by id', 'component': component})
                return component
            except Exception as e:
                # The API will return HTTP 404 Not Found if the component exists in the IBM Blockchain Platform
                # console, but not in Kubernetes. Try again without requesting the deployment attributes, and
                # add a value to the result that will trigger the calling module to delete the component.
                self.module.json_log({'msg': 'failed to get component by id', 'error': str(e)})
                if isinstance(e, urllib.error.HTTPError) and deployment_attrs == 'included':
                    is_404 = e.code == 404
                    # Sometimes the HTTP 404 Not Found is buried in a HTTP 503 Service Unavailable message, so
                    # we need to check for that as well.
                    if e.code == 503:
                        try:
                            error = json.load(e)
                            is_404 = error.get('response', dict()).get('status', 0) == 404
                        except Exception:
                            pass
                    if is_404:
                        result = self.get_component_by_id(id, 'omitted')
                        result['deployment_attrs_missing'] = True
                        return result
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get component by ID', e)

    def get_component_by_display_name(self, component_type, display_name, deployment_attrs='omitted'):
        components = self.get_all_components()
        for component in components:
            if component.get('display_name', None) == display_name and component.get('type', None) == component_type:
                return self.get_component_by_id(component['id'], deployment_attrs)
        return None

    def get_components_by_cluster_name(self, component_type, cluster_name, deployment_attrs='omitted'):
        components = self.get_all_components()
        results = list()
        for component in components:
            if component.get('cluster_name', None) == cluster_name and component.get('type', None) == component_type:
                results.append(self.get_component_by_id(component['id'], deployment_attrs))
        return results

    def create_ca(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './kubernetes/components/fabric-ca')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to create certificate authority', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'created certificate authority', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to create certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create certificate authority', e)

    def update_ca(self, id, data):

        # Go through the changes.
        response = None
        for change in data:
            permitted_change = change in ['version', 'resources', 'zone', 'config_override', 'replicas']
            if not permitted_change:
                continue
            request = {
                change: data[change]
            }
            response = self._update_ca(id, request)
            if change == 'version':
                time.sleep(60)
            else:
                time.sleep(10)
        return response

    def _update_ca(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-ca/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        serialized_data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to update certificate authority', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, serialized_data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'updated certificate authority', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to update certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update certificate authority', e)

    def delete_ca(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to delete certificate authority', 'id': id, 'url': url, 'attempt': attempt})
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                self.module.json_log({'msg': 'deleted certificate authority'})
                return
            except Exception as e:
                self.module.json_log({'msg': 'failed to delete certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete certificate authority', e)

    def extract_ca_info(self, ca):
        return {
            'name': ca['display_name'],
            'api_url': ca['api_url'],
            'operations_url': ca['operations_url'],
            'ca_url': ca['api_url'],
            'type': 'fabric-ca',
            'ca_name': ca['ca_name'],
            'tlsca_name': ca['tlsca_name'],
            'pem': ca.get('tls_ca_root_cert', ca.get('tls_cert', None)),
            'tls_cert': ca.get('tls_ca_root_cert', ca.get('tls_cert', None)),
            'location': ca['location']
        }

    def create_ext_ca(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './components/fabric-ca')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to create external certificate authority', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'created external certificate authority', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to create external certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create external certificate authority', e)

    def update_ext_ca(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/fabric-ca/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to update external certificate authority', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'updated external certificate authority', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to update external certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update external certificate authority', e)

    def delete_ext_ca(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to delete external certificate authority', 'id': id, 'url': url, 'attempt': attempt})
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                self.module.json_log({'msg': 'deleted external certificate authority'})
                return
            except Exception as e:
                self.module.json_log({'msg': 'failed to delete external certificate authority', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete external certificate authority', e)

    def create_peer(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './kubernetes/components/fabric-peer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to create peer', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'created peer', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to create peer', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create peer', e)

    def update_peer(self, id, data):

        # Go through the changes.
        response = None
        for change in data:
            permitted_change = change in ['version', 'resources', 'zone', 'config_override']
            if not permitted_change:
                continue
            request = {
                change: data[change]
            }
            response = self._update_peer(id, request)
            if change == 'version':
                time.sleep(60)
            else:
                time.sleep(10)
        return response

    def _update_peer(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-peer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        serialized_data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to update peer', 'data': data, 'url': url, 'attempt': attempt})
                response = open_url(url, serialized_data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                component = json.load(response)
                self.module.json_log({'msg': 'updated peer', 'component': component})
                return component
            except Exception as e:
                self.module.json_log({'msg': 'failed to update peer', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update peer', e)

    def delete_peer(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                self.module.json_log({'msg': 'attempting to delete peer', 'id': id, 'url': url, 'attempt': attempt})
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                self.module.json_log({'msg': 'deleted peer'})
                return
            except Exception as e:
                self.module.json_log({'msg': 'failed to delete peer', 'error': str(e)})
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete peer', e)

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

    def create_ext_peer(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './components/fabric-peer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create external peer', e)

    def update_ext_peer(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/fabric-peer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update external peer', e)

    def delete_ext_peer(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete external peer', e)

    def create_ordering_service(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './kubernetes/components/fabric-orderer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                json_response = json.load(response)
                if isinstance(json_response, list):
                    return json_response
                elif 'created' in json_response:
                    return json_response['created']
                return json_response
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create ordering service', e)

    def delete_ordering_service(self, cluster_id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/tags/{cluster_id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                if response.getcode() == 207:
                    json_response = json.load(response)
                    for deleted in json_response['deleted']:
                        statusCode = deleted['statusCode']
                        if statusCode >= 200 and statusCode < 300:
                            pass
                        elif statusCode == 404:
                            # The API will return HTTP 404 Not Found if the component exists in the IBM Blockchain Platform
                            # console, but not in Kubernetes. Try to delete the component again, but only from the IBM
                            # Blockchain Platform console this time.
                            new_url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/tags/{cluster_id}')
                            open_url(new_url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                        else:
                            raise Exception(f'{deleted}')
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete ordering service', e)

    def extract_ordering_service_info(self, ordering_service):
        results = list()
        for node in ordering_service:
            results.append(self.extract_ordering_service_node_info(node))
        return results

    def delete_ext_ordering_service(self, cluster_id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/tags/{cluster_id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                if response.getcode() == 207:
                    json_response = json.load(response)
                    for deleted in json_response['deleted']:
                        statusCode = deleted['statusCode']
                        if statusCode >= 200 and statusCode < 300:
                            pass
                        else:
                            raise Exception(f'{deleted}')
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete external ordering service', e)

    def edit_ordering_service_node(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        # Extract only the parameters we're allowed to update.
        stripped_data = dict()
        for permitted_change in ['cluster_name', 'display_name', 'api_url', 'operations_url', 'grpcwp_url', 'msp_id', 'consenter_proposal_fin', 'location', 'system_channel_id', 'tags']:
            if permitted_change in data:
                stripped_data[permitted_change] = data[permitted_change]
        serialized_data = json.dumps(stripped_data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, serialized_data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to edit ordering service node', e)

    def update_ordering_service_node(self, id, data):

        # Go through the changes.
        response = None
        for change in data:
            permitted_change = change in ['version', 'resources', 'zone', 'config_override']
            if not permitted_change:
                continue
            request = {
                change: data[change]
            }
            response = self._update_ordering_service_node(id, request)
            if change == 'version':
                time.sleep(60)
            else:
                time.sleep(10)
        return response

    def _update_ordering_service_node(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        serialized_data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, serialized_data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update ordering service node', e)

    def delete_ordering_service_node(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete ordering service node', e)

    def extract_ordering_service_node_info(self, ordering_service_node):
        return {
            'name': ordering_service_node['display_name'],
            'api_url': ordering_service_node['api_url'],
            'operations_url': ordering_service_node['operations_url'],
            'grpcwp_url': ordering_service_node['grpcwp_url'],
            'type': 'fabric-orderer',
            'msp_id': ordering_service_node['msp_id'],
            'pem': ordering_service_node.get('tls_ca_root_cert', ordering_service_node.get('pem', None)),
            'tls_ca_root_cert': ordering_service_node.get('tls_ca_root_cert', ordering_service_node.get('pem', None)),
            'tls_cert': ordering_service_node.get('tls_cert', None),
            'location': ordering_service_node['location'],
            'system_channel_id': ordering_service_node['system_channel_id'],
            'cluster_id': ordering_service_node['cluster_id'],
            'cluster_name': ordering_service_node['cluster_name'],
            'client_tls_cert': ordering_service_node.get('client_tls_cert', None),
            'server_tls_cert': ordering_service_node.get('server_tls_cert', None),
            'consenter_proposal_fin': ordering_service_node.get('consenter_proposal_fin', True)
        }

    def create_ext_ordering_service_node(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './components/fabric-orderer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create external ordering service node', e)

    def update_ext_ordering_service_node(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update external ordering service node', e)

    def delete_ext_ordering_service_node(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete external ordering service node', e)

    def edit_admin_certs(self, id, append_admin_certs, remove_admin_certs):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/{id}/certs')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = {
            'append_admin_certs': append_admin_certs,
            'remove_admin_certs': remove_admin_certs
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to edit admin certificates', e)

    def create_organization(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './components/msp')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create organization', e)

    def update_organization(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/msp/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update peer', e)

    def delete_organization(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete peer', e)

    def extract_organization_info(self, organization):
        return {
            'name': organization['display_name'],
            'msp_id': organization['msp_id'],
            'type': 'msp',
            'root_certs': organization.get('root_certs', list()),
            'intermediate_certs': organization.get('intermediate_certs', list()),
            'admins': organization.get('admins', list()),
            'revocation_list': organization.get('revocation_list', list()),
            'tls_root_certs': organization.get('tls_root_certs', list()),
            'tls_intermediate_certs': organization.get('tls_intermediate_certs', list()),
            'fabric_node_ous': organization['fabric_node_ous'],
            'organizational_unit_identifiers': organization.get('organizational_unit_identifiers', list()),
            'host_url': organization.get('host_url', None)
        }

    def submit_config_block(self, id, config_block):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/{id}/config')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(dict(b64_block=config_block))
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to submit config block to ordering service node', e)

    def should_retry_error(self, error, attempt):
        if attempt >= self.retries:
            return False
        elif isinstance(error, urllib.error.HTTPError):
            # All of these HTTP status codes usually suggest a transient
            # networking problem getting the request to the back end
            # and are safe to retry.
            # HTTP 502 - Bad Gateway
            # HTTP 503 - Service Unavailable
            # HTTP 504 - Gateway Timeout
            transient = error.code in [502, 503, 504]
            if transient:
                time.sleep(5)
                return True
            # HTTP 429 Too Many Requests means we should sleep and retry
            # after the specified period of time because too many requests
            # were made at the same time, either by us or by other clients.
            ratelimited = error.code == 429
            if ratelimited:
                retry_after = error.headers.get('retry-after')
                time.sleep(int(retry_after))
                return True
        elif isinstance(error, urllib.error.URLError):
            # This catches a whole bunch of sins, including incorrect DNS
            # names and other user input errors, but also a whole bunch of
            # transient networking problems such as EOF, read timeouts, etc.
            time.sleep(5)
            return True
        elif isinstance(error, ssl.SSLError):
            # Catch any SSL/TLS errors; this can include read timeout errors.
            time.sleep(5)
            return True
        # Catch any other errors based on error messages.
        other_errors = ['timed out', 'EOF']
        if any(x in str(error) for x in other_errors):
            time.sleep(5)
            return True
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

    def is_free_cluster(self):
        return self.settings.get('CLUSTER_DATA', dict()).get('type', None) == 'free'

    def is_saas(self):
        return self.settings.get('AUTH_SCHEME', None) == 'iam'

    def is_software(self):
        return self.settings.get('AUTH_SCHEME', None) == 'couchdb'

    def is_v1(self):
        return self.v1

    def get_host_url(self):
        split_url = urllib.parse.urlsplit(self.api_endpoint)
        scheme = split_url.scheme
        hostname = split_url.hostname
        port = split_url.port
        if not port:
            if split_url.scheme == "http":
                port = 80
            elif split_url.scheme == "https":
                port = 443
            else:
                raise Exception(f'Invalid scheme {scheme} in console URL {self.api_endpoint}')
        return urllib.parse.urlunsplit((scheme, f'{hostname}:{port}', '', '', ''))

    def get_users(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './permissions/users')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                break
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get the list of console users', e)
        data = json.load(response)
        result = list()
        for uuid in data['users']:
            user = data['users'][uuid]
            user['uuid'] = uuid
            result.append(user)
        return result

    def get_user(self, email):
        users = self.get_users()
        # Emails are stored in lowercase, so do a case-insensitive comparision.
        return next((user for user in users if user['email'].lower() == email.lower()), None)

    def create_user(self, email, roles):
        user = self.get_user(email)
        if user is not None:
            raise Exception(f'The specified user {email} already exists')
        url = urllib.parse.urljoin(self.api_base_url, './permissions/users')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = {
            'users': {
                email: {
                    'roles': roles
                }
            }
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                break
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create console user', e)
        return self.get_user(email)

    def update_user(self, email, roles):
        user = self.get_user(email)
        if user is None:
            raise Exception(f'The specified user {email} does not exist')
        url = urllib.parse.urljoin(self.api_base_url, './permissions/users')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = {
            'uuids': {
                user['uuid']: {
                    'roles': roles
                }
            }
        }
        data = json.dumps(data)
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
                break
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to update console user', e)
        return self.get_user(email)

    def delete_user(self, email):
        user = self.get_user(email)
        if user is None:
            raise Exception(f'The specified user {email} does not exist')
        url = urllib.parse.urljoin(self.api_base_url, f'./permissions/users?uuids={json.dumps([user["uuid"]])}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
                return
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to delete console user', e)

    def get_msps_by_msp_id(self, msp_id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./components/msps/{msp_id}')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                parsed_response = json.load(response)
                return parsed_response.get('msps', list())
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get MSPs by MSP ID', e)

    def get_all_fabric_versions(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, './kubernetes/fabric/versions')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        for attempt in range(1, self.retries + 1):
            try:
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                parsed_response = json.load(response)
                return parsed_response.get('versions', dict())
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to get supported Fabric versions', e)

    def get_all_ca_versions(self):
        all_fabric_versions = self.get_all_fabric_versions()
        return all_fabric_versions.get('ca', dict()).keys()

    def get_all_peer_versions(self):
        all_fabric_versions = self.get_all_fabric_versions()
        return all_fabric_versions.get('peer', dict()).keys()

    def get_all_ordering_service_node_versions(self):
        all_fabric_versions = self.get_all_fabric_versions()
        return all_fabric_versions.get('orderer', dict()).keys()

    def resolve_ca_version(self, version):

        # Determine if the version is just a version, and return it if so.
        version_pattern = re.compile('^\\d+\\.\\d+\\.\\d+(?:-\\d+)?$')
        if version_pattern.match(version):
            return version

        # Ensure we have semantic versioning support.
        if not HAS_SEMANTIC_VERSION:
            raise Exception(missing_required_lib('semantic_version')) from SEMANTIC_VERSION_IMPORT_ERR

        # Get the list of possible versions.
        all_ca_versions = self.get_all_ca_versions()

        # Select the best possible version.
        s = SimpleSpec(version)
        versions = map(Version, all_ca_versions)
        result = s.select(versions)

        # Ensure we selected a valid version.
        if result is None:
            raise Exception(f'Unable to resolve certificate authority version {version} from available versions {all_ca_versions}')
        return str(result)

    def resolve_peer_version(self, version):

        # Determine if the version is just a version, and return it if so.
        version_pattern = re.compile('^\\d+\\.\\d+\\.\\d+(?:-\\d+)?$')
        if version_pattern.match(version):
            return version

        # Ensure we have semantic versioning support.
        if not HAS_SEMANTIC_VERSION:
            raise Exception(missing_required_lib('semantic_version')) from SEMANTIC_VERSION_IMPORT_ERR

        # Get the list of possible versions.
        all_peer_versions = self.get_all_peer_versions()

        # Select the best possible version.
        s = SimpleSpec(version)
        versions = map(Version, all_peer_versions)
        result = s.select(versions)

        # Ensure we selected a valid version.
        if result is None:
            raise Exception(f'Unable to resolve peer version {version} from available versions {all_peer_versions}')
        return str(result)

    def resolve_ordering_service_node_version(self, version):

        # Determine if the version is just a version, and return it if so.
        version_pattern = re.compile('^\\d+\\.\\d+\\.\\d+(?:-\\d+)?$')
        if version_pattern.match(version):
            return version

        # Ensure we have semantic versioning support.
        if not HAS_SEMANTIC_VERSION:
            raise Exception(missing_required_lib('semantic_version')) from SEMANTIC_VERSION_IMPORT_ERR

        # Get the list of possible versions.
        all_ordering_service_node_versions = self.get_all_ordering_service_node_versions()

        # Select the best possible version.
        s = SimpleSpec(version)
        versions = map(Version, all_ordering_service_node_versions)
        result = s.select(versions)

        # Ensure we selected a valid version.
        if result is None:
            raise Exception(f'Unable to resolve ordering service node version {version} from available versions {all_ordering_service_node_versions}')
        return str(result)
