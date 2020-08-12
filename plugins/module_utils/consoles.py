#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.urls import open_url

import base64
import json
import time
import urllib.parse


class Console:

    def __init__(self, api_endpoint, api_timeout, api_token_endpoint, retries=5):
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
        try:
            data = urllib.parse.urlencode({
                'apikey': api_key,
                'grant_type': 'urn:ibm:params:oauth:grant-type:apikey'
            })
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            auth_response = open_url(url=self.api_token_endpoint, method='POST', headers=headers, data=data, timeout=self.api_timeout)
            auth = json.load(auth_response)
            access_token = auth['access_token']
            self.authorization = f'Bearer {access_token}'
        except Exception as e:
            raise Exception(f'Failed to log in to IBM Cloud: {e}')

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
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
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
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
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
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                parsed_response = json.load(response)
                return parsed_response.get('components', list())
            except Exception as e:
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
                response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                # The API will return HTTP 404 Not Found if the component exists in the IBM Blockchain Platform
                # console, but not in Kubernetes. Try again without requesting the deployment attributes, and
                # add a value to the result that will trigger the calling module to delete the component.
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

    def get_component_by_display_name(self, display_name, deployment_attrs='omitted'):
        components = self.get_all_components()
        ca = next((component for component in components if component.get('display_name', None) == display_name), None)
        if ca is not None:
            return self.get_component_by_id(ca['id'], deployment_attrs)

    def get_components_by_cluster_name(self, cluster_name, deployment_attrs='omitted'):
        components = self.get_all_components()
        results = list()
        for component in components:
            if component.get('cluster_name', None) == cluster_name:
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
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create certificate authority', e)

    def update_ca(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-ca/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        # Extract only the parameters we're allowed to update.
        stripped_data = dict()
        for permitted_change in ['resources', 'zone', 'config_override', 'replicas', 'version']:
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
                return self.handle_error('Failed to update certificate authority', e)

    def delete_ca(self, id):
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

    def delete_ext_ca(self, id):
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
                response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
                return json.load(response)
            except Exception as e:
                if self.should_retry_error(e, attempt):
                    continue
                return self.handle_error('Failed to create peer', e)

    def update_peer(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-peer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        # Extract only the parameters we're allowed to update.
        stripped_data = dict()
        for permitted_change in ['resources', 'zone', 'config_override', 'version']:
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
                return self.handle_error('Failed to update peer', e)

    def delete_peer(self, id):
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
                return json.load(response)
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
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_base_url, f'./kubernetes/components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        # Extract only the parameters we're allowed to update.
        stripped_data = dict()
        for permitted_change in ['resources', 'zone', 'config_override', 'version']:
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
                return self.handle_error('Failed to create ordering service node', e)

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
                return self.handle_error('Failed to update ordering service node', e)

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
            transient = error.code in [502, 503, 504]
            if transient:
                time.sleep(1)
                return True
            ratelimited = error.code == 429
            if ratelimited:
                retry_after = error.headers.get('retry-after')
                time.sleep(int(retry_after))
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
            raise Exception(f'{message}: {error}')

    def is_free_cluster(self):
        return self.settings.get('CLUSTER_DATA', dict()).get('type', None) == 'free'

    def is_saas(self):
        return self.settings.get('AUTH_SCHEME', None) == 'iam'

    def is_software(self):
        return self.settings.get('AUTH_SCHEME', None) == 'couchdb'

    def is_v1(self):
        return self.is_v1

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
