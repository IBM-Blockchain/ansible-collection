#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleActionFail
from ansible.module_utils.urls import open_url

import base64
import json
import urllib.parse


class Console:

    def __init__(self, api_endpoint, api_timeout, api_token_endpoint):
        self.api_endpoint = api_endpoint
        self.api_timeout = api_timeout
        self.api_token_endpoint = api_token_endpoint
        self.authorization = None

    def login(self, api_authtype, api_key, api_secret):
        if api_authtype == 'ibmcloud':
            self._login_ibmcloud(api_key)
        elif api_authtype == 'basic':
            self._login_basic(api_key, api_secret)
        else:
            raise AnsibleActionFail(f'invalid authentication type "{api_authtype}" specified, valid values are "ibmcloud" and "basic"')
        try:
            self.health = self.get_health()
            self.settings = self.get_settings()
        except Exception as e:
            raise AnsibleActionFail(f'Failed to access IBM Blockchain Platform console: {e}')

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
            raise AnsibleActionFail(f'Failed to log in to IBM Cloud: {e}')

    def _login_basic(self, api_key, api_secret):
        credentials = f'{api_key}:{api_secret}'
        self.authorization = f'Basic {base64.b64encode(credentials.encode("utf8")).decode("utf8")}'

    def _ensure_loggedin(self):
        if self.authorization is None:
            raise AnsibleActionFail(f'Not logged in')

    def get_health(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/health')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        try:
            response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to get console health', e)

    def get_settings(self):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/settings')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        try:
            response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to get console settings', e)

    def get_all_components(self, deployment_attrs='omitted'):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components?deployment_attrs={deployment_attrs}&cache=skip')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        try:
            response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
            parsed_response = json.load(response)
            return parsed_response.get('components', list())
        except Exception as e:
            return self.handle_error('Failed to get all components', e)

    def get_component_by_id(self, id, deployment_attrs='omitted'):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/{id}?deployment_attrs={deployment_attrs}&cache=skip')
        headers = {
            'Accepts': 'application/json',
            'Authorization': self.authorization
        }
        try:
            response = open_url(url, None, headers, 'GET', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
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
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/kubernetes/components/fabric-ca')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to create certificate authority', e)

    def update_ca(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/fabric-ca/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to update certificate authority', e)

    def delete_ca(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
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

    def create_peer(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/kubernetes/components/fabric-peer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to create peer', e)

    def update_peer(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/fabric-peer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to update peer', e)

    def delete_peer(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
            return self.handle_error('Failed to delete peer', e)

    def extract_peer_info(self, peer):
        return {
            'name': peer['display_name'],
            'api_url': peer['api_url'],
            'operations_url': peer['operations_url'],
            'grpcwp_url': peer['grpcwp_url'],
            'type': 'fabric-peer',
            'msp_id': peer['msp_id'],
            'pem': peer.get('tls_ca_root_cert', peer.get('tls_cert', None)),
            'tls_cert': peer.get('tls_ca_root_cert', peer.get('tls_cert', None)),
            'location': peer['location']
        }

    def create_ordering_service(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/kubernetes/components/fabric-orderer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to create ordering service', e)

    def delete_ordering_service(self, cluster_id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/tags/{cluster_id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
            return self.handle_error('Failed to delete ordering service', e)

    def extract_ordering_service_info(self, ordering_service):
        results = list()
        for node in ordering_service:
            results.append(self.extract_ordering_service_node_info(node))
        return results

    def update_ordering_service_node(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/kubernetes/components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to update ordering service node', e)

    def extract_ordering_service_node_info(self, ordering_service_node):
        return {
            'name': ordering_service_node['display_name'],
            'api_url': ordering_service_node['api_url'],
            'operations_url': ordering_service_node['operations_url'],
            'grpcwp_url': ordering_service_node['grpcwp_url'],
            'type': 'fabric-orderer',
            'msp_id': ordering_service_node['msp_id'],
            'pem': ordering_service_node.get('tls_ca_root_cert', ordering_service_node.get('tls_cert', None)),
            'tls_cert': ordering_service_node.get('tls_ca_root_cert', ordering_service_node.get('tls_cert', None)),
            'location': ordering_service_node['location'],
            'system_channel_id': ordering_service_node['system_channel_id'],
            'cluster_id': ordering_service_node['cluster_id'],
            'cluster_name': ordering_service_node['cluster_name'],
            'client_tls_cert': ordering_service_node.get('client_tls_cert', None),
            'server_tls_cert': ordering_service_node.get('server_tls_cert', None)
        }

    def delete_ext_ordering_service(self, cluster_id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/tags/{cluster_id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
            return self.handle_error('Failed to delete external ordering service', e)

    def create_ext_ordering_service_node(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/components/fabric-orderer')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to create ordering service node', e)

    def update_ext_ordering_service_node(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/fabric-orderer/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to update ordering service node', e)

    def delete_ext_ordering_service_node(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
            return self.handle_error('Failed to delete external ordering service node', e)

    def create_organization(self, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, '/ak/api/v2/components/msp')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'POST', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to create organization', e)

    def update_organization(self, id, data):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/msp/{id}')
        headers = {
            'Accepts': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': self.authorization
        }
        data = json.dumps(data)
        try:
            response = open_url(url, data, headers, 'PUT', validate_certs=False, timeout=self.api_timeout)
            return json.load(response)
        except Exception as e:
            return self.handle_error('Failed to update peer', e)

    def delete_organization(self, id):
        self._ensure_loggedin()
        url = urllib.parse.urljoin(self.api_endpoint, f'/ak/api/v2/components/{id}')
        headers = {
            'Authorization': self.authorization
        }
        try:
            open_url(url, None, headers, 'DELETE', validate_certs=False, timeout=self.api_timeout)
        except Exception as e:
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
            'fabric_node_ous': organization['fabric_node_ous']
        }

    def handle_error(self, message, error):
        if isinstance(error, urllib.error.HTTPError):
            str = error.read()
            try:
                str = json.loads(str)
            except Exception:
                pass
            raise AnsibleActionFail(f'{message}: HTTP status code {error.code}: {str}')
        else:
            raise AnsibleActionFail(f'{message}: {error}')

    def is_free_cluster(self):
        return self.settings.get('CLUSTER_DATA', dict()).get('type', None) == 'free'
