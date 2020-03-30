#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .fabric_utils import get_fabric_cfg_path
from .msp_utils import convert_identity_to_msp_path

from ansible.module_utils.urls import open_url

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib


class OrderingServiceNode:

    def __init__(self, name, api_url, operations_url, grpcwp_url, msp_id, pem, location, system_channel_id, cluster_id, cluster_name, client_tls_cert, server_tls_cert):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.grpcwp_url = grpcwp_url
        self.msp_id = msp_id
        self.pem = pem
        self.location = location
        self.system_channel_id = system_channel_id
        self.cluster_id = cluster_id
        self.cluster_name = cluster_name
        self.client_tls_cert = client_tls_cert
        self.server_tls_cert = server_tls_cert

    def clone(self):
        return OrderingServiceNode(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            grpcwp_url=self.grpcwp_url,
            msp_id=self.msp_id,
            pem=self.pem,
            location=self.location,
            system_channel_id=self.system_channel_id,
            cluster_id=self.cluster_id,
            cluster_name=self.cluster_name,
            client_tls_cert=self.client_tls_cert,
            server_tls_cert=self.server_tls_cert
        )

    def equals(self, other):
        return (
            self.name == other.name and
            self.api_url == other.api_url and
            self.operations_url == other.operations_url and
            self.grpcwp_url == other.grpcwp_url and
            self.msp_id == other.msp_id and
            self.pem == other.pem and
            self.location == other.location and
            self.system_channel_id == other.system_channel_id and
            self.cluster_id == other.cluster_id and
            self.cluster_name == other.cluster_name and
            self.client_tls_cert == other.client_tls_cert and
            self.server_tls_cert == other.server_tls_cert
        )

    def to_json(self):
        return dict(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            grpcwp_url=self.grpcwp_url,
            type='fabric-orderer',
            msp_id=self.msp_id,
            pem=self.pem,
            tls_cert=self.pem,
            location=self.location,
            system_channel_id=self.system_channel_id,
            cluster_id=self.cluster_id,
            cluster_name=self.cluster_name,
            client_tls_cert=self.client_tls_cert,
            server_tls_cert=self.server_tls_cert
        )

    @staticmethod
    def from_json(data):
        return OrderingServiceNode(
            name=data['name'],
            api_url=data['api_url'],
            operations_url=data['operations_url'],
            grpcwp_url=data['grpcwp_url'],
            msp_id=data['msp_id'],
            pem=data['pem'],
            location=data['location'],
            system_channel_id=data['system_channel_id'],
            cluster_id=data['cluster_id'],
            cluster_name=data['cluster_name'],
            client_tls_cert=data['client_tls_cert'],
            server_tls_cert=data['server_tls_cert']
        )

    def wait_for(self, timeout):
        started = False
        for x in range(timeout):
            try:
                url = urllib.parse.urljoin(self.operations_url, '/healthz')
                response = open_url(url, None, None, method='GET', validate_certs=False)
                if response.code == 200:
                    healthz = json.load(response)
                    if healthz['status'] == 'OK':
                        started = True
                        break
            except Exception:
                pass
            time.sleep(1)
        if not started:
            raise Exception(f'Ordering service node failed to start within {timeout} seconds')

    def connect(self, identity, msp_id):
        return OrderingServiceNodeConnection(self, identity, msp_id)


class OrderingServiceNodeConnection:

    def __init__(self, ordering_service_node, identity, msp_id):
        self.ordering_service_node = ordering_service_node
        self.identity = identity
        self.msp_id = msp_id

    def __enter__(self):
        temp = tempfile.mkstemp()
        os.write(temp[0], base64.b64decode(self.ordering_service_node.pem))
        os.close(temp[0])
        self.pem_path = temp[1]
        self.msp_path = convert_identity_to_msp_path(self.identity)
        self.fabric_cfg_path = get_fabric_cfg_path()
        return self

    def __exit__(self, type, value, tb):
        os.remove(self.pem_path)
        shutil.rmtree(self.msp_path)
        shutil.rmtree(self.fabric_cfg_path)

    def fetch(self, channel, target, path):
        env = self._get_environ()
        netloc = urllib.parse.urlparse(self.ordering_service_node.api_url).netloc
        process = subprocess.run([
            'peer', 'channel', 'fetch', target, path,
            '--channelID', channel,
            '--cafile', self.pem_path, '--orderer', netloc, '--tls'
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to fetch block from ordering service node: {process.stdout}')

    def update(self, channel, path):
        env = self._get_environ()
        netloc = urllib.parse.urlparse(self.ordering_service_node.api_url).netloc
        process = subprocess.run([
            'peer', 'channel', 'update', '-f', path,
            '--channelID', channel,
            '--cafile', self.pem_path, '--orderer', netloc, '--tls'
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to update channel on ordering service node: {process.stdout}')

    def _get_environ(self):
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['FABRIC_CFG_PATH'] = self.fabric_cfg_path
        return env


class OrderingService:

    def __init__(self, nodes):
        self.nodes = nodes

    def clone(self):
        nodes = list()
        for node in self.nodes:
            nodes.append(node.clone())
        return OrderingService(nodes=nodes)

    def equals(self, other):
        if len(self.nodes) != len(other.nodes):
            return False
        i = 0
        while i < len(self.nodes):
            if not self.nodes[i].equals(other.nodes[i]):
                return False
            i += 1
        return True

    def to_json(self):
        nodes = list()
        for node in self.nodes:
            nodes.append(node.to_json())
        return nodes

    @staticmethod
    def from_json(data):
        nodes = list()
        for node in data:
            nodes.append(OrderingServiceNode.from_json(node))
        return OrderingService(nodes=nodes)

    def wait_for(self, timeout):
        for node in self.nodes:
            try:
                node.wait_for(timeout)
                return
            except Exception:
                pass
        raise Exception(f'Ordering service failed to start within {timeout} seconds')

    def connect(self, identity, msp_id):
        return OrderingServiceConnection(self, identity, msp_id)


class OrderingServiceConnection:

    def __init__(self, ordering_service, identity, msp_id):
        self.ordering_service = ordering_service
        self.identity = identity
        self.msp_id = msp_id

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        pass

    def fetch(self, channel, target, path):
        last_e = None
        for node in self.ordering_service.nodes:
            try:
                with node.connect(self.identity, self.msp_id) as connection:
                    connection.fetch(channel, target, path)
                return
            except Exception as e:
                last_e = e
        raise Exception(f'Could not fetch block from any ordering service node: {last_e}')

    def update(self, channel, path):
        last_e = None
        for node in self.ordering_service.nodes:
            try:
                with node.connect(self.identity, self.msp_id) as connection:
                    connection.update(channel, path)
                return
            except Exception as e:
                last_e = e
        raise Exception(f'Could not update channel on any ordering service node: {last_e}')
