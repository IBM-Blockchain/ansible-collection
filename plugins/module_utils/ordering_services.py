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

    def __init__(self, name, api_url, operations_url, grpcwp_url, msp_id, pem, tls_ca_root_cert, tls_cert, location, system_channel_id, cluster_id, cluster_name, client_tls_cert, server_tls_cert, consenter_proposal_fin):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.grpcwp_url = grpcwp_url
        self.msp_id = msp_id
        self.pem = pem
        self.tls_ca_root_cert = tls_ca_root_cert
        self.tls_cert = tls_cert
        self.location = location
        self.system_channel_id = system_channel_id
        self.cluster_id = cluster_id
        self.cluster_name = cluster_name
        self.client_tls_cert = client_tls_cert
        self.server_tls_cert = server_tls_cert
        self.consenter_proposal_fin = consenter_proposal_fin

    def clone(self):
        return OrderingServiceNode(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            grpcwp_url=self.grpcwp_url,
            msp_id=self.msp_id,
            pem=self.pem,
            tls_ca_root_cert=self.tls_ca_root_cert,
            tls_cert=self.tls_cert,
            location=self.location,
            system_channel_id=self.system_channel_id,
            cluster_id=self.cluster_id,
            cluster_name=self.cluster_name,
            client_tls_cert=self.client_tls_cert,
            server_tls_cert=self.server_tls_cert,
            consenter_proposal_fin=self.consenter_proposal_fin
        )

    def equals(self, other):
        return (
            self.name == other.name and
            self.api_url == other.api_url and
            self.operations_url == other.operations_url and
            self.grpcwp_url == other.grpcwp_url and
            self.msp_id == other.msp_id and
            self.pem == other.pem and
            self.tls_ca_root_cert == other.tls_ca_root_cert and
            self.tls_cert == other.tls_cert and
            self.location == other.location and
            self.system_channel_id == other.system_channel_id and
            self.cluster_id == other.cluster_id and
            self.cluster_name == other.cluster_name and
            self.client_tls_cert == other.client_tls_cert and
            self.server_tls_cert == other.server_tls_cert and
            self.consenter_proposal_fin == other.consenter_proposal_fin
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
            tls_ca_root_cert=self.tls_ca_root_cert,
            tls_cert=self.tls_cert,
            location=self.location,
            system_channel_id=self.system_channel_id,
            cluster_id=self.cluster_id,
            cluster_name=self.cluster_name,
            client_tls_cert=self.client_tls_cert,
            server_tls_cert=self.server_tls_cert,
            consenter_proposal_fin=self.consenter_proposal_fin
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
            tls_ca_root_cert=data['tls_ca_root_cert'],
            tls_cert=data['tls_cert'],
            location=data['location'],
            system_channel_id=data['system_channel_id'],
            cluster_id=data['cluster_id'],
            cluster_name=data['cluster_name'],
            client_tls_cert=data['client_tls_cert'],
            server_tls_cert=data['server_tls_cert'],
            consenter_proposal_fin=data['consenter_proposal_fin']
        )

    def wait_for(self, timeout):
        # If the ordering service node has been pre-created, then it will
        # not be running, so we do not want to wait for it.
        if not self.consenter_proposal_fin:
            return
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

    def connect(self, identity, msp_id, hsm, tls_handshake_time_shift=None):
        return OrderingServiceNodeConnection(self, identity, msp_id, hsm, tls_handshake_time_shift)


class OrderingServiceNodeConnection:

    def __init__(self, ordering_service_node, identity, msp_id, hsm, tls_handshake_time_shift=None):
        if hsm and not identity.hsm:
            raise Exception('HSM configuration specified, but specified identity does not use HSM')
        elif not hsm and identity.hsm:
            raise Exception('Specified identity uses HSM, but no HSM configuration specified')
        self.ordering_service_node = ordering_service_node
        self.identity = identity
        self.msp_id = msp_id
        self.hsm = hsm
        self.tls_handshake_time_shift = tls_handshake_time_shift

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
        args = [
            'peer', 'channel', 'fetch', target, path,
            '--channelID', channel
        ]
        args.extend(self._get_ordering_service())
        process = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to fetch block from ordering service node: {process.stdout}')

    def update(self, channel, path):
        env = self._get_environ()
        args = [
            'peer', 'channel', 'update', '-f', path,
            '--channelID', channel,
        ]
        args.extend(self._get_ordering_service())
        process = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to update channel on ordering service node: {process.stdout}')

    def _get_environ(self):
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['FABRIC_CFG_PATH'] = self.fabric_cfg_path
        if self.identity.hsm:
            env['CORE_PEER_BCCSP_DEFAULT'] = 'PKCS11'
            env['CORE_PEER_BCCSP_PKCS11_LIBRARY'] = self.hsm['pkcs11library']
            env['CORE_PEER_BCCSP_PKCS11_LABEL'] = self.hsm['label']
            env['CORE_PEER_BCCSP_PKCS11_PIN'] = self.hsm['pin']
            env['CORE_PEER_BCCSP_PKCS11_HASH'] = 'SHA2'
            env['CORE_PEER_BCCSP_PKCS11_SECURITY'] = '256'
            env['CORE_PEER_BCCSP_PKCS11_FILEKEYSTORE_KEYSTORE'] = os.path.join(self.msp_path, 'keystore')
        return env

    def _get_ordering_service(self):
        netloc = urllib.parse.urlparse(self.ordering_service_node.api_url).netloc
        result = ['--cafile', self.pem_path, '--orderer', netloc, '--tls']
        if self.tls_handshake_time_shift:
            result.extend(['--tlsHandshakeTimeShift', self.tls_handshake_time_shift])
        return result


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

    def connect(self, identity, msp_id, hsm, tls_handshake_time_shift=None):
        return OrderingServiceConnection(self, identity, msp_id, hsm, tls_handshake_time_shift)


class OrderingServiceConnection:

    def __init__(self, ordering_service, identity, msp_id, hsm, tls_handshake_time_shift=None):
        if hsm and not identity.hsm:
            raise Exception('HSM configuration specified, but specified identity does not use HSM')
        elif not hsm and identity.hsm:
            raise Exception('Specified identity uses HSM, but no HSM configuration specified')
        self.ordering_service = ordering_service
        self.identity = identity
        self.msp_id = msp_id
        self.hsm = hsm
        self.tls_handshake_time_shift = tls_handshake_time_shift

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        pass

    def fetch(self, channel, target, path):
        last_e = None
        for node in self.ordering_service.nodes:
            if not node.consenter_proposal_fin:
                # Don't connect to ordering service nodes that are not ready.
                continue
            try:
                with node.connect(self.identity, self.msp_id, self.hsm, self.tls_handshake_time_shift) as connection:
                    connection.fetch(channel, target, path)
                return
            except Exception as e:
                last_e = e
        raise Exception(f'Could not fetch block from any ordering service node: {last_e}')

    def update(self, channel, path):
        last_e = None
        for node in self.ordering_service.nodes:
            if not node.consenter_proposal_fin:
                # Don't connect to ordering service nodes that are not ready.
                continue
            try:
                with node.connect(self.identity, self.msp_id, self.hsm, self.tls_handshake_time_shift) as connection:
                    connection.update(channel, path)
                return
            except Exception as e:
                last_e = e
        raise Exception(f'Could not update channel on any ordering service node: {last_e}')
