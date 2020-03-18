#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .msp_utils import convert_identity_to_msp_path

from ansible.module_utils.urls import open_url

import base64
import json
import os
import shutil
import subprocess
import urllib
import tempfile
import time
import urllib

class Peer:

    def __init__(self, name, api_url, operations_url, grpcwp_url, msp_id, pem, location):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.grpcwp_url = grpcwp_url
        self.msp_id = msp_id
        self.pem = pem
        self.location = location

    def clone(self):
        return Peer(
            name = self.name,
            api_url = self.api_url,
            operations_url = self.operations_url,
            grpcwp_url = self.grpcwp_url,
            msp_id = self.msp_id,
            pem = self.pem,
            location = self.location
        )

    def equals(self, other):
        return (
            self.name == other.name and
            self.api_url == other.api_url and
            self.operations_url == other.operations_url and
            self.grpcwp_url == other.grpcwp_url and
            self.msp_id == other.msp_id and
            self.pem == other.pem and
            self.location == other.location
        )

    def to_json(self):
        return dict(
            name = self.name,
            api_url = self.api_url,
            operations_url = self.operations_url,
            grpcwp_url = self.grpcwp_url,
            type='fabric-peer',
            msp_id = self.msp_id,
            pem = self.pem,
            tls_cert = self.pem,
            location = self.location
        )

    @staticmethod
    def from_json(data):
        return Peer(
            name=data['name'],
            api_url=data['api_url'],
            operations_url=data['operations_url'],
            grpcwp_url=data['grpcwp_url'],
            msp_id=data['msp_id'],
            pem=data['pem'],
            location=data['location']
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
            except:
                pass
            time.sleep(1)
        if not started:
            raise Exception(f'Peer failed to start within {timeout} seconds')

    def connect(self, identity, msp_id):
        return PeerConnection(self, identity, msp_id)

class PeerConnection:

    def __init__(self, peer, identity, msp_id):
        self.peer = peer
        self.identity = identity
        self.msp_id = msp_id

    def __enter__(self):
        temp = tempfile.mkstemp()
        os.write(temp[0], base64.b64decode(self.peer.pem))
        os.close(temp[0])
        self.pem_path = temp[1]
        self.msp_path = convert_identity_to_msp_path(self.identity)
        return self

    def __exit__(self, type, value, tb):
        os.remove(self.pem_path)
        shutil.rmtree(self.msp_path)

    def list_channels(self):
        api_url_parsed = urllib.parse.urlparse(self.peer.api_url)
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['CORE_PEER_ADDRESS'] = api_url_parsed.netloc
        env['CORE_PEER_TLS_ENABLED'] = 'true'
        env['CORE_PEER_TLS_ROOTCERT_FILE'] = self.pem_path
        process = subprocess.run([
            'peer', 'channel', 'list'
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            channels = list()
            found_marker = False
            for line in process.stdout.splitlines():
                if line.endswith('has joined: '):
                    found_marker = True
                elif found_marker:
                    channels.append(line)
            return channels
        else:
            raise Exception(f'Failed to fetch block from ordering service node: {process.stdout}')

    def join_channel(self, path):
        api_url_parsed = urllib.parse.urlparse(self.peer.api_url)
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['CORE_PEER_ADDRESS'] = api_url_parsed.netloc
        env['CORE_PEER_TLS_ENABLED'] = 'true'
        env['CORE_PEER_TLS_ROOTCERT_FILE'] = self.pem_path
        process = subprocess.run([
            'peer', 'channel', 'join', '-b', path
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to fetch block from ordering service node: {process.stdout}')