#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .msp_utils import convert_identity_to_msp_path
from .proto_utils import proto_to_json

from ansible.module_utils.urls import open_url

import base64
import json
import os
import random
import re
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
        self.other_paths = list()
        return self

    def __exit__(self, type, value, tb):
        for other_path in self.other_paths:
            os.remove(other_path)
        os.remove(self.pem_path)
        shutil.rmtree(self.msp_path)

    def list_channels(self):
        env = self._get_environ()
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
            raise Exception(f'Failed to list channels on peer: {process.stdout}')

    def join_channel(self, path):
        env = self._get_environ()
        process = subprocess.run([
            'peer', 'channel', 'join', '-b', path
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to join channel on peer: {process.stdout}')

    def fetch_channel(self, channel, target, path):
        env = self._get_environ()
        process = subprocess.run([
            'peer', 'channel', 'fetch', target, path,
            '--channelID', channel
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to fetch block from peer: {process.stdout}')

    def list_installed_chaincodes(self):
        env = self._get_environ()
        process = subprocess.run([
            'peer', 'chaincode', 'list', '--installed'
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            chaincodes = list()
            found_marker = False
            for line in process.stdout.splitlines():
                if line.endswith('installed chaincodes on peer:'):
                    found_marker = True
                elif found_marker:
                    p = re.compile('^Name: (.+), Version: (.+), Path: (.+), Id: (.+)$')
                    m = p.match(line)
                    if m is None:
                        continue
                    (name, version, path, id) = m.groups()
                    chaincodes.append(dict(name=name, version=version, path=path, id=id))
            return chaincodes
        else:
            raise Exception(f'Failed to list installed chaincode on peer: {process.stdout}')

    def install_chaincode(self, path):
        env = self._get_environ()
        process = subprocess.run([
            'peer', 'chaincode', 'install', path
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to install chaincode on peer: {process.stdout}')

    def list_instantiated_chaincodes(self, channel):
        env = self._get_environ()
        process = subprocess.run([
            'peer', 'chaincode', 'list', '--instantiated', '-C', channel
        ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            chaincodes = list()
            found_marker = False
            for line in process.stdout.splitlines():
                if line.endswith(f'instantiated chaincodes on channel {channel}:'):
                    found_marker = True
                elif found_marker:
                    p = re.compile('^Name: (.+), Version: (.+), Path: (.+), Input: (.+), Escc: (.+), Vscc: (.+)$')
                    m = p.match(line)
                    if m is None:
                        continue
                    (name, version, path, input, escc, vscc) = m.groups()
                    chaincodes.append(dict(name=name, version=version, path=path, input=input, escc=escc, vscc=vscc))
            return chaincodes
        else:
            raise Exception(f'Failed to list installed chaincode on peer: {process.stdout}')

    def instantiate_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'instantiate', '-C', channel, '-n', name, '-v', version]
        if ctor is not None:
            args.extend(['-c', ctor])
        if endorsement_policy is not None:
            args.extend(['-P', endorsement_policy])
        if collections_config is not None:
            args.extend(['--collections-config', collections_config])
        if escc is not None:
            args.extend(['-E', escc])
        if vscc is not None:
            args.extend(['-V', vscc])
        args.extend(self._get_ordering_service(channel))
        process = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to instantiate chaincode on channel: {process.stdout}')

    def upgrade_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'upgrade', '-C', channel, '-n', name, '-v', version]
        if ctor is not None:
            args.extend(['-c', ctor])
        if endorsement_policy is not None:
            args.extend(['-P', endorsement_policy])
        if collections_config is not None:
            args.extend(['--collections-config', collections_config])
        if escc is not None:
            args.extend(['-E', escc])
        if vscc is not None:
            args.extend(['-V', vscc])
        args.extend(self._get_ordering_service(channel))
        process = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True, close_fds=True)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to upgrade chaincode on channel: {process.stdout}')

    def _get_environ(self):
        api_url_parsed = urllib.parse.urlparse(self.peer.api_url)
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['CORE_PEER_ADDRESS'] = api_url_parsed.netloc
        env['CORE_PEER_TLS_ENABLED'] = 'true'
        env['CORE_PEER_TLS_ROOTCERT_FILE'] = self.pem_path
        return env

    def _get_ordering_service(self, channel):
        temp = tempfile.mkstemp()
        os.close(temp[0])
        block_path = temp[1]
        try:
            self.fetch_channel(channel, 'config', block_path)
            with open(block_path, 'rb') as file:
                block = proto_to_json('common.Block', file.read())
            channel_group = block['data']['data'][0]['payload']['data']['config']['channel_group']
            orderer_group = channel_group['groups']['Orderer']
            consenters = orderer_group['values']['ConsensusType']['value']['metadata']['consenters']
            consenter = random.choice(consenters)
            temp = tempfile.mkstemp()
            os.write(temp[0], base64.b64decode(consenter['server_tls_cert']))
            os.close(temp[0])
            pem_path = temp[1]
            self.other_paths.append(pem_path)
            address = f'{consenter["host"]}:{consenter["port"]}'
            return ['-o', address, '--tls', '--cafile', pem_path]
        finally:
            os.remove(block_path)