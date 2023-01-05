#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import time
import urllib

from ansible.module_utils.urls import open_url

from .fabric_utils import get_fabric_cfg_path
from .msp_utils import convert_identity_to_msp_path
from .proto_utils import proto_to_json


class Peer:

    def __init__(self, name, api_url, operations_url, grpcwp_url, msp_id, pem, tls_ca_root_cert, tls_cert, location):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.grpcwp_url = grpcwp_url
        self.msp_id = msp_id
        self.pem = pem
        self.tls_ca_root_cert = tls_ca_root_cert
        self.tls_cert = tls_cert
        self.location = location

    def clone(self):
        return Peer(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            grpcwp_url=self.grpcwp_url,
            msp_id=self.msp_id,
            pem=self.pem,
            tls_ca_root_cert=self.tls_ca_root_cert,
            tls_cert=self.tls_cert,
            location=self.location
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
            self.location == other.location
        )

    def to_json(self):
        return dict(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            grpcwp_url=self.grpcwp_url,
            type='fabric-peer',
            msp_id=self.msp_id,
            pem=self.pem,
            tls_ca_root_cert=self.tls_ca_root_cert,
            tls_cert=self.tls_cert,
            location=self.location
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
            tls_ca_root_cert=data['tls_ca_root_cert'],
            tls_cert=data['tls_cert'],
            location=data['location']
        )

    def wait_for(self, timeout):
        started = False
        last_e = None
        for x in range(timeout):
            try:
                url = urllib.parse.urljoin(self.operations_url, '/healthz')
                response = open_url(url, None, None, method='GET', validate_certs=False, follow_redirects='all')
                if response.code == 200:
                    healthz = json.load(response)
                    if healthz['status'] == 'OK':
                        started = True
                        break
            except Exception as e:
                last_e = e
            time.sleep(1)
        if not started:
            raise Exception(f'Peer failed to start within {timeout} seconds: {str(last_e)}')

    def connect(self, module, identity, msp_id, hsm):
        return PeerConnection(module, self, identity, msp_id, hsm)


class PeerConnection:

    def __init__(self, module, peer, identity, msp_id, hsm, retries=5):
        if hsm and not identity.hsm:
            raise Exception('HSM configuration specified, but specified identity does not use HSM')
        elif not hsm and identity.hsm:
            raise Exception('Specified identity uses HSM, but no HSM configuration specified')
        self.module = module
        self.peer = peer
        self.identity = identity
        self.msp_id = msp_id
        self.hsm = hsm
        self.retries = retries

    def __enter__(self):
        temp = tempfile.mkstemp()
        os.write(temp[0], base64.b64decode(self.peer.pem))
        os.close(temp[0])
        self.pem_path = temp[1]
        self.msp_path = convert_identity_to_msp_path(self.identity)
        self.other_paths = list()
        self.fabric_cfg_path = get_fabric_cfg_path()
        return self

    def __exit__(self, type, value, tb):
        for other_path in self.other_paths:
            os.remove(other_path)
        os.remove(self.pem_path)
        shutil.rmtree(self.msp_path)
        shutil.rmtree(self.fabric_cfg_path)

    def list_channels(self):
        env = self._get_environ()
        args = ['peer', 'channel', 'list']
        process = self._run_command(args, env)
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
        args = ['peer', 'channel', 'join', '-b', path]
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to join channel on peer: {process.stdout}')

    def fetch_channel(self, channel, target, path):
        env = self._get_environ()
        args = ['peer', 'channel', 'fetch', target, path, '--channelID', channel]
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to fetch block from peer: {process.stdout}')

    def list_installed_chaincodes_oldlc(self):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'list', '--installed']
        process = self._run_command(args, env)
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
            raise Exception(f'Failed to list installed chaincodes on peer: {process.stdout}')

    def install_chaincode_oldlc(self, path):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'install', path]
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to install chaincode on peer: {process.stdout}')

    def list_instantiated_chaincodes(self, channel):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'list', '--instantiated', '-C', channel]
        process = self._run_command(args, env)
        if process.returncode == 0:
            chaincodes = list()
            found_marker = False
            for line in process.stdout.splitlines():
                if line.endswith(f'instantiated chaincodes on channel {channel}:'):
                    found_marker = True
                elif found_marker:
                    p = re.compile('^Name: (.+), Version: (.+), Path: (.+),(?: Input: (.+),)? Escc: (.+), Vscc: (.+)$')
                    m = p.match(line)
                    if m is None:
                        continue
                    (name, version, path, input, escc, vscc) = m.groups()
                    chaincodes.append(dict(name=name, version=version, path=path, input=input, escc=escc, vscc=vscc))
            return chaincodes
        else:
            raise Exception(f'Failed to list instantiated chaincodes on peer: {process.stdout}')

    def instantiate_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc, orderer):
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
        args.extend(self._get_ordering_service(channel, orderer))
        process = self._run_command(args, env)
        if process.returncode == 0:
            transaction_committed = self.wait_for_chaincode(channel, name, version)
            if transaction_committed:
                return
            else:
                raise Exception('Failed to instantiate chaincode on channel, transaction not committed')
        else:
            raise Exception(f'Failed to instantiate chaincode on channel: {process.stdout}')

    def upgrade_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc, orderer):
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
        args.extend(self._get_ordering_service(channel, orderer))
        process = self._run_command(args, env)
        if process.returncode == 0:
            transaction_committed = self.wait_for_chaincode(channel, name, version)
            if transaction_committed:
                return
            else:
                raise Exception('Failed to upgrade chaincode on channel, transaction not committed')
        else:
            raise Exception(f'Failed to upgrade chaincode on channel: {process.stdout}')

    def wait_for_chaincode(self, channel, name, version):
        # The commands for instantiating and upgrading chaincode do not
        # support the --waitForEvent options, which means that if the
        # transactions are lost in the ordering service or fail validation,
        # we will not know about it.
        for attempt in range(0, 30):
            time.sleep(1)
            chaincodes = self.list_instantiated_chaincodes(channel)
            for chaincode in chaincodes:
                if chaincode['name'] == name and chaincode['version'] == version:
                    return True
        return False

    def list_installed_chaincodes_newlc(self):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'queryinstalled', '-O', 'json']
        process = self._run_command(args, env)
        if process.returncode == 0:
            data = json.loads(process.stdout)
            return data.get('installed_chaincodes', [])
        else:
            raise Exception(f'Failed to list installed chaincode on peer: {process.stdout}')

    def install_chaincode_newlc(self, path):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'install', path]
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to install chaincode on peer: {process.stdout}')

    def check_commit_readiness(self, channel, name, version, package_id, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'checkcommitreadiness', '-C', channel, '-n', name, '-v', version, '--sequence', str(sequence), '-O', 'json']
        if endorsement_policy_ref:
            args.extend(['--channel-config-policy', endorsement_policy_ref])
        elif endorsement_policy:
            args.extend(['--signature-policy', endorsement_policy])
        if endorsement_plugin:
            args.extend(['--endorsement-plugin', endorsement_plugin])
        if validation_plugin:
            args.extend(['--validation-plugin', validation_plugin])
        if init_required:
            args.extend(['--init-required'])
        if collections_config:
            args.extend(['--collections-config', collections_config])
        process = self._run_command(args, env)
        if process.returncode == 0:
            data = json.loads(process.stdout)
            return data.get('approvals', {})
        else:
            raise Exception(f'Failed to check commit readiness on peer: {process.stdout}')

    def approve_chaincode(self, channel, name, version, package_id, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config, timeout, orderer):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'approveformyorg', '-C', channel, '-n', name, '-v', version, '--package-id', package_id, '--sequence', str(sequence), '--waitForEventTimeout', str(timeout) + "s"]
        if endorsement_policy_ref:
            args.extend(['--channel-config-policy', endorsement_policy_ref])
        elif endorsement_policy:
            args.extend(['--signature-policy', endorsement_policy])
        if endorsement_plugin:
            args.extend(['--endorsement-plugin', endorsement_plugin])
        if validation_plugin:
            args.extend(['--validation-plugin', validation_plugin])
        if init_required:
            args.extend(['--init-required'])
        if collections_config:
            args.extend(['--collections-config', collections_config])
        args.extend(self._get_ordering_service(channel, orderer))
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to approve chaincode on peer: {process.stdout}')

    def query_approved_chaincodes(self, channel):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'queryapproved', '-C', channel, '-O', 'json']
        process = self._run_command(args, env)
        if process.returncode == 0:
            data = json.loads(process.stdout)
            return data.get('chaincode_definitions', [])
        else:
            raise Exception(f'Failed to query approved chaincodes on peer: {process.stdout}')

    def query_committed_chaincodes(self, channel):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'querycommitted', '-C', channel, '-O', 'json']
        process = self._run_command(args, env)
        if process.returncode == 0:
            data = json.loads(process.stdout)
            return data.get('chaincode_definitions', [])
        else:
            raise Exception(f'Failed to query committed chaincodes on peer: {process.stdout}')

    def query_committed_chaincode(self, channel, name):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'querycommitted', '-C', channel, '-n', name, '-O', 'json']
        process = self._run_command(args, env)
        if process.returncode == 0:
            return json.loads(process.stdout)
        else:
            raise Exception(f'Failed to query committed chaincode on peer: {process.stdout}')

    def commit_chaincode(self, channel, msp_ids, name, version, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config, timeout, orderer):
        env = self._get_environ()
        args = ['peer', 'lifecycle', 'chaincode', 'commit', '-C', channel, '-n', name, '-v', version, '--sequence', str(sequence), '--waitForEventTimeout', str(timeout) + "s"]
        if endorsement_policy_ref:
            args.extend(['--channel-config-policy', endorsement_policy_ref])
        elif endorsement_policy:
            args.extend(['--signature-policy', endorsement_policy])
        if endorsement_plugin:
            args.extend(['--endorsement-plugin', endorsement_plugin])
        if validation_plugin:
            args.extend(['--validation-plugin', validation_plugin])
        if init_required:
            args.extend(['--init-required'])
        if collections_config:
            args.extend(['--collections-config', collections_config])
        args.extend(self._get_anchor_peers(channel, msp_ids))
        args.extend(self._get_ordering_service(channel, orderer))
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to commit chaincode on peer: {process.stdout}')

    def init_chaincode(self, channel, msp_ids, name, initJsonStr, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, timeout, orderer):
        env = self._get_environ()
        args = ['peer', 'chaincode', 'invoke', '-C', channel, '-n', name, '--isInit', '--ctor', initJsonStr, '--waitForEventTimeout', str(timeout) + "s"]
        if endorsement_policy_ref:
            args.extend(['--channel-config-policy', endorsement_policy_ref])
        elif endorsement_policy:
            args.extend(['--signature-policy', endorsement_policy])
        if endorsement_plugin:
            args.extend(['--endorsement-plugin', endorsement_plugin])
        if validation_plugin:
            args.extend(['--validation-plugin', validation_plugin])
        args.extend(self._get_anchor_peers(channel, msp_ids))
        args.extend(self._get_ordering_service(channel, orderer))
        process = self._run_command(args, env)
        if process.returncode == 0:
            return
        else:
            raise Exception(f'Failed to init legacy chaincode on peer: {process.stdout}')

    def _get_environ(self):
        api_url_parsed = urllib.parse.urlparse(self.peer.api_url)
        env = os.environ.copy()
        env['CORE_PEER_MSPCONFIGPATH'] = self.msp_path
        env['CORE_PEER_LOCALMSPID'] = self.msp_id
        env['CORE_PEER_ADDRESS'] = api_url_parsed.netloc
        env['CORE_PEER_TLS_ENABLED'] = 'true'
        env['CORE_PEER_TLS_ROOTCERT_FILE'] = self.pem_path
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

    def _get_anchor_peers(self, channel, msp_ids):
        temp = tempfile.mkstemp()
        os.close(temp[0])
        block_path = temp[1]
        try:
            self.fetch_channel(channel, 'config', block_path)
            with open(block_path, 'rb') as file:
                block = proto_to_json('common.Block', file.read())
            channel_group = block['data']['data'][0]['payload']['data']['config']['channel_group']
            application_groups = channel_group['groups']['Application']['groups']
            args = []
            for msp_id in msp_ids:
                msp = application_groups.get(msp_id, None)
                if msp is None:
                    raise Exception(f'Organization {msp_id} is not a member of the channel {channel}')
                msp_value = msp['values']['MSP']
                msp_config = msp_value['value']['config']
                tls_root_certs = msp_config['tls_root_certs']
                if tls_root_certs is None:
                    tls_root_certs = []
                tls_intermediate_certs = msp_config['tls_intermediate_certs']
                if tls_intermediate_certs is None:
                    tls_intermediate_certs = []
                tls_certs = tls_root_certs + tls_intermediate_certs
                temp = tempfile.mkstemp()
                for tls_cert in tls_certs:
                    decoded_tls_cert = base64.b64decode(tls_cert)
                    os.write(temp[0], decoded_tls_cert)
                    if not decoded_tls_cert.endswith(b'\n'):
                        os.write(temp[0], b'\n')
                os.close(temp[0])
                pem_path = temp[1]
                self.other_paths.append(pem_path)
                anchor_peers_value = msp['values'].get('AnchorPeers', None)
                if anchor_peers_value is None:
                    raise Exception(f'Organization {msp_id} has no anchor peers defined for channel {channel}')
                anchor_peers = anchor_peers_value['value']['anchor_peers']
                if not anchor_peers:
                    raise Exception(f'Organization {msp_id} has no anchor peers defined for channel {channel}')
                anchor_peer = random.choice(anchor_peers)
                host = anchor_peer['host']
                port = anchor_peer['port']
                address = f'{host}:{port}'
                args.extend(['--peerAddresses', address, '--tlsRootCertFiles', pem_path])
            return args
        finally:
            os.remove(block_path)

    def _get_ordering_service(self, channel, orderer):
        temp = tempfile.mkstemp()
        os.close(temp[0])
        block_path = temp[1]
        try:

            if orderer:
                ordererNode = random.choice(orderer.nodes)
                tlsCert = ordererNode.tls_ca_root_cert
                apiUrl = urllib.parse.urlparse(ordererNode.api_url)
                address = f'{apiUrl.hostname}:{apiUrl.port}'
                self.module.json_log({"msg": "using task specified orderer", "tls_cert": tlsCert, "api_url": address})
            else:
                self.fetch_channel(channel, 'config', block_path)
                with open(block_path, 'rb') as file:
                    block = proto_to_json('common.Block', file.read())

                channel_group = block['data']['data'][0]['payload']['data']['config']['channel_group']
                orderer_group = channel_group['groups']['Orderer']
                consenters = orderer_group['values']['ConsensusType']['value']['metadata']['consenters']
                consenter = random.choice(consenters)
                tlsCert = consenter['server_tls_cert']
                address = f'{consenter["host"]}:{consenter["port"]}'
                self.module.json_log({"msg": "using orderer from channel", "tls_cert": tlsCert, "api_url": address})

            temp = tempfile.mkstemp()
            os.write(temp[0], base64.b64decode(tlsCert))
            os.close(temp[0])
            pem_path = temp[1]
            self.other_paths.append(pem_path)
            return ['-o', address, '--tls', '--cafile', pem_path]
        finally:
            os.remove(block_path)

    def _run_command(self, args, env):
        for attempt in range(1, self.retries + 1):
            self.module.json_log({'msg': 'running command', 'args': args, 'env': env, 'attempt': attempt})
            process = subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True, close_fds=True)
            self.module.json_log({'msg': 'command finished [stdout]', 'rc': process.returncode, 'stdout': process.stdout})
            self.module.json_log({'msg': 'command finished [stderr]', 'rc': process.returncode, 'stdout': process.stderr})
            if process.returncode == 0:
                return process
            elif attempt >= self.retries:
                return process
            elif "could not send to orderer node" in process.stdout:
                time.sleep(5)
                continue
            elif "failed to create new connection" in process.stdout:
                time.sleep(5)
                continue
            else:
                return process
