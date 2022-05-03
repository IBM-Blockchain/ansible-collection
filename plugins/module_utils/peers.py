#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
from abc import ABC, abstractmethod

__metaclass__ = type

import time


class Peer:

    def __init__(self, name, api_url, operations_url, grpcwp_url, msp_id, pem, tls_ca_root_cert, tls_cert, location, provider):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.grpcwp_url = grpcwp_url
        self.msp_id = msp_id
        self.pem = pem
        self.tls_ca_root_cert = tls_ca_root_cert
        self.tls_cert = tls_cert
        self.location = location
        self.provider = provider

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
                # url = urllib.parse.urljoin(self.operations_url, '/healthz')
                # response = open_url(url, None, None, method='GET', validate_certs=False)
                # if response.code == 200:
                #     healthz = json.load(response)
                healthz = self.provider.wait_for(self)
                if healthz['status'] == 'OK':
                    started = True
                    break
            except Exception as e:
                last_e = e
            time.sleep(1)
        if not started:
            raise Exception(f'Peer failed to start within {timeout} seconds: {str(last_e)}')

    def connect(self, module, identity, msp_id, hsm):
        return self.provider.newPeerConnection(module, self, identity, msp_id, hsm)


class IPeerConnection(ABC):

    @abstractmethod
    def list_channels(self):
        pass

    @abstractmethod
    def join_channel(self, path):
        pass

    @abstractmethod
    def fetch_channel(self, channel, target, path):
        pass

    @abstractmethod
    def list_installed_chaincodes_oldlc(self):
        pass

    @abstractmethod
    def install_chaincode_oldlc(self, path):
        pass

    @abstractmethod
    def list_instantiated_chaincodes(self, channel):
        pass

    @abstractmethod
    def instantiate_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc, orderer):
        pass

    @abstractmethod
    def upgrade_chaincode(self, channel, name, version, ctor, endorsement_policy, collections_config, escc, vscc, orderer):
        pass

    @abstractmethod
    def wait_for_chaincode(self, channel, name, version):
        pass

    @abstractmethod
    def list_installed_chaincodes_newlc(self):
        pass

    @abstractmethod
    def install_chaincode_newlc(self, path):
        pass

    @abstractmethod
    def check_commit_readiness(self, channel, name, version, package_id, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config):
        pass

    @abstractmethod
    def approve_chaincode(self, channel, name, version, package_id, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config, timeout, orderer):
        pass

    @abstractmethod
    def query_committed_chaincodes(self, channel):
        pass

    @abstractmethod
    def query_committed_chaincode(self, channel, name):
        pass

    @abstractmethod
    def commit_chaincode(self, channel, msp_ids, name, version, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config, timeout, orderer):
        pass

    @abstractmethod
    def init_chaincode(self, channel, msp_ids, name, initJsonStr, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, timeout, orderer):
        pass
