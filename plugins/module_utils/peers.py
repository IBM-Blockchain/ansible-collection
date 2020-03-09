#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.urls import open_url

import json
import time

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
                response = open_url(f'{self.operations_url}/healthz', None, None, method='GET', validate_certs=False)
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