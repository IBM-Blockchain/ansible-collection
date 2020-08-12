#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import base64


class EnrolledIdentity:

    def __init__(self, name, cert, private_key, ca, hsm):
        self.name = name
        self.cert = cert
        self.private_key = private_key
        self.ca = ca
        self.hsm = hsm

    def clone(self):
        return EnrolledIdentity(
            name=self.name,
            cert=self.cert,
            private_key=self.private_key,
            ca=self.ca,
            hsm=self.hsm
        )

    def equals(self, other):
        return self.name == other.name and self.cert == other.cert and self.private_key == other.private_key and self.ca == other.ca and self.hsm == other.hsm

    def to_json(self):
        result = dict(
            name=self.name,
            cert=base64.b64encode(self.cert).decode('utf-8')
        )
        if self.ca:
            result['ca'] = base64.b64encode(self.ca).decode('utf-8')
        if self.hsm:
            result['hsm'] = True
        else:
            result['hsm'] = False
            result['private_key'] = base64.b64encode(self.private_key).decode('utf-8')
        return result

    @staticmethod
    def from_json(data):
        name = data['name']
        cert = base64.b64decode(data['cert'])
        if 'ca' in data:
            ca = base64.b64decode(data['ca'])
        else:
            ca = None
        hsm = data.get('hsm', False)
        if hsm:
            private_key = None
        else:
            private_key = base64.b64decode(data['private_key'])
        return EnrolledIdentity(name, cert, private_key, ca, hsm)
