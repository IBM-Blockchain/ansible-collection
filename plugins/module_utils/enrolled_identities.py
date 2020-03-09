#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from cryptography.hazmat.primitives import serialization

import base64

class EnrolledIdentity:

    def __init__(self, name, cert, private_key, ca):
        self.name = name
        self.cert = cert
        self.private_key = private_key
        self.ca = ca

    def clone(self):
        return EnrolledIdentity(
            name=self.name,
            cert=self.cert,
            private_key=self.private_key,
            ca=self.ca
        )

    def equals(self, other):
        return self.name == other.name and self.cert == other.cert and self.private_key == other.private_key and self.ca == other.ca

    def to_json(self):
        return dict(
            name=self.name,
            cert=base64.b64encode(self.cert).decode('utf-8'),
            private_key=base64.b64encode(self.private_key).decode('utf-8'),
            ca=base64.b64encode(self.ca).decode('utf-8')
        )

    @staticmethod
    def from_json(data):
        return EnrolledIdentity(
            name=data['name'],
            cert=base64.b64decode(data['cert']),
            private_key=base64.b64decode(data['private_key']),
            ca=base64.b64decode(data['ca'])
        )

