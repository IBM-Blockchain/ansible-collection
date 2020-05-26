#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .enrolled_identities import EnrolledIdentity

from ansible.module_utils.urls import open_url
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from hfc.fabric_ca.caservice import ca_service, Enrollment

import base64
import json
import os
import tempfile
import time
import urllib


class CertificateAuthorityException(Exception):

    def __init__(self, code, message):
        super(CertificateAuthorityException, self).__init__(dict(code=code, message=message))
        self.code = code


class CertificateAuthority:

    def __init__(self, name, api_url, operations_url, ca_url, ca_name, tlsca_name, pem, location):
        self.name = name
        self.api_url = api_url
        self.operations_url = operations_url
        self.ca_url = ca_url
        self.ca_name = ca_name
        self.tlsca_name = tlsca_name
        self.pem = pem
        self.location = location

    def clone(self):
        return CertificateAuthority(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            ca_url=self.ca_url,
            ca_name=self.ca_name,
            tlsca_name=self.tlsca_name,
            pem=self.pem,
            location=self.location
        )

    def equals(self, other):
        return (
            self.name == other.name and
            self.api_url == other.api_url and
            self.operations_url == other.operations_url and
            self.ca_url == other.ca_url and
            self.ca_name == other.ca_name and
            self.tlsca_name == other.tlsca_name and
            self.pem == other.pem and
            self.location == other.location
        )

    def to_json(self):
        return dict(
            name=self.name,
            api_url=self.api_url,
            operations_url=self.operations_url,
            ca_url=self.ca_url,
            type='fabric-ca',
            ca_name=self.ca_name,
            tlsca_name=self.tlsca_name,
            pem=self.pem,
            tls_cert=self.pem,
            location=self.location
        )

    @staticmethod
    def from_json(data):
        return CertificateAuthority(
            name=data['name'],
            api_url=data['api_url'],
            operations_url=data['operations_url'],
            ca_url=data['ca_url'],
            ca_name=data['ca_name'],
            tlsca_name=data['tlsca_name'],
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
            except Exception:
                pass
            time.sleep(1)
        if not started:
            raise Exception(f'Certificate authority failed to start within {timeout} seconds')

    def connect(self):
        return CertificateAuthorityConnection(self)


class CertificateAuthorityConnection:

    def __init__(self, certificate_authority):
        self.certificate_authority = certificate_authority

    def __enter__(self):
        temp = tempfile.mkstemp()
        os.write(temp[0], base64.b64decode(self.certificate_authority.pem))
        os.close(temp[0])
        self.pem_path = temp[1]
        self.ca_service = ca_service(self.certificate_authority.api_url, self.pem_path, ca_name=self.certificate_authority.ca_name)
        self.identity_service = self.ca_service.newIdentityService()
        self.certificate_service = self.ca_service.newCertificateService()
        return self

    def __exit__(self, type, value, tb):
        os.remove(self.pem_path)

    def enroll(self, name, enrollment_id, enrollment_secret):
        enrollment = self.ca_service.enroll(enrollment_id, enrollment_secret)
        cert = enrollment.cert
        private_key = enrollment.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ca = enrollment.caCert
        return EnrolledIdentity(
            name=name,
            cert=cert,
            private_key=private_key,
            ca=ca
        )

    def is_registered(self, registrar, enrollment_id):
        result = self.identity_service.getOne(enrollment_id, self._get_enrollment(registrar))
        if result['success']:
            return True
        elif result['errors'][0]['code'] == 63:
            return False
        else:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def get_registration(self, registrar, enrollment_id):
        result = self.identity_service.getOne(enrollment_id, self._get_enrollment(registrar))
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])
        return result['result']

    def create_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        secret = self.identity_service.create(self._get_enrollment(registrar), enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs)
        return secret

    def update_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        result = self.identity_service.update(enrollment_id, self._get_enrollment(registrar), type, affiliation, max_enrollments, attrs, enrollment_secret)
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def delete_registration(self, registrar, enrollment_id):
        result = self.identity_service.delete(enrollment_id, self._get_enrollment(registrar))
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def get_certificates(self, registrar, enrollment_id):
        result = self.certificate_service.getCertificates(self._get_enrollment(registrar), enrollment_id)
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])
        return result['result']

    def generate_crl(self, registrar):
        return self.ca_service.generateCRL(None, None, None, None, self._get_enrollment(registrar))

    def _get_enrollment(self, identity):
        private_key = serialization.load_pem_private_key(identity.private_key, password=None, backend=default_backend())
        return Enrollment(private_key, identity.cert, service=self.ca_service)
