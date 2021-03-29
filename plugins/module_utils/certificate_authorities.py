#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.urls import open_url

from .enrolled_identities import EnrolledIdentity
from .pkcs11.crypto import PKCS11Crypto

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    from hfc.fabric_ca.caservice import Enrollment, ca_service, ecies
except ImportError:
    # Missing dependencies are handled elsewhere.
    pass

import base64
import hashlib
import ipaddress
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
        last_e = None
        for x in range(timeout):
            try:
                url = urllib.parse.urljoin(self.operations_url, '/healthz')
                response = open_url(url, None, None, method='GET', validate_certs=False)
                if response.code == 200:
                    healthz = json.load(response)
                    if healthz['status'] == 'OK':
                        started = True
                        break
            except Exception as e:
                last_e = e
            time.sleep(1)
        if not started:
            raise Exception(f'Certificate authority failed to start within {timeout} seconds: {str(last_e)}')

    def connect(self, module, hsm, tls=False):
        return CertificateAuthorityConnection(module, self, hsm, tls)


class CertificateAuthorityConnection:

    def __init__(self, module, certificate_authority, hsm, tls=False, retries=5):
        self.module = module
        self.certificate_authority = certificate_authority
        self.hsm = hsm
        self.tls = tls
        self.retries = retries

    def __enter__(self):
        temp = tempfile.mkstemp()
        os.write(temp[0], base64.b64decode(self.certificate_authority.pem))
        os.close(temp[0])
        self.pem_path = temp[1]
        if self.hsm:
            self.crypto = PKCS11Crypto(self.hsm['pkcs11library'], self.hsm['label'], self.hsm['pin'])
        else:
            self.crypto = ecies()
        ca_name = self.certificate_authority.ca_name
        if self.tls:
            ca_name = self.certificate_authority.tlsca_name
        self.ca_service = ca_service(self.certificate_authority.api_url, False, ca_name=ca_name, crypto=self.crypto)
        self.identity_service = self.ca_service.newIdentityService()
        self.certificate_service = self.ca_service.newCertificateService()
        return self

    def __exit__(self, type, value, tb):
        os.remove(self.pem_path)

    def get_ca_chain(self):
        return self._run_with_retry(lambda: self._get_ca_chain())

    def _get_ca_chain(self):
        url = urllib.parse.urljoin(self.certificate_authority.api_url, f'/cainfo?ca={self.certificate_authority.ca_name}')
        response = open_url(url, None, None, method='GET', validate_certs=False)
        cainfo = json.load(response)
        return cainfo['result']['CAChain']

    def get_tlsca_chain(self):
        return self._run_with_retry(lambda: self._get_tlsca_chain())

    def _get_tlsca_chain(self):
        url = urllib.parse.urljoin(self.certificate_authority.api_url, f'/cainfo?ca={self.certificate_authority.tlsca_name}')
        response = open_url(url, None, None, method='GET', validate_certs=False)
        cainfo = json.load(response)
        return cainfo['result']['CAChain']

    def enroll(self, name, enrollment_id, enrollment_secret, hosts):
        return self._run_with_retry(lambda: self._enroll(name, enrollment_id, enrollment_secret, hosts))

    def _enroll(self, name, enrollment_id, enrollment_secret, hosts):
        if self.tls:
            return self._enroll_tlsca(name, enrollment_id, enrollment_secret, hosts)
        else:
            return self._enroll_ca(name, enrollment_id, enrollment_secret)

    def _enroll_ca(self, name, enrollment_id, enrollment_secret):
        enrollment = self.ca_service.enroll(enrollment_id, enrollment_secret)
        cert = enrollment.cert
        if self.hsm:
            hsm = True
            private_key = None
        else:
            hsm = False
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
            ca=ca,
            hsm=hsm
        )

    def _enroll_tlsca(self, name, enrollment_id, enrollment_secret, hosts):
        private_key = self.crypto.generate_private_key()
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, enrollment_id)
        ])
        extensions = []
        if hosts:
            names = []
            for host in hosts:
                names.append(self._get_name_for_host(host))
            extension = x509.SubjectAlternativeName(names)
            extensions.append(x509.Extension(extension.oid, False, extension))
        csr = self.crypto.generate_csr(private_key, subject_name, extensions)
        enrollment = self.ca_service.enroll(enrollment_id, enrollment_secret, csr)
        cert = enrollment.cert
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ca = enrollment.caCert
        return EnrolledIdentity(
            name=name,
            cert=cert,
            private_key=private_key_bytes,
            ca=ca,
            hsm=None
        )

    def _get_name_for_host(self, host):
        try:
            ip_address = ipaddress.ip_address(host)
            return x509.IPAddress(ip_address)
        except ValueError:
            return x509.DNSName(host)

    def is_registered(self, registrar, enrollment_id):
        return self._run_with_retry(lambda: self._is_registered(registrar, enrollment_id))

    def _is_registered(self, registrar, enrollment_id):
        result = self.identity_service.getOne(enrollment_id, self._get_enrollment(registrar))
        if result['success']:
            return True
        elif result['errors'][0]['code'] == 63:
            return False
        else:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def get_registration(self, registrar, enrollment_id):
        return self._run_with_retry(lambda: self._get_registration(registrar, enrollment_id))

    def _get_registration(self, registrar, enrollment_id):
        result = self.identity_service.getOne(enrollment_id, self._get_enrollment(registrar))
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])
        return result['result']

    def create_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        return self._run_with_retry(lambda: self._create_registration(registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs))

    def _create_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        secret = self.identity_service.create(self._get_enrollment(registrar), enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs)
        return secret

    def update_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        return self._run_with_retry(lambda: self._update_registration(registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs))

    def _update_registration(self, registrar, enrollment_id, enrollment_secret, type, affiliation, max_enrollments, attrs):
        result = self.identity_service.update(enrollment_id, self._get_enrollment(registrar), type, affiliation, max_enrollments, attrs, enrollment_secret)
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def delete_registration(self, registrar, enrollment_id):
        return self._run_with_retry(lambda: self._delete_registration(registrar, enrollment_id))

    def _delete_registration(self, registrar, enrollment_id):
        result = self.identity_service.delete(enrollment_id, self._get_enrollment(registrar))
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])

    def get_certificates(self, registrar, enrollment_id):
        return self._run_with_retry(lambda: self._get_certificates(registrar, enrollment_id))

    def _get_certificates(self, registrar, enrollment_id):
        result = self.certificate_service.getCertificates(self._get_enrollment(registrar), enrollment_id)
        if not result['success']:
            raise CertificateAuthorityException(result['errors'][0]['code'], result['errors'][0]['message'])
        return result['result']

    def generate_crl(self, registrar):
        return self._run_with_retry(lambda: self._generate_crl(registrar))

    def _generate_crl(self, registrar):
        return self.ca_service.generateCRL(None, None, None, None, self._get_enrollment(registrar))

    def _get_enrollment(self, identity):
        if self.hsm and not identity.hsm:
            raise Exception('HSM configuration specified, but specified identity does not use HSM')
        elif not self.hsm and identity.hsm:
            raise Exception('Specified identity uses HSM, but no HSM configuration specified')
        elif self.hsm:
            cert = x509.load_pem_x509_certificate(identity.cert, default_backend())
            ecpt = cert.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            hash = hashlib.sha256(ecpt)
            ski = hash.digest()
            private_key = self.crypto.get_private_key(ski)
        else:
            private_key = serialization.load_pem_private_key(identity.private_key, password=None, backend=default_backend())
        return Enrollment(private_key, identity.cert, service=self.ca_service)

    def _run_with_retry(self, func):
        for attempt in range(1, self.retries + 1):
            try:
                result = func()
                return result
            except Exception as e:
                msg = str(e)
                if attempt >= self.retries:
                    raise e
                elif "timed out" in msg:
                    time.sleep(5)
                    continue
                elif "retries exceeded" in msg:
                    time.sleep(5)
                    continue
                else:
                    raise e
