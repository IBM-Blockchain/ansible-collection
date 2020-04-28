#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

import base64


def load_cert(cert):
    parsed_cert = base64.b64decode(cert).decode('utf8')
    return x509.load_pem_x509_certificate(parsed_cert.encode('utf8'), default_backend())


def load_certs(certs):
    parsed_certs = base64.b64decode(certs).decode('utf8').split('-----END CERTIFICATE-----\n')
    result = list()
    for parsed_cert in parsed_certs:
        if not parsed_cert.strip():
            continue
        parsed_cert += '-----END CERTIFICATE-----\n'
        result.append(x509.load_pem_x509_certificate(parsed_cert.encode('utf8'), default_backend()))
    return result


def get_ski_for_cert(cert):
    result = None
    try:
        ski_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        result = ski_extension.value.digest
    except x509.ExtensionNotFound:
        pass
    return result


def get_aki_for_cert(cert):
    result = None
    try:
        aki_extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        result = aki_extension.value.key_identifier
    except x509.ExtensionNotFound:
        pass
    return result


def split_ca_chain(chain):
    root_certs = list()
    intermediate_certs = list()
    certs = load_certs(chain)
    for cert in certs:
        ski = get_ski_for_cert(cert)
        aki = get_aki_for_cert(cert)
        serialized_cert = base64.b64encode(cert.public_bytes(Encoding.PEM)).decode('utf8')
        if aki is None or ski == aki:
            root_certs.append(serialized_cert)
        else:
            intermediate_certs.append(serialized_cert)
    return (root_certs, intermediate_certs)
