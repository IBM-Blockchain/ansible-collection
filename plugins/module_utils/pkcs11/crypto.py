#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

try:
    from asn1crypto.core import OctetString
    from asn1crypto.csr import CertificationRequest, CertificationRequestInfo, CRIAttributes
    from asn1crypto.keys import PublicKeyInfo
    from asn1crypto.x509 import Name
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.x509.oid import NameOID
    from hfc.util.crypto.crypto import Crypto
    import pkcs11
    from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism
    from pkcs11.util.ec import encode_named_curve_parameters, encode_ec_public_key, encode_ecdsa_signature
except ImportError:
    # Missing dependencies are handled elsewhere.
    pass

import hashlib


class PKCS11KeyPair:

    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


class PKCS11Crypto(Crypto):

    def __init__(self, pkcs11library, label, pin):
        self.pkcs11library = pkcs11library
        self.label = label
        self.pin = pin
        lib = pkcs11.lib(pkcs11library)
        self.token = lib.get_token(token_label=self.label)
        self.session = self.token.open(rw=True, user_pin=self.pin)
        self.order = int("115792089210356248762697446949407573529996955224135760342422259061068512044369")
        self.half_order = self.order >> 1

    def close(self):
        self.session.close()

    def generate_private_key(self):
        parameters = self.session.create_domain_parameters(KeyType.EC, {
            Attribute.EC_PARAMS: encode_named_curve_parameters('secp256r1')
        }, local=True)
        public_template = {
            Attribute.KEY_TYPE: KeyType.EC,
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.TOKEN: True,
            Attribute.VERIFY: True,
        }
        private_template = {
            Attribute.KEY_TYPE: KeyType.EC,
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.TOKEN: True,
            Attribute.PRIVATE: True,
            Attribute.SIGN: True,
            Attribute.EXTRACTABLE: False,
            Attribute.SENSITIVE: True
        }
        public_key, private_key = parameters.generate_keypair(store=True, public_template=public_template, private_template=private_template)
        ecpt = bytes(OctetString.load(public_key[Attribute.EC_POINT]))
        hash = hashlib.sha256(ecpt)
        ski = hash.digest()
        hexski = hash.hexdigest()
        public_key[Attribute.ID] = ski
        public_key[Attribute.LABEL] = hexski
        private_key[Attribute.ID] = ski
        private_key[Attribute.LABEL] = hexski
        return PKCS11KeyPair(public_key, private_key)

    def get_private_key(self, ski):
        ski = ski.hex()
        public_key = self.session.get_key(object_class=ObjectClass.PUBLIC_KEY, key_type=KeyType.EC, label=ski)
        private_key = self.session.get_key(object_class=ObjectClass.PRIVATE_KEY, key_type=KeyType.EC, label=ski)
        return PKCS11KeyPair(public_key, private_key)

    def encrypt(self, public_key, message):
        raise Exception('not implemented')

    def decrypt(self, private_key, cipher_text):
        raise Exception('not implemented')

    def sign(self, private_key, message):
        hash = hashlib.sha256(message).digest()
        signature = private_key.private_key.sign(hash, mechanism=Mechanism.ECDSA)
        encoded_signature = encode_ecdsa_signature(signature)
        r, s = decode_dss_signature(encoded_signature)
        if s > self.half_order:
            s = self.order - s
        return encode_dss_signature(r, s)

    def verify(self, public_key, message, signature):
        raise Exception('not implemented')

    def generate_csr(self, private_key, subject_name, extensions=None):
        common_name = subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        info = CertificationRequestInfo({
            'version': 0,
            'subject': Name.build({
                'country_name': 'US',
                'state_or_province_name': 'North Carolina',
                'organization_name': 'Hyperledger',
                'organizational_unit_name': 'Fabric',
                'common_name': common_name
            }),
            'subject_pk_info': PublicKeyInfo.load(encode_ec_public_key(private_key.public_key)),
            'attributes': CRIAttributes([])
        })
        hash = hashlib.sha256(info.dump()).digest()
        signature = private_key.private_key.sign(hash, mechanism=Mechanism.ECDSA)
        csr = CertificationRequest({
            'certification_request_info': info,
            'signature_algorithm': {
                'algorithm': 'sha256_ecdsa',
                'parameters': None
            },
            'signature': encode_ecdsa_signature(signature)
        })
        der = csr.dump()
        result = x509.load_der_x509_csr(der, default_backend())
        return result
