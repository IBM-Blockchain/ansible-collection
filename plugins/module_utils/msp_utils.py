#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import tempfile

fake_cacert = '''
-----BEGIN CERTIFICATE-----
MIICCTCCAa+gAwIBAgIULtfu81UTt2IcdiWK7GYQU77HhscwCgYIKoZIzj0EAwIw
WjELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMQswCQYDVQQDEwJjYTAeFw0y
MDAzMDYwODU1MDBaFw0zNTAzMDMwODU1MDBaMFoxCzAJBgNVBAYTAlVTMRcwFQYD
VQQIEw5Ob3J0aCBDYXJvbGluYTEUMBIGA1UEChMLSHlwZXJsZWRnZXIxDzANBgNV
BAsTBkZhYnJpYzELMAkGA1UEAxMCY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATq6LSk5TeYmcsSbmLJdwTVoS3pCHNlzZY4m1bkRgvjk8bU3+1vvhKTL3OAGpKZ
L8FM7KaH9jmztT23IgmkZZ7zo1MwUTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU6AC52T9R5Y3K4XGNPqh3bBJR7DIwDwYDVR0RBAgw
BocEfwAAATAKBggqhkjOPQQDAgNIADBFAiEA7OHP7yH7tE0ko6Gp98o/EkhTqo4o
6cGACl2wEnq4tpsCIEStfRFHHweEFuPkf4Ab+nrXTGovTg35WIP+5XkpQOZf
-----END CERTIFICATE-----
'''


def convert_identity_to_msp_path(identity):

    # Create a temporary directory.
    msp_path = tempfile.mkdtemp()

    # Create the admin certificates directory (ideally would be empty, but
    # needs something in it to keep the CLI quiet).
    admincerts_path = os.path.join(msp_path, 'admincerts')
    os.mkdir(admincerts_path)
    with open(os.path.join(admincerts_path, 'cert.pem'), 'wb') as file:
        file.write(identity.cert)

    # Create the CA certificates directory.
    cacerts_path = os.path.join(msp_path, 'cacerts')
    os.mkdir(cacerts_path)
    with open(os.path.join(cacerts_path, 'cert.pem'), 'wb') as file:
        file.write(identity.ca)

    # Create the signing certificates directory.
    signcerts_path = os.path.join(msp_path, 'signcerts')
    os.mkdir(signcerts_path)
    with open(os.path.join(signcerts_path, 'cert.pem'), 'wb') as file:
        file.write(identity.cert)

    # Create the key store directory.
    keystore_path = os.path.join(msp_path, 'keystore')
    os.mkdir(keystore_path)
    if identity.private_key:
        with open(os.path.join(keystore_path, 'key.pem'), 'wb') as file:
            file.write(identity.private_key)

    # Return the temporary directory (user must delete).
    return msp_path


def organization_to_msp(organization, lifecycle_policy_required=False):

    # Build the initial MSP.
    msp = dict(
        groups=dict(),
        mod_policy='Admins',
        policies=dict(
            Admins=dict(
                mod_policy='Admins',
                policy=dict(
                    type=1,
                    value=dict(
                        identities=list([
                            dict(
                                principal=dict(
                                    msp_identifier=organization.msp_id,
                                    role='ADMIN'
                                ),
                                principal_classification='ROLE'
                            )
                        ]),
                        rule=dict(
                            n_out_of=dict(
                                n=1,
                                rules=list([
                                    dict(
                                        signed_by=0
                                    )
                                ])
                            )
                        )
                    )
                )
            ),
            Readers=dict(
                mod_policy='Admins',
                policy=dict(
                    type=1,
                    value=dict(
                        identities=list([
                            dict(
                                principal=dict(
                                    msp_identifier=organization.msp_id,
                                    role='MEMBER'
                                ),
                                principal_classification='ROLE'
                            )
                        ]),
                        rule=dict(
                            n_out_of=dict(
                                n=1,
                                rules=list([
                                    dict(
                                        signed_by=0
                                    )
                                ])
                            )
                        )
                    )
                )
            ),
            Writers=dict(
                mod_policy='Admins',
                policy=dict(
                    type=1,
                    value=dict(
                        identities=list([
                            dict(
                                principal=dict(
                                    msp_identifier=organization.msp_id,
                                    role='MEMBER'
                                ),
                                principal_classification='ROLE'
                            )
                        ]),
                        rule=dict(
                            n_out_of=dict(
                                n=1,
                                rules=list([
                                    dict(
                                        signed_by=0
                                    )
                                ])
                            )
                        )
                    )
                )
            )
        ),
        values=dict(
            MSP=dict(
                mod_policy='Admins',
                value=dict(
                    config=dict(
                        admins=organization.admins,
                        crypto_config=dict(
                            identity_identifier_hash_function='SHA256',
                            signature_hash_family='SHA2'
                        ),
                        fabric_node_ous=organization.fabric_node_ous,
                        intermediate_certs=organization.intermediate_certs,
                        name=organization.msp_id,
                        organizational_unit_identifiers=organization.organizational_unit_identifiers,
                        revocation_list=organization.revocation_list,
                        root_certs=organization.root_certs,
                        signing_identity=None,
                        tls_intermediate_certs=organization.tls_intermediate_certs,
                        tls_root_certs=organization.tls_root_certs
                    ),
                    type=0
                )
            )
        )
    )

    # Add the lifecycle policy if required.
    if lifecycle_policy_required:
        msp['policies']['Lifecycle'] = dict(
            mod_policy='Admins',
            policy=dict(
                type=1,
                value=dict(
                    identities=list([
                        dict(
                            principal=dict(
                                msp_identifier=organization.msp_id,
                                role='MEMBER'
                            ),
                            principal_classification='ROLE'
                        )
                    ]),
                    rule=dict(
                        n_out_of=dict(
                            n=1,
                            rules=list([
                                dict(
                                    signed_by=0
                                )
                            ])
                        )
                    )
                )
            )
        )

    # Return the MSP.
    return msp
