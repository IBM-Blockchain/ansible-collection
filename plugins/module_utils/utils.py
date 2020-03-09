#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .blockchain_platform import BlockchainPlatform
from .certificate_authority import CertificateAuthority
from .org import Organization

def get_ibp(module):

    # Log in to the IBP console.
    api_endpoint = module.params['api_endpoint']
    api_authtype = module.params['api_authtype']
    api_key = module.params['api_key']
    api_secret = module.params['api_secret']
    api_timeout = module.params['api_timeout']
    ibp = BlockchainPlatform(api_endpoint, api_timeout)
    ibp.login(api_authtype, api_key, api_secret)
    return ibp

def get_certificate_authority_by_name(ibp, name, fail_on_missing=True):

    # Look up the certificate authority by name.
    component = ibp.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The certificate authority {name} does not exist')
        else:
            return None
    data = ibp.extract_ca_info(component)
    return CertificateAuthority.from_json(data)

def get_certificate_authority_by_module(ibp, module, parameter_name='certificate_authority'):

    # If the certificate authority is a dictionary, then we assume that
    # it contains all of the required keys/values.
    certificate_authority = module.params[parameter_name]
    if isinstance(certificate_authority, dict):
        return certificate_authority

    # Otherwise, it is the display name of a certificate authority that
    # we need to look up.
    component = ibp.get_component_by_display_name(certificate_authority)
    if component is None:
        raise Exception(f'The certificate authority {certificate_authority} does not exist')
    data = ibp.extract_ca_info(component)

    # Return the certificate authority.
    return CertificateAuthority.from_json(data)

def get_organization_by_name(ibp, name, fail_on_missing=True):

    # Look up the organization by name.
    component = ibp.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The organization {name} does not exist')
        else:
            return None
    data = ibp.extract_organization_info(component)
    return Organization.from_json(data)