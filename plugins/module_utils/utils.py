#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .consoles import Console
from .certificate_authorities import CertificateAuthority
from .organizations import Organization
from .peers import Peer

def get_console(module):

    # Log in to the IBP console.
    api_endpoint = module.params['api_endpoint']
    api_authtype = module.params['api_authtype']
    api_key = module.params['api_key']
    api_secret = module.params['api_secret']
    api_timeout = module.params['api_timeout']
    console = Console(api_endpoint, api_timeout)
    console.login(api_authtype, api_key, api_secret)
    return console

def get_certificate_authority_by_name(console, name, fail_on_missing=True):

    # Look up the certificate authority by name.
    component = console.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The certificate authority {name} does not exist')
        else:
            return None
    data = console.extract_ca_info(component)
    return CertificateAuthority.from_json(data)

def get_certificate_authority_by_module(console, module, parameter_name='certificate_authority'):

    # If the certificate authority is a dictionary, then we assume that
    # it contains all of the required keys/values.
    certificate_authority = module.params[parameter_name]
    if isinstance(certificate_authority, dict):
        return certificate_authority

    # Otherwise, it is the display name of a certificate authority that
    # we need to look up.
    component = console.get_component_by_display_name(certificate_authority)
    if component is None:
        raise Exception(f'The certificate authority {certificate_authority} does not exist')
    data = console.extract_ca_info(component)

    # Return the certificate authority.
    return CertificateAuthority.from_json(data)

def get_organization_by_name(console, name, fail_on_missing=True):

    # Look up the organization by name.
    component = console.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The organization {name} does not exist')
        else:
            return None
    data = console.extract_organization_info(component)
    return Organization.from_json(data)

def get_peer_by_name(console, name, fail_on_missing=True):

    # Look up the peer by name.
    component = console.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The peer {name} does not exist')
        else:
            return None
    data = console.extract_peer_info(component)
    return Peer.from_json(data)