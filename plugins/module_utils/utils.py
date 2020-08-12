#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .consoles import Console
from .certificate_authorities import CertificateAuthority
from .enrolled_identities import EnrolledIdentity
from .organizations import Organization
from .ordering_services import OrderingService, OrderingServiceNode
from .peers import Peer

import json


def get_console(module):

    # Log in to the IBP console.
    api_endpoint = module.params['api_endpoint']
    api_authtype = module.params['api_authtype']
    api_key = module.params['api_key']
    api_secret = module.params['api_secret']
    api_timeout = module.params['api_timeout']
    api_token_endpoint = module.params['api_token_endpoint']
    console = Console(api_endpoint, api_timeout, api_token_endpoint)
    console.login(api_authtype, api_key, api_secret)
    if console.is_v1():
        module.warn('Console only supports v1 APIs (IBP < 2.1.3), only limited functionality will be available')
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
        return CertificateAuthority.from_json(certificate_authority)

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


def get_organization_by_module(console, module, parameter_name='organization'):

    # If the organization is a dict, then we assume that
    # it contains all of the required keys/values.
    organization = module.params[parameter_name]
    if isinstance(organization, dict):
        return Organization.from_json(organization)

    # Otherwise, it is the display name of an organization that
    # we need to look up.
    component = console.get_component_by_display_name(organization)
    if component is None:
        raise Exception(f'The organization {organization} does not exist')
    data = console.extract_organization_info(component)

    # Return the organization.
    return Organization.from_json(data)


def get_organizations_by_module(console, module, parameter_name='organizations'):

    # Go over each organization.
    organizations = list()
    for organization in module.params[parameter_name]:

        # If the organization is a dict, then we assume that
        # it contains all of the required keys/values.
        if isinstance(organization, dict):
            organizations.append(Organization.from_json(organization))
            continue

        # Otherwise, it is the display name of an organization that
        # we need to look up.
        component = console.get_component_by_display_name(organization)
        if component is None:
            raise Exception(f'The organization {organization} does not exist')
        data = console.extract_organization_info(component)

        # Add the organization.
        organizations.append(Organization.from_json(data))

    # Return the list of organizations.
    return organizations


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


def get_peer_by_module(console, module, parameter_name='peer'):

    # If the peer is a dict, then we assume that
    # it contains all of the required keys/values.
    peer = module.params[parameter_name]
    if isinstance(peer, dict):
        return Peer.from_json(peer)

    # Otherwise, it is the display name of a peer that
    # we need to look up.
    component = console.get_component_by_display_name(peer)
    if component is None:
        raise Exception(f'The peer {peer} does not exist')
    data = console.extract_peer_info(component)

    # Return the peer.
    return Peer.from_json(data)


def get_peers_by_module(console, module, parameter_name='peers'):

    # Go over each peer.
    peers = list()
    for peer in module.params[parameter_name]:

        # If the peer is a dict, then we assume that
        # it contains all of the required keys/values.
        if isinstance(peer, dict):
            peers.append(Peer.from_json(peer))
            continue

        # Otherwise, it is the display name of an peer that
        # we need to look up.
        component = console.get_component_by_display_name(peer)
        if component is None:
            raise Exception(f'The peer {peer} does not exist')
        data = console.extract_peer_info(component)

        # Add the peer.
        peers.append(Peer.from_json(data))

    # Return the list of organizations.
    return peers


def get_ordering_service_by_name(console, name, fail_on_missing=True):

    # Look up the ordering service by name.
    components = console.get_components_by_cluster_name(name)
    if len(components) == 0:
        if fail_on_missing:
            raise Exception(f'The ordering service {name} does not exist')
        else:
            return None
    data = console.extract_ordering_service_info(components)
    return OrderingService.from_json(data)


def get_ordering_service_by_module(console, module, parameter_name='ordering_service'):

    # If the ordering service is a list, then we assume that
    # it contains all of the required keys/values.
    ordering_service = module.params[parameter_name]
    if isinstance(ordering_service, list):
        return OrderingService.from_json(ordering_service)

    # Otherwise, it is the display name of a ordering service that
    # we need to look up.
    components = console.get_components_by_cluster_name(ordering_service)
    if len(components) == 0:
        raise Exception(f'The ordering service {ordering_service} does not exist')
    data = console.extract_ordering_service_info(components)

    # Return the ordering service.
    return OrderingService.from_json(data)


def get_ordering_service_node_by_name(console, name, fail_on_missing=True):

    # Look up the ordering service node by name.
    component = console.get_component_by_display_name(name)
    if component is None:
        if fail_on_missing:
            raise Exception(f'The peer {name} does not exist')
        else:
            return None
    data = console.extract_ordering_service_node_info(component)
    return OrderingServiceNode.from_json(data)


def get_ordering_service_node_by_module(console, module, parameter_name='ordering_service_node'):

    # If the ordering service is a list, then we assume that
    # it contains all of the required keys/values.
    ordering_service_node = module.params[parameter_name]
    if isinstance(ordering_service_node, dict):
        return OrderingServiceNode.from_json(ordering_service_node)

    # Otherwise, it is the display name of a ordering service that
    # we need to look up.
    component = console.get_component_by_display_name(ordering_service_node)
    if component is None:
        raise Exception(f'The ordering service node {ordering_service_node} does not exist')
    data = console.extract_ordering_service_node_info(component)

    # Return the ordering service.
    return OrderingServiceNode.from_json(data)


def get_ordering_service_nodes_by_module(console, module, parameter_name='ordering_service_nodes'):

    # Go over each ordering service node.
    ordering_service_nodes = list()
    for ordering_service_node in module.params[parameter_name]:

        # If the ordering service node is a dict, then we assume that
        # it contains all of the required keys/values.
        if isinstance(ordering_service_node, dict):
            ordering_service_nodes.append(OrderingServiceNode.from_json(ordering_service_node))
            continue

        # Otherwise, it is the display name of an ordering service node
        # that we need to look up.
        component = console.get_component_by_display_name(ordering_service_node)
        if component is None:
            raise Exception(f'The ordering service node {ordering_service_node} does not exist')
        data = console.extract_ordering_service_node_info(component)

        # Add the ordering service node.
        ordering_service_nodes.append(OrderingServiceNode.from_json(data))

    # Return the list of ordering service nodes.
    return ordering_service_nodes


def get_identity_by_module(module, parameter_name='identity'):

    # If the identity is a dictionary, then we assume that
    # it contains all of the required keys/values.
    identity = module.params[parameter_name]
    if isinstance(identity, dict):
        return EnrolledIdentity.from_json(identity)

    # Otherwise, it is the file name of a identity that
    # we need to read.
    with open(identity, 'r') as file:
        data = json.load(file)
    return EnrolledIdentity.from_json(data)
