#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.ordering_services import OrderingService
from ..module_utils.dict_utils import merge_dicts, equal_dicts, copy_dict, diff_dicts
from ..module_utils.utils import get_console, get_ordering_service_by_name, get_certificate_authority_by_module

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

import json
import urllib

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ordering_service
short_description: Manage a Hyperledger Fabric ordering service
description:
    - Create, update, or delete a Hyperledger Fabric ordering service by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    state:
        description:
            - C(absent) - An ordering service matching the specified name will be stopped and removed.
            - C(present) - Asserts that an ordering service matching the specified name and configuration exists.
              If no ordering service matches the specified name, an ordering service will be created.
              If an ordering service matches the specified name but the configuration does not match, then the
              ordering service will be updated, if it can be. If it cannot be updated, it will be removed and
              re-created with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    api_endpoint:
        description:
            - The URL for the IBM Blockchain Platform console.
        type: str
    api_authtype:
        description:
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication. You must provide
              a valid API key using I(ibp_api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication. You must provide both a
              valid API key using I(ibp_api_key) and API secret using I(ibp_api_secret).
        type: str
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(ibp_api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: integer
        default: 60
    name:
        description:
            - The name for the ordering service.
        type: str
    msp_id:
        description:
            - The MSP ID for this ordering service.
        type: str
    orderer_type:
        description:
            - C(raft) - The ordering service will use the Raft consensus algorithm.
        default: raft
        type: str
        choices:
            - raft
    system_channel_id:
        description:
            - The name of the system channel for this ordering service.
        default: testchainid
        type: str
    certificate_authority:
        description:
            - The certificate authority to use to enroll the identity for this ordering service.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
            - Only required when I(config) is not specified.
        type: raw
    enrollment_id:
        description:
            - The enrollment ID, or user name, of an identity registered on the certificate authority for this ordering service.
            - Only required when I(config) is not specified.
        type: str
    enrollment_secret:
        description:
            - The enrollment secret, or password, of an identity registered on the certificate authority for this ordering service.
            - Only required when I(config) is not specified.
        type: str
    admin_certificates:
        description:
            - The list of administrator certificates for this ordering service.
            - Administrator certificates must be supplied as base64 encoded PEM files.
            - Only required when I(config) is not specified.
        type: list
        elements: str
    nodes:
        description:
            - The number of ordering service nodes in this ordering service.
        type: int
    config:
        description:
            - The initial configuration for the ordering service. This is only required if you need more advanced configuration than
              is provided by this module using I(certificate_authority) and related options.
            - You must provide initial configuration for each ordering service node in the ordering service, as defined by I(nodes).
            - See the IBM Blockchain Platform documentation for available options: https://cloud.ibm.com/docs/services/blockchain?topic=blockchain-ibp-v2-apis#ibp-v2-apis-config
        type: list
        elements: dict
    config_override:
        description:
            - The configuration overrides for the ordering service.
            - You must provide configuration overrides for each ordering service node in the ordering service, as defined by I(nodes).
            - See the Hyperledger Fabric documentation for available options: https://github.com/hyperledger/fabric/blob/release-1.4/sampleconfig/core.yaml
        type: list
        elements: dict
    resources:
        description:
            - The Kubernetes resource configuration for the ordering service.
        type: dict
        suboptions:
            orderer:
                description:
                    - The Kubernetes resource configuration for the orderer container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the orderer container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the orderer container.
                                type: str
                                default: 250m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the orderer container.
                                type: str
                                default: 500M
            proxy:
                description:
                    - The Kubernetes resource configuration for the proxy container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the proxy container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the proxy container.
                                type: str
                                default: 100m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the proxy container.
                                type: str
                                default: 200M
    storage:
        description:
            - The Kubernetes storage configuration for the ordering service.
        type: dict
        suboptions:
            orderer:
                description:
                    - The Kubernetes storage configuration for the orderer container.
                type: dict
                suboptions:
                    size:
                        description:
                            - The size of the Kubernetes persistent volume claim for the orderer container.
                        type: str
                        default: 100Gi
                    class:
                        default:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the orderer container.
                        type: str
                        default: default
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the ordering service is available.
        type: integer
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
'''

RETURN = '''
---
nodes:
    description:
        - The list of ordering service nodes in this ordering service.
    type: list
    elements: dict
    suboptions:
        name:
            description:
                - The name of the ordering service node.
            type: str
        api_url:
            description:
                - The URL for the API of the ordering service node.
            type: str
        operations_url:
            description:
                - The URL for the operations service of the ordering service node.
            type: str
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the ordering service node.
            type: str
        msp_id:
            description:
                - The MSP ID of the ordering service node.
            type: str
        pem:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        tls_cert:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        location:
            description:
                - The location of the ordering service node.
            type: str
        system_channel_id:
            description:
                - The name of the system channel for the ordering service node.
            type: str
        client_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
        server_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
'''

def get_config(console, module):

    # Determine how many ordering service nodes there are.
    nodes = module.params['nodes']

    # See if the user provided their own configuration.
    config = module.params['config']
    if config is not None:
        if len(config) != nodes:
            raise Exception(f'Number of nodes is {nodes}, but only {len(config)} config objects provided')
        return config

    # Otherwise, provide an enrollment configuration.
    config_element = {
        'enrollment': get_enrollment_config(console, module)
    }
    config = list()
    i = 0
    while i < nodes:
        config.append(config_element)
        i = i + 1
    return config

def get_enrollment_config(console, module):

    # Get the enrollment configuration.
    return {
        'component': get_enrollment_component_config(console, module),
        'tls': get_enrollment_tls_config(console, module),
    }

def get_enrollment_component_config(console, module):

    # Get the enrollment configuration for the peers MSP.
    certificate_authority = get_certificate_authority_by_module(console, module)
    certificate_authority_url = urllib.parse.urlsplit(certificate_authority.api_url)
    enrollment_id = module.params['enrollment_id']
    enrollment_secret = module.params['enrollment_secret']
    admin_certificates = module.params['admin_certificates']
    return {
        'cahost': certificate_authority_url.hostname,
        'caport': str(certificate_authority_url.port),
        'caname': certificate_authority.ca_name,
        'catls': {
            'cacert': certificate_authority.pem
        },
        'enrollid': enrollment_id,
        'enrollsecret': enrollment_secret,
        'admincerts': admin_certificates
    }

def get_enrollment_tls_config(console, module):

    # Get the enrollment configuration for the peers TLS.
    certificate_authority = get_certificate_authority_by_module(console, module)
    certificate_authority_url = urllib.parse.urlsplit(certificate_authority.api_url)
    enrollment_id = module.params['enrollment_id']
    enrollment_secret = module.params['enrollment_secret']
    return {
        'cahost': certificate_authority_url.hostname,
        'caport': str(certificate_authority_url.port),
        'caname': certificate_authority.tlsca_name,
        'catls': {
            'cacert': certificate_authority.pem
        },
        'enrollid': enrollment_id,
        'enrollsecret': enrollment_secret
    }

def main():

    # Create the module.
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True),
        api_secret=dict(type='str'),
        api_timeout=dict(type='int', default=60),
        name=dict(type='str', required=True),
        msp_id=dict(type='str'),
        orderer_type=dict(type='str', default='raft', choices=['raft']),
        system_channel_id=dict(type='str', default='testchainid'),
        certificate_authority=dict(type='raw'),
        enrollment_id=dict(type='str'),
        enrollment_secret=dict(type='str'),
        admin_certificates=dict(type='list', elements='str'),
        nodes=dict(type='int'),
        config=dict(type='list', elements='dict'),
        config_override=dict(type='raw'),
        resources=dict(type='dict'),
        storage=dict(type='dict'),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['msp_id', 'nodes'])
    ]
    required_one_of = [
        ['certificate_authority', 'config']
    ]
    required_together = [
        ['certificate_authority', 'enrollment_id'],
        ['certificate_authority', 'enrollment_secret'],
        ['certificate_authority', 'admin_certificates']
    ]
    mutually_exclusive = [
        ['certificate_authority', 'config']
    ]
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        required_one_of=required_one_of,
        required_together=required_together,
        mutually_exclusive=mutually_exclusive)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the ordering service exists.
        name = module.params['name']
        ordering_service = console.get_components_by_cluster_name(name, deployment_attrs='included')
        ordering_service_exists = len(ordering_service) > 0

        # Extract the ordering service configuration.
        msp_id = module.params['msp_id']
        orderer_type = module.params['orderer_type']
        system_channel_id = module.params['system_channel_id']
        resources = module.params['resources']
        storage = module.params['storage']

        # Handle appropriately based on state.
        state = module.params['state']
        changed = False
        if state == 'present' and not ordering_service_exists:

            # Get the config.
            config = get_config(console, module)

            # Get the config overrides.
            nodes = module.params['nodes']
            config_override = module.params['config_override']
            if config_override is not None:
                if len(config_override) != nodes:
                    raise Exception(f'Number of nodes is {nodes}, but only {len(config_override)} config override objects provided')
            else:
                config_override = list()
                i = 0
                while i < nodes:
                    config_override.append(dict())
                    i = i + 1

            # Set the default configuration.
            new_ordering_service = dict(
                display_name=name,
                cluster_name=name,
                msp_id=msp_id,
                orderer_type=orderer_type,
                system_channel_id=system_channel_id,
                config=config,
                config_override=config_override,
                resources=dict(
                    orderer=dict(
                        requests=dict(
                            cpu='250m',
                            memory='500M'
                        )
                    ),
                    proxy=dict(
                        requests=dict(
                            cpu='100m',
                            memory='200M'
                        )
                    )
                ),
                storage=dict(
                    orderer=dict(
                        size='100Gi'
                    )
                )
            )

            # Merge the user provided configuration over the defaults.
            if resources is not None:
                merge_dicts(new_ordering_service['resources'], resources)
            if storage is not None:
                merge_dicts(new_ordering_service['storage'] ,resources)

            # Create the ordering service.
            ordering_service = console.create_ordering_service(new_ordering_service)
            changed = True

        elif state == 'present' and ordering_service_exists:

            # Check to see if the number of nodes has changed.
            nodes = module.params['nodes']
            if nodes != len(ordering_service):
                raise Exception(f'nodes cannot be changed from {len(ordering_service)} to {nodes} for existing ordering service')

            # Go through each node.
            i = 0
            while i < len(ordering_service):

                # Get the node.
                node = ordering_service[i]
                # TODO: remove hack for bug
                if isinstance(node.get('config_override', None), list):
                    node['config_override'] = node['config_override'][i]
                elif node.get('config_override', None) is None:
                    node['config_override'] = dict()
                new_node = copy_dict(node)

                # Check to see if the config overrides have changed.
                config_override = module.params['config_override']
                if config_override is not None:
                    new_node['config_override'] = config_override
                else:
                    new_node['config_override'] = dict()

                # Check to see if the resources have changed.
                new_resources=dict(
                    orderer=dict(
                        requests=dict(
                            cpu='250m',
                            memory='500M'
                        )
                    ),
                    proxy=dict(
                        requests=dict(
                            cpu='100m',
                            memory='200M'
                        )
                    )
                )
                if resources is not None:
                    merge_dicts(new_resources, resources)
                merge_dicts(new_node['resources'], new_resources)

                # Check to see if the storage has changed.
                new_storage = dict(
                    orderer=dict(
                        size='100Gi'
                    )
                )
                if storage is not None:
                    merge_dicts(new_storage, storage)
                merge_dicts(new_node['storage'], new_storage)

                # Check to see if any banned changes have been made.
                banned_changes = ['msp_id', 'orderer_type', 'system_channel_id', 'storage']
                diff = diff_dicts(node, new_node)
                for banned_change in banned_changes:
                    if banned_change in diff:
                        raise Exception(f'{banned_change} cannot be changed from {node[banned_change]} to {new_node[banned_change]} for existing ordering service')

                # If the node has changed, apply the changes.
                node_changed = not equal_dicts(node, new_node)
                if node_changed:
                    ordering_service[i] = console.update_ordering_service_node(new_node['id'], new_node)
                    changed = True

                # Move to the next node.
                i = i + 1

        elif state == 'absent' and ordering_service_exists:

            # The ordering service should not exist, so delete it.
            console.delete_ordering_service(ordering_service[0]['cluster_id'])
            return module.exit_json(changed=True)

        else:

            # The ordering service should not exist and doesn't.
            return module.exit_json(changed=False)

        # Wait for the ordering service to start.
        ordering_service = OrderingService.from_json(console.extract_ordering_service_info(ordering_service))
        timeout = module.params['wait_timeout']
        ordering_service.wait_for(timeout)

        # Return the ordering service.
        module.exit_json(changed=changed, nodes=ordering_service.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))

if __name__ == '__main__':
    main()