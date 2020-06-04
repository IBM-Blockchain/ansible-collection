#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import copy_dict, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.ordering_services import OrderingService
from ..module_utils.utils import get_console

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: external_ordering_service
short_description: Manage an external Hyperledger Fabric ordering service
description:
    - Import or remove an external Hyperledger Fabric ordering service by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    api_endpoint:
        description:
            - The URL for the IBM Blockchain Platform console.
        type: str
        required: true
    api_authtype:
        description:
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication.
              You must provide a valid API key using I(api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication.
              You must provide both a valid API key using I(api_key) and API secret using I(api_secret).
        type: str
        required: true
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
        required: true
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: int
        default: 60
    api_token_endpoint:
        description:
            - The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.
            - Only required when I(api_authtype) is C(ibmcloud), and you are using IBM internal staging servers for testing.
        type: str
        default: https://iam.cloud.ibm.com/identity/token
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
    name:
        description:
            - The name of the external ordering service.
            - Only required when I(state) is C(absent).
        type: str
    ordering_service:
        description:
            - The definition of the external ordering service, as a list of ordering service nodes.
            - Only required when I(state) is C(present).
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
            cluster_id:
                description:
                    - The unique ID of the ordering service cluster.
                type: str
            cluster_name:
                description:
                    - The name of the ordering service cluster.
                type: str

notes: []
requirements: []
'''

EXAMPLES = '''
- name: Import the ordering service
  ibm.blockchain_platform.external_ordering_service:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ordering_service: "{{ lookup('file', 'Ordering Service.json') }}"

- name: Remove the imported ordering service
  ibm.blockchain_platform.external_ordering_service:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Ordering Service
'''

RETURN = '''
---
ordering_service:
    description:
        - The ordering service, as a list of ordering service nodes.
    returned: when I(state) is C(present)
    type: list
    elements: dict
    contains:
        name:
            description:
                - The name of the ordering service node.
            type: str
            sample: Ordering Service_1
        api_url:
            description:
                - The URL for the API of the ordering service node.
            type: str
            sample: grpcs://orderingservice1-api.example.org:32000
        operations_url:
            description:
                - The URL for the operations service of the ordering service node.
            type: str
            sample: https://orderingservice1-operations.example.org:32000
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the ordering service node.
            type: str
            sample: https://orderingservice1-grpcwebproxy.example.org:32000
        msp_id:
            description:
                - The MSP ID of the ordering service node.
            type: str
            sample: OrdererOrgMSP
        pem:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_cert:
            description:
                - The TLS certificate chain for the ordering service node.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        location:
            description:
                - The location of the ordering service node.
            type: str
            sample: ibmcloud
        system_channel_id:
            description:
                - The name of the system channel for the ordering service node.
            type: str
            sample: testchainid
        client_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        server_tls_cert:
            description:
                - The client TLS certificate for the ordering service node.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        cluster_id:
            description:
                - The unique ID of the ordering service cluster.
            type: str
            sample: abcdefgh
        cluster_name:
            description:
                - The name of the ordering service cluster.
            type: str
            sample: Ordering Service
'''


def main():

    # Create the module.
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        api_endpoint=dict(type='str', required=True),
        api_authtype=dict(type='str', required=True, choices=['ibmcloud', 'basic']),
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str'),
        ordering_service=dict(type='list', elements='dict', options=dict(
            name=dict(type='str'),
            api_url=dict(type='str'),
            operations_url=dict(type='str'),
            grpcwp_url=dict(type='str'),
            msp_id=dict(type='str'),
            pem=dict(type='str'),
            tls_cert=dict(type='str'),
            location=dict(type='str'),
            system_channel_id=dict(type='str'),
            client_tls_cert=dict(type='str'),
            server_tls_cert=dict(type='str'),
            cluster_id=dict(type='str'),
            cluster_name=dict(type='str'),
            type=dict(type='str')
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['ordering_service']),
        ('state', 'absent', ['name'])
    ]
    mutually_exclusive = [
        ['name', 'ordering_service']
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the ordering service exists.
        state = module.params['state']
        ordering_service_definition = module.params['ordering_service']
        cluster_name = module.params['name']
        if state == 'present':
            cluster_name = ordering_service_definition[0]['cluster_name']
        existing_ordering_service = console.get_components_by_cluster_name(cluster_name, 'included')
        existing_ordering_service_exists = len(existing_ordering_service) > 0

        # If the ordering service exists, make sure it's an imported one and not
        # a real one - we don't want to delete it, which may lose data or orphan
        # the Kubernetes components.
        if existing_ordering_service_exists:
            has_deployment_attrs = False
            has_location = False
            for ordering_service_node in existing_ordering_service:
                if 'deployment_attrs_missing' not in ordering_service_node:
                    has_deployment_attrs = True
                    break
                elif ordering_service_node.get('location', '-') != '-':
                    has_location = True
                    break
            if has_deployment_attrs or has_location:
                raise Exception('Ordering service exists and appears to be managed by this console, refusing to continue')

        # If state is absent, then handle the removal now.
        if state == 'absent' and existing_ordering_service_exists:

            # The ordering service should not exist, so delete it.
            for ordering_service_node in existing_ordering_service:
                console.delete_ext_ordering_service_node(ordering_service_node['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The ordering service should not exist and doesn't.
            return module.exit_json(changed=False)

        # Go through any nodes in the existing ordering service, and delete them if
        # they shouldn't exist.
        changed = False
        if existing_ordering_service_exists:
            for ordering_service_node in existing_ordering_service:
                found = False
                for expected_ordering_service_node in ordering_service_definition:
                    if ordering_service_node['display_name'] == expected_ordering_service_node['name']:
                        found = True
                if not found:
                    console.delete_ext_ordering_service_node(ordering_service_node['id'])
                    changed = True

        # Go through all of the nodes that should exist.
        ordering_service = list()
        for ordering_service_node in ordering_service_definition:

            # Extract the expected ordering service node configuration.
            expected_ordering_service_node = dict(
                display_name=ordering_service_node['name'],
                api_url=ordering_service_node['api_url'],
                operations_url=ordering_service_node['operations_url'],
                grpcwp_url=ordering_service_node['grpcwp_url'],
                msp_id=ordering_service_node['msp_id'],
                tls_ca_root_cert=ordering_service_node['pem'],
                system_channel_id=ordering_service_node['system_channel_id'],
                client_tls_cert=ordering_service_node['client_tls_cert'],
                server_tls_cert=ordering_service_node['server_tls_cert'],
                cluster_id=ordering_service_node['cluster_id'],
                cluster_name=ordering_service_node['cluster_name']
            )

            # HACK: delete null properties.
            if expected_ordering_service_node['client_tls_cert'] is None:
                del expected_ordering_service_node['client_tls_cert']
            if expected_ordering_service_node['server_tls_cert'] is None:
                del expected_ordering_service_node['server_tls_cert']

            # Determine if it exists.
            ordering_service_node = console.get_component_by_display_name(ordering_service_node['name'])
            ordering_service_node_exists = ordering_service_node is not None

            # Handle appropriately based on state.
            if not ordering_service_node_exists:

                # Create the ordering service node.
                ordering_service_node = console.create_ext_ordering_service_node(expected_ordering_service_node)
                ordering_service.append(ordering_service_node)
                changed = True

            else:

                # Build the new ordering service node, including any defaults.
                new_ordering_service_node = copy_dict(ordering_service_node)
                merge_dicts(new_ordering_service_node, expected_ordering_service_node)

                # If the ordering service node has changed, apply the changes.
                ordering_service_node_changed = not equal_dicts(ordering_service_node, new_ordering_service_node)
                if ordering_service_node_changed:
                    console.delete_ext_ordering_service_node(new_ordering_service_node['id'])
                    ordering_service_node = console.create_ext_ordering_service_node(expected_ordering_service_node)
                    ordering_service.append(ordering_service_node)
                    changed = True

        # Return the ordering service.
        ordering_service = OrderingService.from_json(console.extract_ordering_service_info(ordering_service))
        module.exit_json(changed=changed, ordering_service=ordering_service.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
