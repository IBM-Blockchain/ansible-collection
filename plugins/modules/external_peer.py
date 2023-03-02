#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.dict_utils import copy_dict, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.peers import Peer
from ..module_utils.utils import get_console

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: external_peer
short_description: Manage an external Hyperledger Fabric peer
description:
    - Import or remove an external Hyperledger Fabric peer by using the IBM Blockchain Platform.
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
            - C(absent) - A peer matching the specified name will be stopped and removed.
            - C(present) - Asserts that a peer matching the specified name and configuration exists.
              If no peer matches the specified name, a peer will be created.
              If a peer matches the specified name but the configuration does not match, then the
              peer will be updated, if it can be. If it cannot be updated, it will be removed and
              re-created with the specified configuration.
        type: str
        default: present
        choices:
            - absent
            - present
    name:
        description:
            - The name of the external peer.
            - Only required when I(state) is C(absent).
        type: str
    peer:
        description:
            - The definition of the external peer
            - Only required when I(state) is C(present).
        type: dict
        suboptions:
            name:
                description:
                    - The name of the peer.
                type: str
            api_url:
                description:
                    - The URL for the API of the peer.
                type: str
            operations_url:
                description:
                    - The URL for the operations service of the peer.
                type: str
            grpcwp_url:
                description:
                    - The URL for the gRPC web proxy of the peer.
                type: str
            msp_id:
                description:
                    - The MSP ID of the peer.
                type: str
            pem:
                description:
                    - The TLS certificate chain for the peer.
                    - The TLS certificate chain is returned as a base64 encoded PEM.
                type: str
            tls_ca_root_cert:
                description:
                    - The TLS certificate chain for the peer.
                    - The TLS certificate chain is returned as a base64 encoded PEM.
                type: str
            tls_cert:
                description:
                    - The TLS certificate for the peer.
                    - The TLS certificate is returned as a base64 encoded PEM.
                type: str
            location:
                description:
                    - The location of the peer.
                type: str
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Import the peer
  hyperledger.fabric-ansible-collection.external_peer:
    status: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: "{{ lookup('file', 'Org1 Peer.json') }}"

- name: Remove the imported peer
  hyperledger.fabric-ansible-collection.external_peer:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 Peer
'''

RETURN = '''
---
peer:
    description:
        - The peer.
    returned: when I(state) is C(present)
    type: dict
    contains:
        name:
            description:
                - The name of the peer.
            type: str
            sample: Org1 Peer
        api_url:
            description:
                - The URL for the API of the peer.
            type: str
            sample: grpcs://org1peer-api.example.org:32000
        operations_url:
            description:
                - The URL for the operations service of the peer.
            type: str
            sample: grpcs://org1peer-operations.example.org:32000
        grpcwp_url:
            description:
                - The URL for the gRPC web proxy of the peer.
            type: str
            sample: grpcs://org1peer-grpcwebproxy.example.org:32000
        msp_id:
            description:
                - The MSP ID of the peer.
            type: str
            sample: Org1MSP
        pem:
            description:
                - The TLS certificate chain for the peer.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_ca_root_cert:
            description:
                - The TLS certificate chain for the peer.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_cert:
            description:
                - The TLS certificate for the peer.
                - The TLS certificate is returned as a base64 encoded PEM.
            type: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        location:
            description:
                - The location of the peer.
            type: str
            sample: ibmcloud
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
        peer=dict(type='dict', options=dict(
            name=dict(type='str'),
            api_url=dict(type='str'),
            operations_url=dict(type='str'),
            grpcwp_url=dict(type='str'),
            msp_id=dict(type='str'),
            pem=dict(type='str'),
            tls_ca_root_cert=dict(type='str'),
            tls_cert=dict(type='str'),
            location=dict(type='str'),
            type=dict(type='str')
        ))
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['peer']),
        ('state', 'absent', ['name'])
    ]
    mutually_exclusive = [
        ['name', 'peer']
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

        # Determine if the peer exists.
        state = module.params['state']
        peer_definition = module.params['peer']
        name = module.params['name']
        if state == 'present':
            name = peer_definition['name']
        peer = console.get_component_by_display_name('fabric-peer', name, 'included')
        peer_exists = peer is not None
        module.json_log({
            'msg': 'got external peer',
            'peer': peer,
            'peer_exists': peer_exists
        })

        # If the peer exists, make sure it's an imported one and not
        # a real one - we don't want to delete it, which may lose data or orphan
        # the Kubernetes components.
        if peer_exists:
            has_deployment_attrs = False
            has_location = False
            if 'deployment_attrs_missing' not in peer:
                has_deployment_attrs = True
            elif peer.get('location', '-') != '-':
                has_location = True
            if has_deployment_attrs or has_location:
                raise Exception('Peer exists and appears to be managed by this console, refusing to continue')

        # If state is absent, then handle the removal now.
        if state == 'absent' and peer_exists:

            # The peer should not exist, so delete it.
            console.delete_ext_peer(peer['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The peer should not exist and doesn't.
            return module.exit_json(changed=False)

        # Extract the expected peer configuration.
        expected_peer = dict(
            display_name=peer_definition['name'],
            api_url=peer_definition['api_url'],
            operations_url=peer_definition['operations_url'],
            grpcwp_url=peer_definition['grpcwp_url'],
            msp_id=peer_definition['msp_id'],
            tls_ca_root_cert=peer_definition['tls_ca_root_cert'] or peer_definition['pem'],
        )

        # Handle appropriately based on state.
        changed = False
        if not peer_exists:

            # Create the peer.
            peer = console.create_ext_peer(expected_peer)
            changed = True

        else:

            # Build the new peer, including any defaults.
            new_peer = copy_dict(peer)
            merge_dicts(new_peer, expected_peer)

            # If the peer has changed, apply the changes.
            peer_changed = not equal_dicts(peer, new_peer)
            if peer_changed:
                module.json_log({
                    'msg': 'differences detected, updating external peer',
                    'peer': peer,
                    'new_peer': new_peer
                })
                peer = console.update_ext_peer(new_peer['id'], new_peer)
                changed = True

        # Return the peer.
        peer = Peer.from_json(console.extract_peer_info(peer))
        module.exit_json(changed=changed, peer=peer.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
