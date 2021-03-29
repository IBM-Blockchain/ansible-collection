#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import (get_console, get_identity_by_module,
                                  get_organizations_by_module,
                                  get_peer_by_module, resolve_identity)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: committed_chaincode
short_description: Manage an committed chaincode on a Hyperledger Fabric channel
description:
    - Commit a chaincode definition on a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
            - C(absent) - If a chaincode definition matching the specified name, version and configuration is
              committed, then an error will be thrown, as it is not possible to uncommit a chaincode definition.
            - C(present) - Asserts that a chaincode definition matching the specified name, version and configuration
              is committed on the specified channel. If it is not committed, then the chaincode definition with the
              specified name, version and configuration will be committed on the specified channel.
        type: str
        default: present
        choices:
            - absent
            - present
    peer:
        description:
            - The peer to use to manage the committed chaincode definition.
            - You can pass a string, which is the display name of a peer registered
              with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one of the
              M(peer_info) or M(peer) modules.
        type: raw
        required: true
    identity:
        description:
            - The identity to use when interacting with the peer.
            - You can pass a string, which is the path to the JSON file where the enrolled
              identity is stored.
            - You can also pass a dict, which must match the result format of one of the
              M(enrolled_identity_info) or M(enrolled_identity) modules.
        type: raw
        required: true
    msp_id:
        description:
            - The MSP ID to use for interacting with the peer.
        type: str
        required: true
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for digital signatures."
            - Only required if the identity specified in I(identity) was enrolled using an HSM.
        type: dict
        suboptions:
            pkcs11library:
                description:
                    - "The PKCS #11 library that should be used for digital signatures."
                type: str
            label:
                description:
                    - The HSM label that should be used for digital signatures.
                type: str
            pin:
                description:
                    - The HSM pin that should be used for digital signatures.
                type: str
    channel:
        description:
            - The name of the channel.
        type: str
        required: true
    organizations:
        description:
            - The list of organizations to use to endorse the transaction for
              committing the chaincode definition.
            - The organizations must all be members of the channel, must all have
              approved the chaincode definition, and must all have at least one
              anchor peer defined.
            - You can pass strings, which are the names of organizations that are
              registered with the IBM Blockchain Platform console.
            - You can also pass a dict, which must match the result format of one
              of the M(organization_info) or M(organization) modules.
            - Only required when I(state) is C(present).
        type: list
        elements: raw
    name:
        description:
            - The name of the chaincode definition.
        type: str
        required: true
    version:
        description:
            - The version of the chaincode definition.
        type: str
        required: true
    sequence:
        description:
            - The sequence number of the chaincode definition.
        type: int
        required: true
    endorsement_policy_ref:
        description:
            - A reference to a channel policy to use as the endorsement policy for this chaincode definition, for example I(/Channel/Application/MyEndorsementPolicy).
        type: str
    endorsement_policy:
        description:
            - The endorsement policy for this chaincode definition.
        type: str
    endorsement_plugin:
        description:
            - The endorsement plugin for this chaincode definition.
        type: str
    validation_plugin:
        description:
            - The validation plugin for this chaincode definition.
        type: str
    init_required:
        description:
            - True if this chaincode definition requires called the I(Init) method before the I(Invoke) method,
              false otherwise.
        type: bool
    collections_config:
        description:
            - The path to the collections configuration file for the chaincode definition.
        type: str
'''

EXAMPLES = '''
- name: Commit the chaincode definition on the channel
  ibm.blockchain_platform.committed_chaincode:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    channel: mychannel
    name: fabcar
    version: 1.0.0
    sequence: 1

- name: Commit the chaincode definition on the channel with an endorsement policy and collection configuration
  ibm.blockchain_platform.committed_chaincode:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    channel: mychannel
    name: fabcar
    version: 1.0.0
    sequence: 1
    endorsement_policy: AND('Org1MSP.peer', 'Org2MSP.peer')
    collections_config: collections-config.json

- name: Ensure the chaincode definition is not committed on the channel
  ibm.blockchain_platform.committed_chaincode:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    channel: mychannel
    name: fabcar
    version: 1.0.0
    sequence: 1
'''

RETURN = '''
---
committed_chaincode:
    description:
        - The committed chaincode definition.
    type: dict
    returned: when I(state) is C(present)
    contains:
        channel:
            description:
                - The name of the channel.
            type: str
            sample: mychannel
        name:
            description:
                - The name of the chaincode definition.
            type: str
            sample: fabcar
        version:
            description:
                - The version of the chaincode definition.
            type: str
            sample: 1.0.0
        sequence:
            description:
                - The sequence number of the chaincode definition.
            type: int
            sample: 1
        endorsement_policy_ref:
            description:
                - The reference to a channel policy used as the endorsement policy for this chaincode definition.
            type: str
            sample: /Channel/Application/MyEndorsementPolicy
        endorsement_policy:
            description:
                - The endorsement policy for this chaincode definition.
            type: str
        endorsement_plugin:
            description:
                - The endorsement plugin for this chaincode definition.
            type: str
        validation_plugin:
            description:
                - The validation plugin for this chaincode definition.
            type: str
        init_required:
            description:
                - True if this chaincode definition requires called the I(Init) method before the I(Invoke) method,
                  false otherwise.
            type: bool
        collections_config:
            description:
                - The path to the collections configuration file for the chaincode definition.
            type: str
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
        peer=dict(type='raw', required=True),
        identity=dict(type='raw', required=True),
        msp_id=dict(type='str', required=True),
        hsm=dict(type='dict', options=dict(
            pkcs11library=dict(type='str', required=True),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        channel=dict(type='str', required=True),
        organizations=dict(type='list', elements='raw'),
        name=dict(type='str', required=True),
        version=dict(type='str', required=True),
        sequence=dict(type='int', required=True),
        endorsement_policy_ref=dict(type='str'),
        endorsement_policy=dict(type='str'),
        endorsement_plugin=dict(type='str', default='escc'),
        validation_plugin=dict(type='str', default='vscc'),
        init_required=dict(type='bool'),
        collections_config=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['organizations'])
    ]
    mutually_exclusive = [
        ['endorsement_policy_ref', 'endorsement_policy']
    ]
    module = BlockchainModule(
        min_fabric_version='2.1.1',
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive)

    # Validate HSM requirements if HSM is specified.
    if module.params['hsm']:
        module.check_for_missing_hsm_libs()

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Get the peer, identity, and MSP ID.
        peer = get_peer_by_module(console, module)
        identity = get_identity_by_module(module)
        msp_id = module.params['msp_id']
        hsm = module.params['hsm']
        identity = resolve_identity(console, module, identity, msp_id)

        # Extract the chaincode information.
        channel = module.params['channel']
        name = module.params['name']
        version = module.params['version']
        sequence = module.params['sequence']
        endorsement_policy_ref = module.params['endorsement_policy_ref']
        endorsement_policy = module.params['endorsement_policy']
        endorsement_plugin = module.params['endorsement_plugin']
        validation_plugin = module.params['validation_plugin']
        init_required = module.params['init_required']
        collections_config = module.params['collections_config']

        # Check if this chaincode is already committed on the channel.
        with peer.connect(module, identity, msp_id, hsm) as peer_connection:
            committed_chaincodes = peer_connection.query_committed_chaincodes(channel)
        committed_chaincode = next((committed_chaincode for committed_chaincode in committed_chaincodes if committed_chaincode['name'] == name and committed_chaincode['version'] == version and committed_chaincode['sequence'] == sequence and committed_chaincode['endorsement_plugin'] == endorsement_plugin and committed_chaincode['validation_plugin'] == validation_plugin), None)
        committed_chaincode_exists = committed_chaincode is not None

        # Handle the cases when the committed chaincode should be absent.
        state = module.params['state']
        if state == 'absent' and committed_chaincode_exists:

            # The chaincode should not be committed, but it is.
            # We can't remove it, so throw an exception.
            raise Exception(f'cannot remove committed chaincode {name}@{version} from channel')

        elif state == 'absent':

            # The chaincode should not be committed and isn't.
            return module.exit_json(changed=False)

        # Now handle the cases when the committed chaincode should be present.
        changed = False
        if not committed_chaincode_exists:

            # Build the list of MSP IDs that will endorse this transaction.
            organizations = get_organizations_by_module(console, module)
            msp_ids = []
            for organization in organizations:
                msp_ids.append(organization.msp_id)

            # Commit the chaincode.
            with peer.connect(module, identity, msp_id, hsm) as peer_connection:
                peer_connection.commit_chaincode(channel, msp_ids, name, version, sequence, endorsement_policy_ref, endorsement_policy, endorsement_plugin, validation_plugin, init_required, collections_config)
                changed = True

        # Return the committed chaincode.
        return module.exit_json(changed=changed, committed_chaincode=dict(channel=channel, name=name, version=version, sequence=sequence, endorsement_policy_ref=endorsement_policy_ref, endorsement_policy=endorsement_policy, endorsement_plugin=endorsement_plugin, validation_plugin=validation_plugin, init_required=init_required, collections_config=collections_config))

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
