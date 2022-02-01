#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json

from ansible.module_utils._text import to_native

from ..module_utils.module import BlockchainModule
from ..module_utils.utils import (get_console, get_identity_by_module,
                                  get_peer_by_module, resolve_identity, get_ordering_service_by_name)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: instantiated_chaincode
short_description: Manage a instantiated chaincode on a Hyperledger Fabric channel
description:
    - Instantiate a chaincode on a Hyperledger Fabric channel by using the IBM Blockchain Platform.
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
            - C(absent) - If a chaincode matching the specified name and version is instantiated, then an error
              will be thrown, as it is not possible to uninstantiate chaincode.
            - C(present) - Asserts that a chaincode matching the specified name and version is instantiated on
              the specified channel. If it is not instantiated, then the chaincode with the specified name and
              version is instantiated on the specified channel. If it is instantiated with a different version,
              then the chaincode is upgraded on the specified channel. Otherwise, the instantiated chaincode is
              checked to ensure that it matches the specified ESCC and VSCC. It is not possible to check that
              the instantiated chaincode matches the specified endorsement policy and collections configuration.
              If the instantiated chaincode does not match, then an error will be thrown, as it is not possible
              to update instantiated chaincode without upgrading to a new version.
        type: str
        default: present
        choices:
            - absent
            - present
    peer:
        description:
            - The peer to use to manage the instantiated chaincode.
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
    name:
        description:
            - The name of the chaincode.
        type: str
        required: true
    version:
        description:
            - The version of the chaincode.
        type: str
        required: true
    constructor:
        description:
            - The constructor for the chaincode.
        type: dict
        suboptions:
            function:
                description:
                    - The function name to call in the chaincode.
                type: str
            args:
                description:
                    - The arguments to pass to the chaincode function.
                type: list
                elements: str
    endorsement_policy:
        description:
            - The endorsement policy for the chaincode.
        type: str
    collections_config:
        description:
            - The path to the collections configuration file for the chaincode.
        type: str
    escc:
        description:
            - The name of the endorsement system chaincode (ESCC) to use for the chaincode.
        type: str
        default: escc
    vscc:
        description:
            - The name of the validation system chaincode (VSCC) to use for the chaincode.
        type: str
        default: vscc
    orderer_name:
        description:
            - The name of the ordering service node to get the tls-certificate from
        type: str
        sample: Ordering Service_1
        default: the tls_cert for the orderering service will be found from the channel configuration
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Instantiate the chaincode on the channel
  ibm.blockchain_platform.instantiated_chaincode:
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

- name: Instantiate the chaincode on the channel with an endorsement policy and collection configuration
  ibm.blockchain_platform.instantiated_chaincode:
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
    endorsement_policy: AND('Org1MSP.peer', 'Org2MSP.peer')
    collections_config: collections-config.json

- name: Ensure the chaincode is not instantiated on the channel
  ibm.blockchain_platform.instantiated_chaincode:
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
'''

RETURN = '''
---
instantiated_chaincode:
    description:
        - The instantiated chaincode.
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
                - The name of the chaincode.
            type: str
            sample: fabcar
        version:
            description:
                - The version of the chaincode.
            type: str
            sample: 1.0.0
        escc:
            description:
                - The name of the endorsement system chaincode (ESCC) used by the chaincode.
            type: str
            sample: escc
        vscc:
            description:
                - The name of the validation system chaincode (VSCC) used by the chaincode.
            type: str
            sample: vscc
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
        name=dict(type='str', required=True),
        version=dict(type='str'),
        constructor=dict(type='dict', default=dict(), options=dict(
            function=dict(type='str'),
            args=dict(type='list', elements='str', default=list())
        )),
        endorsement_policy=dict(type='str'),
        collections_config=dict(type='str'),
        escc=dict(type='str', default='escc'),
        vscc=dict(type='str', default='vscc'),
        orderer_name=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['version'])
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if)

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

        if module.params['orderer_name']:
            orderer = get_ordering_service_by_name(console, module.params['orderer_name'])
        else:
            orderer = None

        # Extract the chaincode information.
        channel = module.params['channel']
        name = module.params['name']
        version = module.params['version']

        # Determine the chaincodes instantiated on the channel.
        with peer.connect(module, identity, msp_id, hsm) as peer_connection:
            instantiated_chaincodes = peer_connection.list_instantiated_chaincodes(channel)

        # Find a matching chaincode, if one exists.
        instantiated_chaincode_name_and_version = next((instantiated_chaincode for instantiated_chaincode in instantiated_chaincodes if instantiated_chaincode['name'] == name and instantiated_chaincode['version'] == version), None)
        instantiated_chaincode_name = next((instantiated_chaincode for instantiated_chaincode in instantiated_chaincodes if instantiated_chaincode['name'] == name), None)
        chaincode_instantiated_exact = instantiated_chaincode_name_and_version is not None
        chaincode_instantiated_name_only = instantiated_chaincode_name is not None

        # Handle the chaincode when it should be absent.
        state = module.params['state']
        if state == 'absent' and chaincode_instantiated_name_only:

            # The chaincode should not be instantiated, but it is.
            # We can't remove it, so throw an exception.
            raise Exception(f'cannot remove instantiated chaincode {name}@{instantiated_chaincode_name["version"]} from channel')

        elif state == 'absent' and not chaincode_instantiated_name_only:

            # The chaincode should not be instantiated and isn't.
            return module.exit_json(changed=False)

        # Extract the other parameters.
        ctor = dict()
        constructor = module.params['constructor']
        if 'function' in constructor:
            ctor['Function'] = constructor['function']
        ctor['Args'] = constructor['args']
        endorsement_policy = module.params['endorsement_policy']
        collections_config = module.params['collections_config']
        escc = module.params['escc']
        vscc = module.params['vscc']

        # Handle the chaincode when it should be present.
        changed = False
        if state == 'present' and chaincode_instantiated_exact:

            # Check that the ESCC and VSCC match. If they don't, we
            # cannot update the instantiated version, so throw an
            # exception.
            if escc != instantiated_chaincode_name_and_version['escc']:
                raise Exception(f'cannot update instantiated chaincode {name}@{version} with ESCC {instantiated_chaincode_name_and_version["escc"]}')
            elif vscc != instantiated_chaincode_name_and_version['vscc']:
                raise Exception(f'cannot update instantiated chaincode {name}@{version} with VSCC {instantiated_chaincode_name_and_version["vscc"]}')

        elif state == 'present' and instantiated_chaincode_name:

            # Upgrade the chaincode.
            with peer.connect(module, identity, msp_id, hsm) as peer_connection:
                peer_connection.upgrade_chaincode(channel, name, version, json.dumps(ctor), endorsement_policy, collections_config, escc, vscc, orderer)
            changed = True

        else:

            # Instantiate the chaincode.
            with peer.connect(module, identity, msp_id, hsm) as peer_connection:
                peer_connection.instantiate_chaincode(channel, name, version, json.dumps(ctor), endorsement_policy, collections_config, escc, vscc, orderer)
            changed = True

        # Return the chaincode.
        return module.exit_json(changed=changed, instantiated_chaincode=dict(channel=channel, name=name, version=version, escc=escc, vscc=vscc))

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
