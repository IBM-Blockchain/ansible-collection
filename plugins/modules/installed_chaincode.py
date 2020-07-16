#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.module import BlockchainModule
from ..module_utils.proto_utils import proto_to_json
from ..module_utils.utils import get_console, get_peer_by_module, get_identity_by_module

from ansible.module_utils.basic import _load_params
from ansible.module_utils._text import to_native

import base64
import hashlib
import json
import tarfile

NSIBLE_METADATA = {'metadata_version': '1.1',
                   'status': ['preview'],
                   'supported_by': 'community'}

DOCUMENTATION = '''
---
module: installed_chaincode
short_description: Manage a chaincode installed on a Hyperledger Fabric peer
description:
    - Install a chaincode on a Hyperledger Fabric peer by using the IBM Blockchain Platform.
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
            - C(absent) - If a chaincode matching the specified name and version is installed, then an error
              will be thrown, as it is not possible to uninstall chaincode.
            - C(present) - Asserts that a chaincode matching the specified name and version is installed. If
              it is not installed, then the chaincode is installed using the chaincode package at the specified
              path. If it is installed, then the chaincode is checked to make sure that the installed chaincode
              matches the chaincode in the chaincode package at the specified path. If the installed chaincode
              does not match, then an error will be thrown, as it is not possible to update installed chaincode.
        type: str
        default: present
        choices:
            - absent
            - present
    peer:
        description:
            - The peer to use to manage the installed chaincode.
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
    name:
        description:
            - The name of the chaincode.
            - Only required when I(state) is C(absent) and when using the chaincode
              lifecycle in Hyperledger Fabric v1.4.
        type: str
    version:
        description:
            - The version of the chaincode.
            - Only required when I(state) is C(absent) and when using the chaincode
              lifecycle in Hyperledger Fabric v1.4.
        type: str
    id:
        description:
            - The ID of the chaincode.
            - Only required when I(state) is C(absent) and when using the chaincode
              lifecycle in Hyperledger Fabric v2.x.
        type: str
    path:
        description:
            - The path to the chaincode package.
            - When using the chaincode lifecycle in Hyperledger Fabric v1.4, the
              chaincode package must be a CDS file created using the C(peer chaincode
              package) command, the IBM Blockchain Platform extension for Visual Studio
              Code, or a Hyperledger Fabric SDK.
            - When using the chaincode lifecycle in Hyperledger Fabric v2.x, the
              chaincode package must be a tar file created using the C(peer lifecycle
              chaincode package) command, the IBM Blockchain Platform extension for
              Visual Studio Code, or a Hyperledger Fabric SDK.
            - Only required when I(state) is C(present).
        type: str

notes: []
requirements: []
'''

EXAMPLES = '''
- name: Install the chaincode on the peer using Hyperledger Fabric v1.4 lifecycle
  ibm.blockchain_platform.installed_chaincode:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    path: fabcar@1.0.0.cds

- name: Install the chaincode on the peer using Hyperledger Fabric v2.x lifecycle
  ibm.blockchain_platform.installed_chaincode:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    path: fabcar@1.0.0.tgz

- name: Ensure the chaincode is not installed on the peer using Hyperledger Fabric v1.4 lifecycle
  ibm.blockchain_platform.installed_chaincode:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    name: fabcar
    version: 1.0.0

- name: Ensure the chaincode is not installed on the peer using Hyperledger Fabric v2.x lifecycle
  ibm.blockchain_platform.installed_chaincode:
    state: absent
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    peer: Org1 Peer
    identity: Org1 Admin.json
    msp_id: Org1MSP
    id: fabcar:8eaffdff050ff04779879aa524a51b308da9327b4a5bb1e0477db5a96598455b
'''

RETURN = '''
---
installed_chaincode:
    description:
        - The installed chaincode.
    type: dict
    returned: when I(state) is C(present)
    contains:
        name:
            description:
                - The name of the chaincode.
            type: str
            sample: fabcar
            returned: when using the chaincode lifecycle in Hyperledger Fabric v1.4
        version:
            description:
                - The version of the chaincode.
            type: str
            sample: 1.0.0
            returned: when using the chaincode lifecycle in Hyperledger Fabric v1.4
        label:
            description:
                - The label of the chaincode.
            type: str
            sample: fabcar-1.0.0
            returned: when using the chaincode lifecycle in Hyperledger Fabric v2.x
        id:
            description:
                - The ID of the chaincode.
            type: str
            sample: 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
'''


def do_old_lifecycle(module, console, peer, identity, msp_id, hsm):

    # Extract the chaincode information.
    name = module.params['name']
    version = module.params['version']
    path = module.params['path']
    id = None

    # If the path is provided, name and version won't be, so we need to extract them from the package.
    if path is not None:
        with open(path, 'rb') as file:
            cds = proto_to_json('protos.ChaincodeDeploymentSpec', file.read())
        name = cds['chaincode_spec']['chaincode_id']['name']
        version = cds['chaincode_spec']['chaincode_id']['version']
        code_package = base64.b64decode(cds['code_package'])
        code_package_hash = hashlib.sha256(code_package).digest()
        hasher = hashlib.sha256(name.encode('utf-8'))
        hasher.update(version.encode('utf-8'))
        metadata_hash = hasher.digest()
        hasher = hashlib.sha256(code_package_hash)
        hasher.update(metadata_hash)
        id = hasher.hexdigest()

    # Determine the chaincodes installed on the peer.
    with peer.connect(identity, msp_id, hsm) as peer_connection:
        installed_chaincodes = peer_connection.list_installed_chaincodes_oldlc()

    # Find a matching chaincode, if one exists.
    installed_chaincode = next((installed_chaincode for installed_chaincode in installed_chaincodes if installed_chaincode['name'] == name and installed_chaincode['version'] == version), None)
    chaincode_installed = installed_chaincode is not None

    # Handle the chaincode appropriately based on state.
    state = module.params['state']
    if state == 'absent' and chaincode_installed:

        # The chaincode should not be installed, but it is.
        # We can't remove it, so throw an exception.
        raise Exception(f'cannot remove installed chaincode {name}@{version} from peer')

    elif state == 'absent' and not chaincode_installed:

        # The chaincode should not be installed and isn't.
        return module.exit_json(changed=False)

    elif state == 'present' and chaincode_installed:

        # Check that the ID matches. If it doesn't, we
        # cannot update the installed version, so throw
        # an exception.
        if id != installed_chaincode['id']:
            raise Exception(f'cannot update installed chaincode {name}@{version} with ID {installed_chaincode["id"]}')
        return module.exit_json(changed=False, installed_chaincode=dict(name=name, version=version, id=id))

    else:

        # Install the chaincode.
        with peer.connect(identity, msp_id, hsm) as peer_connection:
            peer_connection.install_chaincode_oldlc(path)
        return module.exit_json(changed=True, installed_chaincode=dict(name=name, version=version, id=id))


def do_new_lifecycle(module, console, peer, identity, msp_id, hsm):

    # Extract the chaincode information.
    path = module.params['path']
    id = module.params['id']

    # If the path is provided, name and version won't be, so we need to extract them from the package.
    if path is not None:
        with tarfile.open(path, 'r') as tar:
            metadata_file = tar.extractfile('metadata.json')
            metadata = json.load(metadata_file)
        label = metadata['label']
        with open(path, 'rb') as f:
            hash = hashlib.sha256(f.read()).hexdigest()
        id = f'{label}:{hash}'

    # Determine the chaincodes installed on the peer.
    with peer.connect(identity, msp_id, hsm) as peer_connection:
        installed_chaincodes = peer_connection.list_installed_chaincodes_newlc()

    # Find a matching chaincode, if one exists.
    installed_chaincode = next((installed_chaincode for installed_chaincode in installed_chaincodes if installed_chaincode['package_id'] == id), None)
    chaincode_installed = installed_chaincode is not None

    # Handle the chaincode appropriately based on state.
    state = module.params['state']
    if state == 'absent' and chaincode_installed:

        # The chaincode should not be installed, but it is.
        # We can't remove it, so throw an exception.
        raise Exception(f'cannot remove installed chaincode {id} from peer')

    elif state == 'absent' and not chaincode_installed:

        # The chaincode should not be installed and isn't.
        return module.exit_json(changed=False)

    elif state == 'present' and chaincode_installed:

        # The chaincode should be installed and is.
        label = installed_chaincode['label']
        return module.exit_json(changed=False, installed_chaincode=dict(id=id, label=label))

    else:

        # Install the chaincode.
        with peer.connect(identity, msp_id, hsm) as peer_connection:
            peer_connection.install_chaincode_newlc(path)
        return module.exit_json(changed=True, installed_chaincode=dict(id=id, label=label))


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
        name=dict(type='str'),
        version=dict(type='str'),
        path=dict(type='str'),
        id=dict(type='str')
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['path'])
    ]
    # Ansible doesn't allow us to say "require one of X and Y only if condition A is true",
    # so we need to handle this ourselves by seeing what was passed in.
    actual_params = _load_params()
    if actual_params.get('state', 'present') == 'absent':
        required_one_of = [
            ['name', 'id']
        ]
    else:
        required_one_of = []
    required_together = [
        ['name', 'version']
    ]
    mutually_exclusive = [
        ['name', 'path'],
        ['version', 'path'],
        ['id', 'path'],
        ['id', 'name']
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if,
        required_one_of=required_one_of,
        required_together=required_together,
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

        # Determine which lifecycle we are using.
        path = module.params['path']
        id = module.params['id']
        if path is not None:
            new_lifecycle = tarfile.is_tarfile(path)
        else:
            new_lifecycle = id is not None

        # Switch to new lifecycle code if requird.
        if new_lifecycle:
            return do_new_lifecycle(module, console, peer, identity, msp_id, hsm)
        else:
            return do_old_lifecycle(module, console, peer, identity, msp_id, hsm)

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
