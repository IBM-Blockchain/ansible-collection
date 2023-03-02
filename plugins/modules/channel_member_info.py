#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.module import BlockchainModule
from ..module_utils.msp_utils import msp_to_organization
from ..module_utils.proto_utils import proto_to_json

from ansible.module_utils._text import to_native

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: channel_member_info
short_description: Get information about a member for a Hyperledger Fabric channel
description:
    - Get information about a Hyperledger Fabric channel by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    path:
        description:
            - Path to current the channel configuration file.
            - This file can be fetched by using the M(channel_config) module.
            - This file will be updated in place. You will need to keep a copy of the original file for computing the configuration
              update.
        type: str
        required: true
    msp_id:
        description:
            - The MSP ID of the channel member.
        type: string
        required: true
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Get the organization from the channel
  hyperledger.fabric-ansible-collectionble-collection.channel_member_info:
    path: channel_config.bin
    msp_id: Org1MSP
'''

RETURN = '''
---
exists:
    description:
        - True if the channel member exists, false otherwise.
    type: boolean
organization:
    description:
        - The organization.
    type: dict
    returned: if channel member exists
    contains:
        name:
            description:
                - The name of the organization.
            type: str
            sample: Org1
        msp_id:
            description:
                - The MSP ID for the organization.
            type: str
            sample: Org1MSP
        root_certs:
            description:
                - The list of root certificates for this organization.
                - Root certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        intermediate_certs:
            description:
                - The list of intermediate certificates for this organization.
                - Intermediate certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        admins:
            description:
                - The list of administrator certificates for this organization.
                - Administrator certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        revocation_list:
            description:
                - The list of revoked certificates for this organization.
                - Revoked certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_root_certs:
            description:
                - The list of TLS root certificates for this organization.
                - TLS root certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        tls_intermediate_certs:
            description:
                - The list of TLS root certificates for this organization.
                - TLS intermediate certificates must be supplied as base64 encoded PEM files.
            type: list
            elements: str
            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
        fabric_node_ous:
            description:
                - Configuration specific to the identity classification.
            type: dict
            contains:
                enable:
                    description:
                        - True if identity classification is enabled for this organization, false otherwise.
                    type: boolean
                    sample: true
                admin_ou_identifier:
                    description:
                        - Configuration specific to the admin identity classification.
                    type: dict
                    contains:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            sample: admin
                client_ou_identifier:
                    description:
                        - Configuration specific to the client identity classification.
                    type: dict
                    contains:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            sample: client
                peer_ou_identifier:
                    description:
                        - Configuration specific to the peer identity classification.
                    type: dict
                    contains:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            sample: peer
                orderer_ou_identifier:
                    description:
                        - Configuration specific to the orderer identity classification.
                    type: dict
                    contains:
                        certificate:
                            description:
                                - The root or intermediate certificate for this identity classification.
                                - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                            type: str
                            sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
                        organizational_unit_identifier:
                            description:
                                - The organizational unit (OU) identifier for this identity classification.
                            type: str
                            sample: orderer
        organizational_unit_identifiers:
            description:
                - The list of organizational unit identifiers for this organization.
            type: list
            elements: dict
            contains:
                certificate:
                    description:
                        - The root or intermediate certificate for this organizational unit identifier.
                        - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                    type: str
                    sample: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
                organizational_unit_identifier:
                    description:
                        - The organizational unit (OU) identifier.
                    type: str
                    sample: acctdept
'''


def main():

    # Create the module.
    argument_spec = dict(
        path=dict(type='str', required=True),
        msp_id=dict(type='str', required=True),
    )
    module = BlockchainModule(argument_spec=argument_spec, supports_check_mode=True)

    # Ensure all exceptions are caught.
    try:

        # Get the organization and the target path.
        path = module.params['path']
        msp_id = module.params['msp_id']

        # Read the config.
        with open(path, 'rb') as file:
            config_json = proto_to_json('common.Config', file.read())

        # Check to see if the consortium member exists.
        application_groups = config_json['channel_group']['groups']['Application']['groups']
        msp = application_groups.get(msp_id, None)

        # If it doesn't exist, return now.
        if msp is None:
            return module.exit_json(exists=False)

        # Return organization information.
        organization = msp_to_organization(msp_id, msp)
        return module.exit_json(exists=True, organization=organization.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
