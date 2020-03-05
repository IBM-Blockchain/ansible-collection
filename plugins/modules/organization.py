#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: organization
short_description: Manage a Hyperledger Fabric organization
description:
    - Create, update, or delete a Hyperledger Fabric organization by using the IBM Blockchain Platform.
    - A Hyperledger Fabric organziation is also known as a Membership Services Provider (MSP).
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    state:
        description:
            - C(absent) - An organization matching the specified name will be stopped and removed.
            - C(present) - Asserts that an organization matching the specified name and configuration exists.
              If no organization matches the specified name, an organization will be created.
              If an organization matches the specified name but the configuration does not match, then the
              organization will be updated, if it can be. If it cannot be updated, it will be removed and
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
            - The name of the organization.
        type: str
    msp_id:
        description:
            - The MSP ID for the organization.
        type: str
    certificate_authority:
        description:
            - The certificate authority to use to build this organization.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
        type: raw
    root_certs:
        description:
            - The list of root certificates for this organization.
            - Root certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    intermediate_certs:
        description:
            - The list of intermediate certificates for this organization.
            - Intermediate certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    admins:
        description:
            - The list of administrator certificates for this organization.
            - Administrator certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    revocation_list:
        description:
            - The list of revoked certificates for this organization.
            - Revoked certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    tls_root_certs:
        description:
            - The list of TLS root certificates for this organization.
            - TLS root certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    tls_intermediate_certs:
        description:
            - The list of TLS root certificates for this organization.
            - TLS intermediate certificates must be supplied as base64 encoded PEM files.
        type: list
        elements: str
    fabric_node_ous:
        description:
            - Configuration specific to the identity classification.
        type: dict
        suboptions:
            enable:
                description:
                    - True if identity classification is enabled for this organization, false otherwise.
                default: true
                type: boolean
            admin_ou_identifier:
                description:
                    - Configuration specific to the admin identity classification.
                type: dict
                suboptions:
                    certificate:
                        description:
                            - The root or intermediate certificate for this identity classification.
                            - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                        type: str
                    organizational_unit_identifier:
                        description:
                            - The organizational unit (OU) identifier for this identity classification.
                        type: str
                        default: admin
            client_ou_identifier:
                description:
                    - Configuration specific to the client identity classification.
                type: dict
                suboptions:
                    certificate:
                        description:
                            - The root or intermediate certificate for this identity classification.
                            - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                        type: str
                    organizational_unit_identifier:
                        description:
                            - The organizational unit (OU) identifier for this identity classification.
                        type: str
                        default: client
            peer_ou_identifier:
                description:
                    - Configuration specific to the peer identity classification.
                type: dict
                suboptions:
                    certificate:
                        description:
                            - The root or intermediate certificate for this identity classification.
                            - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                        type: str
                    organizational_unit_identifier:
                        description:
                            - The organizational unit (OU) identifier for this identity classification.
                        type: str
                        default: peer
            orderer_ou_identifier:
                description:
                    - Configuration specific to the orderer identity classification.
                type: dict
                suboptions:
                    certificate:
                        description:
                            - The root or intermediate certificate for this identity classification.
                            - Root or intermediate certificates must be supplied as base64 encoded PEM files.
                        type: str
                    organizational_unit_identifier:
                        description:
                            - The organizational unit (OU) identifier for this identity classification.
                        type: str
                        default: orderer

notes: []
requirements: []
'''

EXAMPLES = '''
'''