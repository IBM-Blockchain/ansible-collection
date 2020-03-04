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
module: peer
short_description: Manage a Hyperledger Fabric peer
description:
    - Create, update, or delete a Hyperledger Fabric peer by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
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
    display_name:
        description:
            - The display name for the peer.
        type: str
    msp_id:
        description:
            - The MSP ID for this peer.
        type: str
    state_database:
        description:
            - C(couchdb) - Use CouchDB as the state database for this peer.
            - C(leveldb) - Use LevelDB as the state database for this peer.
        type: str
        default: couchdb
        choices:
            - couchdb
            - leveldb
    certificate_authority:
        description:
            - The certificate authority to use to enroll the identity for this peer.
            - You can pass a string, which is the display name of a certificate authority registered
              with the IBM Blockchain Platform console.
            - You can also pass a dictionary, which must match the result format of one of the
              M(certificate_authority_info) or M(certificate_authority) modules.
            - Only required when I(config) is not specified.
        type: raw
    enrollment_id:
        description:
            - The enrollment ID, or user name, of an identity registered on the certificate authority for this peer.
            - Only required when I(config) is not specified.
        type: str
    enrollment_secret:
        description:
            - The enrollment secret, or password, of an identity registered on the certificate authority for this peer.
            - Only required when I(config) is not specified.
        type: str
    admin_certificates:
        description:
            - The list of administrator certificates for this peer.
            - Administrator certificates must be supplied as base64 encoded PEM files.
            - Only required when I(config) is not specified.
        type: list
        elements: str
    config:
        description:
            - The initial configuration for the peer. This is only required if you need more advanced configuration than
              is provided by this module using I(certificate_authority) and related options.
            - See the IBM Blockchain Platform documentation for available options: https://cloud.ibm.com/docs/services/blockchain?topic=blockchain-ibp-v2-apis#ibp-v2-apis-config
        type: dict
    config_override:
        description:
            - The configuration overrides for the peer.
            - See the Hyperledger Fabric documentation for available options: https://github.com/hyperledger/fabric/blob/release-1.4/sampleconfig/core.yaml
        type: dict
    resources:
        description:
            - The Kubernetes resource configuration for the peer.
        type: dict
        suboptions:
            peer:
                description:
                    - The Kubernetes resource configuration for the peer container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the peer container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the peer container.
                                type: str
                                default: 200m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the peer container.
                                type: str
                                default: 1000M
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
            couchdb:
                description:
                    - The Kubernetes resource configuration for the CouchDB container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the CouchDB container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the CouchDB container.
                                type: str
                                default: 200m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the CouchDB container.
                                type: str
                                default: 400M
            dind:
                description:
                    - The Kubernetes resource configuration for the Docker in Docker (DinD) container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the Docker in Docker (DinD) container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the Docker in Docker (DinD) container.
                                type: str
                                default: 1000m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the Docker in Docker (DinD) container.
                                type: str
                                default: 1000M
    storage:
        description:
            - The Kubernetes storage configuration for the peer.
        type: dict
        suboptions:
            peer:
                description:
                    - The Kubernetes storage configuration for the peer container.
                type: dict
                suboptions:
                    size:
                        description:
                            - The size of the Kubernetes persistent volume claim for the peer container.
                        type: str
                        default: 100Gi
                    class:
                        default:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the certificate authority container.
                        type: str
                        default: default
            couchdb:
                description:
                    - The Kubernetes storage configuration for the CouchDB container.
                type: dict
                suboptions:
                    size:
                        description:
                            - The size of the Kubernetes persistent volume claim for the CouchDB container.
                        type: str
                        default: 100Gi
                    class:
                        default:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the certificate authority container.
                        type: str
                        default: default
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the peer is available.
        type: integer
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
'''