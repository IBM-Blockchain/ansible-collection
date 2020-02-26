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
module: certificate_authority
short_description: Manage a Hyperledger Fabric certificate authority
description:
    - Create, update, or delete a Hyperledger Fabric certificate authority by using the IBM Blockchain Platform.
    - This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain
      Platform software running in a Red Hat OpenShift or Kubernetes cluster.
author: Simon Stone (@sstone1)
options:
    state:
        description:
            - C(absent) - A certificate authority matching the specified name will be stopped and removed.
            - C(present) - Asserts that a certificate authority matching the specified name and configuration exists.
              If no certificate authority matches the specified name, a certificate authority will be created.
              If a certificate authority matches the specified name but the configuration does not match, then the
              certificate authority will be updated, if it can be. If it cannot be updated, it will be removed and
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
            - The display name for the certificate authority.
        type: str
    config_override:
        description:
            - The configuration overrides for the certificate authority.
            - See the Hyperledger Fabric documentation for available options: https://hyperledger-fabric-ca.readthedocs.io/en/release-1.4/serverconfig.html
        type: dict
    resources:
        description:
            - The Kubernetes resource configuration for the certificate authority.
        type: dict
        suboptions:
            ca:
                description:
                    - The Kubernetes resource configuration for the certificate authority container.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the certificate authority container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the certificate authority container.
                                type: str
                                default: 100m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the certificate authority container.
                                type: str
                                default: 200M
    storage:
        description:
            - The Kubernetes storage configuration for the certificate authority.
        type: dict
        suboptions:
            ca:
                description:
                    - The Kubernetes storage configuration for the certificate authority container.
                type: dict
                suboptions:
                    size:
                        description:
                            - The size of the Kubernetes persistent volume claim for the certificate authority container.
                        type: str
                        default: 20Gi
                    class:
                        default:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the certificate authority container.
                        type: str
                        default: default
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the certificate authority is available.
        type: integer
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
'''