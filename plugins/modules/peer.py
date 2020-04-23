#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import copy_dict, diff_dicts, equal_dicts, merge_dicts
from ..module_utils.peers import Peer
from ..module_utils.utils import get_console, get_certificate_authority_by_module

from ansible.module_utils.basic import AnsibleModule, _load_params
from ansible.module_utils._text import to_native

import urllib

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
    api_endpoint:
        description:
            - The URL for the IBM Blockchain Platform console.
        type: str
    api_authtype:
        description:
            - C(ibmcloud) - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication.
              You must provide a valid API key using I(api_key).
            - C(basic) - Authenticate to the IBM Blockchain Platform console using basic authentication.
              You must provide both a valid API key using I(api_key) and API secret using I(api_secret).
        type: str
    api_key:
        description:
            - The API key for the IBM Blockchain Platform console.
        type: str
    api_secret:
        description:
            - The API secret for the IBM Blockchain Platform console.
            - Only required when I(api_authtype) is C(basic).
        type: str
    api_timeout:
        description:
            - The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.
        type: integer
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
            - The name of the peer.
        type: str
    msp_id:
        description:
            - The MSP ID for this peer.
        type: str
    state_db:
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
    admins:
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
            - "See the IBM Blockchain Platform documentation for available options: https://cloud.ibm.com/docs/services/blockchain?topic=blockchain-ibp-v2-apis#ibp-v2-apis-config"
        type: dict
    config_override:
        description:
            - The configuration overrides for the peer.
            - "See the Hyperledger Fabric documentation for available options: https://github.com/hyperledger/fabric/blob/release-1.4/sampleconfig/core.yaml"
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
                                default: 1G
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
                                default: 1
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the Docker in Docker (DinD) container.
                                type: str
                                default: 1G
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
                        description:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the peer container.
                        type: str
                        default: default
            statedb:
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
                        description:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the CouchDB container.
                        type: str
                        default: default
    hsm:
        description:
            - The PKCS #11 compliant HSM configuration to use for the peer.
            - "See the IBM Blockchain Platform documentation for more information: https://cloud.ibm.com/docs/blockchain?topic=blockchain-ibp-console-adv-deployment#ibp-console-adv-deployment-cfg-hsm"
        type: dict
        suboptions:
            pkcs11endpoint:
                description:
                    - The HSM proxy endpoint that the peer should use.
                type: str
            label:
                description:
                    - The HSM label that the peer should use.
                type: str
            pin:
                description:
                    - The HSM pin that the peer should use.
                type: str
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

RETURN = '''
---
peer:
    description: The peer.
    type: dict
    contains:
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
        tls_cert:
            description:
                - The TLS certificate chain for the peer.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        location:
            description:
                - The location of the peer.
            type: str
'''


def get_config(console, module):

    # See if the user provided their own configuration.
    config = module.params['config']
    if config is not None:
        return config

    # Otherwise, provide an enrollment configuration.
    return {
        'enrollment': get_enrollment_config(console, module)
    }


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
    admins = module.params['admins']
    return {
        'cahost': certificate_authority_url.hostname,
        'caport': str(certificate_authority_url.port),
        'caname': certificate_authority.ca_name,
        'catls': {
            'cacert': certificate_authority.pem
        },
        'enrollid': enrollment_id,
        'enrollsecret': enrollment_secret,
        'admincerts': admins
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
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str', required=True),
        msp_id=dict(type='str'),
        state_db=dict(type='str', default='couchdb', choices=['couchdb', 'leveldb']),
        certificate_authority=dict(type='raw'),
        enrollment_id=dict(type='str'),
        enrollment_secret=dict(type='str'),
        admins=dict(type='list', elements='str', aliases=['admin_certificates']),
        config=dict(type='dict'),
        config_override=dict(type='dict', default=dict()),
        resources=dict(type='dict', default=dict(), options=dict(
            peer=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='200m'),
                    memory=dict(type='str', default='1G')
                ))
            )),
            proxy=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='100m'),
                    memory=dict(type='str', default='200M')
                ))
            )),
            couchdb=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='200m'),
                    memory=dict(type='str', default='400M')
                ))
            )),
            dind=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='1'),
                    memory=dict(type='str', default='1G')
                ))
            ))
        )),
        storage=dict(type='dict', default=dict(), options=dict(
            peer=dict(type='dict', default=dict(), options={
                'size': dict(type='str', default='100Gi'),
                'class': dict(type='str', default='default')
            }),
            statedb=dict(type='dict', default=dict(), options={
                'size': dict(type='str', default='100Gi'),
                'class': dict(type='str', default='default')
            })
        )),
        hsm=dict(type='dict', options=dict(
            pkcs11endpoint=dict(type='str', required=True),
            label=dict(type='str', required=True),
            pin=dict(type='str', required=True)
        )),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['name', 'msp_id'])
    ]
    required_one_of = [
        ['certificate_authority', 'config']
    ]
    required_together = [
        ['certificate_authority', 'enrollment_id'],
        ['certificate_authority', 'enrollment_secret'],
        ['certificate_authority', 'admins']
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

        # Determine if the peer exists.
        name = module.params['name']
        peer = console.get_component_by_display_name(name, deployment_attrs='included')
        peer_exists = peer is not None

        # If this is a free cluster, we cannot accept resource/storage configuration,
        # as these are ignored for free clusters. We must also delete the defaults,
        # otherwise they cause a mismatch with the values that actually get set.
        if console.is_free_cluster():
            actual_params = _load_params()
            if 'resources' in actual_params or 'storage' in actual_params:
                raise Exception(f'Cannot specify resources or storage for a free IBM Kubernetes Service cluster')
            if peer_exists:
                module.params['resources'] = dict()
                module.params['storage'] = dict()

        # If the peer should not exist, handle that now.
        state = module.params['state']
        if state == 'absent' and peer_exists:

            # The peer should not exist, so delete it.
            console.delete_peer(peer['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The peer should not exist and doesn't.
            return module.exit_json(changed=False)

        # Extract the expected peer configuration.
        expected_peer = dict(
            display_name=name,
            msp_id=module.params['msp_id'],
            state_db=module.params['state_db'],
            config_override=module.params['config_override'],
            resources=module.params['resources'],
            storage=module.params['storage']
        )

        # Add the HSM configuration if it is specified.
        hsm = module.params['hsm']
        if hsm is not None:
            pkcs11endpoint = hsm['pkcs11endpoint']
            expected_peer['hsm'] = dict(pkcs11endpoint=pkcs11endpoint)
            hsm_config_override = dict(
                peer=dict(
                    BCCSP=dict(
                        Default='PKCS11',
                        PKCS11=dict(
                            Label=hsm['label'],
                            Pin=hsm['pin']
                        )
                    )
                )
            )
            merge_dicts(expected_peer['config_override'], hsm_config_override)

        # Either create or update the peer.
        changed = False
        if state == 'present' and not peer_exists:

            # Delete the resources and storage configuration for a new peer
            # being deployed to a free cluster.
            if console.is_free_cluster():
                del expected_peer['resources']
                del expected_peer['storage']

            # Get the config.
            expected_peer['config'] = get_config(console, module)

            # Create the peer.
            peer = console.create_peer(expected_peer)
            changed = True

        elif state == 'present' and peer_exists:

            # HACK: never send the limits back, as they are rejected.
            for thing in ['peer', 'proxy', 'couchdb', 'dind']:
                if thing in peer['resources']:
                    if 'limits' in peer['resources'][thing]:
                        del peer['resources'][thing]['limits']

            # Update the peer configuration.
            new_peer = copy_dict(peer)
            merge_dicts(new_peer, expected_peer)

            # Check to see if any banned changes have been made.
            banned_changes = ['msp_id', 'state_db', 'storage']
            diff = diff_dicts(peer, new_peer)
            for banned_change in banned_changes:
                if banned_change in diff:
                    raise Exception(f'{banned_change} cannot be changed from {peer[banned_change]} to {new_peer[banned_change]} for existing peer')

            # If the peer has changed, apply the changes.
            peer_changed = not equal_dicts(peer, new_peer)
            if peer_changed:
                peer = console.update_peer(new_peer['id'], new_peer)
                changed = True

        # Wait for the peer to start.
        peer = Peer.from_json(console.extract_peer_info(peer))
        timeout = module.params['wait_timeout']
        peer.wait_for(timeout)

        # Return the peer.
        module.exit_json(changed=changed, peer=peer.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
