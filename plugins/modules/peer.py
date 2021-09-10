#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import urllib
from distutils.version import LooseVersion

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import _load_params

from ..module_utils.cert_utils import normalize_whitespace
from ..module_utils.dict_utils import (copy_dict, diff_dicts, equal_dicts,
                                       merge_dicts)
from ..module_utils.module import BlockchainModule
from ..module_utils.peers import Peer
from ..module_utils.utils import (get_certificate_authority_by_module,
                                  get_console)

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
            - The name of the peer.
        type: str
        required: true
    msp_id:
        description:
            - The MSP ID for this peer.
            - Only required when I(state) is C(present).
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
                    - This configuration is only used if the peer is using Hyperledger Fabric v1.4.
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
            chaincodelauncher:
                description:
                    - The Kubernetes resource configuration for the chaincode launcher container.
                    - This configuration is only used if the peer is using Hyperledger Fabric v2.0 or later.
                type: dict
                suboptions:
                    requests:
                        description:
                            - The Kubernetes resource requests for the chaincode launcher container.
                        type: str
                        suboptions:
                            cpu:
                                description:
                                    - The Kubernetes CPU resource request for the chaincode launcher container.
                                type: str
                                default: 200m
                            memory:
                                description:
                                    - The Kubernetes memory resource request for the chaincode launcher container.
                                type: str
                                default: 400M
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
                            - By default, the Kubernetes storage class for the IBM Blockchain Platform console is used.
                        type: str
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
                            - By default, the Kubernetes storage class for the IBM Blockchain Platform console is used.
                        type: str
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for the peer."
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
    zone:
        description:
            - The Kubernetes zone for this peer.
            - If you do not specify a Kubernetes zone, and multiple Kubernetes zones are available, then a random Kubernetes zone will be selected for you.
            - "See the Kubernetes documentation for more information: https://kubernetes.io/docs/setup/best-practices/multiple-zones/"
        type: str
    version:
        description:
            - The version of Hyperledger Fabric to use for this peer.
            - If you do not specify a version, the default Hyperledger Fabric version will be used for a new peer.
            - If you do not specify a version, an existing peer will not be upgraded.
            - If you specify a new version, an existing peer will be automatically upgraded.
            - The version can also be specified as a version range specification, for example C(>=2.2,<3.0), which will match Hyperledger Fabric v2.2 and greater, but not Hyperledger Fabric v3.0 and greater.
            - "See the C(semantic_version) Python module documentation for more information: https://python-semanticversion.readthedocs.io/en/latest/reference.html#semantic_version.SimpleSpec"
        type: str
    wait_timeout:
        description:
            - The timeout, in seconds, to wait until the peer is available.
        type: int
        default: 60
notes: []
requirements: []
'''

EXAMPLES = '''
- name: Create peer
  ibm.blockchain_platform.peer:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 Peer
    msp_id: Org1MSP
    certificate_authority: Org1 CA
    enrollment_id: org1peer
    enrollment_secret: org1peerpw
    admin_certificates:
      - LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...

- name: Create peer with custom resources and storage
  ibm.blockchain_platform.peer:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 Peer
    msp_id: Org1MSP
    certificate_authority: Org1 CA
    enrollment_id: org1peer
    enrollment_secret: org1peerpw
    admin_certificates:
      - LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
    resources:
      peer:
        requests:
          cpu: 400m
          memory: 2G
    storage:
      peer:
        size: 200Gi
        class: ibmc-file-gold

- name: Create peer that uses an HSM
  ibm.blockchain_platform.peer:
    state: present
    api_endpoint: https://ibp-console.example.org:32000
    api_authtype: basic
    api_key: xxxxxxxx
    api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    name: Org1 Peer
    msp_id: Org1MSP
    certificate_authority: Org1 CA
    enrollment_id: org1peer
    enrollment_secret: org1peerpw
    admin_certificates:
      - LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
    hsm:
      pkcs11endpoint: tcp://pkcs11-proxy.example.org:2345
      label: Org1 CA label
      pin: 12345678

- name: Destroy peer
  ibm.blockchain_platform.peer:
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
    description: The peer.
    type: dict
    returned: when I(state) is C(present)
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
        api_key=dict(type='str', required=True, no_log=True),
        api_secret=dict(type='str', no_log=True),
        api_timeout=dict(type='int', default=60),
        api_token_endpoint=dict(type='str', default='https://iam.cloud.ibm.com/identity/token'),
        name=dict(type='str', required=True),
        msp_id=dict(type='str'),
        state_db=dict(type='str', default='couchdb', choices=['couchdb', 'leveldb']),
        certificate_authority=dict(type='raw'),
        enrollment_id=dict(type='str'),
        enrollment_secret=dict(type='str', no_log=True),
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
            )),
            chaincodelauncher=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='200m'),
                    memory=dict(type='str', default='400M')
                ))
            ))
        )),
        storage=dict(type='dict', default=dict(), options=dict(
            peer=dict(type='dict', default=dict(), options={
                'size': dict(type='str', default='100Gi'),
                'class': dict(type='str')
            }),
            statedb=dict(type='dict', default=dict(), options={
                'size': dict(type='str', default='100Gi'),
                'class': dict(type='str')
            })
        )),
        hsm=dict(type='dict', options=dict(
            pkcs11endpoint=dict(type='str'),
            label=dict(type='str', required=True, no_log=True),
            pin=dict(type='str', required=True, no_log=True)
        )),
        zone=dict(type='str'),
        version=dict(type='str'),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret']),
        ('state', 'present', ['name', 'msp_id'])
    ]
    # Ansible doesn't allow us to say "require one of X and Y only if condition A is true",
    # so we need to handle this ourselves by seeing what was passed in.
    actual_params = _load_params()
    if actual_params.get('state', 'present') == 'present':
        required_one_of = [
            ['certificate_authority', 'config']
        ]
    else:
        required_one_of = []
    required_together = [
        ['certificate_authority', 'enrollment_id'],
        ['certificate_authority', 'enrollment_secret'],
        ['certificate_authority', 'admins']
    ]
    mutually_exclusive = [
        ['certificate_authority', 'config']
    ]
    module = BlockchainModule(
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
        peer = console.get_component_by_display_name('fabric-peer', name, deployment_attrs='included')
        peer_exists = peer is not None
        peer_corrupt = peer is not None and 'deployment_attrs_missing' in peer
        module.json_log({
            'msg': 'got peer',
            'peer': peer,
            'peer_exists': peer_exists,
            'peer_corrupt': peer_corrupt
        })

        # If this is a free cluster, we cannot accept resource/storage configuration,
        # as these are ignored for free clusters. We must also delete the defaults,
        # otherwise they cause a mismatch with the values that actually get set.
        if console.is_free_cluster():
            actual_params = _load_params()
            if 'resources' in actual_params or 'storage' in actual_params:
                raise Exception('Cannot specify resources or storage for a free IBM Kubernetes Service cluster')
            if peer_exists:
                module.params['resources'] = dict()
                module.params['storage'] = dict()

        # If the peer should not exist, handle that now.
        state = module.params['state']
        if state == 'absent' and peer_exists:

            # The peer should not exist, so delete it.
            if peer_corrupt:
                console.delete_ext_peer(peer['id'])
            else:
                console.delete_peer(peer['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The peer should not exist and doesn't.
            return module.exit_json(changed=False)

        # HACK: strip out the storage class if it is not specified. Can't pass null as the API barfs.
        storage = module.params['storage']
        for storage_type in storage:
            if 'class' not in storage[storage_type]:
                continue
            storage_class = storage[storage_type]['class']
            if storage_class is None:
                del storage[storage_type]['class']

        # Extract the expected peer configuration.
        expected_peer = dict(
            display_name=name,
            msp_id=module.params['msp_id'],
            state_db=module.params['state_db'],
            config_override=module.params['config_override'],
            resources=module.params['resources'],
            storage=storage
        )

        # Add the HSM configuration if it is specified.
        hsm = module.params['hsm']
        if hsm is not None:
            pkcs11endpoint = hsm['pkcs11endpoint']
            if pkcs11endpoint:
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

        # Add the zone if it is specified.
        zone = module.params['zone']
        if zone is not None:
            expected_peer['zone'] = zone

        # Add the version if it is specified.
        version = module.params['version']
        if version is not None:
            resolved_version = console.resolve_peer_version(version)
            expected_peer['version'] = resolved_version

        # If the peer is corrupt, delete it first. This may happen if somebody imported an external peer
        # with the same name, or if somebody deleted the Kubernetes resources directly.
        changed = False
        if peer_corrupt:
            module.warn('Peer exists in console but not in Kubernetes, deleting it before continuing')
            console.delete_ext_peer(peer['id'])
            peer_exists = peer_corrupt = False
            changed = True

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

            # We should only send dind resources if the peer is running Fabric v1.4.
            # We should only send chaincodelauncher resources if the peer is running Fabric v2.x.
            if LooseVersion(expected_peer['version']) >= LooseVersion('2.0'):
                expected_peer['resources'].pop('dind', None)
            elif LooseVersion(expected_peer['version']) < LooseVersion('2.0'):
                expected_peer['resources'].pop('chaincodelauncher', None)

            # Create the peer.
            peer = console.create_peer(expected_peer)
            changed = True

        elif state == 'present' and peer_exists:

            # HACK: never send the limits back, as they are rejected.
            for thing in ['peer', 'proxy', 'couchdb', 'dind', 'chaincodelauncher']:
                if thing in peer['resources']:
                    if 'limits' in peer['resources'][thing]:
                        del peer['resources'][thing]['limits']

            # HACK: never send the fluentd and init resources back, as they are rejected.
            peer['resources'].pop('fluentd', None)
            peer['resources'].pop('init', None)

            # Update the peer configuration.
            new_peer = copy_dict(peer)
            merge_dicts(new_peer, expected_peer)

            # We should only send dind resources if the peer is running Fabric v1.4.
            # We should only send chaincodelauncher resources if the peer is running Fabric v2.x.
            if LooseVersion(new_peer['version']) >= LooseVersion('2.0'):
                new_peer['resources'].pop('dind', None)
            elif LooseVersion(new_peer['version']) < LooseVersion('2.0'):
                new_peer['resources'].pop('chaincodelauncher', None)

            # Check to see if any banned changes have been made.
            # HACK: zone is documented as a permitted change, but it has no effect.
            permitted_changes = ['resources', 'config_override', 'version']
            diff = diff_dicts(peer, new_peer)
            for change in diff:
                if change not in permitted_changes:
                    raise Exception(f'{change} cannot be changed from {peer[change]} to {new_peer[change]} for existing peer')

            # HACK: the BCCSP section of the config overrides cannot be specified,
            # even if it has not changed, so never send it in as part of an update.
            peer['config_override'].get('peer', dict()).pop('BCCSP', None)
            new_peer['config_override'].get('peer', dict()).pop('BCCSP', None)

            # HACK: if the version has not changed, do not send it in. The current
            # version may not be supported by the current version of IBP.
            if peer['version'] == new_peer['version']:
                del peer['version']
                del new_peer['version']

            # If the peer has changed, apply the changes.
            peer_changed = not equal_dicts(peer, new_peer)
            if peer_changed:

                # Log the differences.
                module.json_log({
                    'msg': 'differences detected, updating peer',
                    'peer': peer,
                    'new_peer': new_peer
                })

                # Remove anything that hasn't changed from the updates.
                things = list(new_peer.keys())
                for thing in things:
                    if thing not in diff:
                        del new_peer[thing]

                # Apply the updates.
                peer = console.update_peer(peer['id'], new_peer)
                changed = True

            # Now need to compare the list of admin certs. The admin certs may be passed in via
            # three different parameters (admins, config.enrollment.component.admincerts, and
            # config.msp.component.admincerts) so we need to find them.
            # HACK: if the admin certs did not get returned, we're running on IBP v2.1.3
            # and it does not support this feature.
            expected_admins = module.params['admins']
            if not expected_admins:
                config = module.params['config']
                if config:
                    for config_type in ['enrollment', 'msp']:
                        expected_admins = config.get(config_type, dict()).get('component', dict()).get('admincerts', None)
                        if expected_admins:
                            break
            if expected_admins:
                expected_admins_set = set(map(normalize_whitespace, expected_admins))
                actual_admins = peer.get('admin_certs', None)
                if actual_admins is not None:
                    actual_admins_set = set(map(normalize_whitespace, actual_admins))
                    append_admin_certs = list(expected_admins_set.difference(actual_admins_set))
                    remove_admin_certs = list(actual_admins_set.difference(expected_admins_set))
                    if append_admin_certs or remove_admin_certs:
                        console.edit_admin_certs(peer['id'], append_admin_certs, remove_admin_certs)
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
