#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.certificate_authorities import CertificateAuthority
from ..module_utils.dict_utils import copy_dict, diff_dicts, equal_dicts, merge_dicts
from ..module_utils.module import BlockchainModule
from ..module_utils.utils import get_console

from ansible.module_utils.basic import _load_params
from ansible.module_utils._text import to_native

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
    name:
        description:
            - The display name for the certificate authority.
        type: str
    config_override:
        description:
            - The configuration overrides for the root certificate authority and the TLS certificate authority.
            - If configuration overrides are provided for the root certificate authority, but not the TLS certificate authority, then the configuration overrides for the root certificate authority will be copied for the TLS certificate authority.
        type: dict
        suboptions:
            ca:
                description:
                    - The configuration overrides for the root certificate authority.
                    - "See the Hyperledger Fabric documentation for available options: https://hyperledger-fabric-ca.readthedocs.io/en/release-1.4/serverconfig.html"
                type: dict
            tlsca:
                description:
                    - The configuration overrides for the TLS certificate authority.
                    - "See the Hyperledger Fabric documentation for available options: https://hyperledger-fabric-ca.readthedocs.io/en/release-1.4/serverconfig.html"
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
                        description:
                            - The Kubernetes storage class for the the Kubernetes persistent volume claim for the certificate authority container.
                        type: str
                        default: default
    hsm:
        description:
            - "The PKCS #11 compliant HSM configuration to use for the certificate authority."
            - "See the IBM Blockchain Platform documentation for more information: https://cloud.ibm.com/docs/blockchain?topic=blockchain-ibp-console-adv-deployment#ibp-console-adv-deployment-cfg-hsm"
        type: dict
        suboptions:
            pkcs11endpoint:
                description:
                    - The HSM proxy endpoint that the certificate authority should use.
                type: str
            label:
                description:
                    - The HSM label that the certificate authority should use.
                type: str
            pin:
                description:
                    - The HSM pin that the certificate authority should use.
                type: str
    zone:
        description:
            - The Kubernetes zone for this certificate authority.
            - If you do not specify a Kubernetes zone, and multiple Kubernetes zones are available, then a random Kubernetes zone will be selected for you.
            - "See the Kubernetes documentation for more information: https://kubernetes.io/docs/setup/best-practices/multiple-zones/"
        type: str
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

RETURN = '''
---
certificate_authority:
    description:
        - The certificate authority.
    type: dict
    contains:
        name:
            description:
                - The name of the certificate authority.
            type: str
        api_url:
            description:
                - The URL for the API of the certificate authority.
            type: str
        operations_url:
            description:
                - The URL for the operations service of the certificate authority.
            type: str
        ca_url:
            description:
                - The URL for the API of the certificate authority.
            type: str
        ca_name:
            description:
                - The certificate authority name to use for enrollment requests.
            type: str
        tlsca_name:
            description:
                - The certificate authority name to use for TLS enrollment requests.
            type: str
        location:
            description:
                - The location of the certificate authority.
            type: str
        pem:
            description:
                - The TLS certificate chain for the certificate authority.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
        tls_cert:
            description:
                - The TLS certificate chain for the certificate authority.
                - The TLS certificate chain is returned as a base64 encoded PEM.
            type: str
'''


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
        config_override=dict(type='dict', default=dict(), options=dict(
            ca=dict(type='dict'),
            tlsca=dict(type='dict'),
        )),
        resources=dict(type='dict', default=dict(), options=dict(
            ca=dict(type='dict', default=dict(), options=dict(
                requests=dict(type='dict', default=dict(), options=dict(
                    cpu=dict(type='str', default='100m'),
                    memory=dict(type='str', default='200M')
                ))
            ))
        )),
        storage=dict(type='dict', default=dict(), options=dict(
            ca=dict(type='dict', default=dict(), options={
                'size': dict(type='str', default='20Gi'),
                'class': dict(type='str', default='default')
            })
        )),
        hsm=dict(type='dict', options=dict(
            pkcs11endpoint=dict(type='str', required=True),
            label=dict(type='str', required=True),
            pin=dict(type='str', required=True)
        )),
        zone=dict(type='str'),
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    module = BlockchainModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=required_if)

    # Ensure all exceptions are caught.
    try:

        # Log in to the IBP console.
        console = get_console(module)

        # Determine if the certificate authority exists.
        name = module.params['name']
        certificate_authority = console.get_component_by_display_name(name, deployment_attrs='included')
        certificate_authority_exists = certificate_authority is not None
        certificate_authority_corrupt = certificate_authority is not None and 'deployment_attrs_missing' in certificate_authority

        # If this is a free cluster, we cannot accept resource/storage configuration,
        # as these are ignored for free clusters. We must also delete the defaults,
        # otherwise they cause a mismatch with the values that actually get set.
        if console.is_free_cluster():
            actual_params = _load_params()
            if 'resources' in actual_params or 'storage' in actual_params:
                raise Exception('Cannot specify resources or storage for a free IBM Kubernetes Service cluster')
            if certificate_authority_exists:
                module.params['resources'] = dict()
                module.params['storage'] = dict()

        # If the certificate authority should not exist, handle that now.
        state = module.params['state']
        if state == 'absent' and certificate_authority_exists:

            # The certificate authority should not exist, so delete it.
            console.delete_ca(certificate_authority['id'])
            return module.exit_json(changed=True)

        elif state == 'absent':

            # The certificate authority should not exist and doesn't.
            return module.exit_json(changed=False)

        # If config overrides are provided for the CA, but not the TLSCA, copy
        # the CA ones into place. This is what the REST API does.
        config_override = module.params['config_override']
        ca = config_override['ca']
        tlsca = config_override['tlsca']
        if ca is not None and tlsca is None:
            config_override['tlsca'] = ca

        # Extract the expected certificate authority configuration.
        expected_certificate_authority = dict(
            display_name=name,
            config_override=config_override,
            resources=module.params['resources'],
            storage=module.params['storage']
        )

        # Add the HSM configuration if it is specified.
        hsm = module.params['hsm']
        if hsm is not None:
            pkcs11endpoint = hsm['pkcs11endpoint']
            expected_certificate_authority['hsm'] = dict(pkcs11endpoint=pkcs11endpoint)
            bccsp = dict(
                BCCSP=dict(
                    Default='PKCS11',
                    PKCS11=dict(
                        Label=hsm['label'],
                        Pin=hsm['pin']
                    )
                )
            )
            if ca is None:
                config_override['ca'] = ca = dict()
            if tlsca is None:
                config_override['tlsca'] = tlsca = dict()
            merge_dicts(ca, bccsp)
            merge_dicts(tlsca, bccsp)

        # Add the zone if it is specified.
        zone = module.params['zone']
        if zone is not None:
            expected_certificate_authority['zone'] = zone

        # If the certificate authority is corrupt, delete it first. This may happen if somebody imported an external certificate
        # authority with the same name, or if somebody deleted the Kubernetes resources directly.
        changed = False
        if certificate_authority_corrupt:
            module.warn('Certificate authority exists in console but not in Kubernetes, deleting it before continuing')
            console.delete_ext_ca(certificate_authority['id'])
            certificate_authority_exists = certificate_authority_corrupt = False
            changed = True

        # Either create or update the certificate authority.
        if state == 'present' and not certificate_authority_exists:

            # Delete the resources and storage configuration for a new certificate
            # authority being deployed to a free cluster.
            if console.is_free_cluster():
                del expected_certificate_authority['resources']
                del expected_certificate_authority['storage']

            # Create the certificate authority.
            certificate_authority = console.create_ca(expected_certificate_authority)
            changed = True

        elif state == 'present' and certificate_authority_exists:

            # HACK: never send the limits back, as they are rejected.
            for thing in ['ca']:
                if thing in certificate_authority['resources']:
                    if 'limits' in certificate_authority['resources'][thing]:
                        del certificate_authority['resources'][thing]['limits']

            # Update the certificate authority configuration.
            new_certificate_authority = copy_dict(certificate_authority)
            merge_dicts(new_certificate_authority, expected_certificate_authority)

            # You can't change the registry after creation, but the remote names and secrets are redacted.
            # In order to diff properly, we need to redact the incoming secrets.
            identities = new_certificate_authority.get('config_override', dict()).get('ca', dict()).get('registry', dict()).get('identities', list())
            for identity in identities:
                if 'name' in identity:
                    identity['name'] = '[redacted]'
                if 'pass' in identity:
                    identity['pass'] = '[redacted]'
            identities = new_certificate_authority.get('config_override', dict()).get('tlsca', dict()).get('registry', dict()).get('identities', list())
            for identity in identities:
                if 'name' in identity:
                    identity['name'] = '[redacted]'
                if 'pass' in identity:
                    identity['pass'] = '[redacted]'

            # Check to see if any banned changes have been made.
            # HACK: zone is documented as a permitted change, but it has no effect.
            permitted_changes = ['resources', 'config_override', 'replicas', 'version']
            diff = diff_dicts(certificate_authority, new_certificate_authority)
            for change in diff:
                if change not in permitted_changes:
                    raise Exception(f'{change} cannot be changed from {certificate_authority[change]} to {new_certificate_authority[change]} for existing certificate authority')

            # If the certificate authority has changed, apply the changes.
            certificate_authority_changed = not equal_dicts(certificate_authority, new_certificate_authority)
            if certificate_authority_changed:
                certificate_authority = console.update_ca(new_certificate_authority['id'], new_certificate_authority)
                changed = True

        # Wait for the certificate authority to start.
        certificate_authority = CertificateAuthority.from_json(console.extract_ca_info(certificate_authority))
        timeout = module.params['wait_timeout']
        certificate_authority.wait_for(timeout)

        # Return the certificate authority.
        module.exit_json(changed=changed, certificate_authority=certificate_authority.to_json())

    # Notify Ansible of the exception.
    except Exception as e:
        module.fail_json(msg=to_native(e))


if __name__ == '__main__':
    main()
