#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ..module_utils.dict_utils import copy_dict, diff_dicts, equal_dicts, merge_dicts
from ..module_utils.certificate_authorities import CertificateAuthority
from ..module_utils.utils import get_console

from ansible.module_utils.basic import AnsibleModule, _load_params
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
            - The configuration overrides for the certificate authority.
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
        config_override=dict(type='dict', default=dict()),
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
        wait_timeout=dict(type='int', default=60)
    )
    required_if = [
        ('api_authtype', 'basic', ['api_secret'])
    ]
    module = AnsibleModule(
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

        # If this is a free cluster, we cannot accept resource/storage configuration,
        # as these are ignored for free clusters. We must also delete the defaults,
        # otherwise they cause a mismatch with the values that actually get set.
        if console.is_free_cluster():
            actual_params = _load_params()
            if 'resources' in actual_params or 'storage' in actual_params:
                raise Exception(f'Cannot specify resources or storage for a free IBM Kubernetes Service cluster')
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

        # Extract the expected certificate authority configuration.
        expected_certificate_authority = dict(
            display_name=name,
            config_override=module.params['config_override'],
            resources=module.params['resources'],
            storage=module.params['storage']
        )

        # Either create or update the peer.
        changed = False
        if state == 'present' and not certificate_authority_exists:

            # Create the certificate authority.
            certificate_authority = console.create_ca(expected_certificate_authority)
            changed = True

        elif state == 'present' and certificate_authority_exists:

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
            banned_changes = ['storage']
            diff = diff_dicts(certificate_authority, new_certificate_authority)
            for banned_change in banned_changes:
                if banned_change in diff:
                    raise Exception(f'{banned_change} cannot be changed from {certificate_authority[banned_change]} to {new_certificate_authority[banned_change]} for existing certificate authority')

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
