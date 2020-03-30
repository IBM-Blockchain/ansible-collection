..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/master/docs/source/roles/ordering_organization.rst


ordering_organization -- Build Hyperledger Fabric components for an ordering organization
===========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly build Hyperledger Fabric components for an ordering organization. An ordering organization has a certificate authority and an ordering service.

This module works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

Parameters
----------

  api_endpoint (optional, str, None)
    The URL for the IBM Blockchain Platform console.

  api_authtype (optional, str, None)
    ``ibmcloud`` - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication. You must provide a valid API key using *api_key*.

    ``basic`` - Authenticate to the IBM Blockchain Platform console using basic authentication. You must provide both a valid API key using *api_key* and API secret using *api_secret*.

  api_key (optional, str, None)
    The API key for the IBM Blockchain Platform console.

  api_secret (optional, str, None)
    The API secret for the IBM Blockchain Platform console.

    Only required when *api_authtype* is ``basic``.

  api_timeout (optional, integer, 60)
    The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.

  api_token_endpoint (optional, str, https://iam.cloud.ibm.com/identity/token)
    The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.

    Only required when *api_authtype* is ``ibmcloud``, and you are using IBM internal staging servers for testing.

  state (optional, str, present)
    ``absent`` - All components for the ordering organization will be stopped and removed, if they exist.

    ``present`` - All components for the ordering organization will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

  organization_name (optional, str, None)
    The name of the ordering organization.

  organization_msp_id (optional, str, None)
    The MSP ID of the ordering organization.

  ca_admin_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered as the administrator of the certificate authority.

  ca_admin_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered as the administrator of the certificate authority.

  organization_admin_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered as the administrator of the certificate authority.

  organization_admin_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered as the administrator of the organization.

  ordering_service_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered for the ordering service.

  ordering_service_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered for the ordering service.

  wait_timeout (optional, integer, 60)
    The timeout, in seconds, to wait until the certificate authority and the ordering service is available.

Examples
--------

.. code-block:: yaml+jinja

Return Values
-------------


Status
------

- This is not guaranteed to have a backwards compatible interface. *[preview]*
- This is maintained by community.

Authors
~~~~~~~

- Simon Stone (@sstone1)
