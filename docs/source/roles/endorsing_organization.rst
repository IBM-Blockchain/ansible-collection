..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/master/docs/source/roles/endorsing_organization.rst


endorsing_organization -- Build Hyperledger Fabric components for an endorsing organization
===========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly build Hyperledger Fabric components for an endorsing organization. An endorsing organization has a certificate authority and a peer.

This role works with the IBM Blockchain Platform managed service running in IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

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
    ``absent`` - All components for the endorsing organization will be stopped and removed, if they exist.

    ``present`` - All components for the endorsing organization will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

  organization_name (optional, str, None)
    The name of the endorsing organization.

  organization_msp_id (optional, str, None)
    The MSP ID of the endorsing organization.

  ca_admin_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered as the administrator of the certificate authority.

  ca_admin_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered as the administrator of the certificate authority.

  ca_name (optional, str, *organization_name* CA)
    The name of the certificate authority.

  ca_resources (optional, dict, None)
    The Kubernetes resource configuration for the certificate authority.

    For more information, review the documentation for the *resources* parameter of the *certificate_authority* module: `certificate_authority <../modules/certificate_authority.html>`_

  ca_storage (optional, dict, None)
    The Kubernetes storage configuration for the certificate authority.

    For more information, review the documentation for the *storage* parameter of the *certificate_authority* module: `certificate_authority <../modules/certificate_authority.html>`_

  organization_admin_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered as the administrator of the certificate authority.

  organization_admin_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered as the administrator of the organization.

  peer_enrollment_id (optional, str, None)
    The enrollment ID, or user name, of the identity registered for the peer.

  peer_enrollment_secret (optional, str, None)
    The enrollment secret, or password, of the identity registered for the peer.

  peer_name (optional, str, *organization_name* Peer)
    The name of the peer.

  peer_state_db (optional, str, couchdb)
    ``couchdb`` - Use CouchDB as the state database for this peer.

    ``leveldb`` - Use LevelDB as the state database for this peer.

  peer_resources (optional, dict, None)
    The Kubernetes resource configuration for the peer.

    For more information, review the documentation for the *resources* parameter of the *peer* module: `peer <../modules/peer.html>`_

  peer_storage (optional, dict, None)
    The Kubernetes storage configuration for the peer.

    For more information, review the documentation for the *storage* parameter of the *peer* module: `peer <../modules/peer.html>`_

  wait_timeout (optional, integer, 60)
    The timeout, in seconds, to wait until the certificate authority and the peer are available.

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
