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

  api_endpoint (required)
    The URL for the IBM Blockchain Platform console.

    | **Type**: str

  api_authtype (required)
    ``ibmcloud`` - Authenticate to the IBM Blockchain Platform console using IBM Cloud authentication. You must provide a valid API key using *api_key*.

    ``basic`` - Authenticate to the IBM Blockchain Platform console using basic authentication. You must provide both a valid API key using *api_key* and API secret using *api_secret*.

    | **Type**: str

  api_key (required)
    The API key for the IBM Blockchain Platform console.

    | **Type**: str

  api_secret
    The API secret for the IBM Blockchain Platform console.

    Only required when *api_authtype* is ``basic``.

    | **Type**: str

  api_timeout
    The timeout, in seconds, to use when interacting with the IBM Blockchain Platform console.

    | **Type**: int
    | **Default value**: ``60``

  api_token_endpoint
    The IBM Cloud IAM token endpoint to use when using IBM Cloud authentication.

    Only required when *api_authtype* is ``ibmcloud``, and you are using IBM internal staging servers for testing.

    | **Type**: str
    | **Default value**: ``https://iam.cloud.ibm.com/identity/token``

  state
    ``absent`` - All components for the endorsing organization will be stopped and removed, if they exist.

    ``present`` - All components for the endorsing organization will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

    | **Type**: str
    | **Default value**: ``present``

  organization_name (required)
    The name of the endorsing organization.

    | **Type**: str

  organization_msp_id (required)
    The MSP ID of the endorsing organization.

    | **Type**: str

  ca_admin_enrollment_id (required)
    The enrollment ID, or user name, of the identity registered as the administrator of the certificate authority.

    | **Type**: str

  ca_admin_enrollment_secret (required)
    The enrollment secret, or password, of the identity registered as the administrator of the certificate authority.

    | **Type**: str

  ca_name
    The name of the certificate authority.

    By default, the certificate authority name is *organization_name* followed by `CA`, for example ``Org1 CA``.

    | **Type**: str

  ca_resources
    The Kubernetes resource configuration for the certificate authority.

    For more information, review the documentation for the *resources* parameter of the *certificate_authority* module: `certificate_authority <../modules/certificate_authority.html>`_

    | **Type**: dict

  ca_storage
    The Kubernetes storage configuration for the certificate authority.

    For more information, review the documentation for the *storage* parameter of the *certificate_authority* module: `certificate_authority <../modules/certificate_authority.html>`_

    | **Type**: dict

  organization_admin_enrollment_id (required)
    The enrollment ID, or user name, of the identity registered as the administrator of the organization.

    | **Type**: str

  organization_admin_enrollment_secret (required)
    The enrollment secret, or password, of the identity registered as the administrator of the organization.

    | **Type**: str

  peers
    The number of peers.

    For development and test purposes, use one peer. Three peers provides high availability, even if one of the peers is taken down for maintenance, and is suitable for production networks.

    | **Type**: int
    | **Default value**: ``1``

  peer_enrollment_id (required)
    The enrollment ID, or user name, of the identity registered for the peer.

    | **Type**: str

  peer_enrollment_secret (required)
    The enrollment secret, or password, of the identity registered for the peer.

    | **Type**: str

  peer_name
    The name of the peer.

    If more than one peer is being created using the *peers* parameter, then a number will be appended to the specified peer name.

    By default, the peer name is *organization_name* followed by `Peer`, for example ``Org1 Peer``.

    | **Type**: str

  peer_state_db
    ``couchdb`` - Use CouchDB as the state database for this peer.

    ``leveldb`` - Use LevelDB as the state database for this peer.

    | **Type**: str
    | **Default value**: ``couchdb``

  peer_resources
    The Kubernetes resource configuration for the peer.

    For more information, review the documentation for the *resources* parameter of the *peer* module: `peer <../modules/peer.html>`_

    | **Type**: dict

  peer_storage
    The Kubernetes storage configuration for the peer.

    For more information, review the documentation for the *storage* parameter of the *peer* module: `peer <../modules/peer.html>`_

    | **Type**: dict

  wait_timeout
    The timeout, in seconds, to wait until the certificate authority and the peer are available.

    | **Type**: int
    | **Default value**: ``60``

Examples
--------

.. code-block:: yaml+jinja

  - name: Create components for an endorsing organization
    vars:
      state: present
      api_endpoint: https://ibp-console.example.org:32000
      api_authtype: basic
      api_key: xxxxxxxx
      api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      organization_name: Org1
      organization_msp_id: Org1MSP
      ca_admin_enrollment_id: admin
      ca_admin_enrollment_secret: adminpw
      organization_admin_enrollment_id: org1admin
      organization_admin_enrollment_secret: org1adminpw
      peer_enrollment_id: org1peer
      peer_enrollment_secret: org1peerpw
      wait_timeout: 3600
    roles:
      - ibm.blockchain_platform.endorsing_organization

  - name: Destroy components for an endorsing organization
    vars:
      state: present
      api_endpoint: https://ibp-console.example.org:32000
      api_authtype: basic
      api_key: xxxxxxxx
      api_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      organization_name: Org1
      wait_timeout: 3600
    roles:
      - ibm.blockchain_platform.endorsing_organization