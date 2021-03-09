..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/main/docs/source/roles/crds.rst


crds -- Deploy the IBM Blockchain Platform custom resource definitions into Kubernetes or Red Hat OpenShift
===========================================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly deploy the IBM Blockchain Platform custom resource definitions.

This role works with both Kubernetes clusters and Red Hat OpenShift clusters, running on either x86-64 or IBM Z hardware.

Parameters
----------

  state
    ``absent`` - All components for the custom resource definitions will be stopped and removed, if they exist.

    ``present`` - All components for the custom resource definitions will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

    | **Type**: str
    | **Default**: ``present``

  target (required)
    ``k8s`` - Deploy the custom resource definitions into a Kubernetes cluster.

    ``openshift`` - Deploy the custom resource definitions into a Red Hat OpenShift cluster.

    | **Type**: str

  arch (required)
    ``amd64`` - Specify this if the architecture of the cluster is amd64.

    ``s390x`` - Specify this if the architecture of the cluster is s390x.

    | **Type**: str

  namespace
    The name of the Kubernetes namespace to deploy the custom resource definitions to. The namespace will be created if it does not exist.

    Only required when *target* is ``k8s``.

    | **Type**: str

  project
    The name of the Red Hat OpenShift project to deploy the custom resource definitions to. The project will be created if it does not exist.

    Only required when *target* is ``openshift``.

    | **Type**: str

  image_pull_secret
    The name of the image pull secret. The image pull secret will be used to pull all IBM Blockchain Platform images from the specified image registry.

    | **Type**: str
    | **Default value**: ``docker-key-secret``

  image_registry
    The image registry to pull images from. The image registry must contain the IBM Blockchain Platform images.

    The default image registry, ``cp.icr.io``, is the standard IBM Entitlement Registry.

    You only need to specify an alternative image registry if you are behind a firewall and cannot access the standard IBM Entitlement Registry.

    | **Type**: str
    | **Default value**: ``cp.icr.io``

  image_registry_username
    The username for authenticating to the image registry.

    The default image registry username, ``cp``, is the username for the standard IBM Entitlement Registry.

    You only need to specify an alternative image registry username if you are using an alternative image registry.

    | **Type**: str
    | **Default value**: ``cp``

  image_registry_email (required)
    The email address for authenticating to the image registry.

    If you are using the default image registry, this is the email address you use to log in to the My IBM dashboard.

    | **Type**: str

  image_registry_password (required)
    The password for authenticating to the image registry.

    If you are using the default image registry, this is the entitlement key that you can obtain from the My IBM dashboard.

    | **Type**: str

  image_repository
    The image repository on the image registry to pull images from.

    The default image repository, ``cp``, is the image repository for the standard IBM Entitlement Registry.

    You only need to specify an alternative image repository if you are using an alternative image registry.

    | **Type**: str
    | **Default value**: ``cp``

  role
    The name of the role.

    By default, the role has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    | **Type**: str

  role_binding
    The name of the role binding.

    By default, the role binding has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    | **Type**: str

  security_context_constraints
    The name of the security context constraints.

    By default, the security context contraints have the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    Only required when *target* is ``openshift``.

    | **Type**: str

  service_account
    The name of the service account to use.

    | **Type**: str
    | **Default value**: ``default``

  webhook
    The name of the webhook.

    | **Type**: str
    | **Default value**: ``ibp-webhook``

  product_version
    The version of IBM Blockchain Platform to use.

    | **Type**: str
    | **Default value**: ``2.5.1``

  webhook_version
    The version of the IBM Blockchain Platform operator to use.

    The image tag used for the IB1001 Blockchain Platform webhook is *product_version*-*webhook_version*-*arch*, for example ``2.5.1-20210222-amd64``.

    | **Type**: str
    | **Default value**: ``20210222``

  wait_timeout
    The timeout, in seconds, to wait until the custom resource defintions are available.

    | **Type**: int
    | **Default value**: ``60``

Examples
--------

.. code-block:: yaml+jinja

    - name: Deploy IBM Blockchain Platform custom resource definitions on Kubernetes
      hosts: localhost
      vars:
        state: present
        target: k8s
        arch: amd64
        namespace: ibpinfra
        image_registry_password: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        image_registry_email: admin@example.org
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.crds

    - name: Deploy IBM Blockchain Platform custom resource definitions on Red Hat OpenShift
      hosts: localhost
      vars:
        state: present
        target: openshift
        arch: amd64
        project: ibpinfra
        image_registry_password: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        image_registry_email: admin@example.org
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.crds

    - name: Remove IBM Blockchain Platform custom resource definitions from Kubernetes
      hosts: localhost
      vars:
        state: absent
        target: k8s
        arch: amd64
        namespace: ibpinfra
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.crds

    - name: Remove IBM Blockchain Platform custom resource definitions from Red Hat OpenShift
      hosts: localhost
      vars:
        state: absent
        target: openshift
        arch: amd64
        project: ibpinfra
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.crds
