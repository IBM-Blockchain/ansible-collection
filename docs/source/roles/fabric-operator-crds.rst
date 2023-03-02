..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/main/docs/source/roles/crds.rst


fabric-operator-crds -- Deploy the Fabric Operator and custom resource definitions into Kubernetes or Red Hat OpenShift
=======================================================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly deploy the Fabric Operator and custom resource definitions.

This role works with both Kubernetes clusters and Red Hat OpenShift clusters, running on either x86-64

Ingress Controllers
-------------------

This role does not install an ingress controller; for the opensource Fabric Operations Console and Fabric operator
you must configure a suitable ingress controller. Please read the `tutorial <../tutorial/install-fabric-operator-console.rst>`_.

Beta Notes
----------

This role is currently in BETA

Currently only the k8s target and x86-64 architectures supported;  OpenShift and arm64 should follow later.
It is not expected that s390x will be supported

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

    # operation-install.yml playbook
    ---
    - name: Deploy Opensource custom resource definitions and operator
      hosts: localhost
      vars_files:
        - vars.yml
      vars:
        state: present
        wait_timeout: 3600
      roles:
        - hyperledger.fabric-ansible-collection.fabric_operator_crds


      # yars.yml
      ---
      # The type of K8S cluster this is using
      target: k8s
      arch: amd64

      # k8s namespace for the operator and console
      namespace: fabricinfra

      # Console name/domain
      console_name: hlf-console
      console_domain: localho.st

      #  default configuration for the console
      # password reset will be required on first login
      console_email: admin
      console_default_password: password

      # different k8s clusters will be shipped with differently named default storage providers
      # or none at all.  KIND for example has one called 'standard'
      console_storage_class: standard