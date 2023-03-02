..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/main/docs/source/roles/console.rst


fabric-console -- Deploy the Fabric Operations Console into Kubernetes or Red Hat OpenShift
===========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly deploy the `Hyperledger Fabric Operations Console <https://github.com/hyperledger-labs/fabric-operations-console>`_

This role works with both Kubernetes clusters and Red Hat OpenShift clusters, running on x86-64.

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
    ``absent`` - All components for the console will be stopped and removed, if they exist.

    ``present`` - All components for the console will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

    | **Type**: str
    | **Default**: ``present``

  target (required)
    ``k8s`` - Deploy the console into a Kubernetes cluster.

    ``openshift`` - Deploy the console into a Red Hat OpenShift cluster.

    | **Type**: str

  arch (required)
    ``amd64`` - Specify this if the architecture of the cluster is amd64.

    | **Type**: str

  namespace
    The name of the Kubernetes namespace to deploy the console to. The namespace will be created if it does not exist.

    Only required when *target* is ``k8s``.

    | **Type**: str

  project
    The name of the Red Hat OpenShift project to deploy the console to. The project will be created if it does not exist.

    Only required when *target* is ``openshift``.

    | **Type**: str

  image_pull_secret
    The name of the image pull secret. The image pull secret will be used to pull all Fabric Operations Console images from the specified image registry.

    | **Type**: str
    | **Default value**: ``docker-key-secret``

  image_registry
    The image registry to pull images from. The image registry must contain the Fabric Operations Console images.

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

  cluster_role
    The name of the cluster role.

    By default, the cluster role has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    | **Type**: str

  cluster_role_binding
    The name of the cluster role binding.

    By default, the cluster role binding has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    | **Type**: str

  pod_security_policy
    The name of the pod security policy.

    By default, the pod security policy has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    Only required when *target* is ``k8s``.

    | **Type**: str

  role_binding
    The name of the role binding.

    By default, the role binding has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    Only required when *target* is ``k8s``.

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

  operator
    The name of the operator.

    | **Type**: str
    | **Default value**: ``ibp-operator``

  console
    The name of the console.

    | **Type**: str
    | **Default value**: ``ibp-console``

  console_domain (required)
    The DNS domain for the console.

    This DNS domain will be used as the base DNS domain for the console, as well as any certificate authorities, peers, and ordering services created using the console.

    | **Type**: str

  console_email (required)
    The email address of the default console user.

    | **Type**: str

  console_default_password (required)
    The default password for all console users, including the default console user.

    | **Type**: str

  console_storage_class
    The storage class to use for the console.

    | **Type**: str
    | **Default value**: ``default``

  console_storage_size
    The storage size to use for the console.

    | **Type**: str
    | **Default value**: ``10Gi``

  console_tls_secret
    The TLS secret name to use for the console.

    If specified this secret must already exist in the specified Kubernetes namespace or Red Hat OpenShift project and must contain the TLS certificate and private key that the console will use.

    If not specified the console will generate it's own self-signed certificates.

    | **Type**: str

  product_version
    The version of Fabric Operations Console to use.

    | **Type**: str
    | **Default value**: ``2.5.1``

  operator_version
    The version of the Fabric Operations Console operator to use.

    The image tag used for the Fabric Operations Console operator is *product_version*-*operator_version*-*arch*, for example ``2.5.1-20210222-amd64``.

    | **Type**: str
    | **Default value**: ``20210222``

  zones
    The list of Kubernetes zones that this console can deploy components into.

    If you do not specify a list of Kubernetes zones, and multiple Kubernetes zones are available, then a random Kubernetes zone will be selected for you when you attempt to create any components.

    See the Kubernetes documentation for more information: https://kubernetes.io/docs/setup/best-practices/multiple-zones/

    | **Type**: list
    | **Elements**: str

  wait_timeout
    The timeout, in seconds, to wait until the console is available.

    | **Type**: int
    | **Default value**: ``60``

Examples
--------

.. code-block:: yaml+jinja

      # console-install.yml playbook
      ---
      - name: Deploy Fabric Operations Console
        hosts: localhost
        vars_files:
          - vars.yml
        vars:
          state: present
          wait_timeout: 3600
        roles:
          - hyperledger.fabric-ansible-collection.fabric_console


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