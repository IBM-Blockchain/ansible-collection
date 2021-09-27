..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/main/docs/source/roles/console.rst


console -- Deploy the IBM Support for Hyperledger Fabric console into Kubernetes or Red Hat OpenShift
==========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly deploy the IBM Support for Hyperledger Fabric console.

This role works with Red Hat OpenShift clusters, running on either x86-64 or IBM Z hardware.

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

    ``s390x`` - Specify this if the architecture of the cluster is s390x.

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
    The name of the image pull secret. The image pull secret will be used to pull all IBM Support for Hyperledger Fabric images from the specified image registry.

    | **Type**: str
    | **Default value**: ``docker-key-secret``

  image_registry
    The image registry to pull images from. The image registry must contain the IBM Support for Hyperledger Fabricimages.

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
    | **Default value**: ``ibm-hlfsupport-operator``

  console
    The name of the console.

    | **Type**: str
    | **Default value**: ``ibm-hlfsupport-console``

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

    If specified this secret must already exist in the specified Red Hat OpenShift project and must contain the TLS certificate and private key that the console will use.

    If not specified the console will generate it's own self-signed certificates.

    | **Type**: str

  product_version
    The version of IBM Support for Hyperledger Fabric to use.

    | **Type**: str
    | **Default value**: ``1.0.0``

  operator_version
    The version of the IBM Support for Hyperledger Fabric operator to use.

    The image tag used for the IIBM Support for Hyperledger Fabric operator is *product_version*-*operator_version*-*arch*, for example ``1.0.0-20210915-amd64``.

    | **Type**: str
    | **Default value**: ``20210915``

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

    - name: Deploy IBM Support for Hyperledger Fabric console on Red Hat OpenShift
      hosts: localhost
      vars:
        state: present
        target: openshift
        arch: amd64
        project: my-project
        image_registry_password: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        image_registry_email: admin@example.org
        console_domain: example.org
        console_email: admin@example.org
        console_default_password: passw0rd
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.hlfsupport_console

    - name: Remove IBM Support for Hyperledger Fabric console from Red Hat OpenShift
      hosts: localhost
      vars:
        state: absent
        target: openshift
        arch: amd64
        project: my-project
        wait_timeout: 3600
      roles:
        - ibm.blockchain_platform.hlfsupport_console
