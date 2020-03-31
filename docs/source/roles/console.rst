..
.. SPDX-License-Identifier: Apache-2.0
..

:github_url: https://github.com/IBM-Blockchain/ansible-collection/edit/master/docs/source/roles/endorsing_organization.rst


console -- Deploy the IBM Blockchain Platform console into Kubernetes or Red Hat OpenShift
==========================================================================================

.. contents::
   :local:
   :depth: 1


Synopsis
--------

This role allows you to quickly deploy the IBM Blockchain Platform console.

This role works with both Kubernetes clusters and Red Hat OpenShift clusters, running on either x86-64 or IBM Z hardware.

Parameters
----------

  state (optional, str, present)
    ``absent`` - All components for the console will be stopped and removed, if they exist.

    ``present`` - All components for the console will be created if they do not exist, or will be updated if their current configuration does not match the expected configuration.

  target (required, str, None)
    ``k8s`` - Deploy the console into a Kubernetes cluster.

    ``openshift`` - Deploy the console into a Red Hat OpenShift cluster.

  arch (required, str, None)
    ``amd64`` - Specify this if the architecture of the cluster is amd64.

    ``s390x`` - Specify this if the architecture of the cluster is s390x.

  namespace (required, str, None)
    The name of the Kubernetes namespace to deploy the console to. The namespace will be created if it does not exist.

    Only required when *target* is ``k8s``.

  project (required, str, None)
    The name of the Red Hat OpenShift project to deploy the console to. The project will be created if it does not exist.

    Only required when *target* is ``openshift``.

  image_pull_secret (optional, str, docker-key-secret)
    The name of the image pull secret. The image pull secret will be used to pull all IBM Blockchain Platform images from the specified image registry.

  image_registry (optional, str, cp.icr.io)
    The image registry to pull images from. The image registry must contain the IBM Blockchain Platform images.

    The default image registry, ``cp.icr.io``, is the standard IBM Entitlement Registry.

    You only need to specify an alternative image registry if you are behind a firewall and cannot access the standard IBM Entitlement Registry.

  image_registry_username (optional, str, cp)
    The username for authenticating to the image registry.

    The default image registry username, ``cp``, is the username for the standard IBM Entitlement Registry.

    You only need to specify an alternative image registry username if you are using an alternative image registry.

  image_registry_email (required, str, None)
    The email address for authenticating to the image registry.

    If you are using the default image registry, this is the email address you use to log in to the My IBM dashboard.

  image_registry_password (required, str, None)
    The password for authenticating to the image registry.

    If you are using the default image registry, this is the entitlement key that you can obtain from the My IBM dashboard.

  image_repository (optional, str, cp)
    The image repository on the image registry to pull images from.

    The default image repository, ``cp``, is the image repository for the standard IBM Entitlement Registry.

    You only need to specify an alternative image repository if you are using an alternative image registry.

  cluster_role (optional, str, None)
    The name of the cluster role.

    By default, the cluster role has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

  cluster_role_binding (optional, str, None)
    The name of the cluster role binding.

    By default, the cluster role binding has the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

  security_context_constraints (optional, str, None)
    The name of the security context constraints.

    By default, the security context contraints have the same name as the specified Kubernetes namespace or Red Hat OpenShift project.

    Only required when *target* is ``openshift``.

  service_account (optional, str, default)
    The name of the service account to use.

  operator (optional, str, ibp-operator)
    The name of the operator.

  console (optional, str, ibp-console)
    The name of the console.

  console_domain (required, str, None)
    The DNS domain for the console.

    This DNS domain will be used as the base DNS domain for the console, as well as any certificate authorities, peers, and ordering services created using the console.

  console_email (required, str, None)
    The email address of the default console user.

  console_default_password (required, str, None)
    The default password for all console users, including the default console user.

  console_storage_class (optional, str, default)
    The storage class to use for the console.

  console_storage_size (optional, str, 10Gi)
    The storage size to use for the console.

  wait_timeout (optional, str, 60)
    The timeout, in seconds, to wait until the console is available.

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
