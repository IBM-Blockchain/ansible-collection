..
.. SPDX-License-Identifier: Apache-2.0
..

Installation
============

Requirements
------------

In order to use this Ansible collection, you must have the following pre-requisite software installed and available:

**Python v3.7+**

    Python can be installed from a variety of sources, including the package manager for your operating system (apt, yum, etc).
    If you install Python from the package manager for your operating system, you must also install the development libraries (usually a package named ``python3-devel``), as these are required when installing modules through ``pip``.

    - The official Python website: https://www.python.org/downloads/
    - The unofficial Python version manager: https://github.com/pyenv/pyenv

**Ansible v2.8+**

    Python can be installed from a variety of sources, including the package manager for your operating system (apt, yum, etc). You can also install it using ``pip``, the package manager for Python:

    ::

        pip install ansible

**IBM Blockchain Platform v2.1.3+**

    This Ansible collection can deploy Hyperledger Fabric networks using the IBM Blockchain Platform v2.1.3 or later. Previous versions of the IBM Blockchain Platform cannot be used with this Ansible collection.

    You can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

    You must have deployed the IBM Blockchain Platform before using this Ansible collection. This Ansible collection cannot currently be used to deploy the IBM Blockchain Platform itself.

    If you are using the IBM Blockchain Platform on IBM Cloud, you must create service credentials for this Ansible collection to use. The ``api_endpoint`` and ``api_key`` properties in the service credentials must be passed into the modules and roles in this Ansible collection.

    If you are using the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster, you must determine the URL of your IBM Blockchain Platform console - this will be the ``api_endpoint`` property. You must also provide a valid API key ``api_key`` and secret ``api_secret`` for the IBM Blockchain Platform console. These properties must be passed into the modules and roles in this Ansible collection.

**Hyperledger Fabric v1.4.x binaries**

    This Ansible collection uses the Hyperledger Fabric v1.4 binaries to interact with the peers and ordering services in your Hyperledger Fabric networks. These binaries include ``configtxgen``, ``peer``, and ``fabric-ca-client``.

    You can install these binaries by following the Hyperledger Fabric documentation: https://hyperledger-fabric.readthedocs.io/en/release-1.4/install.html

    These binaries must be on the ``PATH`` of the system that will be used to run your Ansible Playbooks. You can check that the binaries are installed correctly by running:

    ::

        peer version

**Hyperledger Fabric SDK for Python v0.8.1+**

    This Ansible collection uses the Hyperledger Fabric SDK for Python to interact with the certificate authorities in your Hyperledger Fabric networks.

    You can install this SDK using ``pip``, the package manager for Python:

    ::

        pip install fabric-sdk-py

**OpenShift client for Python v0.10.3+**

    This Ansible collection uses the OpenShift client for Python to interact with your Red Hat OpenShift or Kubernetes cluster when installing the IBM Blockchain Platform console.

    You can install this SDK using ``pip``, the package manager for Python:

    ::

        pip install openshift

Installing using Ansible Galaxy
-------------------------------

You can use the ``ansible-galaxy`` command to install a collection from Ansible Galaxy, the package manager for Ansible:

::

    ansible-galaxy collection install ibm.blockchain_platform

Installing from source
----------------------

You can use the ``ansible-galaxy`` command to install a collection built from source. To build your own collection, follow these steps:

1. Clone the repository:

::

    git clone https://github.com/IBM-Blockchain/ansible-collection.git

2. Build the collection artifact:

::

    cd ansible-collection
    ansible-galaxy collection build

3. Install the collection, replacing ``x.y.z`` with the current version:

::

    ansible-galaxy collection install ibm-blockchain_platform-x.y.z.tar.gz

Using a Docker image
--------------------

As an alternative to installing all of the requirements on your system, you can build a Docker image that contains all of the requirements.
You can then use that Docker image to run your playbooks.

An example Dockerfile can be found here: https://github.com/IBM-Blockchain/ansible-collection/blob/master/docker/Dockerfile

The Dockerfile makes use of the Docker multi-stage build feature to reduce the size of the image built by 50%.

Assuming you have built the Docker image and tagged it as ``mydockerorg/ansible``, you can run a playbook by volume mounting it into the container:

::

    docker run --rm -v /path/to/playbooks:/playbooks mydockerorg/ansible ansible-playbook /playbooks/playbook.yml