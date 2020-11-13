..
.. SPDX-License-Identifier: Apache-2.0
..

Installation
============

There are three options for installing the IBM Blockchain Platform collection for Ansible:

* Installing using Ansible Galaxy

  Ansible Galaxy is the package manager for Ansible. The collection is published to Ansible Galaxy on a regular basis: https://galaxy.ansible.com/ibm/blockchain_platform

  In order to install using Ansible Galaxy, you must:

  1. Install all of the software listed in :ref:`Requirements`.
  2. Follow the instructions for :ref:`Installing using Ansible Galaxy`.

* Installing from source

  You may wish to install the collection from source if you cannot access Ansible Galaxy due to firewall or proxy issues, or if you need to install a version of the collection that has not yet been published.

  In order to install from source, you must:

  1. Install all of the software listed in :ref:`Requirements`.
  2. Follow the instructions for :ref:`Installing from source`.

* Using a Docker image

  If you do not want to, or can not, install all of the required software for this collection on your system, you may wish to build a Docker image that contains all of the software required to run Ansible playbooks which use this collection.

  In order to build a Docker image, you must:

  1. Follow the instructions for :ref:`Using a Docker image`.

Requirements
------------

In order to use this Ansible collection, you must have the following pre-requisite software installed and available:

**Python v3.7+**

    Python can be installed from a variety of sources, including the package manager for your operating system (apt, yum, etc).
    If you install Python from the package manager for your operating system, you must also install the development libraries (usually a package named ``python3-devel``), as these are required when installing modules through ``pip``.

    - The official Python website: https://www.python.org/downloads/
    - The unofficial Python version manager: https://github.com/pyenv/pyenv

**Ansible v2.8+**

    Ansible can be installed from a variety of sources, including the package manager for your operating system (apt, yum, etc). You can also install it using ``pip``, the package manager for Python:

    ::

        pip install ansible

**Hyperledger Fabric v2.2.1+ binaries**

    This Ansible collection requires use of the binaries from Hyperledger Fabric v2.2.1 or later to interact with the peers and ordering services in your Hyperledger Fabric networks. These binaries include ``configtxlator`` and ``peer``.

    You can install these binaries by following the Hyperledger Fabric documentation: https://hyperledger-fabric.readthedocs.io/en/release-2.2/install.html

    These binaries must be on the ``PATH`` of the system that will be used to run your Ansible Playbooks. You can check that the binaries are installed correctly by running:

    ::

        peer version

    Note that the Hyperledger Fabric v2.x binaries can still be used to manage Hyperledger Fabric v1.4 networks. If you find that you must use Hyperledger Fabric v1.4 binaries, then you must use the binaries from Hyperledger Fabric v1.4.3 or later.

**Hyperledger Fabric SDK for Python v0.8.1+**

    This Ansible collection uses the Hyperledger Fabric SDK for Python to interact with the certificate authorities in your Hyperledger Fabric networks.

    You can install this SDK using ``pip``, the package manager for Python:

    ::

        pip install fabric-sdk-py

**PKCS #11/Cryptoki for Python v0.6.0+**

    Optional: only required if you wish to store enrolled identities in a PKCS #11 compliant HSM.

    You can install this SDK using ``pip``, the package manager for Python:

    ::

        pip install python-pkcs11

**OpenShift client for Python v0.10.3+**

    This Ansible collection uses the OpenShift client for Python to interact with your Red Hat OpenShift or Kubernetes cluster when installing the IBM Blockchain Platform software.

    You can install this SDK using ``pip``, the package manager for Python:

    ::

        pip install openshift

**Semantic Versioning for Python v2.8.5+**

    This Ansible collection uses Semantic Versioning for Python to handle version ranges when determining which version of Hyperledger Fabric to use.

    You can install this SDK using using ``pip``, the package manager for Python:

    ::

        pip install semantic_version

**IBM Blockchain Platform v2.1.3, v2.5.0, v2.5.1**

    This Ansible collection requires use of IBM Blockchain Platform v2.1.3 or later. Previous versions of the IBM Blockchain Platform cannot be used with this Ansible collection. You can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

    You can not use this Ansible collection to create an instance of the IBM Blockchain Platform service on IBM Cloud. If you want to use the IBM Blockchain Platform on IBM Cloud, you must create the instance before you attempt to use this Ansible collection: https://cloud.ibm.com/catalog/services/blockchain-platform#about

    You can use this Ansible collection to install the IBM Blockchain Platform software into a Red Hat Openshift or Kubernetes cluster, if you have not already installed it. To see how to do this, follow this tutorial: `Installing the IBM Blockchain Platform <./tutorials/installing.html>`_

    If you are using the IBM Blockchain Platform on IBM Cloud, you must create service credentials for this Ansible collection to use. The ``api_endpoint`` and ``api_key`` properties in the service credentials must be passed into the modules and roles in this Ansible collection.

    If you are using the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster, you must determine the URL of your IBM Blockchain Platform console - this will be the ``api_endpoint`` property. You must also provide a valid API key ``api_key`` and secret ``api_secret`` for the IBM Blockchain Platform console. These properties must be passed into the modules and roles in this Ansible collection.

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

As an alternative to installing all of the requirements on your system, you can use a Docker image that contains all of the requirements.
You can then use that Docker image to run your playbooks.

A Docker image, ``ibmcom/ibp-ansible``, has been published to Docker Hub.

You can run a playbook using this Docker image, by volume mounting the playbook into the Docker container and running the ``ansible-playbook`` command:

::

    docker run --rm -u $(id -u) -v /path/to/playbooks:/playbooks ibmcom/ibp-ansible ansible-playbook /playbooks/playbook.yml

Note that the UID flag ``-u $(id -u)`` ensures that Ansible can write connection profile and identity files to the volume mount.

The Docker image is supported for use in Docker, Kubernetes, and Red Hat OpenShift.

If you need to build or customize the Docker image, you can find the Dockerfile here: https://github.com/IBM-Blockchain/ansible-collection/blob/master/Dockerfile

