..
.. SPDX-License-Identifier: Apache-2.0
..

Deploying a smart contract
==========================

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the process of deploying a smart contract to an existing Hyperledger Fabric network.

In this tutorial, you will use the IBM Blockchain Platform collection for Ansible to deploy the FabCar sample smart contract to an existing Hyperledger Fabric network. The existing Hyperledger Fabric network has three organizations - an ordering organization "Ordering Org", and two endorsing organizations "Org1" and "Org2". Both organizations are members of an existing channel called "mychannel". You will install the FabCar sample smart contract onto the peers for both "Org1" and "Org2", and then instantiate the smart contract on the channel "mychannel".

For this tutorial, you can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

Before you start
----------------

This tutorial builds upon the Hyperledger Fabric that is created as part of the `Building a network <./building.html>`_ and the `Joining a network <./joining.html>`_ tutorials. Ensure that you have followed these tutorials, and that you have the network up and running.

You will need to use the GitHub repository that you cloned in the previous tutorial. Ensure that you are in the tutorials directory:

    .. highlight:: none

    ::

        cd ansible-collection/tutorials

Deploying the smart contract
----------------------------

There are multiple Ansible playbooks used in this tutorial. Each Ansible playbook performs a part of the set of tasks required to deploy the smart contract. Each of the Ansible playbooks is run as one of the endorsing organizations "Org1" or "Org2".

The contents of these playbooks are explored at the end of this tutorial. For now, a script `deploy_smart_contract.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/deploy_smart_contract.sh>`_ has been provided which runs these Ansible playbooks in order for you.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

    ::

        ./deploy_smart_contract.sh

If you have installed the collection by building a Docker image, then run the script as follows:

    ::

        docker run --rm -v "$PWD:/tutorials" mydockerorg/ansible ansible-playbook /tutorials/deploy_smart_contract.sh

Exploring the playbooks
-----------------------

When you ran the script `join_network.sh`, you ran multiple Ansible playbooks. Each Ansible playbook performed a different part of joining the network. This section will explain which organization ran each Ansible playbook, and what each of the playbooks did.

Here are the Ansible playbooks that were executed by the script above:

* `18-install-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/18-install-chaincode.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 18-install-chaincode.yml --extra-vars "@org1-vars.yml"

  | This playbook uses the Ansible module `installed_chaincode <../modules/installed_chaincode.html>`_ to install the FabCar smart contract onto the peer `Org1 Peer`.

* `19-install-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/19-install-chaincode.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 19-install-chaincode.yml --extra-vars "@org2-vars.yml"

  | This playbook uses the Ansible module `installed_chaincode <../modules/installed_chaincode.html>`_ to install the FabCar smart contract onto the peer `Org2 Peer`.

* `20-instantiate-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/20-instantiate-chaincode.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 20-instantiate-chaincode.yml --extra-vars "@org1-vars.yml"

  | This playbook uses the Ansible module `instantiated_chaincode <../modules/instantiated_chaincode.html>`_ to instantiate the FabCar smart contract on the channel `mychannel`.