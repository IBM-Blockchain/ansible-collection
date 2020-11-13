..
.. SPDX-License-Identifier: Apache-2.0
..

Deploying a smart contract
==========================

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the process of deploying a smart contract to an existing Hyperledger Fabric network.

In this tutorial, you will use the IBM Blockchain Platform collection for Ansible to deploy the FabCar sample smart contract to an existing Hyperledger Fabric network. The existing Hyperledger Fabric network has three organizations - an ordering organization "Ordering Org", and two endorsing organizations "Org1" and "Org2". Both organizations are members of an existing channel called "mychannel". You will install the FabCar sample smart contract onto the peers for both "Org1" and "Org2", approve the FabCar smart contract definition on the channel "mychannel" as both organizations, and then commit that smart contract definition.

For this tutorial, you can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

Before you start
----------------

This tutorial builds upon the Hyperledger Fabric that is created as part of the `Building a network <./building.html>`_ and the `Joining a network <./joining.html>`_ tutorials. Ensure that you have followed these tutorials, and that you have the network up and running.

You will need to use the GitHub repository that you cloned in the previous tutorial. Ensure that you are in the tutorial directory:

    .. highlight:: none

    ::

        cd ansible-collection/tutorial

Deploying the smart contract
----------------------------

There are multiple Ansible playbooks used in this tutorial. Each Ansible playbook performs a part of the set of tasks required to deploy the smart contract. Each of the Ansible playbooks is run as one of the endorsing organizations "Org1" or "Org2".

The contents of these playbooks are explored at the end of this tutorial. For now, a script `deploy_smart_contract.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/deploy_smart_contract.sh>`_ has been provided which runs these Ansible playbooks in order for you.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

    ::

        ./deploy_smart_contract.sh

If you have installed the collection by building a Docker image, then run the script as follows:

    ::

        docker run --rm -u $(id -u) -v "$PWD:/tutorial" ibmcom/ibp-ansible /tutorial/deploy_smart_contract.sh

Exploring the network
---------------------

The Ansible playbooks that you just ran installed the FabCar smart contract onto the peers `Org1 Peer` and `Org2 Peer`. The Ansible playbooks also approved the FabCar smart contract definition on the channel `mychannel` as both organizations, and then committed that smart contract definition.

At this point, the FabCar smart contract is deployed and ready for applications to connect to the network and submit transactions. An application that wishes to connect to the network requires two things: an identity and a connection profile. The connection profile is a JSON document that provides the application with a list of endpoints or URLs that the application can use to connect to the network.

The Ansible playbooks registered an application identity for each organization. The organization `Org1` has an application identity named `org1app`, with an enrollment secret of `org1apppw`. The organization `Org2` has an application identity named `org2app`, with an enrollment secret of `org2apppw`. You can use this information to enroll the identity against the respective organizations certificate authority, `Org1 CA` or `Org2 CA`.

The Ansible playbooks created a connection profile for each organization. These connection profiles are created on disk, as JSON files in the same directory as the playbooks. The connection profiles are:

- `Org1 Gateway.json`
- `Org2 Gateway.json`

An application that uses one of the available Fabric SDKs (Go, Java, or Node.js) can use the identity and connection profile for an organization to connect to the network and submit a transaction. You could also try using the `IBM Blockchain Platform extension for Visual Studio Code <https://marketplace.visualstudio.com/items?itemName=IBMBlockchain.ibm-blockchain-platform>`_ to connect to the network and submit a transaction.

Exploring the playbooks
-----------------------

When you ran the script `deploy_smart_contract.sh`, you ran multiple Ansible playbooks. Each Ansible playbook performed a different part of deploying the smart contract. This section will explain which organization ran each Ansible playbook, and what each of the playbooks did.

Here are the Ansible playbooks that were executed by the script above:

* `19-install-and-approve-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/19-install-and-approve-chaincode.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 19-install-and-approve-chaincode.yml

  | This playbook uses the Ansible module `installed_chaincode <../modules/installed_chaincode.html>`_ to install the FabCar smart contract onto the peer `Org1 Peer`, and the Ansible module `approved_chaincode <../modules/approved_chaincode.html>` to approve the FabCar smart contract definition on the channel `mychannel`.

* `20-install-and-approve-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/20-install-and-approve-chaincode.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 20-install-and-approve-chaincode.yml

  | This playbook uses the Ansible module `installed_chaincode <../modules/installed_chaincode.html>`_ to install the FabCar smart contract onto the peer `Org2 Peer`, and the Ansible module `approved_chaincode <../modules/approved_chaincode.html>` to approve the FabCar smart contract definition on the channel `mychannel`.

* `21-commit-chaincode.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/21-commit-chaincode.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 21-commit-chaincode.yml

  | This playbook uses the Ansible module `committed_chaincode <../modules/committed_chaincode.html>`_ to commit the FabCar smart contract definition on the channel `mychannel`.

* `22-register-application.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/22-register-application.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 22-register-application.yml

  | This playbook uses the Ansible module `registered_identity <../modules/registered_identity.html>`_ to register a new identity in the certificate authority `Org1 CA`. This playbook also uses the Ansible module `connection_profile <../modules/connection_profile.html>`_ to create a connection profile for the organization `Org1`. The identity and the connection profile can be used by the organizations FabCar applications to interact with the network and smart contract.

* `23-register-application.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/23-register-application.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 23-register-application.yml

  | This playbook uses the Ansible module `registered_identity <../modules/registered_identity.html>`_ to register a new identity in the certificate authority `Org2 CA`. This playbook also uses the Ansible module `connection_profile <../modules/connection_profile.html>`_ to create a connection profile for the organization `Org2`. The identity and the connection profile can be used by the organizations FabCar applications to interact with the network and smart contract.