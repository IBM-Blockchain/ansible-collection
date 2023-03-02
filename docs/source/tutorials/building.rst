..
.. SPDX-License-Identifier: Apache-2.0
..

Building a network
==================

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the process of building a new Hyperledger Fabric network.

In this tutorial, you will use the IBM Blockchain Platform collection for Ansible to build a Hyperledger Fabric network with two organizations. One organization "Ordering Org" will be the ordering organization, and that organization will run the ordering service. The other organization "Org1" will be an endorsing organization, and that organization will run a peer. You will also create a channel, and join the endorsing organizations peer into that channel.

For this tutorial, you can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

Before you start
----------------

Ensure that you have installed all of the pre-requisite software described in `Installation <../installation.html>`_.

You must have access to an existing IBM Blockchain Plaform instance, either on IBM Cloud, or using the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

If you wish, you can deploy the components for each organization into a separate IBM Blockchain Platform instance. If you choose to do this, then there are additional steps that you must follow which will be described below.

Cloning the repository
----------------------

The playbooks for this tutorial are stored in a GitHub repository. You must clone this GitHub repository in order to run the playbooks locally:

    .. highlight:: none

    ::

        git clone https://github.com/IBM-Blockchain/ansible-collection.git

After cloning the GitHub repository, you must change into the tutorial directory:

    .. highlight:: none

    ::

        cd ansible-collection/tutorial

Editing the variable files
--------------------------

Variable files are used to store variables that are used across multiple Ansible playbooks. Each organization has their own variable file, and you must edit these files to specify the connection details for the IBM Blockchain Platform instance for that organization.

Edit the variable files `ordering-org-vars.yml` (for Ordering Org) and `org1-vars.yml` (for Org1). The values you set depend on whether the organization is using the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software:

* If the organization is using IBM Blockchain Platform on IBM Cloud:

  1. Create service credentials for the IBM Blockchain Platform service instance, if they have not been created already.
  2. Set ``api_endpoint`` to the value of ``api_endpoint`` specified in the service credentials.
  3. Set ``api_authtype`` to ``ibmcloud``.
  4. Set ``api_key`` to the value of ``api_key`` specified in the service credentials.
  5. Note that you do not need to specify a value for ``api_secret``.

* If the organization is using IBM Blockchain Platform software:

  1. Determine the URL of your IBM Blockchain Platform console.
  2. Determine the API key and secret you use to access your IBM Blockchain Platform console. You can also use a username and password instead of an API key and secret.
  3. Set ``api_endpoint`` to the URL of your IBM Blockchain Platform console.
  4. Set ``api_authtype`` to ``basic``.
  5. Set ``api_key`` to your API key or username.
  6. Set ``api_secret`` to your API secret or password.

There is also a common variables file, `common-vars.yml`. You do not need to edit this variable file. This file contains variables that are used by multiple organizations, for example the name of the channel that will be created, and the name of the smart contract that will be deployed.

The variable files are specified in the Ansible playbooks using the ``vars_files`` argument for each play. When the Ansible playbooks are run, Ansible loads all variables from all variable files specified and makes them available for use in that play.

Finally, all of the organization specific variable files contain a ``wait_timeout`` variable, with the default set to ``600`` (seconds). This is the amount of time in seconds to wait for certificate authorities, peers, and ordering services to start. Depending on your environment, you may need to increase this timeout, for example if it takes a long time to provision the persistent volumes for each component.

Building the network
--------------------

There are multiple Ansible playbooks used in this tutorial. Each Ansible playbook performs a part of the set of tasks required to build the network. Each of the Ansible playbooks is run as either the ordering organization "Ordering Org", or the endorsing organization "Org1".

The contents of these playbooks are explored at the end of this tutorial. For now, a script `build_network.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/build_network.sh>`_ has been provided which runs these Ansible playbooks in order for you.

Note that if each organization has their own IBM Blockchain Platform instance, you must run a different command. This is required as organization and ordering service information must be exported and then imported into the other IBM Blockchain Platform instance.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        ./build_network.sh build

* Each organization has their own IBM Blockchain Platform instance:

    ::

        ./build_network.sh -i build

If you have installed the collection by building a Docker image, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        docker run --rm -u $(id -u) -v "$PWD:/tutorial" ibmcom/ibp-ansible /tutorial/build_network.sh build

* Each organization has their own IBM Blockchain Platform instance:

    ::

        docker run --rm -u $(id -u) -v "$PWD:/tutorial" ibmcom/ibp-ansible /tutorial/build_network.sh -i build

After the script has finished, you should examine the output of the script to check that no errors have occurred whilst running the Ansible playbooks. After each Ansible playbook runs, Ansible outputs a ``PLAY RECAP`` section that details how many tasks have been executed, and how many of those tasks have failed.

Exploring the network
---------------------

The Ansible playbooks that you just ran created the following components:

- An ordering organization named `Ordering Org`, with a certificate authority named `Ordering Org CA`, and an ordering service named `Ordering Service`.
- An endorsing organization named `Org1`, with a certificate authority named `Org1 CA`, and a peer named `Org1 Peer`.
- A single channel called `mychannel`, with the endorsing organization `Org1` as the only member, and the peer `Org1 Peer` as the only anchor peer.

The Ansible playbooks also registered and enrolled several identities - digital certificate and private key pairs - that act as the administrator for each organization. These identities are created on disk, as JSON files in the same directory as the playbooks, and you must store these identities somewhere.

The identities created are:

- `Ordering Org CA Admin.json`

  | This is the identity of the administrator for the certificate authority `Ordering Org CA`. You can use this identity to register new users, and revoke existing users.

- `Ordering Org Admin.json`

  | This is the identity of the administrator for the ordering organization `Ordering Org`, and the ordering service `Ordering Service`. You can use this identity to manage the organization and the ordering service.

- `Org1 CA Admin.json`

  | This is the identity of the administrator for the certificate authority `Org1 CA`. You can use this identity to register new users, and revoke existing users.

- `Org1 Admin.json`

  | This is the identity of the administrator for the endorsing organization `Org1`, and the peer `Org1 Peer`. You can use this identity to manage the organization and the peer.

If you log in to the IBM Blockchain Platform console for each organization using a web browser, you should find that these components are now displayed in the list of nodes.

You can also import the JSON files containing the identities listed above into the IBM Blockchain Platform console wallet. Once all of the identities have been imported, you can associate each component with the appropriate identity. This will allow you to manage and view those components using the IBM Blockchain Platform console.

Exploring the playbooks
-----------------------

When you ran the script `build_network.sh`, you ran multiple Ansible playbooks. Each Ansible playbook performed a different part of building the network. This section will explain which organization ran each Ansible playbook, and what each of the playbooks did.

Firstly, each of these Ansible playbooks require information that allows them to connect to the IBM Blockchain Platform instance, so they can interact with the IBM Blockchain Platform APIs. Before you ran the Ansible playbooks, you edited the variable files `ordering-org-vars.yml` and `org1-vars.yml`. These variable files are specified in the Ansible playbooks using the ``vars_files`` argument for each play, for example:

  ::

    - name: Add the organization to the consortium
      hosts: localhost
      vars_files:
        - common-vars.yml
        - ordering-org-vars.yml

When the Ansible playbooks are run, Ansible loads all variables from all variable files specified and makes them accessible for use in tasks within the Ansible playbook being run. You will see these variables are referenced when calling the Ansible modules in this collection, for example:

  ::

    hyperledger.fabric-ansible-collection.channel_block:
      api_endpoint: "{{ api_endpoint }}"
      api_authtype: "{{ api_authtype }}"
      api_key: "{{ api_key }}"
      api_secret: "{{ api_secret | default(omit) }}"

Note that this tutorial instructs you to place secrets (API keys, API secrets, passwords, etc) in plain text in these variable files. It is possible to encrypt these variables using built-in Ansible functionality, for example `Ansible Vault <https://docs.ansible.com/ansible/latest/user_guide/vault.html>`_ or Ansible lookup plugins such as `hashi_vault <https://docs.ansible.com/ansible/latest/plugins/lookup/hashi_vault.html>`_.

Here are the Ansible playbooks that were executed by the script above:

* `01-create-ordering-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/01-create-ordering-organization-components.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 01-create-ordering-organization-components.yml

  | This playbook creates the components for the ordering organization `Ordering Org`. It makes use of the Ansible role `ordering_organization <../roles/ordering_organization.html>`_ to set up the certificate authority, organization (MSP) and ordering service for this organization, along with the administrator identities for this organization.

* `02-create-endorsing-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/02-create-endorsing-organization-components.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 02-create-endorsing-organization-components.yml

  | This playbook creates the components for the endorsing organization `Org1`. It makes use of the Ansible role `endorsing_organization <../roles/endorsing_organization.html>`_ to set up the certificate authority, organization (MSP) and peer for this organization, along with the administrator identities for this organization.

* `03-export-organization.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/03-export-organization.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 03-export-organization.yml

  | This playbook uses the Ansible module `organization_info <../modules/organization_info.html>`_ to export the organization `Org1` to a file. This is so that `Org1` can pass this file to the ordering organization `Ordering Org`. `Ordering Org` can then import this file into their IBM Blockchain Platform console, so they can add `Org1` into the consortium for the ordering service.

  | Note: this playbook only needs to be executed when the organizations `Ordering Org` and `Org1` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `04-import-organization.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/04-import-organization.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 04-import-organization.yml

  | This playbook uses the Ansible module `external_organization <../modules/external_organization.html>`_ to import the organization `Org1` from a file. This file was passed to `Ordering Org` by `Org1`, so that `Ordering Org` could add `Org1` into the consortium for the ordering service.

  | Note: this playbook only needs to be executed when the organizations `Ordering Org` and `Org1` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `05-enable-capabitilies.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/05-enable-capabilities.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 05-enable-capabilities.yml

  | This playbook enables Fabric v2.x capabilities on the ordering service. It uses the Ansible modules `channel_config <../modules/channel_config.html>`_ and `channel_capabilities <../modules/channel_capabilities.html>`_ to update the system channel configuration.

* `06-add-organization-to-consortium.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/06-add-organization-to-consortium.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 06-add-organization-to-consortium.yml

  | This playbook adds the organization `Org1` into the consortium for the ordering service. It uses the Ansible modules `channel_config <../modules/channel_config.html>`_ and `consortium_member <../modules/consortium_member.html>`_ to update the system channel configuration, which contains the list of consortium members.

* `07-export-ordering-service.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/07-export-ordering-service.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 07-export-ordering-service.yml

  | This playbook uses the Ansible module `ordering_service_info <../modules/ordering_service_info.html>`_ to export the ordering service to a file. This is so that `Ordering Org` can pass this file to the organization `Org1`. `Org1` can then import this file into their IBM Blockchain Platform console, so they can start to create channels on the ordering service.

  | Note: this playbook only needs to be executed when the organizations `Ordering Org` and `Org1` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `08-import-ordering-service.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/08-import-ordering-service.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 08-import-ordering-service.yml

  | This playbook uses the Ansible module `external_ordering_service <../modules/external_ordering_service.html>`_ to import the ordering service from a file. This file was passed to `Org1` by `Ordering Org`, so that `Org1` could start to create channels on the ordering service.

  | Note: this playbook only needs to be executed when the organizations `Ordering Org` and `Org1` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `09-create-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-create-channel.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 09-create-channel.yml

  | This playbook creates a channel called `mychannel` on the ordering service. The channel contains a single organization, `Org1`. The policies for this channel are supplied in policy files:

  * `Admins`: `09-admins-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-admins-policy.json>`_
  * `Readers`: `09-readers-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-readers-policy.json>`_
  * `Writers`: `09-writers-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-writers-policy.json>`_
  * `Endorsement`: `09-endorsement-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-endorsement-policy.json>`_
  * `LifecycleEndorsement`: `09-lifecycle-endorsement-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/09-lifecycle-endorsement-policy.json>`_

  |
  | The Ansible module `channel_config <../modules/channel_config.html>`_ is used to create the channel.

* `10-join-peer-to-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/10-join-peer-to-channel.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 10-join-peer-to-channel.yml

  | This playbook uses the Ansible module `channel_block <../modules/channel_block.html>`_ to fetch the genesis block for the channel, before using the Ansible module `peer_channel <../modules/peer_channel.html>`_ to join the peer `Org1 Peer` to the channel.

* `11-add-anchor-peer-to-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/11-add-anchor-peer-to-channel.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 11-add-anchor-peer-to-channel.yml

  | This playbook updates the organization (MSP) definition for `Org1` in the channel `mychannel` to specify that the peer `Org1 Peer` is an anchor peer for the channel. It uses the Ansible modules `channel_config <../modules/channel_config.html>`_ and `channel_member <../modules/channel_member.html>`_ to update the channel configuration.

Finally, there are also two Ansible playbooks that can be used to destroy the network components for `Ordering Org` and `Org1`. They are:

* `97-delete-endorsing-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/97-delete-endorsing-organization-components.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 97-delete-endorsing-organization-components.yml

  | This playbook deletes the components for the endorsing organization `Org1`. It makes use of the Ansible role `endorsing_organization <../roles/endorsing_organization.html>`_ to remove the certificate authority, organization (MSP) and peer for this organization, along with the administrator identities for this organization.

  | Note: this is the same Ansible role that is used to create the components, but the ``state: absent`` variable tells this role that we do not want these components to exist.

* `99-delete-ordering-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/99-delete-ordering-organization-components.yml>`_

  | Organization: Ordering Org
  | Command:

    ::

      ansible-playbook 99-delete-ordering-organization-components.yml

  | This playbook deletes the components for the ordering organization `Ordering Org`. It makes use of the Ansible role `ordering_organization <../roles/ordering_organization.html>`_ to remove up the certificate authority, organization (MSP) and ordering service for this organization, along with the administrator identities for this organization.

  | Note: this is the same Ansible role that is used to create the components, but the ``state: absent`` variable tells this role that we do not want these components to exist.

Destroying the network
----------------------

If you wish to destroy the network in order to remove all of the components created by this tutorial, then you can run additional Ansible playbooks to do this for you. You can use the `build_network.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/main/tutorial/build_network.sh>`_ script again to run these Ansible playbooks.

Note that if each organization has their own IBM Blockchain Platform instance, you must run a different command.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        ./build_network.sh destroy

* Each organization has their own IBM Blockchain Platform instance:

    ::

        ./build_network.sh -i destroy

If you have installed the collection by building a Docker image, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        docker run --rm -u $(id -u) -v "$PWD:/tutorial" ibmcom/ibp-ansible /tutorial/build_network.sh destroy

* Each organization has their own IBM Blockchain Platform instance:

    ::

        docker run --rm -u $(id -u) -v "$PWD:/tutorial" ibmcom/ibp-ansible /tutorial/build_network.sh -i destroy

After the script has finished, you should examine the output of the script to check that no errors have occurred whilst running the Ansible playbooks. After each Ansible playbook runs, Ansible outputs a ``PLAY RECAP`` section that details how many tasks have been executed, and how many of those tasks have failed.

Finally, if you have imported any identities into the IBM Blockchain Platform console wallet that have been created by these Ansible playbooks, then these identities will still remain in the wallet even after the network has been destroyed. Ansible cannot remove these identities from the wallet. You must remove these identities yourself using the IBM Blockchain Platform console.