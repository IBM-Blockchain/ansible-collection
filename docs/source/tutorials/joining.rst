..
.. SPDX-License-Identifier: Apache-2.0
..

Joining a network
=================

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the process of joining an existing Hyperledger Fabric network.

In this tutorial, you will use the IBM Blockchain Platform collection for Ansible to join an existing Hyperledger Fabric network. The existing Hyperledger Fabric network has two organizations - an ordering organization "Ordering Org", and an endorsing organization "Org1". You will create a new endorsing organization "Org2", and that organization will run a peer. You will add the new organization "Org2" into an existing channel, and join the new organizations peer into that channel.

For this tutorial, you can use the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster.

Before you start
----------------

This tutorial builds upon the Hyperledger Fabric that is created as part of the `Building a network <./building.html>`_ tutorial. Ensure that you have followed this tutorial, and that you have the network up and running.

If you used separate IBM Blockchain Platform instances for each organization in the previous tutorial, you will need another IBM Blockchain Platform instance for the new organization created during this tutorial. Again, if you use separate IBM Blockchain Platform instances, then there are additional steps that you must follow which will be described below.

You will need to use the GitHub repository that you cloned in the previous tutorial. Ensure that you are in the tutorials directory:

    .. highlight:: none

    ::

        cd ansible-collection/tutorials

Editing the variable file
-------------------------

Variable files are used to store variables that are used across multiple Ansible playbooks. Each organization has their own variable file, and you must edit these files to specify the connection details for the IBM Blockchain Platform instance for that organization.

In the previous tutorial, you edited the variable files `ordering-org-vars.yml` (for Ordering Org) and `org1-vars.yml` (for Org1).

You must now edit the variable file for the new organization Org2, `org2-vars.yml`. The values you set depend on whether the organization is using the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software:

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

When the Ansible playbooks are run, the variable files are passed in to Ansible using the ``--extra-vars`` option, for example:

  ::

    ansible-playbook 11-create-endorsing-organization-components.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

Finally, all of the organization specific variable files contain a ``wait_timeout`` variable, with the default set to ``600`` (seconds). This is the amount of time in seconds to wait for certificate authorities, peers, and ordering services to start. Depending on your environment, you may need to increase this timeout, for example if it takes a long time to provision the persistent volumes for each component.

Joining the network
-------------------

There are multiple Ansible playbooks used in this tutorial. Each Ansible playbook performs a part of the set of tasks required to build the network. Each of the Ansible playbooks is run as either the existing endorsing organization "Org1", or the new endorsing organization "Org2".

The contents of these playbooks are explored at the end of this tutorial. For now, a script `join_network.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/join_network.sh>`_ has been provided which runs these Ansible playbooks in order for you.

Note that if each organization has their own IBM Blockchain Platform instance, you must run a different command. This is required as organization and ordering service information must be exported and then imported into the other IBM Blockchain Platform instance.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        ./join_network.sh join

* Each organization has their own IBM Blockchain Platform instance:

    ::

        ./join_network.sh -i join

If you have installed the collection by building a Docker image, then run the script as follows:

* Both organizations use the same IBM Blockchain Platform instance:

    ::

        docker run --rm -v "$PWD:/tutorials" mydockerorg/ansible /tutorials/join_network.sh join

* Each organization has their own IBM Blockchain Platform instance:

    ::

        docker run --rm -v "$PWD:/tutorials" mydockerorg/ansible /tutorials/join_network.sh -i join

After the script has finished, you should examine the output of the script to check that no errors have occurred whilst running the Ansible playbooks. After each Ansible playbook runs, Ansible outputs a ``PLAY RECAP`` section that details how many tasks have been executed, and how many of those tasks have failed.

Exploring the network
---------------------

The Ansible playbooks that you just ran created the following new components:

- An endorsing organization named `Org2`, with a certificate authority named `Org2 CA`, and a peer named `Org2 Peer`.

The Ansible playbooks also added the endorsing organization `Org2` to the channel `mychannel`, with `Org2 Peer` as an anchor peer for the channel. The channel policy `Admins` was updated so that both endorsing organizations `Org1` and `Org2` must sign any future configuration updates for this channel.

The Ansible playbooks also registered and enrolled several identities - digital certificate and private key pairs - that act as the administrator for each organization. These identities are created on disk, as JSON files in the same directory as the playbooks, and you must store these identities somewhere.

The new identities created are:

- `Org2 CA Admin.json`

  | This is the identity of the administrator for the certificate authority `Org2 CA`. You can use this identity to register new users, and revoke existing users.

- `Org2 Admin.json`

  | This is the identity of the administrator for the endorsing organization `Org2`, and the peer `Org2 Peer`. You can use this identity to manage the organization and the peer.

If you log in to the IBM Blockchain Platform console for the new organization using a web browser, you should find that these components are now displayed in the list of nodes.

You can also import the JSON files containing the identities listed above into the IBM Blockchain Platform console wallet. Once all of the identities have been imported, you can associate each component with the appropriate identity. This will allow you to manage and view those components using the IBM Blockchain Platform console.

Exploring the playbooks
-----------------------

When you ran the script `join_network.sh`, you ran multiple Ansible playbooks. Each Ansible playbook performed a different part of joining the network. This section will explain which organization ran each Ansible playbook, and what each of the playbooks did.

Here are the Ansible playbooks that were executed by the script above:

* `11-create-endorsing-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/11-create-endorsing-organization-components.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 11-create-endorsing-organization-components.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook creates the components for the endorsing organization `Org2`. It makes use of the Ansible role `endorsing_organization <../roles/endorsing_organization.html>`_ to set up the certificate authority, organization (MSP) and peer for this organization, along with the administrator identities for this organization.

* `12-export-organization.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/12-export-organization.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 12-export-organization.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook uses the Ansible module `organization_info <../modules/organization_info.html>`_ to export the organization `Org2` to a file. This is so that `Org2` can pass this file to the endorsing organization `Org1`. `Org1` can then import this file into their IBM Blockchain Platform console, so they can add `Org2` into the existing channel `mychannel`.

  | Note: this playbook only needs to be executed when the organizations `Org1` and `Org2` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `13-import-organization.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/13-import-organization.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 13-import-organization.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook uses the Ansible module `external_organization <../modules/external_organization.html>`_ to import the organization `Org2` from a file. This file was passed to `Org1` by `Org2`, so that `Org1` could add `Org2` into the existing channel `mychannel`.

  | Note: this playbook only needs to be executed when the organizations `Org1` and `Org2` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `14-add-organization-to-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/14-add-organization-to-channel.yml>`_

  | Organization: Org1
  | Command:

    ::

      ansible-playbook 14-add-organization-to-channel.yml --extra-vars "@org1-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook adds the organization `Org2` into the existing channel `Org1`. The channel now contains two organizations, `Org1` and `Org2`. The policies for this channel are updated, using new policies that are supplied in policy files:

  * `Admins`: `14-admins-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/14-admins-policy.json>`_
  * `Readers`: `14-readers-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/14-readers-policy.json>`_
  * `Writers`: `14-writers-policy.json <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/14-writers-policy.json>`_

  |
  | The Ansible modules `channel_config <../modules/channel_config.html>`_, `channel_member <../modules/channel_member.html>`_, and `channel_policy <../modules/channel_policy.html>`_ are used to update the channel.

* `15-import-ordering-service.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/15-import-ordering-service.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 15-import-ordering-service.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook uses the Ansible module `external_ordering_service <../modules/external_ordering_service.html>`_ to import the ordering service from a file. This file was passed to `Org2` by `Org1`, so that `Org2` could start to join channels on the ordering service.

  | Note: this playbook only needs to be executed when the organizations `Org1` and `Org2` are using separate IBM Blockchain Platform instances. If they are using the same instances, then this information is already available to both organizations.

* `16-join-peer-to-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/16-join-peer-to-channel.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 16-join-peer-to-channel.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook uses the Ansible module `channel_block <../modules/channel_block.html>`_ to fetch the genesis block for the channel, before using the Ansible module `peer_channel <../modules/peer_channel.html>`_ to join the peer `Org2 Peer` to the channel.

* `17-add-anchor-peer-to-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/17-add-anchor-peer-to-channel.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 17-add-anchor-peer-to-channel.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook updates the organization (MSP) definition for `Org2` in the channel `mychannel` to specify that the peer `Org2 Peer` is an anchor peer for the channel. It uses the Ansible modules `channel_config <../modules/channel_config.html>`_ and `channel_member <../modules/channel_member.html>`_ to update the channel configuration.

Finally, there is one Ansible playbook that can be used to destroy the network components for `Org2`. It is:

* `98-delete-endorsing-organization-components.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/98-delete-endorsing-organization-components.yml>`_

  | Organization: Org2
  | Command:

    ::

      ansible-playbook 98-delete-endorsing-organization-components.yml --extra-vars "@org2-vars.yml" --extra-vars "@common-vars.yml"

  | This playbook deletes the components for the endorsing organization `Org2`. It makes use of the Ansible role `endorsing_organization <../roles/endorsing_organization.html>`_ to remove the certificate authority, organization (MSP) and peer for this organization, along with the administrator identities for this organization.

  | Note: this is the same Ansible role that is used to create the components, but the ``state: absent`` variable tells this role that we do not want these components to exist.

Destroying the network
----------------------

If you wish to destroy the network in order to remove all of the components created by this tutorial, then you can run additional Ansible playbooks to do this for you. You can use the `join_network.sh <https://github.com/IBM-Blockchain/ansible-collection/blob/master/tutorial/join_network.sh>`_ script again to run these Ansible playbooks. This script will also remove all of the components for the organizations `Ordering Org` and `Org1` created by the previous tutorial.

Note that if each organization has their own IBM Blockchain Platform instance, you must run a different command.

If you have installed the collection using Ansible Galaxy, or from source, then run the script as follows:

* All organizations use the same IBM Blockchain Platform instance:

    ::

        ./join_network.sh destroy

* All organizations have their own IBM Blockchain Platform instance:

    ::

        ./join_network.sh -i destroy

If you have installed the collection by building a Docker image, then run the script as follows:

* All organizations use the same IBM Blockchain Platform instance:

    ::

        docker run --rm -v "$PWD:/tutorials" mydockerorg/ansible /tutorials/join_network.sh destroy

* All organizations have their own IBM Blockchain Platform instance:

    ::

        docker run --rm -v "$PWD:/tutorials" mydockerorg/ansible /tutorials/join_network.sh -i destroy

After the script has finished, you should examine the output of the script to check that no errors have occurred whilst running the Ansible playbooks. After each Ansible playbook runs, Ansible outputs a ``PLAY RECAP`` section that details how many tasks have been executed, and how many of those tasks have failed.

Finally, if you have imported any identities into the IBM Blockchain Platform console wallet that have been created by these Ansible playbooks, then these identities will still remain in the wallet even after the network has been destroyed. Ansible cannot remove these identities from the wallet. You must remove these identities yourself using the IBM Blockchain Platform console.