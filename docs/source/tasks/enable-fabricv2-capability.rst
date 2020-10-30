..
.. SPDX-License-Identifier: Apache-2.0
..

Enable Hyperledger Fabric v2.x capabilities
===========================================

Fabric v2 capability is distinct from Fabric v2.x binaries, and the most common scenario will be where the binaries on a network have been upgraded to v2.x, leaving the Capability of the channels at V1.x.  This playbook example can be used to upgrade firstly the system channel, then an array of named application channels.

Note that when an application channel has been upgraded to v2 capability it is incompatible with the Fabric v1.x chaincode lifecycle, and the new v2.* lifecycle must be used to upgrade or deploy new chaincodes (contracts).

v2 capability should only be enabled when all nodes on the network are running v2.x binaries.

Before you start
----------------

This task guide assumes that you have installed Ansible and the IBM Blockchain Platform collection for Ansible, and are familiar with how to use these technologies.

Cloning the repository
----------------------

This task guide uses a set of example playbooks which are stored in a GitHub repository. You must clone this GitHub repository in order to run the playbooks locally:

    .. highlight:: none

    ::

        git clone https://github.com/IBM-Blockchain/ansible-collection.git

After cloning the GitHub repository, you must change into the examples directory for this task guide:

    ::

        cd ansible-collection/examples/enable-fabricv2-capability

Editing the variable file
-------------------------

You need to edit the variable file ``vars.yml``. This file is used to pass information about your network into the example Ansible playbooks.

The first set of values that you must set depend on whether the organization is using the IBM Blockchain Platform on IBM Cloud, or the IBM Blockchain Platform software:

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

The second set of values must always be set:

* Set ``ordering_service_name`` to the name of the ordering service, for example ``Ordering Service``.
* Set ``organization_name`` to the name of the organization.
* Set ``organization_msp_id`` to the MSP ID of the organization.
* Set ``organization_admin_identity`` to the path of a JSON identity file containing the identity of the organization administrator.
* Set ``ordering_service_admin_identity`` to the path to a JSON identity file containing the identity of an ordering service administrator.
* Set ``ordering_service_admin_msp_id`` to the MSP ID of the ordering service administrator.
* Set ``channel_names`` to an array of channel names that need to have Fabric v2 capability enabled. Do not include the system channel name in this value.



Enabling v2 Capability for the System Channel
---------------------------------------------

The first task is to enable v2 capability on the system channel of the Orderer.
Note that any new channels created after updating the System Channel will have v2 capability enabled by default, but readers are encouraged to verify that all the capabilities are enabled for the new channels.

Review the example playbook `01-enable-fabricv2-systemchannel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/enable-fabricv2-capability/01-enable-fabricv2-systemchannel.yml>`_.

Ensure that the JSON identity files specified in the ``vars.yml`` file have been copied to the working directory.

Run the playbook as follows:

  ::

    ansible-playbook 01-enable-fabricv2-systemchannel.yml

Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.


Enabling v2 Capability for Specified Channels
---------------------------------------------

The second step in this task is to enable v2 capability for the application channels.  Application channels do not have to be v2 enabled immediately after the system channel, channels can continue to run with V1.x capability if required.

Note that when you have enabled v2 Capability on a channel you are commited to using the new v2 Chaincode Lifecycle on that channel.

v2 capability requires that a *Channel Application Endorsement Policy* be added to the channel.  This playbook uses an example policy ``endorsement-policy.json``.
v2 capability enables a default majority Lifecycle Endorsement Policy, but if a different policy is required, this playbook can be modified to include such a policy at the time v2 capability is enabled.

In this example playbook both the Ordering Service Administrator identity, and the Organisation Administrator identity are used to sign the modified channel configuration but in other scenarios these identities for signing may be different.

Review the example playbook `02-enable-fabricv2-channels.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/enable-fabricv2-capability/02-enable-fabricv2-channels.yml>`_.

When reviewing the playbook you will note that an additional playbook is used on a loop across the array of channels listed in the variables file  `02-enable-fabricv2-channel.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/enable-fabricv2-capability/tasks/02-enable-fabricv2-channel.yml>`_.

Run the playbook as follows:

  ::

    ansible-playbook 02-enable-fabricv2-channels.yml

Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.
