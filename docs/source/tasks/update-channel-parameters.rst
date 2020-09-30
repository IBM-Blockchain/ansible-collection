..
.. SPDX-License-Identifier: Apache-2.0
..

Updating Channel Parameters
===========================

Hyperledger Fabric allows each channel to be configured with specific BatchSize parameters and a BatchTimeout for blocks.  This playbook example shows how an Architect or Chaincode Developer could to set these values for a particular application channel on IBM Blockchain Platform.

The details and implications of setting the parameters is covered in the Hyperledger Fabric documentation set.

Before you start
----------------

This task guide assumes that you have installed Ansible and the IBM Blockchain Platform collection for Ansible, and are familiar with how to use these technologies.

This task guide also assumes that you have created a PostgresSQL database and that you have the connection details available.

Cloning the repository
----------------------

This task guide uses a set of example playbooks which are stored in a GitHub repository. You must clone this GitHub repository in order to run the playbooks locally:

    .. highlight:: none

    ::

        git clone https://github.com/IBM-Blockchain/ansible-collection.git

After cloning the GitHub repository, you must change into the examples directory for this task guide:

    ::

        cd ansible-collection/examples/create-ha-ca

Editing the variable file
-------------------------

You need to edit the variable file ``vars.yml``. This file is used to pass information about your network into the example Ansible playbook.

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

The remaining values must always be set:

* Set ``ordering_service_name`` to the name of the ordering service, for example ``Ordering Service``.
* Set ``organization_name`` to the name of the organization.
* Set ``organization_msp_id`` to the MSP ID of the organization.
* Set ``organization_admin_identity`` to the path of a JSON identity file containing the identity of the organization administrator.
* Set ``ordering_service_admin_identity`` to the path to a JSON identity file containing the identity of an ordering service administrator.
* Set ``ordering_service_admin_msp_id`` to the MSP ID of the ordering service administrator.
* Set ``target_channel`` to the name of the  channel that you want to update parameters.
* Set ``ch_max_message_count`` to the maximum number of transactions in a Block for the target channel.
* Set ``ch_absolute_max_bytes`` to the absolute maximum Block size for the target channel.
* Set ``ch_preferred_max_bytes`` to the preferred maximum Block size for the target channel.
* Set ``ch_batch_timeout`` to the amount of time to wait after the first transaction before cutting a Block for the target channel.


Updating the channel parameters
-------------------------------

Review the example playbook `update-channel-parameters.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/update-channel-parameters/update-channel-parameters.yml>`_, then run it as follows:

  ::

    ansible-playbook update-channel-parameters.yml

Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

