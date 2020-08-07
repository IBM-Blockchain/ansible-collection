..
.. SPDX-License-Identifier: Apache-2.0
..

Adding an administrator certificate
===================================

A organization in Hyperledger Fabric has one or more administrators that are able to perform administrative actions such as installing a smart contract onto a peer, or editing channel configuration.

When NodeOU support is enabled for an organization (the default in IBM Blockchain Platform), any enrolled identity with a type of ``admin`` is automatically recognized as an administrator for that organization. If that enrolled identity expires, or is revoked, then you can just enroll a new identity and that new identity will also be automatically recognized as an administrator for that organization.

However, if NodeOU support is disabled for an organization, then the definition of that organization must specify an explicit list of enrolled identities which will be recognized as administrators. If you need to enroll a new identity, then you must add that new identity to the list of administrators for the organization before it can be recognized as an administrator.

The list of administrators for an organization is stored in multiple places:

  * The organization's definition that is stored in the IBM Blockchain Platform console.
  * The organization's MSP that is stored in the ordering service system channel, as either an ordering service administrator or a member of the consortium.
  * The organization's MSP that is stored in all channels that the organization is a member of.
  * The peer or ordering service nodes file system.

This task guide walks you through the process of adding a new administrator certificate to an existing organization. You should only follow this task guide if NodeOU support is disabled for the organization.

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

        cd ansible-collection/examples/add-admin-cert

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
* Set ``organization_old_admin_identity`` to the path of a JSON identity file containing the identity of the old or current organization administrator.
* Set ``organization_new_admin_identity`` to the path of a JSON identity file containing the identity of the new organization administrator.
* Set ``channel_names`` to an array of channel names that need to be updated. Do not include the system channel name in this value.

The final set of values must only be set if the organization being updated is a member of the ordering service consortium, but is not an administrator of the ordering service:

* Set ``ordering_service_admin_identity`` to the path to a JSON identity file containing the identity of an ordering service administrator.
* Set ``ordering_service_admin_msp_id`` to the MSP ID of the ordering service administrator.

Updating the organization
-------------------------

The first step in this task is to update the organization's definition that is stored in the IBM Blockchain Platform console. It is important to keep the organization in the IBM Blockchain Platform console up to date, as this is used when performing various operational tasks, for example creating a new peer or ordering service node.

Review the example playbook `01-update-organization.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/add-admin-cert/01-update-organization.yml>`_, then run it as follows:

  ::

    ansible-playbook 01-update-organization.yml

Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

Updating the system channel
---------------------------

The system channel for an ordering service contains the definition of all of the organizations that are in the ordering service consortium and all of the organizations that are administrators of the ordering service. If the organization being updated is a member of the ordering service consortium, or an administrator of the ordering service, then you must update the system channel.

If the organization being updated is a member of the ordering service consortium, then it is important to keep the organization in the ordering service consortium up to date, as this is used when creating new channels on the ordering service. Because the consortium is managed by an ordering service administrator, you must have access to an identity for an ordering service administrator in order to complete this step.

If the organization being updated is an administrator of the ordering service, then you must update the definition in the system channel in order to administer the ordering service with the new administrator certificate.

Depending on the role of the organization being updated, perform the appropriate step:

**If the organization is a member of the ordering service consortium**

  Review the example playbook `02-update-syschannel-member.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/add-admin-cert/02-update-syschannel-member.yml>`_, and then run it as follows:

  ::

    ansible-playbook 02-update-syschannel-member.yml

  Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

**If the organization is an administrator of the ordering service**

  Review the example playbook `03-update-syschannel-admin.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/add-admin-cert/03-update-syschannel-admin.yml>`_, and then run it as follows:

  ::

    ansible-playbook 03-update-syschannel-admin.yml

  Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

Updating the channels
---------------------

The final step in this task is to update the organization's definition that is stored in all channels that the organization is a member of. This also applies for organizations that are ordering service administrators, as a copy of the definition of an organization that is n ordering service administrator is stored in each channel.

If you do not complete this step, the new administrator certificate will not be recognized as an administrator for this organization in these channels.

Depending on the role of the organization being updated, perform the appropriate step:

**If the organization is not an administrator of the ordering service**

  Review the example playbook `04-update-channels-member.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/add-admin-cert/04-update-channels-member.yml>`_, then run it as follows:

  ::

    ansible-playbook 04-update-channels-member.yml

  Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

**If the organization is an administrator of the ordering service**

  Review the example playbook `05-update-channels-admin.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/add-admin-cert/05-update-channels-admin.yml>`_, then run it as follows:

  ::

    ansible-playbook 05-update-channels-admin.yml

  Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.