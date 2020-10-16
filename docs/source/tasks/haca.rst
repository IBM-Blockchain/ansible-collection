..
.. SPDX-License-Identifier: Apache-2.0
..

Creating a highly available Certificate Authority
=================================================

The default certificate authority in IBM Blockchain Platform is a single replica with an integrated SQLite database, however it is possible to configure the certificate authority to have an external PostgresSQL database and have multiple replicas of the certificate authority.

The IBM Blockchain Platform documentation describes some limitations with the creation of replicas, including the restriction that an existing certificate authority with an integrated SQLite database cannot be upgraded to use a PostgresSQL database.  Consequently, the playbook for this task checks for the existence of the named certificate authority and fails if it already exists.

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

* Set ``ha_ca_name`` to the name of the new certificate authority, for example ``HAOrg1 CA``.
* Set ``ca_admin_identity`` to the name of the CA administrator enroll ID.
* Set ``ca_admin_pass`` to the CA administrator enroll secret.
* Set ``ca_admin_type`` to ``client`` if you are **not** using NodeOU support or ``admin`` if you **are** using NodeOU support.
* Set ``db_datasource`` to the connection details for your PostgresSQL database, for example:
 ``host=mypostgressql.example.com port=999 user=myUsername password=myPassword dbname=mydb sslmode=verify-full``
* Set ``db_certfile1`` to the Base64 encoded value of the certificate for the PostgresSQL database.
* Set ``ca_replicas`` to the number of replicas of the ca that you require.


Creating the certificate authority
----------------------------------

Review the example playbook `create-ha-ca.yml <https://github.com/IBM-Blockchain/ansible-collection/blob/master/examples/haca/create-ha-ca.yml>`_, then run it as follows:

  ::

    ansible-playbook create-ha-ca.yml

Ensure that the example playbook completed successfully by examining the ``PLAY RECAP`` section in the output from Ansible.

