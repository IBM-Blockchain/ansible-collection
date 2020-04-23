..
.. SPDX-License-Identifier: Apache-2.0
..

Installing the IBM Blockchain Platform
======================================

This tutorial will demonstrate how to use the IBM Blockchain Platform collection for Ansible to automate the installation of the IBM Blockchain Platform software into a Kubernetes or Red Hat OpenShift cluster.

This tutorial uses the ``ibm.blockchain_platform.console`` role to install the IBM Blockchain Platform. You can review the documentation for this role to find all of the options that are available to customize the installation process: `console <../roles/console.html>`_

Before you start
----------------

Ensure that you have installed all of the pre-requisite software described in `Installation <../installation.html>`_.

You must have access to a Kubernetes or Red Hat OpenShift cluster that is supported for use with the IBM Blockchain Platform. Review the list of supported platforms in the IBM Blockchain Platform documentation: `Supported Platforms <https://cloud.ibm.com/docs/blockchain-sw-213?topic=blockchain-sw-213-console-ocp-about#console-ocp-about-prerequisites>`_

If you have a Kubernetes cluster, you must have the Kubernetes CLI (``kubectl``) installed and configured to use your Kubernetes cluster. Verify that it is working by running the following command:

    ::

        kubectl get nodes

If you have a Red Hat OpenShift cluster, you must have the Red Hat OpenShift CLI (``oc``) installed and configured to use your Red Hat OpenShift cluster. Verify that it is working by running the following command:

    ::

        oc get nodes

The IBM Blockchain Platform must be installed into a Kubernetes namespace or Red Hat OpenShift project. If you do not have permissions to create a namespace or project, then ask your administrator to create it for you.

Finally, you must have purchased an entitlement to use the IBM Blockchain Platform. You will need your entitlement key in order to complete this tutorial. For more information, see the IBM Blockchain Platform documentation: `License and pricing <https://cloud.ibm.com/docs/blockchain-sw-213?topic=blockchain-sw-213-console-ocp-about#console-ocp-about-license>`_

Creating the playbook
-----------------------------

Create a new Ansible playbook file called `install-ibp.yml`. Copy and paste the content for Kubernetes or Red Hat OpenShift into this new playbook, depending on the type of cluster that you are using:

**Kubernetes**

    .. highlight:: yaml

    ::

        ---
        - name: Deploy IBM Blockchain Platform console
          hosts: localhost
          vars:
            state: present
            target: k8s
            arch: amd64
            namespace: <namespace>
            image_registry_password: <image_registry_password>
            image_registry_email: <image_registry_email>
            console_domain: <console_domain>
            console_email: <console_email>
            console_default_password: <console_default_password>
            wait_timeout: 3600
          roles:
            - ibm.blockchain_platform.console

**Red Hat OpenShift**

    .. highlight:: yaml

    ::

        ---
        - name: Deploy IBM Blockchain Platform console
          hosts: localhost
          vars:
            state: present
            target: openshift
            arch: amd64
            project: <project>
            image_registry_password: <image_registry_password>
            image_registry_email: <image_registry_email>
            console_domain: <console_domain>
            console_email: <console_email>
            console_default_password: <console_default_password>
            wait_timeout: 3600
          roles:
            - ibm.blockchain_platform.console

Next, you will need to replace the variable placeholders with the required values.

Replace ``<namespace>`` with the name of the Kubernetes namespace, or ``<project>`` with the name of the Red Hat OpenShift project, that you are installing the IBM Blockchain Platform into.

Replace ``<image_registry_email>`` with the email address of your IBMid account that you use to access the My IBM dashboard. Replace ``<image_registry_password>`` with your IBM Blockchain Platform entitlement key.

Replace ``<console_domain>`` with the domain name of your Kubernetes cluster or Red Hat OpenShift cluster. This domain name is used as the base domain name for all ingress or routes created by the IBM Blockchain Platform.

Replace ``<console_email>`` with the email address of the IBM Blockchain Platform console user that will be created during the installation process. You will use this email address to access the IBM Blockchain Platform console after installation.

Replace ``<console_default_password>`` with the default password for the IBM Blockchain Platform console. This default password will be set as the password for all new users, including the user created during the installation process.

By default, the ``<wait_timeout>`` variable is set to ``3600`` seconds (1 hour), which should be sufficient for most environments. You only need to change the value for this variable if you find that timeout errors occur during the installation process.

Running the playbook
------------------------------

Run the Ansible playbook file you created in the previous step by running the following command:

    ::

        ansible-playbook install-ibp.yml

The Ansible playbook will take some time to run. As the playbook runs, it will output information on the tasks being executed.

At the end of the output, you should see text similar to the following:

    .. highlight:: none

    ::

        TASK [console : Wait for console to start] ***********************************************************************
        ok: [localhost]

        TASK [console : Print console URL] *******************************************************************************
        ok: [localhost] => {
            "msg": "IBM Blockchain Platform console available at https://my-namespace-ibp-console-console.apps.my-openshift-cluster.example.org"
        }

        TASK [console : Delete console] **********************************************************************************
        skipping: [localhost]

        PLAY RECAP *******************************************************************************************************
        localhost                  : ok=19   changed=4    unreachable=0    failed=0    skipped=13   rescued=0    ignored=0

Ensure that no errors are reported in the output. Ensure that the failure count in the final ``PLAY RECAP`` section is 0.

The URL of the IBM Blockchain Platform console is displayed as part of the output for the ``Print console URL`` task. When you access this URL, you can log in with the email and default password that you specified in your Ansible playbook.

You have now finished installing the IBM Blockchain Platform software.
