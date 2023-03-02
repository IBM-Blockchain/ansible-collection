..
.. SPDX-License-Identifier: Apache-2.0
..

Installing IBM Support for Hyperledger Fabric
======================================

This tutorial will demonstrate how to use the IBM Support for Hyperledger Fabric collection for Ansible to automate the installation of the IBM Support for Hyperledger Fabric software into a Red Hat OpenShift cluster.

If you are using IBM Support for Hyperledger Fabric on IBM Cloud, you do not need to follow this tutorial. You cannot use this Ansible collection to create an instance of the IBM Support for Hyperledger Fabric service on IBM Cloud. If you want to use IBM Support for Hyperledger Fabric on IBM Cloud, you must create the instance before you attempt to use this Ansible collection. Once you have created an instance, follow the `Building a network <./building.html>`_ tutorial.

This tutorial uses the Ansible roles `crds <../roles/crds.html>`_ and `console <../roles/console.html>`_ to install the IBM Support for Hyperledger Fabric software. If you wish to customize the installation process, then you should review the documentation for these roles.

Before you start
----------------

Ensure that you have installed all of the prerequisite software described in `Installation <../installation.html>`_.

You must have access to a  Red Hat OpenShift cluster that is supported for use with IBM Support for Hyperledger Fabric. Review the list of supported platforms in the IBM Support for Hyperledger Fabric documentation: `Supported Platforms <https://www.ibm.com/docs/en/hlf-support/1.0.0?topic=started-about-support-hyperledger-fabric#console-ocp-about-prerequisites>`_

If you have a Kubernetes cluster, you must have the Kubernetes CLI (``kubectl``) installed and configured to use your Kubernetes cluster. Verify that it is working by running the following command:

    ::

        kubectl get nodes

If you have a Red Hat OpenShift cluster, you must have the Red Hat OpenShift CLI (``oc``) installed and configured to use your Red Hat OpenShift cluster. Verify that it is working by running the following command:

    ::

        oc get nodes

The IBM Support for Hyperledger Fabric software should be installed into two Kubernetes namespaces or Red Hat OpenShift projects.

The first namespace or project will contain the IBM Support for Hyperledger Fabric webhook and custom resource definitions. A single instance of the webhook and custom resource definitions are required per cluster. The webhook automatically handles migration between different versions of the custom resource definitions, allowing different versions of the IBM Support for Hyperledger Fabric to coexist in the same cluster. It is recommended that you call this namespace or project ``ibm-hlfsupport-infra``.

The second namespace or project will contain the IBM Support for Hyperledger Fabric operator and console.

The Ansible collection will attempt to automatically create both of these namespaces or projects for you. If you do not have permissions to create a namespace or project, then ask your administrator to create them for you.

Finally, you must have purchased an entitlement to use the IBM Support for Hyperledger Fabric. You will need your entitlement key in order to complete this tutorial. For more information, see the IBM Support for Hyperledger Fabric documentation: `License and pricing <https://cloud.ibm.com/docs/blockchain-sw-25?topic=blockchain-sw-25-console-ocp-about#console-ocp-about-license>`_

Creating the playbook
---------------------

Create a new Ansible playbook file called `install-ibm-hlfsupport.yml`. Copy and paste the content for  Red Hat OpenShift into this new playbook, depending on the type of cluster that you are using:
**Kubernetes**

    .. highlight:: yaml

    ::

        ---
        - name: Deploy IBM Support for Hyperledger Fabric custom resource definitions
          hosts: localhost
          vars:
            state: present
            target: k8s
            arch: amd64
            namespace: ibm-hlfsupport-infra
            image_registry_password: <image_registry_password>
            image_registry_email: <image_registry_email>
            wait_timeout: 3600
          roles:
            - hyperledger.fabric-ansible-collection.hlfsupport_crds

        - name: Deploy IBM Support for Hyperledger Fabric console
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
            - hyperledger.fabric-ansible-collection.hlfsupport_console

**Red Hat OpenShift**

    .. highlight:: yaml

    ::

        ---
        - name: Deploy IBM Support for Hyperledger Fabric custom resource definitions
          hosts: localhost
          vars:
            state: present
            target: openshift
            arch: amd64
            project: ibm-hlfsupport-infra
            image_registry_password: <image_registry_password>
            image_registry_email: <image_registry_email>
            wait_timeout: 3600
          roles:
            - hyperledger.fabric-ansible-collection.hlfsupport_crds

        - name: Deploy IBM Support for Hyperledger Fabric console
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
            - hyperledger.fabric-ansible-collection.hlfsupport_console

Next, you will need to replace the variable placeholders with the required values.

Replace ``<namespace>`` with the name of the Kubernetes namespace, or ``<project>`` with the name of the Red Hat OpenShift project that you are installing the IBM Support for Hyperledger Fabric operator and console into.

Replace ``<image_registry_password>`` with your IBM Support for Hyperledger Fabric entitlement key.

Replace ``<image_registry_email>`` with the email address of your IBMid account that you use to access the My IBM dashboard.

Replace ``<console_domain>`` with the domain name of your Kubernetes cluster or Red Hat OpenShift cluster. This domain name is used as the base domain name for all ingress or routes created by the IBM Support for Hyperledger Fabric.

Replace ``<console_email>`` with the email address of the IBM Support for Hyperledger Fabric console user that will be created during the installation process. You will use this email address to access the IBM Support for Hyperledger Fabric console after installation.

Replace ``<console_default_password>`` with the default password for the IBM Support for Hyperledger Fabric console. This default password will be set as the password for all new users, including the user created during the installation process.

By default, the ``<wait_timeout>`` variable is set to ``3600`` seconds (1 hour), which should be sufficient for most environments. You only need to change the value for this variable if you find that timeout errors occur during the installation process.

Running the playbook
--------------------

Run the Ansible playbook file you created in the previous step by running the following command:

    ::

        ansible-playbook install-ibm-hlfsupport.yml

The Ansible playbook will take some time to run. As the playbook runs, it will output information on the tasks being executed.

At the end of the output, you should see text similar to the following:

    .. highlight:: none

    ::

        TASK [console : Wait for console to start] ***********************************************************************
        ok: [localhost]

        TASK [console : Print console URL] *******************************************************************************
        ok: [localhost] => {
            "msg": "IBM Support for Hyperledger Fabric console available at https://my-namespace-ibp-console-console.apps.my-openshift-cluster.example.org"
        }

        TASK [console : Delete console] **********************************************************************************
        skipping: [localhost]

        PLAY RECAP *******************************************************************************************************
        localhost                  : ok=19   changed=4    unreachable=0    failed=0    skipped=13   rescued=0    ignored=0

Ensure that no errors are reported in the output. Ensure that the failure count in the final ``PLAY RECAP`` section is 0.

The URL of the IBM Support for Hyperledger Fabric console is displayed as part of the output for the ``Print console URL`` task. When you access this URL, you can log in with the email and default password that you specified in your Ansible playbook.

You have now finished installing the IBM Support for Hyperledger Fabric software.
