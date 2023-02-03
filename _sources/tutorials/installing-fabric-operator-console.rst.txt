..
.. SPDX-License-Identifier: Apache-2.0
..

.. _open_console_operator_tutorial:

Installing the Fabric Operations Console and Operator
=====================================================

This tutorial will demonstrate how to use the Fabric Operations Console and Fabric Operator roles to automate the installation of the IBM Support for Hyperledger Fabric software s Kubernetes cluster

This tutorial uses the Ansible roles `fabric-operator-crds <../roles/fabric-operator-crds.html>`_ and `fabric-console <../roles/fabric-console.html>`_ to install the Fabric Operations Console and Fabric Operator software. If you wish to customize the installation process, then you should review the documentation for these roles.

Before you start
----------------

Ensure that you have installed all of the pre-requisite software described in `Installation <../installation.html>`_.


If you have a Kubernetes cluster, you must have the Kubernetes CLI (``kubectl``) installed and configured to use your Kubernetes cluster. Verify that it is working by running the following command:

    ::

        kubectl get nodes


The Ansible collection will attempt to automatically create both of the namespaces or projects it needs for you. If you do not have permissions to create a namespace or project, then ask your administrator to create them for you.

Ingress Controllers.  You must have a ingress controlled installed for the console and operator to route traffic. Note that other software installed by roles in this collection will handle this; the Fabric Operations Console and Fabric Operator will **not** do this for you.

Examples are given below of setting up such ingress controllers, primarily from a development perspective. These should be considered examples, for more details refer to you kubernetes administrator, and the Fabric Operations Console and Fabric Operator documentation.


Creating the playbook
---------------------

Versions of the files shown here are in the github repo under the `examples/opensource-stack` directory

Create a new Ansible playbook file called `install-ofs.yml`. Copy the following content

    .. highlight:: yaml

    ::

        ---
        - name: Deploy Opensource custom resource definitions and operator
          hosts: localhost
          vars_files:
            - vars.yml
          vars:
            state: present
            wait_timeout: 3600
          roles:
            - ibm.blockchain_platform.fabric_operator_crds

        - name: Deploy Fabric Operations Console
          hosts: localhost
          vars_files:
            - vars.yml
          vars:
            state: present
            wait_timeout: 3600
          roles:
            - ibm.blockchain_platform.fabric_console


KIND Ingress configuration
--------------------------

This configuration works well with the KIND cluster; KIND works well in development as it runs the whole
Kubernetes inside a docker container. The playbook is below; this file and templates are in the `examples/opensource-stack` directory


    ::

        ---
        - name: Setup ingress for KIND for use with Fabric Operator/Console
          hosts: localhost
          tasks:
            - name: Create kubernetes resources for the ingress
              k8s:
                definition: "{{ lookup('kubernetes.core.kustomize', dir='templates/ingress') }}"
              register: resultingress

            - name: Wait for the ingress
              command: kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=2m
              changed_when: false

            # Override the cluster DNS with a local override to refer pods to the HOST interface
            # when connecting to ingress.
            - name: Need the cluster ip address
              k8s_info:
                api_version: v1
                kind: service
                namespace: ingress-nginx
                name: "ingress-nginx-controller"
              register: ingress_info

            - name: Applying CoreDNS overrides for ingress domain
              vars:
                clusterip: "{{ ingress_info.resources[0].spec.clusterIP }}"
              k8s:
                state: present
                namespace: kube-system
                resource_definition: "{{ lookup('template','templates/coredns/coredns.yaml.j2') }}"
                apply: yes

            - name: Rollout the CoreDNS
              shell: |
                kubectl -n kube-system rollout restart deployment/coredns
                kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=2m
              changed_when: false


Running the playbook
--------------------

Create a `vars.yml` file as follows:

    ::

        # The type of K8S cluster this is using
        target: k8s
        arch: amd64

        # k8s namespace for the operator and console
        namespace: fabricinfra

        # Console name/domain
        console_name: hlf-console
        console_domain: localho.st

        #  default configuration for the console
        # password reset will be required on first login
        console_email: admin
        console_default_password: password

        # different k8s clusters will be shipped with differently named default storage providers
        # or none at all.  KIND for example has one called 'standard'
        console_storage_class: standard

Please note the `console_domain` for KIND should be `localho.st`
The `console_storage_class` needs to be changed to match a storage class in the cluster. (`standard` for KIND)

Run the Ansible playbook file you created in the previous step by running the following command:

    ::
        ansible-playbook install-ofs.yml

The Ansible playbook will take some time to run. As the playbook runs, it will output information on the tasks being executed.

At the end of the output, you should see text similar to the following:

    .. highlight:: none

    ::

        TASK [console : Wait for console to start] ***********************************************************************
        ok: [localhost]

        TASK [console : Print console URL] *******************************************************************************
        ok: [localhost] => {
            "msg": "Hyperledger Fabric console available at https://my-namespace-ibp-console-console.apps.my-openshift-cluster.example.org"
        }

        TASK [console : Delete console] **********************************************************************************
        skipping: [localhost]

        PLAY RECAP *******************************************************************************************************
        localhost                  : ok=19   changed=4    unreachable=0    failed=0    skipped=13   rescued=0    ignored=0

Ensure that no errors are reported in the output. Ensure that the failure count in the final ``PLAY RECAP`` section is 0.

The URL of the console is displayed as part of the output for the ``Print console URL`` task. When you access this URL, you can log in with the email and default password that you specified in your Ansible playbook.

You have now finished installing the Hyperledger Fabric software.
