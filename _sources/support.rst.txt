..
.. SPDX-License-Identifier: Apache-2.0
..

Getting support
===============

If you have a problem with the IBM Blockchain Platform collection for Ansible, then there are several avenues provided for requesting support.

The first avenue is to open an issue on GitHub. Support is provided a best can do basis by IBM and the community. There are no guarantees provided around response times for GitHub issues.

The second avenue is to open an IBM support ticket. Support for the IBM Blockchain Platform collection for Ansible is included as part of support for the IBM Blockchain Platform.

The final avenue, available to **IBM employees only**, is to request help in the `#ibp-ansible <https://ibm-blockchain.slack.com/archives/C013KULGEPR>`_ channel on the IBM internal Slack workspace.

Regardless of the avenue you choose, you must gather and provide as much data as possible to help us diagnose your issue.

Gathering data
--------------

When requesting support, please gather and provide as much data as possible from the following list:

* Version information

  If you are not using the Docker image, please provide the output of the following commands:

  ::

    python --version
    pip list
    ansible --version
    cat ~/.ansible/collections/ansible_collections/ibm/blockchain_platform/MANIFEST.json
    peer version
    configtxlator version

  Note that depending on your Python installation, you may need to use ``python3`` and ``pip3`` instead.

* Command line

  Please provide the full command line used when you execute the Ansible playbooks, including the ``docker run`` command and arguments if you are using the Docker image.

* Ansible playbooks and variable files

  If possible, please provide all Ansible playbooks and variable files that you are using. It is strongly recommended that you remove any confidential information, such as secrets or passwords, before sending them.

* Output of running Ansible in verbose mode

  Please provide all output from running Ansible in verbose mode. To run Ansible in verbose mode, add the ``-vvv`` argument, for example:

  ::

    ansible-playbook -vvv playbook.yml > ansible.log 2>&1

* Debug logs from the IBM Blockchain Platform collection for Ansible

  The environment variable ``IBP_ANSIBLE_LOG_FILENAME`` can be used to specify the path to a log file. When this environment variable is set, the IBM Blockchain Platform collection for Ansible will write debug logs to the specified file. These logs are verbose, and provide us with insight into the interactions between Ansible, the IBM Blockchain Platform console, and the Hyperledger Fabric CLI.

  To gather debug logs without using the Docker image:

  ::

    export IBP_ANSIBLE_LOG_FILENAME=/tmp/ibp.log
    ansible-playbook playbook.yml

  To gather debug logs using the Docker image:

  ::

    export IBP_ANSIBLE_LOG_FILENAME=/tmp/ibp.log
    docker run --rm -e IBP_ANSIBLE_LOG_FILENAME -u $(id -u) -v /path/to/playbooks:/playbooks -v /tmp:/tmp ibmcom/ibp-ansible ansible-playbook /playbooks/playbook.yml

Opening an issue on GitHub
--------------------------

You can request support by opening an issue on GitHub: https://github.com/IBM-Blockchain/ansible-collection/issues/new

Opening an IBM support ticket
-----------------------------

If you are using the IBM Blockchain Platform on IBM Cloud, then follow the documentation here for submitting a support case: https://cloud.ibm.com/docs/blockchain?topic=blockchain-blockchain-support

If you are using the IBM Blockchain Platform software running in a Red Hat OpenShift or Kubernetes cluster, then follow the documentation here: https://cloud.ibm.com/docs/blockchain-sw-251?topic=blockchain-sw-251-blockchain-support