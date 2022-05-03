#!/bin/bash
export IBP_ANSIBLE_LOG_FILENAME=ibp.log

ansible-galaxy collection build -f
ansible-galaxy collection install -f ibm-blockchain_platform-1.1.7.tar.gz
export IBP_ANSIBLE_LOG_FILENAM=$(pwd)/generic.log
cd ./tutorial/generic
ansible-playbook -v 001-peer-info.yml
cd -
