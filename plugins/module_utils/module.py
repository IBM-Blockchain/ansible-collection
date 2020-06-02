#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

HFC_IMPORT_ERR = None
try:
    import hfc  # noqa: F401
    HAS_HFC = True
except ImportError as e:
    HAS_HFC = False
    HFC_IMPORT_ERR = str(e)

CRYPTOGRAPHY_IMPORT_ERR = None
try:
    import cryptography  # noqa: F401
    HAS_CRYPTOGRAPHY = True
except ImportError as e:
    HAS_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_IMPORT_ERR = str(e)


class BlockchainModule(AnsibleModule):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.check_for_missing_libs()

    def check_for_missing_libs(self):
        url = 'https://ibm-blockchain.github.io/ansible-collection/installation.html#requirements'
        if not HAS_HFC:
            self.fail_json(msg=missing_required_lib("fabric-sdk-py", url=url), exception=HFC_IMPORT_ERR)
        if not HAS_CRYPTOGRAPHY:
            self.fail_json(msg=missing_required_lib("cryptography", url=url), exception=CRYPTOGRAPHY_IMPORT_ERR)
