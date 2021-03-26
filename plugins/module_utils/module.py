#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import logging
import os
import platform
import re
import subprocess
from distutils.version import LooseVersion
from inspect import getframeinfo, stack

from ansible.module_utils._text import to_native
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

PKCS11_IMPORT_ERR = None
try:
    import pkcs11  # noqa: F401
    HAS_PKCS11 = True
except ImportError as e:
    HAS_PKCS11 = False
    PKCS11_IMPORT_ERR = str(e)

ASN1CRYPTO_IMPORT_ERR = None
try:
    import asn1crypto  # noqa: F401
    HAS_ASN1CRYPTO = True
except ImportError as e:
    HAS_ASN1CRYPTO = False
    ASN1CRYPTO_IMPORT_ERR = str(e)


def missing_required_bin(binary, reason=None, url=None):
    hostname = platform.node()
    msg = "Failed to execute the required binary (%s) on %s." % (binary, hostname)
    if reason:
        msg += " This is required %s." % reason
    if url:
        msg += " See %s for more info." % url

    msg += (" Please read module documentation and install in the appropriate location."
            " If the required binary is installed, then the install directory may not be present in the PATH environment variable (%s)." % os.environ['PATH'])
    return msg


def wrong_version_bin(binary, actual_version, expected_version, reason=None, url=None):
    hostname = platform.node()
    msg = "Required binary (%s) on %s has wrong version, expected version %s but version is %s." % (binary, hostname, expected_version, actual_version)
    if reason:
        msg += " This is required %s." % reason
    if url:
        msg += " See %s for more info." % url

    msg += (" Please read module documentation and install in the appropriate location."
            " If the required binary is installed, then the install directory may not be present in the PATH environment variable (%s)." % os.environ['PATH'])
    return msg


class BlockchainModule(AnsibleModule):

    def __init__(self, min_fabric_version='1.4.3', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.check_for_missing_libs()
        self.check_for_missing_bins(min_fabric_version)
        self.logger = None
        self.setup_logging()

    def check_for_missing_libs(self):
        url = 'https://ibm-blockchain.github.io/ansible-collection/installation.html#requirements'
        if not HAS_HFC:
            self.fail_json(msg=missing_required_lib("fabric-sdk-py", url=url), exception=HFC_IMPORT_ERR)
        if not HAS_CRYPTOGRAPHY:
            self.fail_json(msg=missing_required_lib("cryptography", url=url), exception=CRYPTOGRAPHY_IMPORT_ERR)

    def check_for_missing_bins(self, min_fabric_version='1.4.3'):
        url = 'https://ibm-blockchain.github.io/ansible-collection/installation.html#requirements'
        for binary in ['peer', 'configtxlator']:
            try:
                process = subprocess.run([binary, 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True, close_fds=True)
            except Exception as e:
                self.fail_json(msg=missing_required_bin(binary, url=url), exception=to_native(e), cmd=f'{binary} version')
            if process.returncode != 0:
                self.fail_json(msg=missing_required_bin(binary, url=url), rc=process.returncode, stdout=process.stdout, stderr=process.stderr, cmd=f'{binary} version')
            p = re.compile('Version: (.+)$', re.MULTILINE)
            m = p.search(process.stdout)
            if m is None:
                self.fail_json(msg=wrong_version_bin(binary, '<unknown>', f'>= {min_fabric_version}', url=url), rc=process.returncode, stdout=process.stdout, stderr=process.stderr, cmd=f'{binary} version')
            version = m.group(1)
            if not LooseVersion(version) >= LooseVersion(min_fabric_version):
                self.fail_json(msg=wrong_version_bin(binary, version, f'>= {min_fabric_version}', url=url), rc=process.returncode, stdout=process.stdout, stderr=process.stderr, cmd=f'{binary} version')

    def check_for_missing_hsm_libs(self):
        url = 'https://ibm-blockchain.github.io/ansible-collection/installation.html#requirements'
        if not HAS_PKCS11:
            self.fail_json(msg=missing_required_lib("python-pkcs11", url=url), exception=PKCS11_IMPORT_ERR)
        if not HAS_ASN1CRYPTO:
            self.fail_json(msg=missing_required_lib("asn1crypto", url=url), exception=ASN1CRYPTO_IMPORT_ERR)

    def setup_logging(self):
        filename = os.environ.get('IBP_ANSIBLE_LOG_FILENAME', None)
        if not filename:
            return
        logging.basicConfig(filename=filename, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
        self.logger = logging.getLogger(self._name)

    def json_log(self, msg):
        if not self.logger:
            return
        caller = getframeinfo(stack()[1][0])
        caller_str = f'{caller.filename}:{caller.lineno}'
        msg['caller'] = caller_str
        msg_str = json.dumps(msg, indent=4)
        self.logger.debug(msg_str)
