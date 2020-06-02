#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native
from distutils.version import LooseVersion

import os
import platform
import re
import subprocess

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.check_for_missing_libs()
        self.check_for_missing_bins()

    def check_for_missing_libs(self):
        url = 'https://ibm-blockchain.github.io/ansible-collection/installation.html#requirements'
        if not HAS_HFC:
            self.fail_json(msg=missing_required_lib("fabric-sdk-py", url=url), exception=HFC_IMPORT_ERR)
        if not HAS_CRYPTOGRAPHY:
            self.fail_json(msg=missing_required_lib("cryptography", url=url), exception=CRYPTOGRAPHY_IMPORT_ERR)

    def check_for_missing_bins(self):
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
                self.fail_json(msg=wrong_version_bin(binary, '<unknown>', '>= 1.4.3', url=url), rc=process.returncode, stdout=process.stdout, stderr=process.stderr, cmd=f'{binary} version')
            version = m.group(1)
            if not LooseVersion(version) >= LooseVersion('1.4.3'):
                self.fail_json(msg=wrong_version_bin(binary, version, '>= 1.4.3', url=url), rc=process.returncode, stdout=process.stdout, stderr=process.stderr, cmd=f'{binary} version')
