#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import hashlib
import os
import tempfile

def get_temp_file():
    temp = tempfile.mkstemp()
    os.close(temp[0])
    return temp[1]

def equal_files(file1, file2):
    with open(file1, 'rb') as file:
        hash1 = hashlib.sha256(file.read()).hexdigest()
    with open(file2, 'rb') as file:
        hash2 = hashlib.sha256(file.read()).hexdigest()
    return hash1 == hash2