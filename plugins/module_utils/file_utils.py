#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os
import tempfile

def get_temp_file():
    temp = tempfile.mkstemp()
    os.close(temp[0])
    return temp[1]