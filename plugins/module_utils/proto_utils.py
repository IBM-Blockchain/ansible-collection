#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from .file_utils import get_temp_file

import json
import os
import subprocess


def proto_to_json(proto_type, proto_input):
    temp_file = get_temp_file()
    try:
        subprocess.run([
            'configtxlator', 'proto_decode', f'--type={proto_type}', f'--output={temp_file}'
        ], input=proto_input, text=False, close_fds=True, check=True, capture_output=True)
        with open(temp_file, 'rb') as file:
            return json.load(file)
    finally:
        os.remove(temp_file)


def json_to_proto(proto_type, json_input):
    json_data = json.dumps(json_input).encode('utf-8')
    temp_file = get_temp_file()
    try:
        subprocess.run([
            'configtxlator', 'proto_encode', f'--type={proto_type}', f'--output={temp_file}'
        ], input=json_data, text=False, close_fds=True, check=True, capture_output=True)
        with open(temp_file, 'rb') as file:
            return file.read()
    finally:
        os.remove(temp_file)
