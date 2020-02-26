#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import collections
import json

def copy_dict(source):
    return json.loads(json.dumps(source))

def merge_dicts(target, source):
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(source[key], collections.Mapping):
            merge_dicts(target[key], source[key])
        else:
            target[key] = source[key]

def diff_dicts(target, source):
    result = dict()
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(source[key], collections.Mapping):
            sub_result = diff_dicts(target[key], source[key])
            if bool(sub_result):
                result[key] = sub_result
        elif target.get(key, None) != source[key]:
            result[key] = source[key]
            diff = True
    return result

def equal_dicts(source1, source2):
    json1 = json.dumps(source1, sort_keys=True)
    json2 = json.dumps(source2, sort_keys=True)
    return json1 == json2