#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def get_application_capability(channel_group):
    application_capabilities = channel_group['groups'].get('Application', dict()).get('values', dict()).get('Capabilities', dict()).get('value', dict()).get('capabilities', dict())
    application_capabilities_list = list(application_capabilities.keys())
    application_capability = None
    if application_capabilities_list:
        application_capability = application_capabilities_list[0]
    return application_capability


def get_channel_capability(channel_group):
    channel_capabilities = channel_group['values'].get('Capabilities', dict()).get('value', dict()).get('capabilities', dict())
    channel_capabilities_list = list(channel_capabilities.keys())
    channel_capability = None
    if channel_capabilities_list:
        channel_capability = channel_capabilities_list[0]
    return channel_capability


def get_orderer_capability(channel_group):
    orderer_capabilities = channel_group['groups'].get('Orderer', dict()).get('values', dict()).get('Capabilities', dict()).get('value', dict()).get('capabilities', dict())
    orderer_capabilities_list = list(orderer_capabilities.keys())
    orderer_capability = None
    if orderer_capabilities_list:
        orderer_capability = orderer_capabilities_list[0]
    return orderer_capability


def get_highest_capability(channel_group):
    application_capability = get_application_capability(channel_group)
    channel_capability = get_channel_capability(channel_group)
    orderer_capability = get_orderer_capability(channel_group)
    capabilities = []
    capabilities += [application_capability] if application_capability is not None else []
    capabilities += [channel_capability] if channel_capability is not None else []
    capabilities += [orderer_capability] if orderer_capability is not None else []
    if capabilities:
        return capabilities[0]
    return None
