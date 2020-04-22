#!/usr/bin/python
#
# SPDX-License-Identifier: Apache-2.0
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Organization:

    def __init__(self, name, msp_id, root_certs, intermediate_certs, admins, revocation_list, tls_root_certs, tls_intermediate_certs, fabric_node_ous, organizational_unit_identifiers, host_url):
        self.name = name
        self.msp_id = msp_id
        self.root_certs = root_certs
        self.intermediate_certs = intermediate_certs
        self.admins = admins
        self.revocation_list = revocation_list
        self.tls_root_certs = tls_root_certs
        self.tls_intermediate_certs = tls_intermediate_certs
        self.fabric_node_ous = fabric_node_ous
        self.organizational_unit_identifiers = organizational_unit_identifiers
        self.host_url = host_url

    def clone(self):
        return Organization(
            name=self.name,
            msp_id=self.msp_id,
            root_certs=self.root_certs,
            intermediate_certs=self.intermediate_certs,
            admins=self.admins,
            revocation_list=self.revocation_list,
            tls_root_certs=self.tls_root_certs,
            tls_intermediate_certs=self.tls_intermediate_certs,
            fabric_node_ous=self.fabric_node_ous,
            organizational_unit_identifiers=self.organizational_unit_identifiers,
            host_url=self.host_url
        )

    def equals(self, other):
        return (
            self.name == other.name and
            self.msp_id == other.msp_id and
            self.root_certs == other.root_certs and
            self.intermediate_certs == other.intermediate_certs and
            self.admins == other.admins and
            self.revocation_list == other.revocation_list and
            self.tls_root_certs == other.tls_root_certs and
            self.tls_intermediate_certs == other.tls_intermediate_certs and
            self.fabric_node_ous == other.fabric_node_ous and
            self.organizational_unit_identifiers == other.organizational_unit_identifiers and
            self.host_url == other.host_url
        )

    def to_json(self):
        return dict(
            name=self.name,
            msp_id=self.msp_id,
            root_certs=self.root_certs,
            intermediate_certs=self.intermediate_certs,
            admins=self.admins,
            revocation_list=self.revocation_list,
            tls_root_certs=self.tls_root_certs,
            tls_intermediate_certs=self.tls_intermediate_certs,
            fabric_node_ous=self.fabric_node_ous,
            organizational_unit_identifiers=self.organizational_unit_identifiers,
            host_url=self.host_url,
            type='msp'
        )

    @staticmethod
    def from_json(data):
        return Organization(
            name=data['name'],
            msp_id=data['msp_id'],
            root_certs=data['root_certs'],
            intermediate_certs=data['intermediate_certs'],
            admins=data['admins'],
            revocation_list=data['revocation_list'],
            tls_root_certs=data['tls_root_certs'],
            tls_intermediate_certs=data['tls_intermediate_certs'],
            fabric_node_ous=data['fabric_node_ous'],
            organizational_unit_identifiers=data['organizational_unit_identifiers'],
            host_url=data['host_url']
        )
