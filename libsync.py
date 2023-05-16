#!/usr/bin/env python
import os
import sys
import json
import base64
import ldap3
from ldap3 import Server, Connection, Tls

from AADInternals_python.AADInternals import AADInternals


class AdConnect():

    def __init__(self):


        self.mailadmin = None
        self.passwordadmin = None
        self.proxiesconf = None

        self.dry_run=True

        self.az = None
        self.dict_az_user={}
        self.dict_az_group={}

    def connect(self):
        if not self.az:
            self.az = AADInternals(mail=self.mailadmin,password=self.passwordadmin,proxies=self.proxiesconf)
            self.tenant_id = self.az.tenant_id
            self.mailadmin = None
            self.passwordadmin = None

    def enable_ad_sync(self):
        self.connect()
        if not self.dry_run:
            self.az.set_adsyncenabled(enabledirsync=True)

    def enable_password_hash_sync(self):
        self.connect()
        if not self.dry_run:
            self.az.set_sync_features(enable_features=['PasswordHashSync'])

    def send_obj_to_az(self,entry):
        self.connect()
        if not self.dry_run:
            self.az.set_azureadobject(**entry)

    def delete_user(self,entry):
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='User')

    def delete_group(self,entry):
        if not self.dry_run:
            self.az.remove_azureadoject(sourceanchor=entry,objecttype='Group')

    def generate_all_dict(self):
        self.connect()
        self.dict_az_user = {}
        for user in self.az.list_users():
            if not user['dirSyncEnabled']:
                continue
            if not user.get('immutable_id'):
                continue
            self.dict_az_user[user["immutable_id"]] = user

        self.dict_az_group = {}
        for group in self.az.list_groups():
            if not group['dirSyncEnabled']:
                continue
            if not group.get('immutable_id'):
                continue
            self.dict_az_group[group["immutable_id"]] = group


    def send_hashnt(self,hashnt,sourceanchor):
        self.connect()
        if not self.dry_run:
            self.az.set_userpassword(hashnt=hashnt,sourceanchor=sourceanchor)


class OpenLdapInfo():

    def __init__(self,SourceAnchorAttr_user="uidNumber",SourceAnchorAttr_group="gidNumber",server=None, username=None,password=None,basedn=None):

        self.conn = Connection(server=server, user=username, password=password.encode('utf-8'), raise_exceptions=True)
        self.conn.bind()

        self.basedn = basedn
        self.dict_all_users_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        self.SourceAnchorAttr_user  = SourceAnchorAttr_user
        self.SourceAnchorAttr_group = SourceAnchorAttr_group

        self.dry_run=True


    def return_source_anchor(self,entry,usertype=None):
        if usertype == 'user':
            SourceAnchorAttr=self.SourceAnchorAttr_user
        else:
            SourceAnchorAttr=self.SourceAnchorAttr_group

        SourceAnchor = entry[SourceAnchorAttr][0]


        if SourceAnchorAttr.lower() in ['uidnumber','gidnumer']:
            SourceAnchor = usertype + '_' + str( SourceAnchor)

        return str(SourceAnchor)

    def generate_all_dict(self):
        self.dict_all_users_samba={}
        self.dict_all_group_samba={}
        self.all_dn={}
        self.dict_id_hash = {}
        # Search all users
        self.conn.search(self.basedn, search_filter="(&(objectClass=posixAccount)(%s=*))" % self.SourceAnchorAttr_user,attributes=ldap3.ALL_ATTRIBUTES)
        for user in self.conn.entries:

            if user.uid.value.endswith('$'):
                continue

            SourceAnchor = self.return_source_anchor(user,usertype="user")
            if not SourceAnchor:
                continue

            if user["sambaNTPassword"][0]:
                self.dict_id_hash[SourceAnchor]=user["sambaNTPassword"][0]
            if 'D' in user["sambaAcctFlags"][0]:
                enabled = False
            else:
                enabled = True
            data = {
                       "SourceAnchor"               : SourceAnchor,
                       "accountEnabled"             : enabled,
                       "userPrincipalName"          : user.entry_attributes_as_dict.get('mail',[''])[0],
                       "onPremisesSamAccountName"   : user.uid.value,
                       "onPremisesDistinguishedName": user.entry_dn,
                       "dnsDomainName"              : user.entry_attributes_as_dict.get('sambaDomainName',[''])[0],
                       "displayName"                : user.entry_attributes_as_dict.get('displayName',[''])[0],
                       "givenName"                  : user.entry_attributes_as_dict.get('givenName',[''])[0],
                       "surname"                    : user.entry_attributes_as_dict.get('sn',[''])[0],
                       "commonName"                 : user.entry_attributes_as_dict.get('cn',[''])[0],
                       "physicalDeliveryOfficeName" : user.entry_attributes_as_dict.get("physicalDeliveryOfficeName",[''])[0],
                       "department"                 : user.entry_attributes_as_dict.get("department",[''])[0],
                       "employeeId"                 : user.entry_attributes_as_dict.get("employeeId",[''])[0],
                       "streetAddress"              : user.entry_attributes_as_dict.get("streetAddress",[''])[0],
                       "city"                       : user.entry_attributes_as_dict.get("city",[''])[0],
                       "state"                      : user.entry_attributes_as_dict.get("state",[''])[0],
                       "telephoneNumber"            : user.entry_attributes_as_dict.get("telephoneNumber",[''])[0],
                       "company"                    : user.entry_attributes_as_dict.get("company",[''])[0],
                       "employeeType"               : user.entry_attributes_as_dict.get("employeeType",[''])[0],
                       "facsimileTelephoneNumber"   : user.entry_attributes_as_dict.get("facsimileTelephoneNumber",[''])[0],
                       "mail"                       : user.entry_attributes_as_dict.get("mail",[''])[0],
                       "mobile"                     : user.entry_attributes_as_dict.get("mobile",[''])[0],
                       "title"                      : user.entry_attributes_as_dict.get("title",[''])[0],
                       "proxyAddresses"             : user.entry_attributes_as_dict.get("proxyAddresses",[]),
                       "usertype"                   : "User"

                   }


            self.all_dn[user.uid.value]=SourceAnchor
            self.dict_all_users_samba[SourceAnchor] = data

        self.conn.search(self.basedn, search_filter="(&(objectClass=posixGroup)(%s=*))" % self.SourceAnchorAttr_group,attributes=ldap3.ALL_ATTRIBUTES)
        for group in self.conn.entries:
            SourceAnchor = self.return_source_anchor(group,"group")
            if not SourceAnchor:
                continue

            data = {
                           "SourceAnchor"               : SourceAnchor,
                           "onPremisesSamAccountName"   : group.entry_attributes_as_dict.get("cn",[''])[0],
                           "onPremisesDistinguishedName": group.entry_dn,
                           "displayName"                : group.entry_attributes_as_dict.get("cn",[''])[0],
                           "groupMembers"               : [self.all_dn[m] for m in group.entry_attributes_as_dict.get('memberUid',[]) if m in self.all_dn ],
                           "SecurityEnabled"            : True,
                           "usertype"                   : "Group"
                       }

            self.dict_all_group_samba[SourceAnchor] = data

