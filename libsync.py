#!/usr/bin/env python
import os
import ssl
from ldap3   import Server, Connection, Tls
from certifi import core

from AADInternals_python.AADInternals import AADInternals


class AdConnect():

    def __init__(self):


        self.mailadmin = None
        self.passwordadmin = None
        self.proxiesconf = None


        self.tenant_id= None
        self.save_to_cache=True
        self.use_cache = True
        self.cache_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),'last_token.json')

        self.dry_run=True

        self.az = None
        self.dict_az_user={}
        self.dict_az_group={}

    def connect(self):
        if not self.az:
            self.az = AADInternals(mail=self.mailadmin,
                                   password=self.passwordadmin,
                                   proxies=self.proxiesconf,
                                   use_cache=self.use_cache,
                                   save_to_cache=self.save_to_cache,
                                   tenant_id=self.tenant_id,
                                   cache_file=self.cache_file)
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

        try:
            list_groups = self.az.list_groups()
        except Exception as e:
            if 'Identity synchronization is not yet activated for this company' in str(e):
                list_groups = []
            else:
                raise
            
        for group in list_groups:
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

    def __init__(self,SourceAnchorAttr_user="uidNumber",SourceAnchorAttr_group="gidNumber",server=None, username=None,password=None,basedn=None,port=None,mapping={},verify_cert=False,use_ssl=True,path_to_bundle_crt_ldap=None):

        if verify_cert:
            ldapssl = ssl.CERT_REQUIRED
        else:
            ldapssl = ssl.CERT_NONE

        if use_ssl:
            if path_to_bundle_crt_ldap == 'lib_python_certifi':
                ca_certs_file = core.where()
            else:
                ca_certs_file = path_to_bundle_crt_ldap
            tls = Tls(validate=ldapssl, version=ssl.PROTOCOL_TLSv1_2, ca_certs_file=ca_certs_file)            
            serverobj = Server(server, use_ssl=True , tls=tls  ,port=port)
        else:
            serverobj = Server(server, use_ssl=False, tls=False,port=port)

        self.conn = Connection(server=serverobj, user=username, password=password.encode('utf-8'), raise_exceptions=True)
        self.conn.bind()
        self.mapping = mapping
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


        if SourceAnchorAttr.lower() in ['uidnumber','gidnumber']:
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

            if 'hashnt' in self.mapping['user_mapping']:
                if user.entry_attributes_as_dict.get(self.mapping['user_mapping']['hashnt'],[''])[0]:
                    self.dict_id_hash[SourceAnchor]=user[self.mapping['user_mapping']['hashnt']][0]
                    
            if 'D' in user["sambaAcctFlags"][0]:
                enabled = False
            else:
                enabled = True
            user_mapping= self.mapping['user_mapping']
            data = {
                       "SourceAnchor"               : SourceAnchor,
                       "accountEnabled"             : enabled,
                       "userPrincipalName"          : user.entry_attributes_as_dict.get(user_mapping['userPrincipalName'],[''])[0],
                       "onPremisesSamAccountName"   : user.entry_attributes_as_dict.get(user_mapping['onPremisesSamAccountName'],[''])[0],
                       "onPremisesDistinguishedName": user.entry_dn,
                       "dnsDomainName"              : user.entry_attributes_as_dict.get(user_mapping['dnsDomainName'],[''])[0],
                       "displayName"                : user.entry_attributes_as_dict.get(user_mapping['displayName'],[''])[0],
                       "givenName"                  : user.entry_attributes_as_dict.get(user_mapping['givenName'],[''])[0],
                       "surname"                    : user.entry_attributes_as_dict.get(user_mapping['surname'],[''])[0],
                       "commonName"                 : user.entry_attributes_as_dict.get(user_mapping['commonName'],[''])[0],
                       "physicalDeliveryOfficeName" : user.entry_attributes_as_dict.get(user_mapping['physicalDeliveryOfficeName'],[''])[0],
                       "department"                 : user.entry_attributes_as_dict.get(user_mapping['department'],[''])[0],
                       "employeeId"                 : user.entry_attributes_as_dict.get(user_mapping['employeeId'],[''])[0],
                       "streetAddress"              : user.entry_attributes_as_dict.get(user_mapping['streetAddress'],[''])[0],
                       "city"                       : user.entry_attributes_as_dict.get(user_mapping['city'],[''])[0],
                       "state"                      : user.entry_attributes_as_dict.get(user_mapping['state'],[''])[0],
                       "telephoneNumber"            : user.entry_attributes_as_dict.get(user_mapping['telephoneNumber'],[''])[0],
                       "company"                    : user.entry_attributes_as_dict.get(user_mapping['company'],[''])[0],
                       "employeeType"               : user.entry_attributes_as_dict.get(user_mapping['employeeType'],[''])[0],
                       "facsimileTelephoneNumber"   : user.entry_attributes_as_dict.get(user_mapping['facsimileTelephoneNumber'],[''])[0],
                       "mail"                       : user.entry_attributes_as_dict.get(user_mapping['mail'],[''])[0],
                       "mobile"                     : user.entry_attributes_as_dict.get(user_mapping['mobile'],[''])[0],
                       "title"                      : user.entry_attributes_as_dict.get(user_mapping['title'],[''])[0],
                       "proxyAddresses"             : user.entry_attributes_as_dict.get(user_mapping['proxyAddresses'],[]),
                       "usertype"                   : "User"

                   }


            self.all_dn[user.uid.value]=SourceAnchor
            self.dict_all_users_samba[SourceAnchor] = data

        self.conn.search(self.basedn, search_filter="(&(objectClass=posixGroup)(%s=*))" % self.SourceAnchorAttr_group,attributes=ldap3.ALL_ATTRIBUTES)
        for group in self.conn.entries:
            SourceAnchor = self.return_source_anchor(group,"group")
            if not SourceAnchor:
                continue
            group_mapping= self.mapping['group_mapping']
            data = {
                           "SourceAnchor"               : SourceAnchor,
                           "onPremisesSamAccountName"   : group.entry_attributes_as_dict.get(group_mapping['onPremisesSamAccountName'],[''])[0],
                           "onPremisesDistinguishedName": group.entry_dn,
                           "displayName"                : group.entry_attributes_as_dict.get(group_mapping['displayName'],[''])[0],
                           "groupMembers"               : [self.all_dn[m] for m in group.entry_attributes_as_dict.get('memberUid',[]) if m in self.all_dn ],
                           "SecurityEnabled"            : True,
                           "usertype"                   : "Group"
                       }

            self.dict_all_group_samba[SourceAnchor] = data

