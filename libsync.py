#!/usr/bin/env python
import os
import ssl
import struct
import base64
from ldap3   import Server, Connection, Tls
from certifi import core

from AADInternals_python.AADInternals import AADInternals

def sid_to_base64(sid):
    # Split the SID into its components
    parts = sid.split('-')
    
    # Validate SID format
    if not (parts[0] == 'S' and len(parts) > 2):
        raise ValueError("Invalid SID format")
    
    # Parse the identifier authority (last part before the actual sub-authorities)
    identifier_authority = int(parts[2])
    
    # The first sub-authority number is always in the range 0-4294967295
    # and is represented as an unsigned integer
    sub_authorities = [int(part) for part in parts[3:]]
    
    # Encode the revision (always 1) and sub-authority count (number of sub-authorities)
    revision_and_subauthority_count = struct.pack('BB', 1, len(sub_authorities))
    
    # Encode the identifier authority as a 48-bit (6-byte) value
    identifier_authority_bytes = struct.pack('>Q', identifier_authority)[-6:]
    
    # Encode each sub-authority as a 32-bit (4-byte) value
    sub_authority_bytes = b''.join(struct.pack('<I', sa) for sa in sub_authorities)
    
    # Combine all parts
    binary_sid = revision_and_subauthority_count + identifier_authority_bytes + sub_authority_bytes
    
    # Encode in base64 and return
    return base64.b64encode(binary_sid).decode('utf-8')

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

    def __init__(self,SourceAnchorAttr_user="uidNumber",SourceAnchorAttr_group="gidNumber",server=None, username=None,password=None,basedn=None,port=None,mapping={},verify_cert=False,use_ssl=True,path_to_bundle_crt_ldap=None,sourceanchorattr_user_is_sid=True,sourceanchorattr_group_is_sid=True):

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
        self.dict_guidnumber_sa={}
        self.dict_id_hash = {}
        self.SourceAnchorAttr_user  = SourceAnchorAttr_user
        self.SourceAnchorAttr_group = SourceAnchorAttr_group
        self.sourceanchorattr_user_is_sid  = sourceanchorattr_user_is_sid
        self.sourceanchorattr_group_is_sid = sourceanchorattr_group_is_sid        

        self.dry_run=True


    def return_source_anchor(self,entry,usertype=None):
        if usertype == 'user':
            SourceAnchorAttr=self.SourceAnchorAttr_user
            SourceAnchor = entry[SourceAnchorAttr][0]
            if self.sourceanchorattr_user_is_sid:
                SourceAnchor = sid_to_base64(SourceAnchor)
        else:
            SourceAnchorAttr=self.SourceAnchorAttr_group
            SourceAnchor = entry[SourceAnchorAttr][0]
            if self.sourceanchorattr_group_is_sid:
                SourceAnchor = sid_to_base64(SourceAnchor)

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
            self.all_dn[user.uid.value.split('=',1)[-1]]=SourceAnchor
            self.all_dn[user.entry_dn]=SourceAnchor
            self.dict_all_users_samba[SourceAnchor] = data
            
            gidnumber = user.entry_attributes_as_dict.get(user_mapping['gidNumber'],[''])[0]
            if gidnumber:
                if not gidnumber in dict_guidnumber_sa:
                    self.dict_guidnumber_sa[gidnumber] = [SourceAnchor]
                else:
                    self.dict_guidnumber_sa[gidnumber].append(SourceAnchor)

        self.conn.search(self.basedn, search_filter="(&(objectClass=posixGroup)(%s=*))" % self.SourceAnchorAttr_group,attributes=ldap3.ALL_ATTRIBUTES)
        
        for group in self.conn.entries:
            SourceAnchor = self.return_source_anchor(group,"group")
            if not SourceAnchor:
                continue            
            self.all_dn[group.entry_dn] = SourceAnchor
            self.all_dn[group.entry_dn.split(',')[0]] = SourceAnchor
        
        for group in self.conn.entries:
            SourceAnchor = self.return_source_anchor(group,"group")
            if not SourceAnchor:
                continue
                
            groupMembers = {}
            for attrgrouptest in ["memberUid","member","uniqueMember"]:
                for m in group.entry_attributes_as_dict.get(attrgrouptest,[]): 
                    if m in self.all_dn:
                        groupMembers[self.all_dn[m]] = None

            gidnumber = group.entry_attributes_as_dict.get(user_mapping['gidNumber'],[''])[0]
            if gidnumber:
                for gi in self.dict_guidnumber_sa.get(gidnumber,[]):
                    groupMembers[gi] = None
            
            group_mapping= self.mapping['group_mapping']
            data = {
                           "SourceAnchor"               : SourceAnchor,
                           "onPremisesSamAccountName"   : group.entry_attributes_as_dict.get(group_mapping['onPremisesSamAccountName'],[''])[0],
                           "onPremisesDistinguishedName": group.entry_dn,
                           "displayName"                : group.entry_attributes_as_dict.get(group_mapping['displayName'],[''])[0],
                           "groupMembers"               : list(groupMembers),
                           "SecurityEnabled"            : True,
                           "usertype"                   : "Group"
                       }

            self.dict_all_group_samba[SourceAnchor] = data

