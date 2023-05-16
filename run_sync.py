import os
import datetime
import sys
import json
import pickle
import hashlib
import time
import configparser
from peewee import SqliteDatabase,CharField,Model,TextField,DateTimeField

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from libsync import AdConnect,OpenLdapInfo

azureconf='/etc/azureconf/azure.conf'
config = configparser.ConfigParser()
config.read(azureconf)

db = SqliteDatabase(config.get('common', 'dbpath'))

class AzureObject(Model):
    sourceanchor = CharField(primary_key=True, index=True)
    object_type = CharField(null=True)
    last_data_send = TextField(null=True)
    last_data_send_date = DateTimeField(null=True)
    last_sha256_hashnt_send = TextField(null=True)
    last_send_hashnt_date = DateTimeField(null=True)

    class Meta:
        database = db

def hash_for_data(data):
    return hashlib.sha1(pickle.dumps(data)).hexdigest()

def run_sync(force=False):

    global config
    global db

    dry_run = config.getboolean('common', 'dry_run')

    hash_synchronization = config.getboolean('common', 'hash_synchronization')


    if dry_run:
        print('DRY RUN ON: the script will not perform any actions')

    azure = AdConnect()
    azure.dry_run = dry_run
    azure.mailadmin = config.get('common', 'mailadmin')
    azure.passwordadmin = config.get('common', 'passwordadmin')
    azure.proxiesconf = config.get('common', 'proxy')

    with open('/etc/azureconf/mapping.json','r') as f:
        mapping = json.loads(f.read())

    smb = OpenLdapInfo(SourceAnchorAttr_user  = config.get('common', 'SourceAnchorAttr_user'),
                       SourceAnchorAttr_group = config.get('common', 'SourceAnchorAttr_group'),
                       server                 = config.get('common', 'server_ldap'),
                       username               = config.get('common', 'user_ldap'),
                       password               = config.get('common', 'password_ldap'),
                       basedn                 = config.get('common', 'basedn'),
                       mapping                = mapping
                       )



    smb.dry_run = dry_run



    if not AzureObject.table_exists():
        # enable ad sync
        print('enable ad sync')
        azure.enable_ad_sync()

        # enable password hash sync
        print('enable password hash sync')
        azure.enable_password_hash_sync()

    if not AzureObject.table_exists():
        db.create_tables([AzureObject])


    smb.generate_all_dict()

    if config.getboolean('common', 'do_delete'):

        azure.generate_all_dict()

        # Delete user in azure and not found in samba
        for user in azure.dict_az_user:
            if not user in smb.dict_all_users_samba:
                print('Delete user %s' % azure.dict_az_user[user])
                azure.delete_user(user)
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==user,AzureObject.object_type=='user')


        # Delete group in azure and not found in samba
        for group in azure.dict_az_group:
            if not group in smb.dict_all_group_samba:
                print('Delete group %s' % azure.dict_az_group[group])
                azure.delete_group(group)
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==user,AzureObject.object_type=='group')

    #create all user found samba
    for entry in smb.dict_all_users_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_users_samba[entry] :
            print('Send user %s' % smb.dict_all_users_samba[entry])
            azure.send_obj_to_az(smb.dict_all_users_samba[entry])
            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='user',last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()



    for entry in smb.dict_all_group_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='group').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_group_samba[entry] :
            print('Send group %s' % smb.dict_all_group_samba[entry])
            azure.send_obj_to_az(smb.dict_all_group_samba[entry])
            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='group',last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()




    #send all_password
    if hash_synchronization:
        for entry in smb.dict_id_hash :
            sha2password= hash_for_data(smb.dict_id_hash[entry])
            last_data =  AzureObject.select(AzureObject.last_sha256_hashnt_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
            if force or (not last_data) or last_data.last_sha256_hashnt_send != sha2password :
                print('send hash for SourceAnchor: %s %s' % (entry,smb.dict_all_users_samba[entry]['onPremisesSamAccountName']))

                # Microsoft is very slow between sending the account and sending the password
                try:
                    azure.send_hashnt(smb.dict_id_hash[entry],entry)
                except Exception as e:
                    if "Result" in str(e):
                        print('Fail, we may be a little too fast for microsoft, we will wait and try again ...' )
                        time.sleep(30)
                        azure.send_hashnt(smb.dict_id_hash[entry],entry)
                    else:
                        raise

                if not dry_run:
                    AzureObject.update(last_sha256_hashnt_send = sha2password,last_send_hashnt_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()

if __name__ == '__main__':
    run_sync(force=False)

db.close()
