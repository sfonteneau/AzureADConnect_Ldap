import os
import datetime
import sys
import json
import pickle
import hashlib
import time
import configparser
import traceback
import argparse
from peewee import SqliteDatabase,CharField,Model,TextField,DateTimeField

parser = argparse.ArgumentParser(description='Azure ad sync')
parser.add_argument('--conf', dest='azureconf', default='/etc/azureconf/azure.conf',help='path to conf file')
parser.add_argument('--force', action=argparse.BooleanOptionalAction,dest='force',help='Force synchronization of all objects',default=False)
parser.add_argument('--dryrun', action=argparse.BooleanOptionalAction,dest='dryrun',help='simulate a send but does not actually perform the actions',default=None)
parser.add_argument('--logfile', dest='logfile', default='/var/log/azure_ad_sync',help='File log output')
parser.add_argument('--service-mode', action=argparse.BooleanOptionalAction,dest='servicemode',help='Run the script in service mode',default=False)

args = parser.parse_args()

if "__file__" in locals():
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from libsync import AdConnect,OpenLdapInfo,write_log_json_data,logger,logging

azureconf = args.azureconf
config = configparser.ConfigParser()
config.read(azureconf)
logfile = args.logfile

db = SqliteDatabase(config.get('common', 'dbpath'))

calculate_deletions_based_on_last_sync = False
if config.has_option('common', 'calculate_deletions_based_on_last_sync'):
    calculate_deletions_based_on_last_sync = config.getboolean('common', 'calculate_deletions_based_on_last_sync')

synchronization_interval_service=60

if config.has_option('common', 'synchronization_interval_service'):
    synchronization_interval_service = config.getint('common', 'synchronization_interval_service')

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

def run_sync(force=False,from_db=False):

    global config
    global db


    if args.dryrun != None:
        dry_run = args.dryrun
    else:
        dry_run = config.getboolean('common', 'dry_run')

    if not dry_run:
        if logfile:
            fhandler = logging.FileHandler(logfile)
            logger.addHandler(fhandler)

    use_get_syncobjects = True
    if config.has_option('common', 'use_get_syncobjects'):
        use_get_syncobjects = config.getboolean('common', 'use_get_syncobjects')

    hash_synchronization = config.getboolean('common', 'hash_synchronization')


    if dry_run:
        print('DRY RUN ON: the script will not perform any actions')

    azure = AdConnect()
    azure.dry_run = dry_run
    azure.use_get_syncobjects = use_get_syncobjects


    if config.has_option('common', 'tenant_id'):
        azure.tenant_id = config.get('common', 'tenant_id')

    if config.has_option('common', 'mailadmin'):
        azure.mailadmin = config.get('common', 'mailadmin')

    if config.has_option('common', 'passwordadmin'):
        azure.passwordadmin = config.get('common', 'passwordadmin')

    if config.has_option('common', 'save_to_cache'):
        azure.save_to_cache = config.getboolean('common', 'save_to_cache')

    if config.has_option('common', 'use_cache'):
        azure.use_cache = config.getboolean('common', 'use_cache')  

    if config.has_option('common', 'credential_cache_file'):
        azure.cache_file = config.get('common', 'credential_cache_file')

    if config.get('common', 'proxy'):
        azure.proxiesconf = {'http':config.get('common', 'proxy'),'https':config.get('common','proxy')}
    else:
        azure.proxiesconf = {}

    with open(os.path.join(azureconf.rsplit(os.sep,1)[0] ,'mapping.json'),'r') as f:
        mapping = json.loads(f.read())

    smb = OpenLdapInfo(SourceAnchorAttr_user         = config.get('common', 'SourceAnchorAttr_user'),
                       SourceAnchorAttr_group        = config.get('common', 'SourceAnchorAttr_group'),
                       server                        = config.get('common', 'server_ldap'),
                       username                      = config.get('common', 'user_ldap'),
                       password                      = config.get('common', 'password_ldap', raw=True),
                       port                          = config.getint('common', 'port_ldap'),
                       basedn_user                   = config.get('common', 'basedn_user'),
                       basedn_group                  = config.get('common', 'basedn_group'),
                       filter_user                   = config.get('common', 'filter_user'),
                       filter_group                  = config.get('common', 'filter_group'),
                       use_ssl                       = config.getboolean('common', 'use_ssl_ldap'),
                       verify_cert                   = config.getboolean('common', 'verify_cert_ldap'),
                       mapping                       = mapping,
                       sourceanchorattr_user_is_sid  = config.getboolean('common', 'sourceanchorattr_user_is_sid') if config.has_option('common', 'sourceanchorattr_user_is_sid') else False,
                       sourceanchorattr_group_is_sid = config.getboolean('common', 'sourceanchorattr_group_is_sid') if config.has_option('common', 'sourceanchorattr_group_is_sid') else False,
                       use_novell_get_universal_password = config.getboolean('common', 'use_novell_get_universal_password') if config.has_option('common', 'use_novell_get_universal_password') else False,
                       )



    smb.dry_run = dry_run

    if azure.use_cache:
        azure.connect()

    if not AzureObject.table_exists():
        # enable ad sync
        write_log_json_data('enable_ad_sync',{"EnableDirSync":True})
        azure.enable_ad_sync()

        # enable password hash sync
        write_log_json_data('enable_password_hash_sync',{"PasswordHashSync":True})
        azure.enable_password_hash_sync()

    if not AzureObject.table_exists():
        db.create_tables([AzureObject])


    smb.generate_all_dict()

    if config.getboolean('common', 'do_delete'):
        
        if from_db:
            for u in AzureObject.select(AzureObject.sourceanchor,AzureObject.last_data_send).where(AzureObject.object_type=='user'):
                azure.dict_az_user[u.sourceanchor] = u.last_data_send
        else:
            azure.generate_all_dict()

        # Delete user in azure and not found in samba
        for user in azure.dict_az_user:
            if not user in smb.dict_all_users_samba:
                write_log_json_data('delete',azure.dict_az_user[user])
                try:
                    azure.delete_user(user)
                except:
                    write_log_json_data('error',{'sourceanchor':user,'action':'delete_user','traceback':traceback.format_exc()})
                    continue
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==user,AzureObject.object_type=='user').execute()

        # Delete group in azure and not found in ldap 
        if (not use_get_syncobjects) or from_db:
            for g in AzureObject.select(AzureObject.sourceanchor,AzureObject.last_data_send).where(AzureObject.object_type=='group'):
                azure.dict_az_group[g.sourceanchor] = g.last_data_send

        # Delete group in azure and not found in samba
        for group in azure.dict_az_group:
            if not group in smb.dict_all_group_samba:
                write_log_json_data('delete',azure.dict_az_group[group])
                try:
                    azure.delete_group(group)
                except:
                    write_log_json_data('error',{'sourceanchor':group,'action':'delete_group','traceback':traceback.format_exc()})
                    continue
                if not dry_run:
                    AzureObject.delete().where(AzureObject.sourceanchor==group,AzureObject.object_type=='group').execute()

    #create all user found samba
    for entry in smb.dict_all_users_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_users_samba[entry] :
            write_log_json_data('send',smb.dict_all_users_samba[entry])
            try:
                azure.send_obj_to_az(smb.dict_all_users_samba[entry])
            except:
                write_log_json_data('error',{'sourceanchor':entry,'action':'send_user','traceback':traceback.format_exc()})
                continue 
            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='user',last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_users_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()



    for entry in smb.dict_all_group_samba:
        last_data =  AzureObject.select(AzureObject.last_data_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='group').first()
        if force or (not last_data) or json.loads(last_data.last_data_send) != smb.dict_all_group_samba[entry] :
            write_log_json_data('send',smb.dict_all_group_samba[entry])
            try:
                azure.send_obj_to_az(smb.dict_all_group_samba[entry])
            except:
                write_log_json_data('error',{'sourceanchor':entry,'action':'send_group','traceback':traceback.format_exc()})
                continue
            if not dry_run:
                if not last_data:
                    AzureObject.insert(sourceanchor=entry,object_type='group',last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).execute()
                else:
                    AzureObject.update(last_data_send =json.dumps(smb.dict_all_group_samba[entry]),last_data_send_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()




    #send all_password
    if hash_synchronization:
        for entry in smb.dict_id_hash :
            if len(smb.dict_id_hash[entry]) != 32:
                continue
            sha2password= hash_for_data(smb.dict_id_hash[entry])
            last_data =  AzureObject.select(AzureObject.last_sha256_hashnt_send).where(AzureObject.sourceanchor==entry,AzureObject.object_type=='user').first()
            if force or (not last_data) or last_data.last_sha256_hashnt_send != sha2password :
                write_log_json_data('send_nthash',{'SourceAnchor':entry,'onPremisesSamAccountName':smb.dict_all_users_samba[entry]['onPremisesSamAccountName'],'nthash':'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'})

                # Microsoft is very slow between sending the account and sending the password
                try:
                    azure.send_hashnt(smb.dict_id_hash[entry],entry)
                except Exception as e:
                    if "Result" in str(e):
                        print('Fail, we may be a little too fast for microsoft, we will wait and try again ...' )
                        time.sleep(30)
                        try:
                            azure.send_hashnt(smb.dict_id_hash[entry],entry)
                        except:
                            write_log_json_data('error',{'sourceanchor':entry,'action':'send_hashnt','traceback':traceback.format_exc()})
                            continue
                    else:
                        write_log_json_data('error',{'sourceanchor':entry,'action':'send_hashnt','traceback':traceback.format_exc()})
                        continue

                if not dry_run:
                    AzureObject.update(last_sha256_hashnt_send = sha2password,last_send_hashnt_date = datetime.datetime.now()).where(AzureObject.sourceanchor==entry).execute()

if __name__ == '__main__':
    while True:
        try:
            run_sync(force=args.force,from_db=calculate_deletions_based_on_last_sync)
        except:
            write_log_json_data("error",traceback.format_exc())
            if not args.servicemode :
                raise
        if not args.servicemode :
            break
        calculate_deletions_based_on_last_sync = True
        time.sleep(synchronization_interval_service)


db.close()
