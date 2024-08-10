Install notes
==============

If you are using samba 4 see : https://github.com/sfonteneau/AzureADConnect_Samba4

```
apt-get install git
cd /tmp
git clone https://github.com/sfonteneau/AzureADConnect_Ldap.git
mv AzureADConnect_Ldap /opt/sync-azure
cd /opt/sync-azure/
git submodule update --progress --init -- "AADInternals_python"
cd /opt/sync-azure/AADInternals_python
git submodule update --progress --init -- "python_wcfbin"
mkdir /etc/azureconf/
cd /opt/sync-azure
cp -f azure.conf.exemple /etc/azureconf/azure.conf
cp -f mapping.json.exemple /etc/azureconf/mapping.json
apt-get install python3-peewee python3-passlib python3-xmltodict python3-requests python3-azure python3-ldap3 -y
```


If you are not under debian or if you do not have the packages available :

```
apt-get install python3-pip
pip3 install -r /opt/sync-azure/requirements.txt
pip3 install -r /opt/sync-azure/AADInternals_python/requirements.txt
```

 - Configure /etc/azureconf/azure.conf
   
You can try like this:

python3 /opt/sync-azure/run_sync.py

The script sends all users and groups a first time and then only sends what has been modified since the last send during the next launch.

Warning
========

* Please note that this project uses Microsoft APIs not officially documented. Microsoft may break compatibility at any time

* mail is used for the email address

* "password writeback" not supported

* User and group management only




configuration
========================

LDAP connection settings
-------------------------------

| Params                  | Value exemple              | Description                                                                                                                                                                                          |
| ----------------------- | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| server_ldap             | 192.168.154.172            | Name or ip or the complete url in the scheme://hostname:hostport format of the server (required) - port and scheme (ldap or ldaps) defined here have precedence over the parameters port and use_ssl |
| port_ldap               | 389                        | The port where the DSA server is listening (defaults to 389, for a cleartext connection, 636 for a secured connection)                                                                               |
| use_ssl_ldap            | False                      | Specifies if the connection is on a secure port (defaults to False). When True the secure port is usually set to 636                                                                                 |
| verify_cert_ldap        | False                      | Defined if the ldap ssl/tls connection should be verified and validated                                                                                                                              |
| path_to_bundle_crt_ldap | /root/ldap.crt             | If verify_cert_ldap is True then you must define a certificate bundle path with which the connection will be verified, "lib_python_certifi" indicates to check with the "certifi" library            |     
| user_ldap               | cn=admin,dc=demo,dc=lan    | login for ldap connection                                                                                                                                                                            |
| password_ldap           | password                   | password for ldap connection                                                                                                                                                                         |
| basedn_user             | OU=USER,DC=DEMO,DC=LAN     | indicate several bases dn , separate them with \|                                                                                                                                                    |                            
| basedn_group            | OU=GROUP,DC=DEMO,DC=LAN    | indicate several bases dn , separate them with \|                                                                                                                                                    |     
| filter_user             | (objectClass=posixAccount) | Specifies the ldap filter to use to find users                                                                                                                                                       |
| filter_group            | (objectClass=posixGroup)   | Specifies the ldap filter to use to find groups                                                                                                                                                      |


Other settings
-------------------------------

| Params                  | Value exemple                        | Description                                                                                                                   |
| ----------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------|
| do_delete               | True                                 | defined if objects found online on Azure and not present locally must be deleted.                                             |
| hash_synchronization    | True                                 | hash_synchronization set whether passwords should be synchronized.                                                            |
| dry_run                 | True                                 | he script will display the actions but will not perform the action                                                            |
| dbpath                  | /root/last_send_azuread.db           | the last data sent is stored there.                                                                                           |
| proxy                   | 192.168.1.2:3128                     | define the proxy to use                                                                                                       |
| tenant_id               | 6121018c-f311-9999-9999-ec17bba6e422 | indicate the tenant_id here                                                                                                   |
| credential_cache_file   | /root/last_token_azuread.json        | indicates the path to the credentials cache                                                                                   |

sourceanchor
-----------------------------

The default sourceanchor for user and group in azure.conf.exemple is sambaSID

If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes

You can indicate that the attribute you have chosen is a "sid" with the parameter "sourceanchorattr_user_is_sid" and "sourceanchorattr_group_is_sid" for conform to how Azure Ad Connect windows works (base64 encoding of a binary attribute, sid is binary)

see: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts#selecting-a-good-sourceanchor-attribute

password
-------------------------------------

The password sent to azure ad is an "NTLM hash", if you are using an openldap with samba3 schema then that hash is the sambaNTPassword, configure it with "hashnt" in the mapping.json file.

As far as I know , there is currently no other type of hash supported by microsoft, the other alternative is the plaintext password...

Novell :

Using use_novell_get_universal_password allows you to use ldap3's get_universal_password function with novell. With this operation the password is recovered in plain text and then converted to hashing automatically.
