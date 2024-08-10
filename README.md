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

sourceanchor
-----------------------------

The default sourceanchor for user and group in azure.conf.exemple is sambaSID

If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes

You can indicate that the attribute you have chosen is a "sid" with the parameter "sourceanchorattr_user_is_sid" and "sourceanchorattr_group_is_sid" for conform to how Azure Ad Connect windows works (base64 encoding of a binary attribute, sid is binary)

see: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts#selecting-a-good-sourceanchor-attribute

using specific basedn
-----------------------------

You must specify a specific base DN for each object type:

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN
basedn_group    = OU=GROUP,DC=MYDOMAIN,DC=LAN
```

For precisely several bases dn, separate them with | 

```
basedn_user     = OU=USER,DC=MYDOMAIN,DC=LAN|OU=USER2,DC=MYDOMAIN,DC=LAN
```

filter for search
-----------------------------

You can specify a specific custom ldap filter for search in ldap:

```
filter_user             = (objectClass=posixAccount)
filter_group            = (objectClass=posixGroup)
```


password
-------------------------------------

The password sent to azure ad is an "NTLM hash", if you are using an openldap with samba3 schema then that hash is the sambaNTPassword

As far as I know , there is currently no other type of hash supported by microsoft, the other alternative is the plaintext password...

Novell
+++++++++++++++
Using use_novell_get_universal_password allows you to use ldap3's get_universal_password function with novell. With this operation the password is recovered in plain text and then converted to hashing automatically.
