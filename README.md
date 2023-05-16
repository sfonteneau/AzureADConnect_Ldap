Install notes
==============

If you are using samba 4 see : https://github.com/sfonteneau/AzureADConnect_Samba4

 - apt-get install python3-pip git
 - cd /tmp
 - git https://github.com/sfonteneau/AzureADConnect_Ldap.git
 - mv AzureADConnect_Ldap /opt/sync-azure
 - cd /opt/sync-azure/
 - pip3 install -r requirements.txt
 - git submodule update --progress --init -- "AADInternals_python"
 - cd /opt/sync-azure/AADInternals_python
 - pip3 install -r requirements.txt
 - git submodule update --progress --init -- "python_wcfbin"
 - mkdir /etc/azureconf/
 - cd /opt/sync-azure
 - cp -f azure.conf.exemple /etc/azureconf/azure.conf
 - cp -f mapping.json.exemple /etc/azureconf/mapping.json
 - Configure /etc/azureconf/azure.conf
 - Edit /etc/azureconf/mapping.json if need

You can try like this:

python3 /opt/sync-azure/run_sync.py

The script sends all users and groups a first time and then only sends what has been modified since the last send during the next launch.

Warning
========

* Please note that this project uses Microsoft APIs not officially documented. Microsoft may break compatibility at any time

* The script does not support 2FA authentication for the "mailadmin" account indicated in the conf file

* mail is used for the email address

* "password writeback" not supported

* User and group management only


sourceanchor
=============

The default sourceanchor for user and group in azure.conf.exemple is the uidNumber/guidNumber

If "sourceanchor" changes, it will initiate object deletions and then object recreations. You must therefore choose your sourceanchor well and not change it

A dry_run mode allows you to run the script without making any changes
