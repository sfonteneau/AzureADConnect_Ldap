# Changelog

## [2024-10-31]
- Remove password and mail for login azure, switch to lib msal

## [2024-08-09]
- Add params : calculate_deletions_based_on_last_sync in config file. (allows you not to retrieve the list of users and groups from Azure, thereby limiting the number of requests to Azure)
- Add params : synchronization_interval_service in config file. (allows in service mode to define the synchronization interval)
- Add params : use_get_syncobjects in config file. (allows you not to use get_syncobjects (necessary to retrieve the immutableid of the groups)
- Add args for run : --service-mode (allows you to launch the script in service mode)

## [2024-08-04]
- Add params : basedn_user,basedn_group, filter_user and filter_group in config file.
- Add args for run : --conf, --force, --dryrun, --logfile
- Improve log (json format)
- Add use_novell_get_universal_password params in conf (not testing), 

## [2024-07-31]
- toggle from uidnumber/guidnumber to sambaSID in the example. 
  Added sourceanchorattr_user_is_sid and sourceanchorattr_group_is_sid parameters to conform to how Azure Ad Connect Windows works (base64 encoding of a binary attribute, sid is binary)
  old uidnumber/gidnumber mode is still available

## [2024-05-15]
- FIX "expireOn" delta calculation, this would generate an expired token error. "expireOn" is not in UTC...

## [2023-07-06]
- Multi-factor authentication support. 
  Use the old token to regenerate a new token. The tenant id is now required in conf file
  For the first run an external authentication and a copy paste will be necessary
- New available option in conf file : tenant_id, save_to_cache, use_cache , credential_cache_file

## [2023-05-18]
- Add tls connection options for ldap connection

## [2023-05-17]
- First Commit


