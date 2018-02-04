# keycloak2ldap

This is a simple proxy meant to connect tools with ldap support to keyclaok.

## Requirements

- ldap client in keycloak with "Direct Access Grnts Enabled"
- ldap-api user in keycloak with "View Users" rights in your realm

## Use with Docker

1. create config.json 
2. `docker build -t keycloak2ldap .`
3. `docker run -it --name keycloak2ldap -e config=usr/config.json -v usr:/usr/src/app/usr keycloak2ldap`
