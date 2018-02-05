# keycloak2ldap

This is a simple proxy meant to connect tools with ldap support to keyclaok.

## Usage

If your client id in keycloak is `sentry` your bindDN will be:

    cn=sentry, ou=services, o=company, dc=company, dc=de
    
The `bindPassword` is the clients secret key.

The searchDN will be:

    ou=users, o=company, dc=company, dc=de

## Config

    {
      port: 1389,
      log: {
        name: 'keycloak2ldap',
        level: 'info'
      },
      usersDn: 'ou=users, o=company, dc=group, dc=de',
      servicesDn: 'ou=services, o=company, dc=group, dc=de',
      keycloak: {
        auth: {
          tokenHost: 'http://keycloak-url',
          tokenPath: '/auth/realms/master/protocol/openid-connect/token',
          authorizePath: '/auth/realms/master/protocol/openid-connect/auth'
        }
      },
      apiUser: {
        username: 'ldap-api',
        password: 'ldap-api-user-password'
      }
    }
    
`apiUser` needs to be a keycloak user with the `View-Users` Role.

`keycloak:auth:tokenHost` needs to be the URL of your Keycloak instance.

## Use with Docker

1. `docker build -t keycloak2ldap .`
2. `docker run -it --name keycloak2ldap keycloak2ldap`

All configuration variables can be overwriten using env variables eg. `-e port=1234 -e log:level=debug`
