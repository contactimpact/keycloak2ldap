const nconf         = require('nconf'),
      ldap = require('ldapjs'),
      request = require('request'),
      Oauth2 = require('simple-oauth2');

nconf
  .argv()
  .env();

if (nconf.get('config')) {
  // Overwrite config from file
  nconf.file({
    file: nconf.get('config')
  });
}

nconf.defaults({
  port: 1389,
  log: {
    name: 'keycloak2ldap',
    level: 'error'
  },
  usersDn: 'ou=users, o=company, dc=group, dc=de',
  servicesDn: 'ou=services, o=company, dc=group, dc=de',
  binds: [
    { // add services using this ldap here
      bindDn: 'userid=servicename, ou=services, o=contactimpact, dc=abiligroup, dc=de',
      bindPassword: 'servicepassword'
    }
  ],
  keycloak: {
    client: {
      id: 'ldap',
      secret: 'keycloak-client-secret'
    },
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
});

const oauth2 = Oauth2.create(nconf.get('keycloak'));

oauth2.ownerPassword.getToken(nconf.get('apiUser'), (error, result) => {
  if (error) {
    return console.log('Access Token Error', error.message);
  }
  var accessToken = oauth2.accessToken.create(result);
  var getUsersRequest = {
    method: 'GET',
    uri: 'https://sso.df-srv.de/auth/admin/realms/master/users',
//    uri: 'https://sso.df-srv.de/auth/admin/realms/master/users/'+userId+'/role-mappings/clients/57bbe8df-8f70-4596-b007-e6615bd9aaad/composite',
    json: true,
    auth: {
      bearer: accessToken.token.access_token
    }
  };

  const refreshToken = function(req, res, next) {
    if (accessToken.expired()) {
      accessToken.refresh((error, result) => {
        accessToken = result;
        return next();
      });
    } else {
      return next();
    }
  };

  const getUsers = function(req, res, next) {
    req.users = {};
    request(getUsersRequest, function(error, response, body) {
      body.forEach(function(user, id) {
        if (user.enabled) {
          var ldapUser = {
            dn: 'cn='+user.username+', ' + nconf.get('usersDn'),
            attributes: {
              cn: user.username,
              uid: user.id,
              gid: 1,
              description: user.username + ' federated from keycloak',
              surName: user.lastName,
              givenName: user.firstName,
              email: user.email,
              objectclass: 'ldapUser'
            }
          };
          req.users[user.username] = ldapUser;
        }
      });
      return next();
    });
  }

  var server = ldap.createServer();
  
  var binds = nconf.get('binds');
  
  server.bind(nconf.get('servicesDn'), function(req, res, next) {
    var bind = binds.filter(function(b) { return b.bindDn === req.dn.toString(); });
    if (!bind || !bind.length || bind[0].bindPassword !== req.credentials)
      return next(new ldap.InvalidCredentialsError());

    res.end();
    return next();
  });
  
  server.bind(nconf.get('usersDn'), function(req, res, next) {
    var cnContainer = req.dn.rdns.filter(function(dn) { return dn.attrs && dn.attrs.cn });
    if (cnContainer.length) var cn = cnContainer[0].attrs.cn.value;
    if (cn && req.credentials) {
      oauth2.ownerPassword.getToken({
        username: cn,
        password: req.credentials
      }, (error, result) => {
        if (error) {
          console.log('Access Token Error', error.message);
          return next(new ldap.InvalidCredentialsError());
        }
        res.end();
      });
    } else {
      return next(new ldap.InvalidCredentialsError()); 
    }
  });

  server.search(nconf.get('usersDn'), getUsers, function(req, res, next) {
    Object.keys(req.users).forEach(function(k) {
      if (req.filter.matches(req.users[k].attributes)) {
        res.send(req.users[k]);
      }
    });
    res.end();
    return next();
  });
  
  server.listen(nconf.get('port'), '0.0.0.0', function() {
    console.log('LDAP server up at: %s', server.url);
  });
});