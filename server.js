const nconf         = require('nconf'),
  _ = require('lodash'),
  ldap = require('ldapjs'),
  request = require('request'),
  bunyan = require('bunyan'),
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
});

const log = bunyan.createLogger(nconf.get('log'));

const clients = {
};

const authorize = function(req, res, next) {
  log.debug('authorize', req.connection.ldap.bindDN.toString(), req.connection.ldap.bindPassword);
  var cnContainer = req.connection.ldap.bindDN.rdns.filter(function(dn) {
    return dn.attrs && dn.attrs.cn;
  });
  if (cnContainer.length) {
    var clientId = cnContainer[0].attrs.cn.value;
  }
  log.debug('authorize', 'clientId', clientId);
  if (!clients || !clients[clientId]) {
    return next(new ldap.InsufficientAccessRightsError());
  }
  req.client = clients[clientId];
  // if (req.client.secret !== req.connection.ldap.bindPassword) {
  //   return next(new ldap.InsufficientAccessRightsError());
  // }
  return next();
};

const refreshToken = function (req, res, next) {
  log.debug('refreshToken', req.client.id);
  if (req.client.accessToken.expired()) {
    req.client.accessToken.refresh((error, result) => {
      req.client.accessToken = result;
      return next();
    });
  } else {
    return next();
  }
};

var getUsersRequest = {
  method: 'GET',
  uri: nconf.get('keycloak:auth:tokenHost') + '/auth/admin/realms/master/users',
  //    uri: 'https://sso.df-srv.de/auth/admin/realms/master/users/'+userId+'/role-mappings/clients/57bbe8df-8f70-4596-b007-e6615bd9aaad/composite',
  json: true,
  auth: {
    bearer: ''
  }
};

const getUsers = function (req, res, next) {
  log.debug('getUsers', req.client.id);
  req.users = {
  };
  var getUsersRequestCopy = _.cloneDeep(getUsersRequest);
  getUsersRequestCopy.auth.bearer = req.client.accessToken.token.access_token;
  request(getUsersRequestCopy, function (error, response, body) {
    if (error) {
      log.error('getUsers', req.client.id, error);
      return next(new ldap.BusyError());
    }
    body.forEach(function (user) {
      if (user.enabled) {
        var ldapUser = {
          dn: 'cn=' + user.username + ', ' + nconf.get('usersDn'),
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
};

var pre = [authorize, refreshToken];

var server = ldap.createServer();

server.bind(nconf.get('servicesDn'), function(req, res, next) {
  log.info('bindService', req.dn.toString());
  var cnContainer = req.dn.rdns.filter(function(dn) {
    return dn.attrs && dn.attrs.cn;
  });
  if (cnContainer.length) {
    var clientId = cnContainer[0].attrs.cn.value;
  }
  if (clientId && req.credentials) {
    if (clients[clientId] && clients[clientId].secret === req.credentials) {
      // serivice is correct and already authed
      res.end();
      return next();
    } else {
      var client = {
        id: clientId,
        secret: req.credentials
      };
      var oauthSettings = nconf.get('keycloak');
      oauthSettings.client = client;
      var oauth2 = Oauth2.create(oauthSettings);
      oauth2.ownerPassword.getToken(nconf.get('apiUser'), (error, result) => {
        if (error) {
          return next(new ldap.InvalidCredentialsError());
        }
        clients[clientId] = {
          clientId: clientId,
          secret: req.credentials,
          accessToken: oauth2.accessToken.create(result),
          oauth2: oauth2
        };
        res.end();
        return next();
      });
    }
  } else {
    return next(new ldap.InvalidCredentialsError());
  }
});

server.bind(nconf.get('usersDn'), pre, function(req, res, next) {
  log.info('bindUser', req.client.id, req.dn.toString());
  var cnContainer = req.dn.rdns.filter(function(dn) {
    return dn.attrs && dn.attrs.cn;
  });
  if (cnContainer.length) {
    var cn = cnContainer[0].attrs.cn.value;
  }
  if (cn && req.credentials) {
    req.cient.oauth2.ownerPassword.getToken({
      username: cn,
      password: req.credentials
    }, (error) => {
      if (error) {
        return next(new ldap.InvalidCredentialsError());
      }
      res.end();
    });
  } else {
    return next(new ldap.InvalidCredentialsError());
  }
});

server.search(nconf.get('usersDn'), pre, getUsers, function(req, res, next) {
  log.info('search', req.client.id, req.attributes);
  Object.keys(req.users).forEach(function(k) {
    if (req.filter.matches(req.users[k].attributes)) {
      res.send(req.users[k]);
    }
  });
  res.end();
  return next();
});

server.listen(nconf.get('port'), '0.0.0.0', function() {
  log.info('LDAP server up at: %s', server.url);
});