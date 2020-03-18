/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , url = require('url')
  , Cerbere = require('cerbere');


/**
 * `CerbereStrategy` constructor.
 *
 * The Cerbere authentication strategy authenticates requests based on the
 * CAS 2.0 / SAML 1.1 protocols.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `attributes`, and then calls the `done` callback supplying a
 * `user`.
 * If an exception occurred, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `casURL` is Cerbere CAS 2.0 server url
 *   - `serviceURL` is the callback url to redirect to
 *   - `propertyMap` is the Cerbere SAML 1.1 attributes mapping
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new CerbereStrategy(
 *       function(username, attributes, done) {
 *         User.findOne({ username: username, attributes: attributes }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('CerbereStrategy requires a verify callback'); }
  this.url = options.casURL;
  if (!this.url) { throw new TypeError('CerbereStrategy requires a casURL option'); }
  this.service = options.serviceURL;
  if (!this.service) { throw new TypeError('CerbereStrategy requires a serviceURL option'); }

  passport.Strategy.call(this);
  this.name = 'cerbere';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
  this.propertyMap = options.propertyMap;

  this.cerbere = new Cerbere({ url: this.url });
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function (req, options) {
  options = options || {};

  var self = this;
  var reqURL = url.parse(req.originalUrl || req.url, true);

  // Try to extract the CAS ticket from the URL
  var ticket = reqURL.query["ticket"];
  delete reqURL.query["ticket"];
  var service = service = url.format({
    protocol: req.headers['x-forwarded-proto'] || req.headers['x-proxied-protocol'] || req.protocol || 'http',
    host: req.headers['x-forwarded-host'] || req.headers.host || reqURL.host,
    pathname: req.headers['x-proxied-request-uri'] || reqURL.pathname
    // query: reqURL.query
  });
  if (!ticket) {
    self.redirect(self.url + '/login?service=' + encodeURIComponent(service), 307);
  } else {
    self.cerbere.validate(ticket, service, function (err, status, username, extended) {

      // Ticket validation failed
      if (err) {
        var date = new Date();
        var token = Math.round(date.getTime() / 60000);
        if (req.query['_cas_retry'] != token) {
          // There was a CAS error. A common cause is when an old
          // `ticket` portion of the querystring remains after the
          // session times out and the user refreshes the page.
          // So remove the `ticket` and try again.
          var url = (req.originalUrl || req.url)
            .replace(/_cas_retry=\d+&?/, '')
            .replace(/([?&])ticket=[\w.-]+/, '$1_cas_retry=' + token);
          self.redirect(url, 307);
        } else {
          // Already retried. There is no way to recover from this.
          self.fail(err);
        }
      }

      // Validation successful
      else {
        // The provided `verify` callback will call this on completion
        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }

        var attributes = extended.attributes;
        var profile = {
          provider: 'Cerbere',
          id: attributes.id || username,
          name: {
            civilite: null,
            familyName: null,
            givenName: null,
            middleName: null
          },
          emails: [],
          telephones: [],
          adresses: [],
          organizations: []
        };

        // Map relevant extended attributes returned by Cerbere into the default profile
        for (var key in profile) {
          if (['name'].includes(key)) {
            for (var nameKey in self.propertyMap[key]) {
              profile.name[nameKey] = attributes[self.propertyMap.name[nameKey]];
              delete attributes[nameKey];
            }
            profile.name['displayName'] = profile.name['civilite'] + ' ' + profile.name['givenName'] + ' ' + profile.name['familyName']
          } else if (['emails'].includes(key)) {
            self.propertyMap.emails.forEach(function (email) {
              profile.emails.push({
                'value': attributes[email.key],
                'type': email.type
              });
              delete attributes[email.key];
            });
          } else if (['telephones'].includes(key)) {
            self.propertyMap.telephones.forEach(function (telephone) {
              profile.telephones.push({
                'value': attributes[telephone.key],
                'type': telephone.type
              });
              delete attributes[telephone.type];
            });
          } else if (['adresses'].includes(key)) {
            self.propertyMap.adresses.forEach(function (adresse) {
              profile.adresses.push({
                'street': attributes[adresse.key.street], 
                'town': attributes[adresse.key.town], 
                'streetcode': attributes[adresse.key.streetcode], 
                'country': attributes[adresse.key.country],
                'type': adresse.type
              });
            });
          } else if (['organizations'].includes(key)) {
              self.propertyMap.organizations.forEach(function (organization) {
                profile.organizations.push({
                  'code': attributes[organization.key.code],
                  'name': attributes[organization.key.name],
                  'type': organization.type
                });
              });
          } else {
            if (self.propertyMap.hasOwnProperty(key)) {
              if (Array.isArray(self.propertyMap[key])) {
                for (var subKey in self.propertyMap[key]) {
                  if (attributes.hasOwnProperty(self.propertyMap[key])) {
                    profile[subKey] = attributes[self.propertyMap[key]];
                  }
                }
              } else {
                profile[key] = attributes[self.propertyMap[key]];
              }
            }
          }
        }
        // Add additional properties not defined in default profile
        for (var property in self.propertyMap) {
          if (!profile.hasOwnProperty(property)) {
            profile[property] = attributes[self.propertyMap[property]];
          }
        }

        if (self._passReqToCallback) {
          self._verify(req, username, profile, verified);
        } else {
          self._verify(username, profile, verified);
        }
      }
    });
  }
};

/**
 * Log the user out of the application site, and also out of Cerbere.
 *
 * @param (Object) req
 * @param (Object) res
 * @param {String} returnUrl
 * @api public
 */
Strategy.prototype.logout = function (req, res, returnUrl) {
  req.logout();
  var self = this;
  if (returnUrl) {
    self.cerbere.logout(req, res, returnUrl, true);
  } else {
    self.cerbere.logout(req, res);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;