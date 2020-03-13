/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , url = require('url')
  , Cerbere = require('./cerbere');


/**
 * `Strategy` constructor.
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
  this.url = options.url;
  if (!this.url) { throw new TypeError('CerbereStrategy requires an url option'); }
    
  passport.Strategy.call(this);
  this.name = 'cerbere';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;

  this.cerbere = new Cerbere({url: this.url});
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
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  
  var self = this;
  var reqURL = url.parse(this.url, true);

  // Try to extract the CAS ticket from the URL
  var ticket = reqURL.query["ticket"];
  delete reqURL.query["ticket"];
  var service = url.format({
    protocol: req.protocol || "http",
    host: req.headers["x-forwarded-host"] || req.headers["host"],
    pathname: reqURL.pathname,
    query: reqURL.query
  });
  if (!ticket) {
    self.redirect(self.url + '/login?service=' + encodeURIComponent(service), 307);
  } else {
    self.validate(ticket, service, function(err, status, username, extended) {
      
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
                .replace(/([?&])ticket=[\w.-]+/, '$1_cas_retry='+token);
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
          provider: 'CAS',
          id: extended.id || username,
          displayName: attributes.displayName || username,
          name: {
            familyName: null,
            givenName: null,
            middleName: null
          },
          emails: []
        };
        
        // Map relevant extended attributes returned by CAS into the profile
        for (var key in profile) {
          if (key == 'name') {
            for (var subKey in profile[key]) {
              var mappedKey = self.casPropertyMap[subKey] || subKey;
              var value = attributes[mappedKey];
              if (Array.isArray(value)) {
                profile.name[subKey] = value[0];
              } else {
                profile.name[subKey] = value;
              }
              delete attributes[mappedKey];
            }
          } 
          else if (key == 'emails') {
            var mappedKey = self.casPropertyMap.emails || 'emails';
            var emails = attributes[mappedKey];
            if (Array.isArray(emails)) {
              if (typeof emails[0] == 'object') {
                profile.emails = emails;
              }
              else {
                for (var i=0; i<emails.length; i++) {
                  profile.emails.push({
                    'value': emails[i],
                    'type': 'default'
                  });
                }
              }
            }
            else {
              profile.emails = [emails];
            }
            delete attributes[mappedKey];
          }
          else {
            var mappedKey = self.casPropertyMap[key] || key;
            var value = attributes[mappedKey];
            if (Array.isArray(value)) {
              profile[key] = value[0];
            } 
            else if (value) {
              profile[key] = value;
            }
            delete attributes[mappedKey];
          }
        }
        // Add remaining attributes to the profile object
        for (var key in attributes) {
          profile[key] = attributes[key];
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
 * Expose `Strategy`.
 */
module.exports = Strategy;