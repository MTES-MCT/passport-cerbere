/*!
 * Cerbere client based on CAS 2.0 /SAML 1.1 protocols
 */

/**
 * Module dependencies
 */

var https = require("https");
var url = require("url");
var util = require('util');
var fxp = require("fast-xml-parser");
var uuid = require("node-uuid");

/**
 * Initialize Cerbere client with the given `options`.
 *
 * @param {Object} options
 *     {
 *       'url':
 *           The full URL to the Cerbere CAS server, including the base path.
 *     }
 * @api public
 */
var Cerbere = (module.exports = function Cerbere(options) {
  options = options || {};

  if (!options.url) {
    throw new Error("Required Cerbere option `url` missing.");
  }

  this.cerbere_url = url.parse(options.url);
  if (this.cerbere_url.protocol != "https:") {
    throw new Error("Cerbere url supports only https protocol.");
  }
  if (!this.cerbere_url.hostname) {
    throw new Error(
      "Option `url` must be a valid url like: https://authentification.din.developpement-durable.gouv.fr/cas/public"
    );
  }
  this.base_path = this.cerbere_url.pathname;
});

/**
 * Attempt to validate a given ticket with the Cerbere (CAS 2.0 / SAML 1.1) server.
 * `callback` is called with (err, auth_status, username, extended)
 *
 * @param {String} ticket
 *     A service ticket (ST)
 * @param {Function} callback
 *     callback(err, auth_status, username, extended).
 *     `extended` is an object containing:
 *       - username
 *       - attributes
 *       - ticket
 * @param {String} service
 *     The URL of the service requesting authentication. Optional if
 *     the `service` option was already specified during initialization.
 * @api public
 */
Cerbere.prototype.validate = function(ticket, service, callback) {
  // CAS 2.0 with SAML 1.1 to get attributes
  var validate_path = "/samlValidate";

  var query = { TARGET: service };

  var queryPath = url.format({
    pathname: this.base_path + validate_path,
    query: query
  });

  var headers = {};
  var soapEnvelope = util.format(
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s"><samlp:AssertionArtifact>%s</samlp:AssertionArtifact></samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>',
    uuid.v4(),
    new Date().toISOString(),
    ticket
  );
  var method = "POST";
  var headers = {
    soapaction: "http://www.oasis-open.org/committees/security",
    "content-type": "text/xml; charset=utf-8",
    accept: "text/xml",
    connection: "keep-alive",
    "cache-control": "no-cache",
    pragma: "no-cache"
  };
  var req = https.request(
    {
      host: this.cerbere_url.hostname,
      port: this.cerbere_url.port,
      path: queryPath,
      method: method,
      headers: headers
    },
    function(res) {
      // Handle server errors
      res.on("error", function(e) {
        callback(e);
      });

      // Read result
      res.setEncoding("utf8");
      var response = "";
      res.on("data", function(chunk) {
        response += chunk;
        if (response.length > 1e6) {
          req.connection.destroy();
        }
      });

      res.on("end", function() {
        // CAS 2.0 / SAML 1.1 (XML response, and extended attributes)
        var jsonResponse = {};
        try{
          jsonResponse = fxp.parse(response, {ignoreAttributes : false, ignoreNameSpace : true, parseAttributeValue : false}, true);
        }catch(error){
          callback(error, false);
          console.error(error);
          return;
        }

        // Check for auth success
        var elemResponse = jsonResponse['Envelope']['Body']['Response'];
        var elemStatusCode = elemResponse['Status']['StatusCode'];
        if (['ns2:Success'].includes(elemStatusCode['@_Value'])) {
          var elemAttributeStatement = elemResponse['Assertion'][0]['AttributeStatement'];
          var userId = elemAttributeStatement['Subject']['NameIdentifier']['#text'];
          if (!userId) {
            //  This should never happen
            callback(new Error("No userId?"), false);
            return;
          }

          // Look for optional attributes
          var attributes = parseAttributes(elemAttributeStatement['Attribute']);

          callback(undefined, true, userId, {
            username: userId,
            attributes: attributes,
            ticket: ticket
          });
          return;
        } else {
          var code = elemStatusCode['@_Value'];
          var message = "Validation failed [" + code + "]: ";
          message += elemStatusCode['#text'];
          callback(new Error(message), false);
          return;
        }
      });
    }
  );

  // Connection error with the Cerbere server
  req.on("error", function(err) {
    callback(err);
    req.abort();
  });
  req.write(soapEnvelope);
  req.end();
};

/**
 * Log the user out of their Cerbere session. The user will be redirected to
 * the Cerbere server for this.
 *
 * @param {Object} req
 *     HTTP request object
 * @param {Object} res
 *     HTTP response object
 * @param {String} returnUrl
 *     (optional) The URL that the user will return to after logging out.
 * @param {Boolean} doRedirect
 *     (optional) Set this to TRUE to have the Cerbere CAS server redirect the user 
 *      automatically. Default is for the Cerbere CAS server to only provide a 
 *      hyperlink to be clicked on.
 * @api public
 */
Cerbere.prototype.logout = function(req, res, returnUrl, doRedirect)
{
    var logout_path;
    if (returnUrl && doRedirect) {
        // Logout with auto redirect
        logout_path = '/logout?service=' + encodeURIComponent(returnUrl);
    } else if (returnUrl) {
        // Logout and provide a hyperlink back
        logout_path = '/logout?url=' + encodeURIComponent(returnUrl);
    } else {
        // Logout with no way back
        logout_path = '/logout';
    }
    
    var redirectURL = this.cerbere_url.href + logout_path;
    res.writeHead(307, {'Location' : redirectURL});
    res.write('<a href="' + redirectURL + '">CAS logout</a>');
    res.end();
}

/**
 * Parse a Cerbere (JSONed SOAP response) attributes JSON object.
 *
 * @param {Object} elemAttributes
 *     JSON Attributes object
 * @return {Object}
 *     {
 *         AttributeName: [ AttributeValue ],
 *         ...
 *     }
 */
var parseAttributes = function(elemAttributes) {
  var attributes = {};
  for (var i = 0; i < elemAttributes.length; i++) {
    var elemAttribute = elemAttributes[i];
    if (elemAttribute.hasOwnProperty('@_AttributeName')){
      attributes[elemAttribute['@_AttributeName']] = elemAttribute['AttributeValue']['#text'];
    }
  }
  return attributes;
};