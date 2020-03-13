/*!
 * Cerbere client based on CAS 2.0 /SAML 1.1 protocols
 */

/**
 * Module dependencies
 */

var https = require("https");
var url = require("url");
var util = require('util');
var cheerio = require("cheerio");
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

Cerbere.prototype.redirect = function(res, service) {
  var redirectURL =
      this.cerbere_url.href + "/login?service=" + encodeURIComponent(service);
    res.writeHead(307, { Location: redirectURL });
    res.write('<a href="' + redirectURL + '">CAS login</a>');
    res.end();
}

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
    pathname: this.base_path + "/" + validate_path,
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
      host: this.cerbereURL.hostname,
      port: this.cerbereURL.port,
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
        // Use cheerio to parse the XML repsonse.
        var $ = cheerio.load(response);

        // Check for auth success
        var elemSuccess = $("cas\\:authenticationSuccess").first();
        if (elemSuccess && elemSuccess.length > 0) {
          var elemUser = elemSuccess.find("cas\\:user").first();
          if (!elemUser || elemUser.length < 1) {
            //  This should never happen
            callback(new Error("No username?"), false);
            return;
          }

          // Got username
          var username = elemUser.text();

          // Look for optional attributes
          var attributes = parseAttributes(elemSuccess);

          callback(undefined, true, username, {
            username: username,
            attributes: attributes,
            ticket: ticket
          });
          return;
        } // end if auth success

        // Check for correctly formatted auth failure message
        var elemFailure = $("cas\\:authenticationFailure").first();
        if (elemFailure && elemFailure.length > 0) {
          var code = elemFailure.attr("code");
          var message = "Validation failed [" + code + "]: ";
          message += elemFailure.text();
          callback(new Error(message), false);
          return;
        }

        // The response was not in any expected format, error
        callback(new Error("Bad response format."));
        console.error(response);
        return;
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
 * Parse a cas:authenticationSuccess XML node for CAS attributes.
 * Supports Jasig style, RubyCAS style, and Name-Value.
 *
 * @param {Object} elemSuccess
 *     DOM node
 * @return {Object}
 *     {
 *         attr1: [ attr1-val1, attr1-val2, ... ],
 *         attr2: [ attr2-val1, attr2-val2, ... ],
 *         ...
 *     }
 */
var parseAttributes = function(elemSuccess) {
  var attributes = {};
  var elemAttribute = elemSuccess.find("cas\\:attributes").first();
  if (elemAttribute && elemAttribute.children().length > 0) {
    // "Jasig Style" Attributes:
    //
    //  <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    //      <cas:authenticationSuccess>
    //          <cas:user>jsmith</cas:user>
    //          <cas:attributes>
    //              <cas:attraStyle>RubyCAS</cas:attraStyle>
    //              <cas:surname>Smith</cas:surname>
    //              <cas:givenName>John</cas:givenName>
    //              <cas:memberOf>CN=Staff,OU=Groups,DC=example,DC=edu</cas:memberOf>
    //              <cas:memberOf>CN=Spanish Department,OU=Departments,...</cas:memberOf>
    //          </cas:attributes>
    //          <cas:proxyGrantingTicket>PGTIOU-84678-8a9d2...</cas:proxyGrantingTicket>
    //      </cas:authenticationSuccess>
    //  </cas:serviceResponse>
    //
    for (var i = 0; i < elemAttribute.children().length; i++) {
      var node = elemAttribute.children()[i];
      var attrName = node.name.toLowerCase().replace(/cas:/, "");
      if (attrName != "#text") {
        var attrValue = cheerio(node).text();
        if (!attributes[attrName]) {
          attributes[attrName] = [attrValue];
        } else {
          attributes[attrName].push(attrValue);
        }
      }
    }
  }

  return attributes;
};