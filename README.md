# passport-cerbere

> [Passport](http://passportjs.org/) strategy utilisant le serveur d'authentification [Cerbere](https://authentification.din.developpement-durable.gouv.fr). Il supporte les protocoles CAS 2.0 et SAML 1.1.

## Installation

```shell
npm install passport-cerbere
```

## Configuration

```javascript
var CerbereStrategy = require('passport-cerbere').Strategy;
passport.use(new CerbereStrategy(
    url: 'https://authentification.din.developpement-durable.gouv.fr/cas/public',
        function(username, attributes, done) {
        User.findOne({ username: username, attributes: attributes }, function (err, user) {
            done(err, user);
        });
        }
    ));
```

`User.findOne` est une fonction à implémenter pour les besoins spécifiques.

## Usage

Voir [exemple](https://github.com/MTES-MCT/cerbere-nodejs)