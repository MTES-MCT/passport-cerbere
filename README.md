# passport-cerbere

> [Passport](http://passportjs.org/) strategy utilisant le serveur d'authentification [Cerbere](https://authentification.din.developpement-durable.gouv.fr). Il supporte les protocoles CAS 2.0 et SAML 1.1.

![Build](https://github.com/MTES-MCT/passport-cerbere/workflows/Build/badge.svg)
![Publish](https://github.com/MTES-MCT/passport-cerbere/workflows/Publish/badge.svg?event=release)
[![npm version](https://badge.fury.io/js/passport-cerbere.svg)](https://badge.fury.io/js/passport-cerbere)

## Installation

```shell
npm install passport-cerbere
```

## Configuration

```javascript
var cerbereStrategy = new CerbereStrategy(
  {
    casURL:
      "https://authentification.din.developpement-durable.gouv.fr/cas/public",
    serviceURL: "http://127.0.0.1:3000",
    propertyMap: {
      id: "UTILISATEUR.ID",
      name: {
        civilite: "UTILISATEUR.CIVILITE",
        givenName: "UTILISATEUR.PRENOM",
        familyName: "UTILISATEUR.NOM"
      },
      emails: [{key: "UTILISATEUR.MEL", type: 'principal'}, {key: "UTILISATEUR.MELPR", type: 'professionnel'}],
      unite: "UTILISATEUR.UNITE",
      telephones: [{key: "UTILISATEUR.TEL_FIXE", type: 'fixe'}],
      adresses: [{key: {town: "UTILISATEUR.ADR_VILLE", street: 'UTILISATEUR.ADR_RUE', streetcode: 'UTILISATEUR.ADR_CODEPOSTAL', country: 'UTILISATEUR.ADR_PAYS_NOM'}, type: 'principale'}, {key: {town: "ENTREPRISE.ADR_VILLE", street: 'ENTREPRISE.ADR_RUE', streetcode: 'ENTREPRISE.ADR_CODEPOSTAL', country: 'ENTREPRISE.ADR_PAYS_NOM'}, type: 'entreprise'}],
      organizations: [{key: {code: "ENTREPRISE.SIREN", name: 'ENTREPRISE.RAISON_SOCIALE'}, type: 'principale'}]
    }
  },
  // This is the `verify` callback
  function(username, profile, done) {
    User.findOrCreate(username, profile, function(
      err,
      user
    ) {
      user = { id: username, profile: profile };
      done(err, user);
    });
  }
);
passport.use(cerbereStrategy);
```

`User.findOrCreate` est une fonction à implémenter pour les besoins spécifiques de l'application. Elle permet de contrôler les droits selon une logique métier: profils, etc.

## Requêtes d'authentification

Utilisez `passport.authenticate()`, spécifiez la stratégie `cerbere`, dans les requêtes d'authentification.

Par exemple, en tant que middleware dans [Express](http://expressjs.com/):

```javascript
app.get("/login", function(req, res, next) {
  passport.authenticate("cerbere", function(err, user, info) {
    if (err) {
      return next(err);
    }

    if (!user) {
      req.session.messages = info.message;
      return res.redirect("/");
    }

    req.logIn(user, function(err) {
      if (err) {
        return next(err);
      }

      req.session.messages = "";
      return res.redirect("/");
    });
  })(req, res, next);
});

app.get("/logout", function(req, res) {
  var returnURL = "http://127.0.0.1:3000/";
  cerbereStrategy.logout(req, res, returnURL);
});
```

## Usage

Voir un [exemple complet](https://github.com/MTES-MCT/cerbere-nodejs).
