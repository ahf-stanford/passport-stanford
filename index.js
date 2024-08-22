const saml = require('@node-saml/passport-saml')
const fs = require('fs')
const util = require('util')
const url = require('url')
const idps = require('./lib/idps')
const attrmap = require('./lib/attributes')

// An extension of the Passport SAML strategy for Stanford.
class Strategy extends saml.Strategy {
  constructor(options, verify) {
    // some sensible defaults
    options.protocol = options.protocol || 'https://'
    options.signatureAlgorithm = options.signatureAlgorithm || 'sha256'
    options.identifierFormat = options.identifierFormat || 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    options.acceptedClockSkewMs = options.acceptedClockSkewMs || 60000
    options.attributeConsumingServiceIndex = options.attributeConsumingServiceIndex || false
    options.forceAuthn = options.forceAuthn || false
    options.skipRequestCompression = options.skipRequestCompression || false

    if (options.disableRequestedAuthnContext === undefined) {
      options.disableRequestedAuthnContext = true
    }

    if (options.validatedInResponseTo === undefined) {
      options.validateInResponseTo = 'always'
    }

    if (options.decryptionCertPath) {
      options.decryptionCert = fs.readFileSync(options.decryptionCertPath, 'utf8')
    }

    if (options.decryptionPvkPath) {
      options.decryptionPvk = fs.readFileSync(options.decryptionPvkPath, 'utf8')
    }

    if (options.entityID) {
      options.issuer = options.entityID
    }

    if (options.entityId) {
      options.issuer = options.entityId
    }

    if (options.idp) {
      if (idps[options.idp]) {
        options.entryPoint = idps[options.idp].entryPoint
        options.cert = idps[options.idp].cert
        options.idpCert = idps[options.idp].cert
      } else {
        throw new Error('Unknown IdP: ' + options.idp)
      }
    }

    if (!options.entryPoint || !options.cert) {
      console.warn('No IdP defined - defaulting to ' + idps.dev.entityID)
      options.entryPoint = idps.dev.entryPoint
      options.cert = idps.dev.cert
      options.idpCert = idps.dev.cert
    }

    if (!options.issuer) {
      throw new Error('No entityId defined!')
    }

    // having either both an encryption cert and private key is valid
    // having neither an encryption cert nor a private key is also valid
    // having only one or the other is NOT valid
    if (!options.decryptionCert && options.decryptionPvk) {
      throw new Error('Only a private key was defined; a public cert is also required')
    }

    if (options.decryptionCert && !options.decryptionPvk) {
      throw new Error('Only a public cert was defined; a private key is also required')
    }

    if (!options.loginPath) {
      throw new Error('No loginPath defined!')
    }

    super(options, (req, profile, done) => {
      req.session.strategy = this.name
      this.attributeMapper(profile, done)
    })

    this.loginPath = options.loginPath

    // set up an attribute mapper
    this.attributeMapper = attrmap(options.attributeMap)

    // set the name of this strategy to either the name passed in
    // via the options, or the short name of the idp.
    //
    // if neither is set, the name will be 'suSAML'
    this.name = options.name || options.idp || 'suSAML'
  }

  protect() {
    return (req, res, next) => {
      if (req.isAuthenticated() && req.session.strategy === this.name) {
        return next()
      } else {
        // Handle unauthenticated access
      }
    }
  }
}

module.exports = Strategy