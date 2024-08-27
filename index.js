const saml = require('@node-saml/passport-saml')
const fs = require('fs')
const util = require('util')
const url = require('url')
const idps = require('./lib/idps')
const attrmap = require('./lib/attributes')

//  An extensnion of the Passport SAML strategy for Stanford.
class strategy {
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

        if (options.decryptionCertPath && !options.decryptionCert) {
            options.decryptionCert = fs.readFileSync(options.decryptionCertPath, 'utf8')
        }

        if (options.decryptionPvkPath && !options.decryptionPvk) {
            options.decryptionPvk = fs.readFileSync(options.decryptionPvkPath, 'utf8')
        }

        //console.log('===> options.decryptionPvk: ', String(options.decryptionPvk).substring(28, 33) ?? 'No Key')
        //console.log('===> options.decryptionCert: ', String(options.decryptionCert).substring(28, 33) ?? 'No Cert')

        if (options.entityID) {
            options.issuer = options.entityID
        }

        if (options.entityId) {
            options.issuer = options.entityId
        }
        console.log('===> options.issuer: ', options.issuer)


        if (options.idp) {
            console.log('===> options.idp: ', options.idp)
            if (idps[options.idp]) {
                console.log('===> idps[options.idp].description: ', idps[options.idp].description)
                options.entryPoint = idps[options.idp].entryPoint
                options.cert = idps[options.idp].cert
                options.idpCert = idps[options.idp].cert
                console.log('===> options.entryPoint: ', options.entryPoint)
                console.log('===> options.cert: ', String(options.cert).substring(28, 33) ?? 'No Key')
                console.log('===> options.idpCert: ', String(options.idpCert).substring(28, 33) ?? 'No Key')
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
            throw new Error('Only a private key was defined a public cert is also required')
        }

        if (options.decryptionCert && !options.decryptionPvk) {
            throw new Error('Only a public cert was defined a private key is also required')
        }

        if (!options.loginPath) {
            throw new Error('No loginPath defined!')
        }

        this.loginPath = options.loginPath
        console.log('===> this.loginPath: ', this.loginPath)

        // set up an attribute mapper
        this.attributeMapper = attrmap(options.attributeMap)

        // if neither is set, the name will be 'suSAML'
        this.name = options.name || options.idp || 'suSAML'
        console.log('===> Strategy name: ', this.name)
        
        // call the parent method before setting the strategy name,
        // otherwise the name will always be 'saml'
        let suSaml = new saml.Strategy(options, function (req, profile, done) {
            req.session.strategy = this.name
            this.attributeMapper(profile, done)
        }.bind(this))

        //suSaml.bind(this)
        // saml.Strategy.call(this, options, function (req, profile, done) {
        //     req.session.strategy = this.name
        //     this.attributeMapper(profile, done)
        // }.bind(this))
        // set the name of this strategy to either the name passed in
        // via the options, or the short name of the idp.
        //
    }

    protect() {
        console.log('===> Called: protect()')
        return function (req, res, next) {
            if (req.isAuthenticated() && req.session.strategy === this.name) {
                return next()
            } else {
                if (req.session) {
                    req.session.strategy = this.name
                    req.session.returnTo = req.url
                } else {
                    console.warn('passport-stanford: No session property on request!')
                }
                res.redirect(this.loginPath)
            }
        }.bind(this)
    }

    return(url) {
        console.log('===> Called: return()')
        return function (req, res) {
            if (req.session && req.session.returnTo) {
                url = req.session.returnTo
                delete req.session.returnTo
            }
            res.redirect(url || '/')
        }
    }

    metadata() {
        console.log('===> Called: metadata()')
        return function (req, res) {
            res.type('application/xml')
            res.status(200).send(this.generateServiceProviderMetadata(this._saml.options.decryptionCert))
        }.bind(this)
    }
}

util.inherits(strategy, saml.Strategy)

module.exports.Strategy = strategy