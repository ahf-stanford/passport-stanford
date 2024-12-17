const { Strategy: SAMLStrategy } = require('@node-saml/passport-saml')
const fs = require('fs')
const attrmap = require('./lib/attributes')
const idps = require('./lib/idps')

class Strategy extends SAMLStrategy {
    constructor(options, verify) {
        // Set default options
        const samlOptions = {
            protocol: options.protocol || 'https://',
            signatureAlgorithm: 'sha256',
            identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            acceptedClockSkewMs: options.acceptedClockSkewMs || 60000,
            attributeConsumingServiceIndex: options.attributeConsumingServiceIndex || false,
            forceAuthn: options.forceAuthn || false,
            skipRequestCompression: options.skipRequestCompression || false,
            disableRequestedAuthnContext: options.disableRequestedAuthnContext ?? true,
            validateInResponseTo: options.validateInResponseTo || 'never',
            passReqToCallback: true,
            wantAssertionsSigned: true,
            wantAuthnResponseSigned: true
        }

        // Ensure callbackUrl is set
        if (!options.callbackUrl && options.path) {
            const protocol = options.protocol || 'https://'
            // const host = options.host || samlBackendURL
            const host = options.host
            samlOptions.callbackUrl = `${protocol}${host}${options.path}`
        } else {
            samlOptions.callbackUrl = options.callbackUrl
        }

        // Handle decryption certificates
        if (options.decryptionCertPath && !options.decryptionCert) {
            samlOptions.decryptionCert = fs.readFileSync(options.decryptionCertPath, 'utf8')
        }
        if (options.decryptionPvkPath && !options.decryptionPvk) {
            samlOptions.decryptionPvk = fs.readFileSync(options.decryptionPvkPath, 'utf8')
        }

        // Handle entity ID
        samlOptions.issuer = options.entityID || options.entityId

        // // Configure IDP
        // if (options.idp) {
        //     if (!idps[options.idp]) {
        //         throw new Error('Unknown IdP: ' + options.idp)
        //     }
        //     const idp = idps[options.idp]
        //     Object.assign(samlOptions, {
        //         entryPoint: idp.entryPoint,
        //         cert: idp.cert,
        //         idpCert: idp.cert,
        //         idpIssuer: idp.entityID
        //     })
        // } else if (!options.entryPoint || !options.cert) {
        //     const defaultIdp = idps.dev
        //     Object.assign(samlOptions, {
        //         entryPoint: defaultIdp.entryPoint,
        //         cert: defaultIdp.cert,
        //         idpCert: defaultIdp.cert
        //     })
        //     console.warn('No IdP defined - defaulting to ' + defaultIdp.entityID)
        // }

        // Configure IDP
        if (options.idp) {
            if (!idps[options.idp]) {
                throw new Error('Unknown IdP: ' + options.idp)
            }
            const idp = idps[options.idp]
            Object.assign(samlOptions, {
                entryPoint: idp.entryPoint,
                cert: idp.cert,
                idpCert: idp.cert,
                idpIssuer: idp.entityID,
                logoutUrl: idp.logoutUrl,
                identifierFormat: idp.identifierFormat || samlOptions.identifierFormat
            })
        } else if (!options.entryPoint || !options.cert) {
            const defaultIdp = idps.dev
            Object.assign(samlOptions, {
                entryPoint: defaultIdp.entryPoint,
                cert: defaultIdp.cert,
                idpCert: defaultIdp.cert,
                logoutUrl: defaultIdp.logoutUrl
            })
            console.warn('No IdP defined - defaulting to ' + defaultIdp.entityID)
        }


        // Validate required options
        if (!samlOptions.issuer) {
            throw new Error('No entityId defined!')
        }
        if (!options.loginPath) {
            throw new Error('No loginPath defined!')
        }
        if (!samlOptions.callbackUrl) {
            throw new Error('No callbackUrl defined!')
        }
        if (Boolean(options.decryptionCert) !== Boolean(options.decryptionPvk)) {
            throw new Error('Both decryptionCert and decryptionPvk must be provided if either is present')
        }

        // Set up attribute mapper
        const attributeMapper = attrmap(options.attributeMap)

        // Set strategy name
        const name = options.name || options.idp || 'suSAML'

        // Copy all remaining options
        Object.assign(samlOptions, {
            ...options,
            name,
            additionalParams: {
                RelayState: options.loginPath
            }
        })

        console.log('SAML Strategy Configuration:', {
            name: samlOptions.name,
            issuer: samlOptions.issuer,
            entryPoint: samlOptions.entryPoint,
            callbackUrl: samlOptions.callbackUrl,
            loginPath: options.loginPath
        })

        // Initialize parent class with wrapped verify callback
        super(samlOptions, (req, profile, done) => {
            if (req.session) {
                req.session.strategy = name
            }
            attributeMapper(profile, done)
        })

        this.name = name
        this._loginPath = options.loginPath
    }

    // authenticate(req, options) {
    //     options = options || {}

    //     // Ensure RelayState is set
    //     options.additionalParams = options.additionalParams || {}
    //     options.additionalParams.RelayState = options.additionalParams.RelayState || this._loginPath

    //     // Call parent authenticate method
    //     super.authenticate(req, options)
    // }

    // authenticate(req, options) {
    //     console.log('\n===> Strategy.authenticate called')
    //     console.log('===> Options:', options)
    //     console.log('===> Request session:', req.session ? 'Session exists' : 'No session')

    //     try {
    //         const authenticateResult = super.authenticate(req, {
    //             ...options,
    //             additionalParams: {
    //                 ...options.additionalParams,
    //                 RelayState: options.additionalParams?.RelayState || this._loginPath
    //             }
    //         })
    //         console.log('===> Authentication initiated successfully')
    //         return authenticateResult
    //     } catch (error) {
    //         console.error('===> Error in authenticate method:', error)
    //         throw error
    //     }
    // }

    authenticate(req, options) {
        console.log('\n===> Strategy.authenticate called')
        console.log('===> Options:', options)
        console.log('===> Request session:', req.session ? 'Session exists' : 'No session')

        try {
            console.log('===> Pre-authentication checks:')
            console.log('===> SAML options:', this._saml?.options)
            console.log('===> Creating authentication request...')

            const authenticateResult = super.authenticate(req, {
                ...options,
                additionalParams: {
                    ...options.additionalParams,
                    RelayState: options.additionalParams?.RelayState || this._loginPath
                }
            })

            console.log('===> Authentication initiated successfully')
            console.log('===> Authentication result:', authenticateResult)

            return authenticateResult
        } catch (error) {
            console.error('===> Error in authenticate method:', error)
            throw error
        }
    }

    protected() {
        console.log('===> Called protect() method')
        return super.protect()
    }

    _generateAuthorizeRequest(req, options) {
        console.log('===> Generating authorize request')
        console.log('===> Request options:', options)
        return super._generateAuthorizeRequest(req, options)
    }

    protect() {
        return (req, res, next) => {
            if (req.isAuthenticated() && req.session?.strategy === this.name) {
                return next()
            }

            if (req.session) {
                req.session.strategy = this.name
                req.session.returnTo = req.url
            } else {
                console.warn('passport-stanford: No session property on request!')
            }
            res.redirect(this._loginPath)
        }
    }

    return(url) {
        return (req, res) => {
            let redirectUrl = url
            if (req.session?.returnTo) {
                redirectUrl = req.session.returnTo
                delete req.session.returnTo
            }
            res.redirect(redirectUrl || '/')
        }
    }

    metadata() {
        return (req, res) => {
            res.type('application/xml')
            res.status(200).send(this.generateServiceProviderMetadata(this._saml.options.decryptionCert))
        }
    }
}

module.exports = { Strategy }
