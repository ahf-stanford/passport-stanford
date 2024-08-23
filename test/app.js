import express from 'express'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import morgan from 'morgan'
import bodyParser from 'body-parser'
import passport from 'passport'
import suSAML from 'passport-stanford'
import path from 'path'
import http from 'http'

const app = express()
const samlPath = '/saml'
let forcedSaml, saml

const PORT = 3000
const HOST = 'localhost'

app.set('port', PORT)
app.set('views', path.join(process.cwd(), '/app/views'))
app.set('view engine', 'pug')

app.use(morgan('dev'))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(session({
    secret: 'sooperS3CRET!',
    resave: false,
    saveUninitialized: true,
    name: 'stanford',
    cookie: {
        httpOnly: true,
        maxAge: 600000
    }
}))
app.use(passport.initialize())
app.use(passport.session())

saml = new suSAML.Strategy({
    name: 'saml',
    protocol: 'http://',
    idp: 'stanford',
    entityId: 'https://github.com/scottylogan/passport-stanford',
    callbackUrl: `https://${HOST}:${PORT}${samlPath}`,
    path: samlPath,
    loginPath: samlPath,
    passReqToCallback: true,
    passport: passport,
    decryptionPvkPath: './private.pem',
    decryptionCertPath: './public.pem',
})

forcedSaml = new suSAML.Strategy({
    name: 'forced',
    protocol: 'http://',
    idp: 'stanford',
    entityId: 'https://github.com/scottylogan/passport-stanford',
    callbackUrl: `https://${HOST}:${PORT}${samlPath}`,
    path: samlPath,
    loginPath: samlPath,
    passReqToCallback: true,
    passport: passport,
    forceAuthn: true,
    decryptionPvkPath: './private.pem',
    decryptionCertPath: './public.pem',
})

// Corrected passport.use calls
passport.use('saml', saml)
passport.use('forced', forcedSaml)

passport.serializeUser((user, done) => {
    done(null, JSON.stringify(user))
})

passport.deserializeUser((json, done) => {
    try {
        done(null, JSON.parse(json))
    } catch (err) {
        done(err, null)
    }
})

app.use((err, req, res, next) => {
    res.status(err.status || 500)
    res.render('500', { error: err })
})

app.get('/', (req, res) => {
    res.render('home', {
        user: req.isAuthenticated() ? req.user : null,
        loginPath: samlPath,
    })
})

app.all(samlPath, (req, res, next) => {
    if (['GET', 'POST'].indexOf(req.method) === -1) {
        return res.status(405).send('Method not supported')
    }
    return passport.authenticate(req.session.strategy, {
        successReturnToOrRedirect: '/'
    })(req, res, next)
})

// Removed the call to saml.metadata() as it is not a function
app.get('/metadata', (req, res) => {
    //saml.strategy.metadata()
    res.status(404).send('Metadata not available')
})

// Use passport.authenticate to protect the profile route
app.get('/profile', passport.authenticate('saml', { session: false }), (req, res) => {
    res.render('profile', {
        user: req.user,
    })
})

const server = http.createServer(app)
server.listen(app.get('port'), () => {
    console.log(`Express server listening on port ${app.get('port')}`)
})

