require('dotenv').config();

const fs = require('fs');
const express = require('express');
const session = require('express-session');
var SQLiteStore = require('connect-sqlite3')(session);
const passport = require('passport');
const { Strategy: SamlStrategy } = require('passport-saml');
const path = require('path');
const morgan = require('morgan');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const backend = express.Router();

// Initialize session
app.use(express.static(path.join(__dirname, 'public')));
app.use(
    session({
        secret: process.env.SECRET || 'secret',
        resave: false,
        saveUninitialized: true,
        name: 'ascdmainsalesforcesite',
        store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
    })
);

// Dynamic CORS configuration for handling requests with credentials
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, Authorization'
    );
    res.header('Access-Control-Allow-Credentials', 'true');
    if ('OPTIONS' === req.method) {
        res.sendStatus(200);
    } else {
        next();
    }
});

const PORT = process.env.PORT || 8000;
app.use(morgan('dev'));
app.use(cors());

// Express built-in body parser
app.use(express.json({ limit: '15360mb' }));
app.use(express.urlencoded({ extended: true }));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Initialize Passport and its sessions
app.use(passport.initialize());
app.use(passport.authenticate('session'));

const cert = fs.readFileSync(path.resolve(__dirname, 'config', 'ISTE_SAML_CERT.crt'), 'utf-8');

const generateToken = () => {
    const secretKey = process.env.SECRET;
    if (!secretKey) {
        throw new Error('Secret key is not defined');
    }
    const token = jwt.sign({}, secretKey, { expiresIn: '1h' });
    return token;
};

passport.use(
    new SamlStrategy(
        {
            entryPoint: process.env.SALESFORCE_ENTRY_POINT,
            issuer: process.env.APP_ISSUER,
            callbackUrl: process.env.CALLBACK_URL,
            cert,
        },
        function (profile, done) {
            console.log('>>>profile:', profile);

            const dynamicToken = generateToken();
            return done(null, {
                email: profile.email,
                displayName: profile.username,
                samlNameID: profile.nameID,
                samlNameIDFormat: profile.nameIDFormat,
                salesforceId: profile.userId,
                isPortalUser: profile.is_portal_user,
                issuer: profile.issuer,
                nameQualifier: profile.nameQualifier,
                spNameQualifier: profile.spNameQualifier,
                token: dynamicToken,
            });
        }
    )
);

// When a user initiates the login process, they access this endpoint, which authenticates them and redirects them to the Salesforce endpoint.
backend.get(
    '/login',
    passport.authenticate('saml', {
        failureRedirect: `${process.env.FRONTEND_URL}/login-failed`,
        failureFlash: true,
    }),
    (req, res, next) => {
        // If the user is authenticated and a session user exists, redirect them to the frontend URL.
        if (req.isAuthenticated() && req.session.user) {
            res.redirect(process.env.FRONTEND_URL);
        } else {
            next();
        }
    }
);

// When the page refreshes or reloads, the frontend calls this endpoint to authenticate the user, allowing conditional rendering of components.
backend.get('/getlogin', (req, res) => {
    // If the user is authenticated and a session user exists, return authentication status and user information.
    if (req.isAuthenticated() && req.session.user) {
        return res.status(200).json({
            authenticated: true,
            user: req.session.user,
        });
    }
    // If the user is not authenticated or no session user exists, return authentication status as false and no user information.
    return res.status(200).json({
        authenticated: false,
        user: null,
    });
});

// This endpoint clears the session cookie and redirects the user to the Salesforce logout page. Once the user is logged out from Salesforce, they will be redirected back to the frontend.
backend.get('/logout', (req, res) => {
    // Destroy the session and clear the session cookie.
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Could not logout' });
        }
        res.clearCookie('ascdmainsalesforcesite');

        // Redirect the user to the Salesforce logout page.
        res.redirect(process.env.SALESFORCE_LOGOUT);
    });
});

// SAML callback route updated to respond with status codes
backend.post(
    '/api/auth/saml/callback',
    passport.authenticate('saml', {
        failureRedirect: process.env.FRONTEND_URL,
        failureFlash: true,
    }),
    (req, res) => {
        console.log('>>>req.session.passport: callback', req.session.passport.user);
        const token = req.session.passport?.user?.token;
        req.session.user = req.session.passport.user;
        req.session.save((err) => {
            // Explicitly save the session
            if (err) {
                console.error('Session save error:', err);
            }
            if (token) {
                res.redirect(`${process.env.FRONTEND_URL}`);
            }
        });
    }
);

// Default route to check if the server is running
backend.get('/', (req, res) => {
    console.log('>>status');
    res.status(200).send('ok1');
});

// redirect test
backend.get('/redirect', (req, res) => {
    console.log('>> redirect test');
    res.redirect(process.env.FRONTEND_URL);
});

app.use(process.env.ROUTE_PATH, backend);

// Start the server
app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
});
