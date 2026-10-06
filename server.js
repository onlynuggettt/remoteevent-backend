require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

/*
========================================
REMOTE EVENT CONFIG
========================================
*/

const CLIENT_ID = process.env.ROBLOX_CLIENT_ID;
const CLIENT_SECRET = process.env.ROBLOX_CLIENT_SECRET;

const REDIRECT_URI =
    process.env.REDIRECT_URI;

const FRONTEND_URL =
    process.env.FRONTEND_URL;


/*
========================================
SESSION
========================================
*/

app.set("trust proxy", 1);

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 1000 * 60 * 60 * 24 * 7
        }
    })
);


/*
========================================
HEALTH CHECK
========================================
*/

app.get("/", (req, res) => {

    res.send(`
        <html>
            <head>
                <title>RemoteEvent Backend</title>
            </head>

            <body style="
                background:#08090d;
                color:white;
                font-family:Arial;
                text-align:center;
                padding-top:100px;
            ">

                <h1>RemoteEvent Backend</h1>

                <p>Backend is online.</p>

                <a
                    href="/login"
                    style="
                        color:white;
                        background:#5865f2;
                        padding:12px 20px;
                        border-radius:8px;
                        text-decoration:none;
                    "
                >
                    Test Roblox Login
                </a>

            </body>
        </html>
    `);

});


/*
========================================
BASE64URL
========================================
*/

function base64url(buffer) {

    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

}


/*
========================================
PKCE VERIFIER
========================================
*/

function createVerifier() {

    return base64url(
        crypto.randomBytes(32)
    );

}


/*
========================================
PKCE CHALLENGE
========================================
*/

function createChallenge(verifier) {

    return base64url(
        crypto
            .createHash("sha256")
            .update(verifier)
            .digest()
    );

}


/*
========================================
ROBLOX LOGIN
========================================
*/

app.get("/login", (req, res) => {

    if (!CLIENT_ID || !REDIRECT_URI) {

        return res.status(500).send(
            "Roblox OAuth is not configured correctly."
        );

    }

    const verifier =
        createVerifier();

    const challenge =
        createChallenge(verifier);

    const state =
        base64url(
            crypto.randomBytes(32)
        );


    /*
    Save OAuth information
    inside the user's session.
    */

    req.session.oauth = {

        verifier: verifier,

        state: state

    };


    /*
    Roblox authorization URL
    */

    const params =
        new URLSearchParams({

            client_id:
                CLIENT_ID,

            redirect_uri:
                REDIRECT_URI,

            scope:
                "openid profile",

            response_type:
                "code",

            code_challenge:
                challenge,

            code_challenge_method:
                "S256",

            state:
                state

        });


    const authorizationURL =
        "https://apis.roblox.com/oauth/v1/authorize?" +
        params.toString();


    res.redirect(
        authorizationURL
    );

});


/*
========================================
ROBLOX CALLBACK
========================================
*/

app.get("/callback", async (req, res) => {

    try {

        const code =
            req.query.code;

        const state =
            req.query.state;


        /*
        Check that Roblox actually
        returned an authorization code.
        */

        if (!code) {

            return res.status(400).send(
                "Roblox did not provide an authorization code."
            );

        }


        /*
        Check OAuth state.
        */

        if (
            !req.session.oauth ||
            state !== req.session.oauth.state
        ) {

            return res.status(400).send(
                "Invalid OAuth state."
            );

        }


        /*
        Exchange authorization code
        for an access token.
        */

        const tokenBody =
            new URLSearchParams({

                client_id:
                    CLIENT_ID,

                client_secret:
                    CLIENT_SECRET,

                grant_type:
                    "authorization_code",

                code:
                    code,

                code_verifier:
                    req.session.oauth.verifier,

                redirect_uri:
                    REDIRECT_URI

            });


        const tokenResponse =
            await fetch(
                "https://apis.roblox.com/oauth/v1/token",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/x-www-form-urlencoded"

                    },

                    body:
                        tokenBody.toString()

                }
            );


        const tokens =
            await tokenResponse.json();


        if (!tokenResponse.ok) {

            console.error(
                "Roblox token error:",
                tokens
            );

            return res.status(400).send(
                "Failed to authenticate with Roblox."
            );

        }


        /*
        Get Roblox account information.
        */

        const userResponse =
            await fetch(
                "https://apis.roblox.com/oauth/v1/userinfo",
                {

                    method: "GET",

                    headers: {

                        Authorization:
                            `Bearer ${tokens.access_token}`

                    }

                }
            );


        const user =
            await userResponse.json();


        if (!userResponse.ok) {

            console.error(
                "Roblox userinfo error:",
                user
            );

            return res.status(400).send(
                "Failed to retrieve Roblox account."
            );

        }


        /*
        Store the Roblox account
        in the session.
        */

        req.session.user = {

            id:
                user.sub,

            username:
                user.preferred_username,

            displayName:
                user.name,

            picture:
                user.picture,

            profile:
                user.profile

        };


        /*
        Remove temporary OAuth data.
        */

        delete req.session.oauth;


        /*
        Send the user back
        to your GitHub Pages website.
        */

        res.redirect(
            FRONTEND_URL
        );


    } catch (error) {

        console.error(
            "OAuth error:",
            error
        );

        res.status(500).send(
            "Something went wrong while signing in."
        );

    }

});


/*
========================================
CHECK LOGIN
========================================
*/

app.get("/api/me", (req, res) => {

    if (!req.session.user) {

        return res.json({

            loggedIn: false

        });

    }


    res.json({

        loggedIn: true,

        id:
            req.session.user.id,

        username:
            req.session.user.username,

        displayName:
            req.session.user.displayName,

        picture:
            req.session.user.picture,

        profile:
            req.session.user.profile

    });

});


/*
========================================
LOGOUT
========================================
*/

app.get("/logout", (req, res) => {

    req.session.destroy(
        (error) => {

            if (error) {

                console.error(
                    "Logout error:",
                    error
                );

                return res.status(500).send(
                    "Failed to logout."
                );

            }


            res.redirect(
                FRONTEND_URL
            );

        }
    );

});


/*
========================================
START SERVER
========================================
*/

app.listen(
    PORT,
    () => {

        console.log(
            `RemoteEvent backend running on port ${PORT}`
        );

    }
);