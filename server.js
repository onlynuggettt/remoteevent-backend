require("dotenv").config();

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const ROBLOX_CLIENT_ID = process.env.ROBLOX_CLIENT_ID;
const ROBLOX_CLIENT_SECRET = process.env.ROBLOX_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

const FRONTEND_ORIGIN = "https://onlynuggettt.github.io";

// =========================
// CORS
// =========================

app.use(
    cors({
        origin: FRONTEND_ORIGIN,
        credentials: true
    })
);

app.use(express.json());

// =========================
// SESSION
// =========================

app.set("trust proxy", 1);

app.use(
    session({
        secret: SESSION_SECRET,
        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000
        }
    })
);

// =========================
// HOME
// =========================

app.get("/", (req, res) => {
    res.send(`
        <h1>RemoteEvent Backend</h1>
        <p>Backend is online.</p>
        <p>
            <a href="/login">Test Roblox Login</a>
        </p>
    `);
});

// =========================
// ROBLOX LOGIN
// =========================

app.get("/login", (req, res) => {
    try {
        const state = crypto
            .randomBytes(32)
            .toString("hex");

        const codeVerifier = crypto
            .randomBytes(32)
            .toString("base64url");

        const codeChallenge = crypto
            .createHash("sha256")
            .update(codeVerifier)
            .digest("base64url");

        // Save OAuth information in session
        req.session.oauthState = state;
        req.session.codeVerifier = codeVerifier;

        const params = new URLSearchParams({
            client_id: ROBLOX_CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: "code",
            scope: "openid profile",
            state: state,
            code_challenge: codeChallenge,
            code_challenge_method: "S256"
        });

        res.redirect(
            `https://apis.roblox.com/oauth/v1/authorize?${params.toString()}`
        );

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).send("Failed to start Roblox login.");
    }
});

// =========================
// ROBLOX CALLBACK
// =========================

app.get("/callback", async (req, res) => {
    try {
        const { code, state } = req.query;

        console.log("OAuth callback received.");
        console.log("State received:", state);
        console.log("Session state:", req.session.oauthState);

        if (!code) {
            return res
                .status(400)
                .send("Missing authorization code.");
        }

        // Check OAuth state
        if (
            !state ||
            state !== req.session.oauthState
        ) {
            return res
                .status(400)
                .send("Invalid OAuth state.");
        }

        const codeVerifier =
            req.session.codeVerifier;

        if (!codeVerifier) {
            return res
                .status(400)
                .send("Missing PKCE verifier.");
        }

        // =========================
        // EXCHANGE CODE FOR TOKEN
        // =========================

        const tokenResponse = await fetch(
            "https://apis.roblox.com/oauth/v1/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    client_id:
                        ROBLOX_CLIENT_ID,

                    client_secret:
                        ROBLOX_CLIENT_SECRET,

                    grant_type:
                        "authorization_code",

                    code:
                        code,

                    code_verifier:
                        codeVerifier,

                    redirect_uri:
                        REDIRECT_URI
                })
            }
        );

        const tokenData =
            await tokenResponse.json();

        if (!tokenResponse.ok) {

            console.error(
                "Roblox token error:",
                tokenData
            );

            return res
                .status(500)
                .send(
                    "Failed to get Roblox access token."
                );
        }

        const accessToken =
            tokenData.access_token;

        if (!accessToken) {
            return res
                .status(500)
                .send(
                    "Roblox did not return an access token."
                );
        }

        // =========================
        // GET ROBLOX USER
        // =========================

        const userResponse = await fetch(
            "https://apis.roblox.com/oauth/v1/userinfo",
            {
                headers: {
                    Authorization:
                        `Bearer ${accessToken}`
                }
            }
        );

        const userData =
            await userResponse.json();

        if (!userResponse.ok) {

            console.error(
                "Roblox userinfo error:",
                userData
            );

            return res
                .status(500)
                .send(
                    "Failed to get Roblox user information."
                );
        }

        console.log(
            "Roblox user:",
            userData
        );

        // =========================
        // SAVE USER SESSION
        // =========================

        req.session.user = {
            id: userData.sub,

            username:
                userData.preferred_username ||
                userData.name,

            displayName:
                userData.name,

            picture:
                userData.picture || null,

            profile:
                userData.profile || null
        };

        // Remove temporary OAuth data
        delete req.session.oauthState;
        delete req.session.codeVerifier;

        // =========================
        // SAVE SESSION
        // =========================

        req.session.save((error) => {

            if (error) {

                console.error(
                    "Session save error:",
                    error
                );

                return res
                    .status(500)
                    .send(
                        "Failed to save login session."
                    );
            }

            console.log(
                "Login successful:",
                req.session.user
            );

            // Redirect to GitHub Pages
            res.redirect(
                FRONTEND_URL +
                "?login=success"
            );
        });

    } catch (error) {

        console.error(
            "Callback error:",
            error
        );

        res
            .status(500)
            .send(
                "Something went wrong during Roblox login."
            );
    }
});

// =========================
// CURRENT USER
// =========================

app.get("/api/me", (req, res) => {

    if (!req.session.user) {

        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,

        user: req.session.user
    });
});

// =========================
// LOGOUT
// =========================

app.get("/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {

            console.error(
                "Logout error:",
                error
            );

            return res
                .status(500)
                .json({
                    success: false
                });
        }

        res.clearCookie(
            "connect.sid",
            {
                httpOnly: true,
                secure: true,
                sameSite: "none"
            }
        );

        res.json({
            success: true
        });
    });
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {

    console.log(
        `RemoteEvent Backend running on port ${PORT}`
    );

});
