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

// Allow GitHub Pages to communicate with this backend
app.use(
    cors({
        origin: FRONTEND_ORIGIN,
        credentials: true
    })
);

app.use(express.json());

// Sessions
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
        <a href="/login">Test Roblox Login</a>
    `);
});

// =========================
// ROBLOX LOGIN
// =========================

app.get("/login", (req, res) => {
    const state = crypto.randomBytes(32).toString("hex");

    const codeVerifier = crypto.randomBytes(32).toString("base64url");

    const codeChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");

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
});

// =========================
// ROBLOX CALLBACK
// =========================

app.get("/callback", async (req, res) => {
    try {
        const { code, state } = req.query;

        if (!code) {
            return res.status(400).send("Missing authorization code.");
        }

        if (!state || state !== req.session.oauthState) {
            return res.status(400).send("Invalid OAuth state.");
        }

        const codeVerifier = req.session.codeVerifier;

        if (!codeVerifier) {
            return res.status(400).send("Missing PKCE verifier.");
        }

        // Exchange authorization code for token
        const tokenResponse = await fetch(
            "https://apis.roblox.com/oauth/v1/token",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: new URLSearchParams({
                    client_id: ROBLOX_CLIENT_ID,
                    client_secret: ROBLOX_CLIENT_SECRET,
                    grant_type: "authorization_code",
                    code: code,
                    code_verifier: codeVerifier,
                    redirect_uri: REDIRECT_URI
                })
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok) {
            console.error("Roblox token error:", tokenData);

            return res.status(500).send(
                "Failed to get Roblox access token."
            );
        }

        const accessToken = tokenData.access_token;

        if (!accessToken) {
            return res.status(500).send(
                "Roblox did not return an access token."
            );
        }

        // Get Roblox user information
        const userResponse = await fetch(
            "https://apis.roblox.com/oauth/v1/userinfo",
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            }
        );

        const userData = await userResponse.json();

        if (!userResponse.ok) {
            console.error("Roblox userinfo error:", userData);

            return res.status(500).send(
                "Failed to get Roblox user information."
            );
        }

        console.log("Roblox user:", userData);

        // Save user to session
        req.session.user = {
            id: userData.sub,
            username: userData.preferred_username || userData.name,
            displayName: userData.name,
            picture: userData.picture || null,
            profile: userData.profile || null
        };

        // Clear temporary OAuth information
        delete req.session.oauthState;
        delete req.session.codeVerifier;

        // Save session before redirecting
        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).send("Failed to save login session.");
            }

            res.redirect(FRONTEND_URL);
        });

    } catch (error) {
        console.error("Callback error:", error);

        res.status(500).send(
            "Something went wrong during Roblox login."
        );
    }
});

// =========================
// GET CURRENT USER
// =========================

app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
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
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).json({
                success: false
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            success: true
        });
    });
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
    console.log(`RemoteEvent Backend running on port ${PORT}`);
});
