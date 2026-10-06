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

// =====================================================
// BASIC SETUP
// =====================================================

app.set("trust proxy", 1);

app.use(express.json());

app.use(
    cors({
        origin: FRONTEND_ORIGIN,
        credentials: true
    })
);

// =====================================================
// SESSION
// =====================================================

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

// =====================================================
// ONE-TIME LOGIN TICKETS
// =====================================================

const loginTickets = new Map();

// Ticket expiration: 60 seconds
const TICKET_LIFETIME = 60 * 1000;

// Clean expired tickets every minute
setInterval(() => {
    const now = Date.now();

    for (const [ticket, data] of loginTickets.entries()) {
        if (data.expiresAt < now) {
            loginTickets.delete(ticket);
        }
    }
}, 60 * 1000);

// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {
    res.send(`
        <h1>RemoteEvent Backend</h1>
        <p>Backend is online.</p>
        <a href="/login">Test Roblox Login</a>
    `);
});

// =====================================================
// ROBLOX LOGIN
// =====================================================

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

    const authUrl =
        "https://apis.roblox.com/oauth/v1/authorize?" +
        params.toString();

    res.redirect(authUrl);
});

// =====================================================
// ROBLOX CALLBACK
// =====================================================

app.get("/callback", async (req, res) => {
    try {
        const { code, state } = req.query;

        if (!code) {
            return res.status(400).send("Missing authorization code.");
        }

        if (!state) {
            return res.status(400).send("Missing OAuth state.");
        }

        // Check OAuth state
        if (state !== req.session.oauthState) {
            return res.status(400).send("Invalid OAuth state.");
        }

        const codeVerifier = req.session.codeVerifier;

        if (!codeVerifier) {
            return res.status(400).send("Missing PKCE verifier.");
        }

        // =================================================
        // EXCHANGE CODE FOR TOKEN
        // =================================================

        const tokenResponse = await fetch(
            "https://apis.roblox.com/oauth/v1/token",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },

                body: new URLSearchParams({
                    client_id: ROBLOX_CLIENT_ID,
                    client_secret: ROBLOX_CLIENT_SECRET,
                    grant_type: "authorization_code",
                    code: code,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: codeVerifier
                })
            }
        );

        const tokenData = await tokenResponse.json();

        if (!tokenResponse.ok) {
            console.error("Roblox token error:", tokenData);

            return res.status(400).send(
                "Failed to get Roblox access token."
            );
        }

        const accessToken = tokenData.access_token;

        // =================================================
        // GET ROBLOX USER
        // =================================================

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
            console.error("Roblox user info error:", userData);

            return res.status(400).send(
                "Failed to get Roblox user information."
            );
        }

        console.log("Roblox user logged in:", userData);

        // =================================================
        // CREATE USER OBJECT
        // =================================================

        const user = {
            id: String(userData.sub),
            username: userData.preferred_username || "",
            displayName:
                userData.name ||
                userData.preferred_username ||
                "",
            picture: userData.picture || "",
            profile:
                `https://www.roblox.com/users/${userData.sub}/profile`
        };

        // =================================================
        // CREATE ONE-TIME TICKET
        // =================================================

        const ticket = crypto.randomBytes(32).toString("hex");

        loginTickets.set(ticket, {
            user: user,
            expiresAt: Date.now() + TICKET_LIFETIME
        });

        // Remove temporary OAuth session data
        delete req.session.oauthState;
        delete req.session.codeVerifier;

        // =================================================
        // REDIRECT TO WEBSITE
        // =================================================

        res.redirect(
            `${FRONTEND_URL}?login=success&ticket=${encodeURIComponent(ticket)}`
        );

    } catch (error) {
        console.error("OAuth callback error:", error);

        res.status(500).send(
            "An error occurred while logging in with Roblox."
        );
    }
});

// =====================================================
// EXCHANGE LOGIN TICKET
// =====================================================

app.get("/api/exchange", (req, res) => {
    try {
        const ticket = req.query.ticket;

        if (!ticket) {
            return res.status(400).json({
                error: "Missing login ticket."
            });
        }

        const ticketData = loginTickets.get(ticket);

        if (!ticketData) {
            return res.status(400).json({
                error: "Invalid or expired login ticket."
            });
        }

        // Check expiration
        if (ticketData.expiresAt < Date.now()) {
            loginTickets.delete(ticket);

            return res.status(400).json({
                error: "Login ticket expired."
            });
        }

        // IMPORTANT:
        // Delete immediately so the ticket can only be used once.
        loginTickets.delete(ticket);

        // Save the user into the current session too
        req.session.user = ticketData.user;

        req.session.save((err) => {
            if (err) {
                console.error("Session save error:", err);
            }
        });

        return res.json({
            loggedIn: true,
            user: ticketData.user
        });

    } catch (error) {
        console.error("Ticket exchange error:", error);

        res.status(500).json({
            error: "Failed to exchange login ticket."
        });
    }
});

// =====================================================
// CHECK SESSION
// =====================================================

app.get("/api/me", (req, res) => {
    if (req.session.user) {
        return res.json({
            loggedIn: true,
            user: req.session.user
        });
    }

    return res.json({
        loggedIn: false
    });
});

// =====================================================
// LOGOUT
// =====================================================

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Logout error:", err);

            return res.status(500).json({
                error: "Failed to logout."
            });
        }

        res.clearCookie("connect.sid", {
            httpOnly: true,
            secure: true,
            sameSite: "none"
        });

        res.json({
            success: true
        });
    });
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
    console.log(`RemoteEvent Backend running on port ${PORT}`);
});
