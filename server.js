require("dotenv").config();

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

// =====================================================
// ENVIRONMENT VARIABLES
// =====================================================

const ROBLOX_CLIENT_ID = process.env.ROBLOX_CLIENT_ID;
const ROBLOX_CLIENT_SECRET = process.env.ROBLOX_CLIENT_SECRET;

const REDIRECT_URI = process.env.REDIRECT_URI;
const FRONTEND_URL = process.env.FRONTEND_URL;

const SESSION_SECRET = process.env.SESSION_SECRET;

// Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

// Used to sign RemoteEvent login tokens
const TOKEN_SECRET =
    process.env.TOKEN_SECRET || SESSION_SECRET;

const FRONTEND_ORIGIN =
    "https://onlynuggettt.github.io";

// =====================================================
// BASIC VALIDATION
// =====================================================

const requiredVariables = {
    ROBLOX_CLIENT_ID,
    ROBLOX_CLIENT_SECRET,
    REDIRECT_URI,
    FRONTEND_URL,
    SESSION_SECRET,
    SUPABASE_URL,
    SUPABASE_SERVICE_KEY,
    TOKEN_SECRET
};

for (const [name, value] of Object.entries(requiredVariables)) {
    if (!value) {
        console.warn(
            `WARNING: Missing environment variable: ${name}`
        );
    }
}

// =====================================================
// EXPRESS
// =====================================================

app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));

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
// SUPABASE HELPER
// =====================================================

async function supabaseRequest(
    path,
    options = {}
) {
    const response = await fetch(
        `${SUPABASE_URL}/rest/v1/${path}`,
        {
            ...options,

            headers: {
                apikey: SUPABASE_SERVICE_KEY,

                Authorization:
                    `Bearer ${SUPABASE_SERVICE_KEY}`,

                "Content-Type":
                    "application/json",

                ...(options.headers || {})
            }
        }
    );

    const text = await response.text();

    let data = null;

    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = text;
    }

    if (!response.ok) {
        const error = new Error(
            `Supabase request failed: ${response.status}`
        );

        error.status = response.status;
        error.data = data;

        throw error;
    }

    return data;
}

// =====================================================
// ONE-TIME LOGIN TICKETS
// =====================================================

const loginTickets = new Map();

const TICKET_LIFETIME =
    60 * 1000;

setInterval(() => {
    const now = Date.now();

    for (
        const [ticket, ticketData]
        of loginTickets.entries()
    ) {
        if (
            ticketData.expiresAt < now
        ) {
            loginTickets.delete(ticket);
        }
    }
}, 60 * 1000);

// =====================================================
// REMOTEEVENT API TOKENS
// =====================================================

/*
    Token format:

    base64url(payload).signature

    The payload contains:
    {
        id,
        username,
        displayName,
        picture,
        profile,
        iat,
        exp
    }
*/

function createAuthToken(user) {

    const now =
        Math.floor(Date.now() / 1000);

    const payload = {
        id: String(user.id),

        username:
            user.username || "",

        displayName:
            user.displayName || "",

        picture:
            user.picture || "",

        profile:
            user.profile || "",

        iat: now,

        // 7 day login
        exp: now + (
            7 * 24 * 60 * 60
        )
    };

    const encodedPayload =
        Buffer
            .from(JSON.stringify(payload))
            .toString("base64url");

    const signature =
        crypto
            .createHmac(
                "sha256",
                TOKEN_SECRET
            )
            .update(encodedPayload)
            .digest("base64url");

    return (
        encodedPayload +
        "." +
        signature
    );
}


function verifyAuthToken(token) {

    try {

        if (!token) {
            return null;
        }

        const parts =
            token.split(".");

        if (parts.length !== 2) {
            return null;
        }

        const [
            encodedPayload,
            signature
        ] = parts;

        const expectedSignature =
            crypto
                .createHmac(
                    "sha256",
                    TOKEN_SECRET
                )
                .update(encodedPayload)
                .digest("base64url");

        const signatureBuffer =
            Buffer.from(
                signature
            );

        const expectedBuffer =
            Buffer.from(
                expectedSignature
            );

        if (
            signatureBuffer.length !==
            expectedBuffer.length
        ) {
            return null;
        }

        if (
            !crypto.timingSafeEqual(
                signatureBuffer,
                expectedBuffer
            )
        ) {
            return null;
        }

        const payload =
            JSON.parse(
                Buffer
                    .from(
                        encodedPayload,
                        "base64url"
                    )
                    .toString("utf8")
            );

        const now =
            Math.floor(Date.now() / 1000);

        if (
            !payload.exp ||
            payload.exp < now
        ) {
            return null;
        }

        return payload;

    } catch (error) {

        console.error(
            "Token verification error:",
            error
        );

        return null;
    }
}


// =====================================================
// AUTH MIDDLEWARE
// =====================================================

function requireAuth(req, res, next) {

    let token = null;

    const authorization =
        req.headers.authorization;

    if (
        authorization &&
        authorization.startsWith("Bearer ")
    ) {
        token =
            authorization.slice(7);
    }

    const user =
        verifyAuthToken(token);

    if (!user) {
        return res.status(401).json({
            error: "You must be logged in."
        });
    }

    req.user = user;

    next();
}


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>RemoteEvent Backend</title>
        </head>

        <body
            style="
                background:#08080c;
                color:white;
                font-family:Arial;
                padding:40px;
            "
        >

            <h1>RemoteEvent Backend</h1>

            <p>
                Backend is online.
            </p>

            <p>
                Roblox authentication,
                games API and portfolio API
                are available.
            </p>

            <a
                href="/login"
                style="color:#8b7cff;"
            >
                Test Roblox Login
            </a>

        </body>
        </html>
    `);
});


// =====================================================
// ROBLOX LOGIN
// =====================================================

app.get("/login", (req, res) => {

    try {

        const state =
            crypto
                .randomBytes(32)
                .toString("hex");

        const codeVerifier =
            crypto
                .randomBytes(32)
                .toString("base64url");

        const codeChallenge =
            crypto
                .createHash("sha256")
                .update(codeVerifier)
                .digest("base64url");

        req.session.oauthState =
            state;

        req.session.codeVerifier =
            codeVerifier;

        const params =
            new URLSearchParams({
                client_id:
                    ROBLOX_CLIENT_ID,

                redirect_uri:
                    REDIRECT_URI,

                response_type:
                    "code",

                scope:
                    "openid profile",

                state:
                    state,

                code_challenge:
                    codeChallenge,

                code_challenge_method:
                    "S256"
            });

        const authUrl =
            "https://apis.roblox.com/oauth/v1/authorize?" +
            params.toString();

        res.redirect(authUrl);

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        res.status(500).send(
            "Failed to start Roblox login."
        );
    }
});


// =====================================================
// ROBLOX CALLBACK
// =====================================================

app.get("/callback", async (req, res) => {

    try {

        const {
            code,
            state
        } = req.query;

        if (!code) {
            return res.status(400).send(
                "Missing authorization code."
            );
        }

        if (!state) {
            return res.status(400).send(
                "Missing OAuth state."
            );
        }

        if (
            state !==
            req.session.oauthState
        ) {
            return res.status(400).send(
                "Invalid OAuth state."
            );
        }

        const codeVerifier =
            req.session.codeVerifier;

        if (!codeVerifier) {
            return res.status(400).send(
                "Missing PKCE verifier."
            );
        }

        // =========================================
        // TOKEN EXCHANGE
        // =========================================

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
                        new URLSearchParams({
                            client_id:
                                ROBLOX_CLIENT_ID,

                            client_secret:
                                ROBLOX_CLIENT_SECRET,

                            grant_type:
                                "authorization_code",

                            code:
                                code,

                            redirect_uri:
                                REDIRECT_URI,

                            code_verifier:
                                codeVerifier
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

            return res.status(400).send(
                "Failed to get Roblox access token."
            );
        }

        const accessToken =
            tokenData.access_token;

        // =========================================
        // GET ROBLOX USER
        // =========================================

        const userResponse =
            await fetch(
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
                "Roblox user info error:",
                userData
            );

            return res.status(400).send(
                "Failed to get Roblox user information."
            );
        }

        console.log(
            "Roblox user logged in:",
            userData
        );

        // =========================================
        // USER OBJECT
        // =========================================

        const user = {

            id:
                String(userData.sub),

            username:
                userData.preferred_username || "",

            displayName:
                userData.name ||
                userData.preferred_username ||
                "",

            picture:
                userData.picture || "",

            profile:
                `https://www.roblox.com/users/${userData.sub}/profile`
        };

        // =========================================
        // CREATE REMOTEEVENT TOKEN
        // =========================================

        const authToken =
            createAuthToken(user);

        // =========================================
        // CREATE ONE-TIME LOGIN TICKET
        // =========================================

        const ticket =
            crypto
                .randomBytes(32)
                .toString("hex");

        loginTickets.set(
            ticket,
            {
                user,
                token: authToken,

                expiresAt:
                    Date.now() +
                    TICKET_LIFETIME
            }
        );

        delete req.session.oauthState;
        delete req.session.codeVerifier;

        // =========================================
        // REDIRECT
        // =========================================

        res.redirect(
            `${FRONTEND_URL}?login=success&ticket=${encodeURIComponent(ticket)}`
        );

    } catch (error) {

        console.error(
            "OAuth callback error:",
            error
        );

        res.status(500).send(
            "An error occurred while logging in with Roblox."
        );
    }
});


// =====================================================
// EXCHANGE LOGIN TICKET
// =====================================================

app.get(
    "/api/exchange",
    (req, res) => {

        try {

            const ticket =
                req.query.ticket;

            if (!ticket) {

                return res.status(400).json({
                    error:
                        "Missing login ticket."
                });

            }

            const ticketData =
                loginTickets.get(ticket);

            if (!ticketData) {

                return res.status(400).json({
                    error:
                        "Invalid or expired login ticket."
                });

            }

            if (
                ticketData.expiresAt <
                Date.now()
            ) {

                loginTickets.delete(
                    ticket
                );

                return res.status(400).json({
                    error:
                        "Login ticket expired."
                });

            }

            // One-time ticket
            loginTickets.delete(ticket);

            // Save normal session too
            req.session.user =
                ticketData.user;

            req.session.save(
                (err) => {

                    if (err) {
                        console.error(
                            "Session save error:",
                            err
                        );
                    }

                }
            );

            return res.json({

                loggedIn: true,

                user:
                    ticketData.user,

                // Frontend stores this
                token:
                    ticketData.token

            });

        } catch (error) {

            console.error(
                "Ticket exchange error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to exchange login ticket."
            });
        }
    }
);


// =====================================================
// SESSION CHECK
// =====================================================

app.get(
    "/api/me",
    (req, res) => {

        if (req.session.user) {

            return res.json({

                loggedIn: true,

                user:
                    req.session.user

            });
        }

        return res.json({
            loggedIn: false
        });
    }
);


// =====================================================
// LOGOUT
// =====================================================

app.get(
    "/logout",
    (req, res) => {

        req.session.destroy(
            (err) => {

                if (err) {

                    console.error(
                        "Logout error:",
                        err
                    );

                    return res.status(500).json({
                        error:
                            "Failed to logout."
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
            }
        );
    }
);


// =====================================================
// ROBLOX GAMES
// =====================================================

app.get(
    "/api/games",
    requireAuth,
    async (req, res) => {

        try {

            const userId =
                encodeURIComponent(
                    req.user.id
                );

            const url =
                `https://games.roblox.com/v2/users/${userId}/games?accessFilter=Public&sortOrder=Asc&limit=50`;

            const response =
                await fetch(url);

            const data =
                await response.json();

            if (!response.ok) {

                console.error(
                    "Roblox games error:",
                    data
                );

                return res.status(
                    response.status
                ).json({
                    error:
                        "Failed to get Roblox games."
                });
            }

            const games =
                data.data || [];

            // =====================================
            // GET GAME THUMBNAILS
            // =====================================

            if (games.length > 0) {

                const universeIds =
                    games
                        .map(
                            game =>
                                game.id
                        )
                        .filter(Boolean)
                        .join(",");

                try {

                    const thumbnailResponse =
                        await fetch(
                            "https://thumbnails.roblox.com/v1/games/icons" +
                            `?universeIds=${universeIds}` +
                            "&returnPolicy=PlaceHolder" +
                            "&size=512x512" +
                            "&format=Png" +
                            "&isCircular=false"
                        );

                    if (
                        thumbnailResponse.ok
                    ) {

                        const thumbnailData =
                            await thumbnailResponse.json();

                        const thumbnails =
                            new Map();

                        for (
                            const thumbnail
                            of (
                                thumbnailData.data ||
                                []
                            )
                        ) {

                            thumbnails.set(
                                String(
                                    thumbnail.targetId
                                ),
                                thumbnail.imageUrl
                            );
                        }

                        for (
                            const game
                            of games
                        ) {

                            game.thumbnail =
                                thumbnails.get(
                                    String(game.id)
                                ) || null;

                        }
                    }

                } catch (thumbnailError) {

                    console.error(
                        "Thumbnail error:",
                        thumbnailError
                    );

                }
            }

            return res.json({
                userId:
                    req.user.id,

                games
            });

        } catch (error) {

            console.error(
                "Games API error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load Roblox games."
            });
        }
    }
);


// =====================================================
// GET ALL PORTFOLIO POSTS
// =====================================================

app.get(
    "/api/portfolio",
    async (req, res) => {

        try {

            const data =
                await supabaseRequest(
                    "portfolio_posts?select=*&order=created_at.desc"
                );

            return res.json({
                posts:
                    data || []
            });

        } catch (error) {

            console.error(
                "Portfolio GET error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load portfolio posts."
            });
        }
    }
);


// =====================================================
// GET MY PORTFOLIO POSTS
// =====================================================

app.get(
    "/api/portfolio/me",
    requireAuth,
    async (req, res) => {

        try {

            const userId =
                encodeURIComponent(
                    req.user.id
                );

            const data =
                await supabaseRequest(
                    `portfolio_posts?select=*&roblox_user_id=eq.${userId}&order=created_at.desc`
                );

            return res.json({
                posts:
                    data || []
            });

        } catch (error) {

            console.error(
                "My portfolio error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to load your portfolio."
            });
        }
    }
);


// =====================================================
// CREATE PORTFOLIO POST
// =====================================================

app.post(
    "/api/portfolio",
    requireAuth,
    async (req, res) => {

        try {

            const {
                title,
                description,
                imageUrl,
                projectUrl
            } = req.body;

            // =====================================
            // VALIDATION
            // =====================================

            if (
                typeof title !== "string" ||
                title.trim().length < 1 ||
                title.trim().length > 100
            ) {

                return res.status(400).json({
                    error:
                        "Title must be between 1 and 100 characters."
                });
            }

            if (
                typeof description !== "string" ||
                description.trim().length < 1 ||
                description.trim().length > 2000
            ) {

                return res.status(400).json({
                    error:
                        "Description must be between 1 and 2000 characters."
                });
            }

            if (
                imageUrl !== undefined &&
                imageUrl !== null &&
                typeof imageUrl !== "string"
            ) {

                return res.status(400).json({
                    error:
                        "Invalid image URL."
                });
            }

            if (
                projectUrl !== undefined &&
                projectUrl !== null &&
                typeof projectUrl !== "string"
            ) {

                return res.status(400).json({
                    error:
                        "Invalid project URL."
                });
            }

            // =====================================
            // INSERT
            // =====================================

            const post = {

                roblox_user_id:
                    String(req.user.id),

                username:
                    req.user.username,

                display_name:
                    req.user.displayName,

                avatar_url:
                    req.user.picture,

                title:
                    title.trim(),

                description:
                    description.trim(),

                image_url:
                    imageUrl
                        ? imageUrl.trim()
                        : null,

                project_url:
                    projectUrl
                        ? projectUrl.trim()
                        : null
            };

            const data =
                await supabaseRequest(
                    "portfolio_posts",
                    {
                        method: "POST",

                        headers: {
                            Prefer:
                                "return=representation"
                        },

                        body:
                            JSON.stringify(post)
                    }
                );

            return res.status(201).json({
                success: true,

                post:
                    Array.isArray(data)
                        ? data[0]
                        : data
            });

        } catch (error) {

            console.error(
                "Portfolio create error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to create portfolio post."
            });
        }
    }
);


// =====================================================
// UPDATE PORTFOLIO POST
// =====================================================

app.patch(
    "/api/portfolio/:id",
    requireAuth,
    async (req, res) => {

        try {

            const postId =
                req.params.id;

            const {
                title,
                description,
                imageUrl,
                projectUrl
            } = req.body;

            // =====================================
            // VALIDATION
            // =====================================

            const updates = {};

            if (
                title !== undefined
            ) {

                if (
                    typeof title !== "string" ||
                    title.trim().length < 1 ||
                    title.trim().length > 100
                ) {

                    return res.status(400).json({
                        error:
                            "Invalid title."
                    });
                }

                updates.title =
                    title.trim();
            }

            if (
                description !== undefined
            ) {

                if (
                    typeof description !== "string" ||
                    description.trim().length < 1 ||
                    description.trim().length > 2000
                ) {

                    return res.status(400).json({
                        error:
                            "Invalid description."
                    });
                }

                updates.description =
                    description.trim();
            }

            if (
                imageUrl !== undefined
            ) {

                updates.image_url =
                    imageUrl
                        ? String(imageUrl).trim()
                        : null;
            }

            if (
                projectUrl !== undefined
            ) {

                updates.project_url =
                    projectUrl
                        ? String(projectUrl).trim()
                        : null;
            }

            if (
                Object.keys(updates).length === 0
            ) {

                return res.status(400).json({
                    error:
                        "No changes supplied."
                });
            }

            // =====================================
            // UPDATE ONLY OWNER'S POST
            // =====================================

            const data =
                await supabaseRequest(
                    `portfolio_posts?id=eq.${encodeURIComponent(postId)}&roblox_user_id=eq.${encodeURIComponent(req.user.id)}`,
                    {
                        method: "PATCH",

                        headers: {
                            Prefer:
                                "return=representation"
                        },

                        body:
                            JSON.stringify(updates)
                    }
                );

            if (
                !data ||
                data.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Portfolio post not found or you are not the owner."
                });
            }

            return res.json({
                success: true,

                post:
                    data[0]
            });

        } catch (error) {

            console.error(
                "Portfolio update error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to update portfolio post."
            });
        }
    }
);


// =====================================================
// DELETE PORTFOLIO POST
// =====================================================

app.delete(
    "/api/portfolio/:id",
    requireAuth,
    async (req, res) => {

        try {

            const postId =
                req.params.id;

            const data =
                await supabaseRequest(
                    `portfolio_posts?id=eq.${encodeURIComponent(postId)}&roblox_user_id=eq.${encodeURIComponent(req.user.id)}`,
                    {
                        method: "DELETE",

                        headers: {
                            Prefer:
                                "return=representation"
                        }
                    }
                );

            if (
                !data ||
                data.length === 0
            ) {

                return res.status(404).json({
                    error:
                        "Portfolio post not found or you are not the owner."
                });
            }

            return res.json({
                success: true
            });

        } catch (error) {

            console.error(
                "Portfolio delete error:",
                error
            );

            res.status(500).json({
                error:
                    "Failed to delete portfolio post."
            });
        }
    }
);


// =====================================================
// 404
// =====================================================

app.use(
    (req, res) => {

        res.status(404).json({
            error:
                "Endpoint not found."
        });

    }
);


// =====================================================
// ERROR HANDLER
// =====================================================

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );

        res.status(500).json({
            error:
                "Internal server error."
        });
    }
);


// =====================================================
// START SERVER
// =====================================================

app.listen(
    PORT,
    () => {

        console.log(
            `RemoteEvent Backend running on port ${PORT}`
        );

        console.log(
            `Frontend: ${FRONTEND_ORIGIN}`
        );

        console.log(
            `Supabase configured: ${
                SUPABASE_URL &&
                SUPABASE_SERVICE_KEY
                    ? "YES"
                    : "NO"
            }`
        );

    }
);
