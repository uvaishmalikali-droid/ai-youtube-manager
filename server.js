
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://uvaishmalikali-droid.github.io";

const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  ssl: { rejectUnauthorized: false }
});

const allowedOrigins = [
  FRONTEND_URL,
  "http://localhost:3000"
];

app.set("trust proxy", 1);
app.use(helmet());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "1mb" }));

// YouTube connection
let youtubeConnection = null;


// =====================================
// TOKEN ENCRYPTION
// =====================================

function getEncryptionKey() {
  if (!SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing.");
  }

  return crypto.scryptSync(
    SESSION_SECRET,
    "ai-youtube-manager-token-storage-v1",
    32
  );
}

function encryptToken(value) {
  if (!value) return null;

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(String(value), "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    tag.toString("hex"),
    encrypted.toString("hex")
  ].join(".");
}

function decryptToken(value) {
  if (!value) return null;

  const parts = value.split(".");

  if (parts.length !== 3) {
    throw new Error("Stored token format is invalid.");
  }

  const [ivHex, tagHex, encryptedHex] = parts;

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    Buffer.from(ivHex, "hex")
  );

  decipher.setAuthTag(Buffer.from(tagHex, "hex"));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, "hex")),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}


// =====================================
// DATABASE
// =====================================

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS youtube_connection (
      id INTEGER PRIMARY KEY,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at BIGINT NOT NULL,
      channel TEXT,
      channel_id TEXT
    )
  `);

  console.log("Database table is ready.");
}

async function saveYouTubeConnection(connection) {
  await pool.query(
    `INSERT INTO youtube_connection
      (id, access_token, refresh_token, expires_at, channel, channel_id)
     VALUES (1, $1, $2, $3, $4, $5)
     ON CONFLICT (id) DO UPDATE SET
       access_token = EXCLUDED.access_token,
       refresh_token = EXCLUDED.refresh_token,
       expires_at = EXCLUDED.expires_at,
       channel = EXCLUDED.channel,
       channel_id = EXCLUDED.channel_id`,
    [
      encryptToken(connection.accessToken),
      encryptToken(connection.refreshToken),
      connection.expiresAt,
      connection.channel,
      connection.channelId
    ]
  );
}

async function loadYouTubeConnection() {
  const result = await pool.query(
    `SELECT * FROM youtube_connection WHERE id = 1`
  );

  if (result.rows.length === 0) {
    youtubeConnection = null;
    console.log("No saved YouTube connection.");
    return;
  }

  const row = result.rows[0];

  youtubeConnection = {
    accessToken: decryptToken(row.access_token),
    refreshToken: decryptToken(row.refresh_token),
    expiresAt: Number(row.expires_at),
    channel: row.channel,
    channelId: row.channel_id
  };

  console.log("Saved YouTube connection loaded.");
}

async function deleteYouTubeConnection() {
  await pool.query(
    `DELETE FROM youtube_connection WHERE id = 1`
  );

  youtubeConnection = null;
}


// =====================================
// COOKIE AND OAUTH HELPERS
// =====================================

function readCookies(header = "") {
  const cookies = {};

  header.split(";").filter(Boolean).forEach((item) => {
    const separator = item.indexOf("=");

    if (separator === -1) return;

    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();

    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = value;
    }
  });

  return cookies;
}

function createOAuthState(nonce) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(nonce)
    .digest("hex");
}

function isValidOAuthState(state, cookieState) {
  if (
    typeof state !== "string" ||
    typeof cookieState !== "string"
  ) {
    return false;
  }

  if (state !== cookieState) return false;

  const parts = state.split(".");

  if (parts.length !== 2) return false;

  const [nonce, suppliedSignature] = parts;
  const expectedSignature = createOAuthState(nonce);

  if (
    suppliedSignature.length !== expectedSignature.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(suppliedSignature),
    Buffer.from(expectedSignature)
  );
}

function oauthIsConfigured() {
  return Boolean(
    process.env.GOOGLE_CLIENT_ID &&
    process.env.GOOGLE_CLIENT_SECRET &&
    REDIRECT_URI &&
    SESSION_SECRET
  );
}


// =====================================
// YOUTUBE TOKEN REFRESH
// =====================================

async function refreshYouTubeAccessToken() {
  if (!youtubeConnection) {
    throw new Error("YouTube account is not connected.");
  }

  if (
    youtubeConnection.expiresAt >
    Date.now() + 60000
  ) {
    return youtubeConnection.accessToken;
  }

  if (!youtubeConnection.refreshToken) {
    await deleteYouTubeConnection();

    throw new Error(
      "Google refresh token is missing. Please connect YouTube again."
    );
  }

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        refresh_token: youtubeConnection.refreshToken,
        grant_type: "refresh_token"
      })
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    console.error(
      "Google token refresh failed:",
      data.error || "Unknown error"
    );

    if (data.error === "invalid_grant") {
      await deleteYouTubeConnection();
    }

    throw new Error(
      "Could not refresh Google access. Please connect YouTube again."
    );
  }

  youtubeConnection.accessToken = data.access_token;

  youtubeConnection.expiresAt =
    Date.now() +
    (Number(data.expires_in || 3600) * 1000);

  if (data.refresh_token) {
    youtubeConnection.refreshToken = data.refresh_token;
  }

  await saveYouTubeConnection(youtubeConnection);

  return youtubeConnection.accessToken;
}


// =====================================
// HOME PAGE
// =====================================

app.get("/", (req, res) => {
  res.type("text").send(
    "AI YouTube Manager backend is running."
  );
});


// =====================================
// HEALTH CHECK
// =====================================

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      message: "AI YouTube Manager Backend is running!",
      database: "connected",
      status: "OK"
    });

  } catch (error) {
    console.error("Health check error:", error.message);

    res.status(503).json({
      success: false,
      message: "Database connection failed."
    });
  }
});


// =====================================
// START GOOGLE OAUTH
// =====================================

app.get("/auth/google", (req, res) => {
  if (!oauthIsConfigured()) {
    return res.status(500).send(
      "Google OAuth configuration is missing."
    );
  }

  const nonce = crypto.randomBytes(32).toString("hex");

  const state =
    `${nonce}.${createOAuthState(nonce)}`;

  const secureCookie =
    REDIRECT_URI.startsWith("https://");

  res.cookie("oauth_state", state, {
    httpOnly: true,
    secure: secureCookie,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
    path: "/auth/google/callback"
  });

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope:
      "https://www.googleapis.com/auth/youtube.readonly " +
      "https://www.googleapis.com/auth/youtube.upload",
    access_type: "offline",
    prompt: "consent",
    state
  });

  res.redirect(
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString()
  );
});


// =====================================
// GOOGLE OAUTH CALLBACK
// =====================================

app.get("/auth/google/callback", async (req, res) => {
  const secureCookie = Boolean(
    REDIRECT_URI &&
    REDIRECT_URI.startsWith("https://")
  );

  const cookies = readCookies(req.headers.cookie);
  const state = req.query.state;

  res.clearCookie("oauth_state", {
    httpOnly: true,
    secure: secureCookie,
    sameSite: "lax",
    path: "/auth/google/callback"
  });

  if (!oauthIsConfigured()) {
    return res.status(500).send(
      "Google OAuth configuration is missing."
    );
  }

  if (!isValidOAuthState(state, cookies.oauth_state)) {
    return res.status(403).send(
      "Invalid OAuth state. Please start the connection again."
    );
  }

  if (req.query.error) {
    return res.status(400).send(
      "Google authorization was not completed. Please try again."
    );
  }

  if (
    typeof req.query.code !== "string" ||
    !req.query.code
  ) {
    return res.status(400).send(
      "Google authorization code is missing."
    );
  }

  try {
    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code: req.query.code,
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code"
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      console.error(
        "Google token exchange failed:",
        tokens.error || "Unknown error"
      );

      return res.status(502).send(
        "Google token exchange failed. Please try again."
      );
    }

    const channelResponse = await fetch(
      "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    const channelData = await channelResponse.json();

    if (!channelResponse.ok) {
      console.error(
        "YouTube API error:",
        channelData.error?.message || "Unknown error"
      );

      return res.status(502).send(
        "Could not retrieve YouTube channel. Check YouTube API access."
      );
    }

    if (
      !channelData.items ||
      channelData.items.length === 0
    ) {
      return res.status(404).send(
        "No YouTube channel was found for this Google account."
      );
    }

    youtubeConnection = {
      accessToken: tokens.access_token,
      refreshToken:
        tokens.refresh_token ||
        youtubeConnection?.refreshToken ||
        null,
      expiresAt:
        Date.now() +
        (Number(tokens.expires_in || 3600) * 1000),
      channel:
        channelData.items[0].snippet?.title ||
        "YouTube Channel",
      channelId: channelData.items[0].id
    };

    await saveYouTubeConnection(youtubeConnection);

    const safeChannel = String(youtubeConnection.channel)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

    res.send(`
      <!doctype html>
      <html lang="en">
        <head>
          <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body>
          <h2>YouTube Connected Successfully!</h2>
          <p>Channel: ${safeChannel}</p>
          <p>You can close this page and return to AI YouTube Manager.</p>
        </body>
      </html>
    `);

  } catch (error) {
    console.error("OAuth error:", error.message);

    res.status(500).send(
      "Google OAuth connection failed."
    );
  }
});


// =====================================
// YOUTUBE CONNECTION STATUS
// =====================================

app.get("/api/youtube/status", async (req, res) => {
  if (!youtubeConnection) {
    return res.json({
      connected: false,
      channel: null,
      channelId: null
    });
  }

  try {
    await refreshYouTubeAccessToken();

    return res.json({
      connected: true,
      channel: youtubeConnection.channel,
      channelId: youtubeConnection.channelId
    });

  } catch (error) {
    return res.json({
      connected: false,
      channel: null,
      channelId: null,
      message: error.message
    });
  }
});


// =====================================
// DISCONNECT YOUTUBE ACCOUNT
// =====================================

app.post("/api/youtube/disconnect", async (req, res) => {
  if (youtubeConnection?.accessToken) {
    try {
      await fetch(
        "https://oauth2.googleapis.com/revoke",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: new URLSearchParams({
            token: youtubeConnection.accessToken
          })
        }
      );

    } catch (error) {
      console.error(
        "Google token revoke error:",
        error.message
      );
    }
  }

  try {
    await deleteYouTubeConnection();

    res.json({
      success: true,
      connected: false
    });

  } catch (error) {
    console.error(
      "Disconnect database error:",
      error.message
    );

    res.status(500).json({
      success: false,
      message: "Could not remove YouTube connection."
    });
  }
});


// =====================================
// AI SCRIPT GENERATION
// =====================================

app.post("/api/generate-script", async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "OpenAI API key is missing"
      });
    }

    const {
      topic,
      language,
      style
    } = req.body || {};

    if (
      !topic ||
      typeof topic !== "string" ||
      !topic.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please enter a video topic"
      });
    }

    const prompt = `
Create a YouTube video script.

Topic: ${topic.slice(0, 500)}
Language: ${String(language || "Hindi").slice(0, 50)}
Style: ${String(style || "Engaging").slice(0, 50)}

Include:
1. Catchy title
2. Strong opening hook
3. Complete video script
4. Ending and call to action

Write clearly and naturally.
`;

    const response = await fetch(
      "https://api.openai.com/v1/responses",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization":
            `Bearer ${process.env.OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          model: "gpt-4.1-mini",
          input: prompt,
          max_output_tokens: 1500
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(
        "OpenAI API error:",
        data.error?.message || "Unknown error"
      );

      return res.status(502).json({
        success: false,
        message: "AI script generation failed."
      });
    }

    res.json({
      success: true,
      script:
        data.output_text || "No script was generated."
    });

  } catch (error) {
    console.error(
      "Script error:",
      error.message
    );

    res.status(500).json({
      success: false,
      message: "Server error while generating script"
    });
  }
});


// =====================================
// UNKNOWN API ROUTE
// =====================================

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found"
  });
});


// =====================================
// ERROR HANDLER
// =====================================

app.use((err, req, res, next) => {
  console.error("Server error:", err.message);

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});


// =====================================
// START SERVER
// =====================================

async function startServer() {
  try {
    await initializeDatabase();

    await loadYouTubeConnection();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `AI YouTube Manager server running on port ${PORT}`
      );
    });

  } catch (error) {
    console.error(
      "Database startup failed:",
      error.message
    );

    process.exit(1);
  }
}

startServer();
