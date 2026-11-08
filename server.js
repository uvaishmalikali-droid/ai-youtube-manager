
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
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed"));
  }
}));

app.use(express.json({ limit: "1mb" }));

let activeChannelId = null;


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

  return [
    iv.toString("hex"),
    cipher.getAuthTag().toString("hex"),
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
// DATABASE AND SAFE MIGRATION
// =====================================

async function initializeDatabase() {
  // Keep the old table so its existing data is not deleted.
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_states (
      state TEXT PRIMARY KEY,
      expires_at BIGINT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS youtube_connections (
      channel_id TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at BIGINT NOT NULL,
      channel TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS youtube_settings (
      id INTEGER PRIMARY KEY,
      active_channel_id TEXT
    )
  `);

  await pool.query(`
    INSERT INTO youtube_settings (id, active_channel_id)
    VALUES (1, NULL)
    ON CONFLICT (id) DO NOTHING
  `);

  // Migrate the previously connected channel.
  const old = await pool.query(`
    SELECT * FROM youtube_connection WHERE id = 1
  `);

  if (old.rows.length > 0) {
    const row = old.rows[0];

    if (row.channel_id) {
      await pool.query(
        `INSERT INTO youtube_connections
          (channel_id, access_token, refresh_token,
           expires_at, channel)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (channel_id) DO NOTHING`,
        [
          row.channel_id,
          row.access_token,
          row.refresh_token,
          row.expires_at,
          row.channel
        ]
      );

      await pool.query(
        `UPDATE youtube_settings
         SET active_channel_id = COALESCE(active_channel_id, $1)
         WHERE id = 1`,
        [row.channel_id]
      );
    }
  }

  const setting = await pool.query(
    `SELECT active_channel_id
     FROM youtube_settings WHERE id = 1`
  );

  activeChannelId =
    setting.rows[0]?.active_channel_id || null;

  console.log("Multi-channel database is ready.");
}


// =====================================
// CHANNEL DATABASE HELPERS
// =====================================

async function saveChannel(connection) {
  await pool.query(
    `INSERT INTO youtube_connections
      (channel_id, access_token, refresh_token,
       expires_at, channel, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (channel_id) DO UPDATE SET
       access_token = EXCLUDED.access_token,
       refresh_token = COALESCE(
         EXCLUDED.refresh_token,
         youtube_connections.refresh_token
       ),
       expires_at = EXCLUDED.expires_at,
       channel = EXCLUDED.channel,
       updated_at = NOW()`,
    [
      connection.channelId,
      encryptToken(connection.accessToken),
      encryptToken(connection.refreshToken),
      connection.expiresAt,
      connection.channel
    ]
  );

  if (!activeChannelId) {
    await selectChannel(connection.channelId);
  }
}

async function getChannel(channelId) {
  const result = await pool.query(
    `SELECT * FROM youtube_connections
     WHERE channel_id = $1`,
    [channelId]
  );

  if (!result.rows.length) return null;

  const row = result.rows[0];

  return {
    channelId: row.channel_id,
    channel: row.channel,
    accessToken: decryptToken(row.access_token),
    refreshToken: decryptToken(row.refresh_token),
    expiresAt: Number(row.expires_at)
  };
}

async function selectChannel(channelId) {
  const channel = await getChannel(channelId);

  if (!channel) {
    throw new Error("YouTube channel not found.");
  }

  await pool.query(
    `UPDATE youtube_settings
     SET active_channel_id = $1 WHERE id = 1`,
    [channelId]
  );

  activeChannelId = channelId;
  return channel;
}

async function getAllChannels() {
  const result = await pool.query(
    `SELECT channel_id, channel, created_at
     FROM youtube_connections
     ORDER BY created_at ASC`
  );

  return result.rows.map(row => ({
    channelId: row.channel_id,
    channel: row.channel,
    connected: true,
    active: row.channel_id === activeChannelId
  }));
}

async function deleteChannel(channelId) {
  await pool.query(
    `DELETE FROM youtube_connections
     WHERE channel_id = $1`,
    [channelId]
  );

  if (activeChannelId === channelId) {
    const remaining = await pool.query(
      `SELECT channel_id FROM youtube_connections
       ORDER BY created_at ASC LIMIT 1`
    );

    const nextId = remaining.rows[0]?.channel_id || null;

    await pool.query(
      `UPDATE youtube_settings
       SET active_channel_id = $1 WHERE id = 1`,
      [nextId]
    );

    activeChannelId = nextId;
  }
}


// =====================================
// OAUTH HELPERS
// =====================================

function readCookies(header = "") {
  const cookies = {};

  header.split(";").filter(Boolean).forEach(item => {
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
    typeof cookieState !== "string" ||
    state !== cookieState
  ) return false;

  const parts = state.split(".");
  if (parts.length !== 2) return false;

  const [nonce, signature] = parts;
  const expected = createOAuthState(nonce);

  if (signature.length !== expected.length) return false;

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
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
// TOKEN REFRESH
// =====================================

async function refreshChannelToken(channelId) {
  const channel = await getChannel(channelId);

  if (!channel) {
    throw new Error("YouTube channel is not connected.");
  }

  if (channel.expiresAt > Date.now() + 60000) {
    return channel;
  }

  if (!channel.refreshToken) {
    throw new Error(
      "Refresh token missing. Reconnect this channel."
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
        refresh_token: channel.refreshToken,
        grant_type: "refresh_token"
      })
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    console.error(
      "Token refresh failed:",
      data.error || "Unknown error"
    );

    if (data.error === "invalid_grant") {
      await deleteChannel(channelId);
    }

    throw new Error(
      "Could not refresh channel. Please reconnect it."
    );
  }

  channel.accessToken = data.access_token;
  channel.expiresAt =
    Date.now() + Number(data.expires_in || 3600) * 1000;

  if (data.refresh_token) {
    channel.refreshToken = data.refresh_token;
  }

  await saveChannel(channel);
  return channel;
}


// =====================================
// HOME AND HEALTH
// =====================================

app.get("/", (req, res) => {
  res.type("text").send(
    "AI YouTube Manager multi-channel backend is running."
  );
});

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
    console.error("Health check:", error.message);

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
  const state = `${nonce}.${createOAuthState(nonce)}`;

  const secureCookie = REDIRECT_URI.startsWith("https://");

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
    prompt: "consent select_account",
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
    REDIRECT_URI && REDIRECT_URI.startsWith("https://")
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
      "Invalid OAuth state. Please try again."
    );
  }

  if (req.query.error) {
    return res.status(400).send(
      "Google authorization was not completed."
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
        "Could not retrieve YouTube channel."
      );
    }

    if (!channelData.items?.length) {
      return res.status(404).send(
        "No YouTube channel was found."
      );
    }

    const item = channelData.items[0];

    const connection = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      expiresAt:
        Date.now() + Number(tokens.expires_in || 3600) * 1000,
      channel: item.snippet?.title || "YouTube Channel",
      channelId: item.id
    };

    await saveChannel(connection);

    const safeChannel = String(connection.channel)
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
// LIST ALL CONNECTED CHANNELS
// =====================================

app.get("/api/youtube/channels", async (req, res) => {
  try {
    const channels = await getAllChannels();

    res.json({
      success: true,
      channels,
      activeChannelId
    });
  } catch (error) {
    console.error("Channel list error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load channels."
    });
  }
});


// =====================================
// ACTIVE CHANNEL STATUS
// =====================================

app.get("/api/youtube/status", async (req, res) => {
  try {
    if (!activeChannelId) {
      return res.json({
        connected: false,
        channel: null,
        channelId: null
      });
    }

    const channel = await refreshChannelToken(activeChannelId);

    res.json({
      connected: true,
      channel: channel.channel,
      channelId: channel.channelId
    });
  } catch (error) {
    res.json({
      connected: false,
      channel: null,
      channelId: null,
      message: error.message
    });
  }
});


// =====================================
// SELECT ACTIVE CHANNEL
// =====================================

app.post("/api/youtube/select", async (req, res) => {
  try {
    const channelId = req.body?.channelId;

    if (
      typeof channelId !== "string" ||
      !channelId.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Channel ID is required."
      });
    }

    const channel = await selectChannel(channelId);

    res.json({
      success: true,
      channel: channel.channel,
      channelId: channel.channelId
    });
  } catch (error) {
    res.status(404).json({
      success: false,
      message: error.message
    });
  }
});


// =====================================
// DISCONNECT ONE CHANNEL
// =====================================

app.post("/api/youtube/disconnect", async (req, res) => {
  try {
    const channelId =
      req.body?.channelId || activeChannelId;

    if (!channelId) {
      return res.status(400).json({
        success: false,
        message: "No channel selected."
      });
    }

    const channel = await getChannel(channelId);

    if (!channel) {
      return res.status(404).json({
        success: false,
        message: "Channel not found."
      });
    }

    if (channel.accessToken) {
      try {
        await fetch(
          "https://oauth2.googleapis.com/revoke",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              token: channel.accessToken
            })
          }
        );
      } catch (error) {
        console.error("Token revoke error:", error.message);
      }
    }

    await deleteChannel(channelId);

    res.json({
      success: true,
      channels: await getAllChannels(),
      activeChannelId
    });
  } catch (error) {
    console.error("Disconnect error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not disconnect channel."
    });
  }
});


// =====================================
// GEMINI AI SCRIPT GENERATION
// =====================================

app.post("/api/generate-script", async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: "Gemini API key is missing in Render Environment."
      });
    }

    const { topic, language, style } = req.body || {};

    if (typeof topic !== "string" || !topic.trim()) {
      return res.status(400).json({
        success: false,
        message: "Please enter a video topic."
      });
    }

    const safeTopic = topic.trim().slice(0, 500);
    const safeLanguage = String(language || "Hindi").slice(0, 50);
    const safeStyle = String(style || "Engaging").slice(0, 50);

    const prompt = `
You are a professional YouTube video script writer.

Create an original and engaging YouTube video script.

Topic: ${safeTopic}
Language: ${safeLanguage}
Style: ${safeStyle}

Include:
1. Catchy YouTube title.
2. Strong opening hook.
3. Complete video script.
4. Scene-by-scene ideas where useful.
5. Ending and call to action.

Write clearly and naturally.
Use the requested language.
Do not add unnecessary explanations.
`;

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey
        },
        body: JSON.stringify({
          contents: [{
            role: "user",
            parts: [{ text: prompt }]
          }],
          generationConfig: {
            temperature: 0.8,
            maxOutputTokens: 1500
          }
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(
        "Gemini API error:",
        data.error?.message || "Unknown error"
      );

      return res.status(502).json({
        success: false,
        message: "Gemini AI script generation failed. Check Render logs."
      });
    }

    const generatedScript =
      data.candidates?.[0]?.content?.parts
        ?.map(part => part.text || "")
        .join("")
        .trim();

    if (!generatedScript) {
      return res.status(502).json({
        success: false,
        message: "Gemini did not return a script."
      });
    }

    res.json({
      success: true,
      script: generatedScript
    });

  } catch (error) {
    console.error("Gemini script error:", error.message);

    res.status(500).json({
      success: false,
      message: "Server error while generating script."
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
