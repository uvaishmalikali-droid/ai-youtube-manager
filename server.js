
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://uvaishmalikali-droid.github.io";

const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

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

// Temporary YouTube connection storage
let youtubeConnection = null;
let oauthState = null;

// Backend Health Check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "AI YouTube Manager Backend is running!",
    status: "OK"
  });
});

// Start Google OAuth
app.get("/auth/google", (req, res) => {
  if (
    !process.env.GOOGLE_CLIENT_ID ||
    !process.env.GOOGLE_CLIENT_SECRET ||
    !REDIRECT_URI ||
    !process.env.SESSION_SECRET
  ) {
    return res.status(500).send("Google OAuth configuration is missing.");
  }

  oauthState = crypto.randomBytes(32).toString("hex");

  res.cookie("oauth_state", oauthState, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 10 * 60 * 1000,
    path: "/auth/google/callback"
  });

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/youtube.upload",
    access_type: "offline",
    prompt: "consent",
    state: oauthState
  });

  res.redirect(
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString()
  );
});

// Google OAuth Callback
app.get("/auth/google/callback", async (req, res) => {
  try {
    const cookies = Object.fromEntries(
      (req.headers.cookie || "")
        .split(";")
        .filter(Boolean)
        .map(item => {
          const parts = item.trim().split("=");
          return [parts.shift(), parts.join("=")];
        })
    );

    const state = req.query.state;

    res.clearCookie("oauth_state", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/auth/google/callback"
    });

    if (
      !state ||
      !oauthState ||
      state !== oauthState ||
      state !== cookies.oauth_state
    ) {
      return res.status(403).send("Invalid OAuth state. Please try again.");
    }

    oauthState = null;

    if (req.query.error) {
      return res.status(400).send("Google authorization was not completed.");
    }

    if (!req.query.code) {
      return res.status(400).send("Google authorization code is missing.");
    }

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

    if (!tokenResponse.ok) {
      console.error("Google token exchange failed:", tokens.error);
      return res.status(502).send("Google token exchange failed.");
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
      console.error("YouTube API error:", channelData.error?.message);
      return res.status(502).send("Could not retrieve YouTube channel.");
    }

    youtubeConnection = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      expiresAt: Date.now() + (tokens.expires_in * 1000),
      channel: channelData.items?.[0]?.snippet?.title || "YouTube Channel"
    };

    res.send(`
      <h2>YouTube Connected Successfully!</h2>
      <p>Channel: ${String(youtubeConnection.channel)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")}</p>
      <p>You can close this page.</p>
    `);

  } catch (error) {
    console.error("OAuth error:", error.message);
    res.status(500).send("Google OAuth connection failed.");
  }
});

// YouTube Connection Status
app.get("/api/youtube/status", (req, res) => {
  res.json({
    connected: Boolean(youtubeConnection),
    channel: youtubeConnection?.channel || null
  });
});

// AI Script Generation
app.post("/api/generate-script", async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({
        success: false,
        message: "OpenAI API key is missing"
      });
    }

    const { topic, language, style } = req.body;

    if (!topic || typeof topic !== "string" || !topic.trim()) {
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
          "Authorization": `Bearer ${process.env.OPENAI_API_KEY}`
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
      console.error("OpenAI API error:", data.error?.message);
      return res.status(502).json({
        success: false,
        message: "AI script generation failed."
      });
    }

    res.json({
      success: true,
      script: data.output_text || "No script was generated."
    });

  } catch (error) {
    console.error("Script error:", error.message);
    res.status(500).json({
      success: false,
      message: "Server error while generating script"
    });
  }
});

// Unknown API Route
app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API route not found"
  });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error("Server error:", err.message);
  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `AI YouTube Manager server running on port ${PORT}`
  );
});
