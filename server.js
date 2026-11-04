
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  process.env.FRONTEND_URL ||
    "https://uvaishmalikali-droid.github.io",
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

// Backend Health Check
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "AI YouTube Manager Backend is running!",
    status: "OK"
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
      console.error("OpenAI API error:", data.error?.message || "Unknown error");

      return res.status(502).json({
        success: false,
        message: "AI script generation failed. Please check API settings."
      });
    }

    return res.status(200).json({
      success: true,
      script: data.output_text || "No script was generated."
    });

  } catch (error) {
    console.error("Script error:", error.message);

    return res.status(500).json({
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
