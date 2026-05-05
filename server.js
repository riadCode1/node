require("dotenv").config();
const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  USE_PRELIVE,
} = process.env;

const AUTH_BASE =
  USE_PRELIVE === "true"
    ? "https://prelive-oauth2.quran.foundation"
    : "https://oauth2.quran.foundation";


// 🔹 1. REQUIRED CALLBACK ROUTE (for OAuth redirect)
app.get("/oauth/callback", (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send("Missing authorization code");
  }

  console.log("✅ Received code from OAuth:", code);

  // 👉 Option 1 (simple for now)
  // Just display it so you confirm everything works
  res.send(`
    <h2>Login successful ✅</h2>
    <p>You can close this page.</p>
    <p>Code: ${code}</p>
  `);

  // 👉 Option 2 (advanced - later)
  // Redirect back to your Expo app using deep linking
  // res.redirect(`furkanapp://auth?code=${code}`);
});


// 🔹 2. Exchange code → tokens (called by Expo app)
app.post("/auth/exchange", async (req, res) => {
  const { code, codeVerifier } = req.body;

  if (!code || !codeVerifier) {
    return res.status(400).json({ error: "Missing code or codeVerifier" });
  }

  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    });

    const response = await axios.post(
      `${AUTH_BASE}/oauth2/token`,
      params.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        auth: {
          username: CLIENT_ID,
          password: CLIENT_SECRET,
        },
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("Exchange error:", err.response?.data || err.message);
    res.status(500).json({ error: "Token exchange failed" });
  }
});


// 🔹 3. Refresh token
app.post("/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: "Missing refreshToken" });
  }

  try {
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });

    const response = await axios.post(
      `${AUTH_BASE}/oauth2/token`,
      params.toString(),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        auth: {
          username: CLIENT_ID,
          password: CLIENT_SECRET,
        },
      }
    );

    res.json(response.data);
  } catch (err) {
    console.error("Refresh error:", err.response?.data || err.message);
    res.status(500).json({ error: "Token refresh failed" });
  }
});


// 🔹 Health check
app.get("/health", (req, res) => res.json({ status: "ok" }));


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));