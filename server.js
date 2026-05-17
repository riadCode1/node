const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(express.json());

const {
  QF_CLIENT_ID,
  QF_CLIENT_SECRET,
  QF_REDIRECT_URI,
  QF_USE_PRELIVE,
  PORT = 3001,
} = process.env;

if (!QF_CLIENT_ID || !QF_CLIENT_SECRET || !QF_REDIRECT_URI) {
  console.error("❌ Missing required env vars: QF_CLIENT_ID, QF_CLIENT_SECRET, QF_REDIRECT_URI");
  process.exit(1);
}

const AUTH_BASE =
  QF_USE_PRELIVE === "true"
    ? "https://prelive-oauth2.quran.foundation"
    : "https://oauth2.quran.foundation";

const TOKEN_URL = `${AUTH_BASE}/oauth2/token`;
const REVOKE_URL = `${AUTH_BASE}/oauth2/revoke`;

function safeDecodeJwt(token) {
  return token && typeof token === "string" && token.length > 10
    ? jwt.decode(token)
    : null;
}

// ─── POST /api/auth/qf/exchange ───────────────────────────────────────────────

app.post("/api/auth/qf/exchange", async (req, res) => {
  const { code, codeVerifier, redirectUri } = req.body;

  if (!code || !codeVerifier || !redirectUri) {
    return res.status(400).json({ error: "code, codeVerifier, and redirectUri are required" });
  }

  try {
    const params = new URLSearchParams();
    params.append("grant_type", "authorization_code");
    params.append("code", code);
    params.append("redirect_uri", redirectUri);
    params.append("code_verifier", codeVerifier);
    params.append("client_id", QF_CLIENT_ID);

    const { data } = await axios.post(TOKEN_URL, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      auth: { username: QF_CLIENT_ID, password: QF_CLIENT_SECRET },
    });

    return res.json({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      expiresIn: data.expires_in,
      user: safeDecodeJwt(data.id_token),
    });
  } catch (err) {
    const status = err.response?.status ?? 500;
    const qfError = err.response?.data ?? {};
    console.error("Token exchange failed:", qfError);
    return res.status(status).json({
      error: qfError.error_description ?? qfError.error ?? "Failed to exchange authorization code",
    });
  }
});

// ─── POST /api/auth/qf/refresh ────────────────────────────────────────────────

app.post("/api/auth/qf/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

  try {
    const params = new URLSearchParams();
    params.append("grant_type", "refresh_token");
    params.append("refresh_token", refreshToken);
    params.append("client_id", QF_CLIENT_ID);

    const { data } = await axios.post(TOKEN_URL, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      auth: { username: QF_CLIENT_ID, password: QF_CLIENT_SECRET },
    });

    return res.json({
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? refreshToken,
      idToken: data.id_token,
      expiresIn: data.expires_in,
      user: safeDecodeJwt(data.id_token),
    });
  } catch (err) {
    const status = err.response?.status ?? 500;
    const qfError = err.response?.data ?? {};
    console.error("Token refresh failed:", qfError);
    return res.status(status).json({
      error: qfError.error_description ?? qfError.error ?? "Token refresh failed",
    });
  }
});

// ─── POST /api/auth/qf/logout ─────────────────────────────────────────────────

app.post("/api/auth/qf/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(200).json({ ok: true });

  try {
    const params = new URLSearchParams();
    params.append("token", refreshToken);
    params.append("token_type_hint", "refresh_token");
    params.append("client_id", QF_CLIENT_ID);

    await axios.post(REVOKE_URL, params.toString(), {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      auth: { username: QF_CLIENT_ID, password: QF_CLIENT_SECRET },
    });
  } catch (err) {
    console.warn("Token revocation failed (best-effort):", err.response?.data);
  }

  return res.json({ ok: true });
});

// ─── Health check ─────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`✅ QF OAuth2 backend running on port ${PORT}`);
  console.log(`   Auth base: ${AUTH_BASE}`);
  console.log(`   Redirect:  ${QF_REDIRECT_URI}`);
});
