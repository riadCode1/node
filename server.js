/**
 * backend/server.js — Quran Foundation OAuth2 Backend
 *
 * This server keeps CLIENT_SECRET off the mobile device.
 * It performs:
 *   POST /api/auth/qf/exchange  — code + code_verifier → tokens
 *   POST /api/auth/qf/refresh   — refresh_token → new tokens
 *   POST /api/auth/qf/logout    — revoke refresh_token
 *
 * Deploy to any Node.js host (Railway, Fly.io, Vercel, AWS Lambda, etc.)
 * and set BACKEND_BASE_URL in the mobile app's config.ts.
 *
 * Environment variables required (set via .env or secrets manager):
 *   QF_CLIENT_ID      — your client_id (also needed in mobile app)
 *   QF_CLIENT_SECRET  — ⚠️ NEVER put this in the mobile bundle
 *   QF_REDIRECT_URI   — must match exactly what the app sends
 *   QF_USE_PRELIVE    — "true" for pre-live, omit/false for production
 *   PORT              — optional, defaults to 3001
 */

const express = require("express");
const axios = require("axios");
require("dotenv").config();

const app = express();
app.use(express.json());

// ─── Config ───────────────────────────────────────────────────────────────────

const {
  QF_CLIENT_ID,
  QF_CLIENT_SECRET,
  QF_REDIRECT_URI,
  QF_USE_PRELIVE,
  PORT = 3001,
} = process.env;

if (!QF_CLIENT_ID || !QF_CLIENT_SECRET || !QF_REDIRECT_URI) {
  console.error(
    "❌ Missing required env vars: QF_CLIENT_ID, QF_CLIENT_SECRET, QF_REDIRECT_URI"
  );
  process.exit(1);
}

const AUTH_BASE =
  QF_USE_PRELIVE === "true"
    ? "https://prelive-oauth2.quran.foundation"
    : "https://oauth2.quran.foundation";

const TOKEN_URL = `${AUTH_BASE}/oauth2/token`;
const REVOKE_URL = `${AUTH_BASE}/oauth2/revoke`;

/**
 * Basic Auth header for confidential client token requests.
 * This is how Hydra (QF's auth server) authenticates confidential clients.
 * See: https://api-docs.quran.foundation/docs/tutorials/oidc/getting-started-with-oauth2/
 */
function basicAuth() {
  return Buffer.from(`${QF_CLIENT_ID}:${QF_CLIENT_SECRET}`).toString("base64");
}

// ─── POST /api/auth/qf/exchange ───────────────────────────────────────────────
// Receives: { code, codeVerifier, redirectUri }
// Returns:  { accessToken, refreshToken, idToken, expiresIn, user? }

app.post("/api/auth/qf/exchange", async (req, res) => {
  const { code, codeVerifier, redirectUri } = req.body;

  if (!code || !codeVerifier || !redirectUri) {
    return res.status(400).json({ error: "code, codeVerifier, and redirectUri are required" });
  }

  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      client_id: QF_CLIENT_ID,
    });

    const { data } = await axios.post(TOKEN_URL, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        // Confidential client: authenticate with HTTP Basic Auth
        Authorization: `Basic ${basicAuth()}`,
      },
    });

    return res.json({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      idToken: data.id_token,
      expiresIn: data.expires_in,
      // Optionally decode id_token and return user info so the app
      // doesn't need to decode a JWT itself:
      // user: decodeIdToken(data.id_token),
    });
  } catch (err) {
    const status = err.response?.status ?? 500;
    const qfError = err.response?.data ?? {};
    console.error("Token exchange failed:", qfError);
    return res.status(status).json({
      error: qfError.error_description ?? qfError.error ?? "Token exchange failed",
    });
  }
});

// ─── POST /api/auth/qf/refresh ────────────────────────────────────────────────
// Receives: { refreshToken }
// Returns:  { accessToken, refreshToken, idToken, expiresIn }

app.post("/api/auth/qf/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: "refreshToken is required" });
  }

  try {
    const params = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: QF_CLIENT_ID,
    });

    const { data } = await axios.post(TOKEN_URL, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth()}`,
      },
    });

    return res.json({
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? refreshToken, // QF may rotate it
      idToken: data.id_token,
      expiresIn: data.expires_in,
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
// Receives: { refreshToken }
// Revokes the refresh token at the QF authorization server.

app.post("/api/auth/qf/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(200).json({ ok: true }); // already logged out

  try {
    const params = new URLSearchParams({
      token: refreshToken,
      token_type_hint: "refresh_token",
      client_id: QF_CLIENT_ID,
    });

    await axios.post(REVOKE_URL, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth()}`,
      },
    });
  } catch (err) {
    // Revocation failures are best-effort; still return success to the app
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