
require('dotenv').config();
const express  = require('express');
const axios    = require('axios');
const cors     = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(cors({ origin: process.env.ALLOWED_ORIGIN, methods: ['GET', 'POST'] }));
app.use(express.json());

const CLIENT_ID    = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const USE_PRELIVE  = process.env.USE_PRELIVE === 'true';
const AUTH_BASE    = USE_PRELIVE
  ? 'https://prelive-oauth2.quran.foundation'
  : 'https://oauth2.quran.foundation';
const API_BASE     = USE_PRELIVE
  ? 'https://apis-prelive.quran.foundation'
  : 'https://apis.quran.foundation';

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const basicAuth   = { username: CLIENT_ID, password: CLIENT_SECRET };

// ── Step 1: QF redirects here, forward code to app ───────────
app.get('/oauth/callback', (req, res) => {
  const { code, state, error } = req.query;
  console.log('📥 Callback received. code:', !!code, 'state:', !!state);

  if (error) {
    return res.redirect(`furkan://auth/callback?error=${encodeURIComponent(error)}`);
  }
  if (!code || !state) {
    return res.status(400).send('Missing code or state');
  }

  res.redirect(
    `furkan://Index?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`
  );
});

// ── Step 2: Exchange auth code for tokens ─────────────────────
app.post('/api/auth/qf/exchange', authLimiter, async (req, res) => {
  const { code, codeVerifier, redirectUri } = req.body;

  if (
    typeof code !== 'string'         || code.length > 512 ||
    typeof codeVerifier !== 'string' || codeVerifier.length > 128 ||
    typeof redirectUri !== 'string'  || !redirectUri.startsWith('furkan://')
  ) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  try {
    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  redirectUri,
      code_verifier: codeVerifier,
    });

    const { data } = await axios.post(
      `${AUTH_BASE}/oauth2/token`,
      params.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, auth: basicAuth }
    );

    console.log('✅ Token exchange success');
    res.json({
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      id_token:      data.id_token,
      expires_in:    data.expires_in,
    });
  } catch (err) {
    console.error('❌ Exchange error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Token exchange failed', detail: err.response?.data });
  }
});

// ── Step 3: Refresh expired access token ──────────────────────
app.post('/api/auth/qf/refresh', authLimiter, async (req, res) => {
  const { refreshToken } = req.body;

  if (typeof refreshToken !== 'string' || refreshToken.length > 512) {
    return res.status(400).json({ error: 'Invalid refreshToken' });
  }

  try {
    const params = new URLSearchParams({
      grant_type:    'refresh_token',
      refresh_token: refreshToken,
    });

    const { data } = await axios.post(
      `${AUTH_BASE}/oauth2/token`,
      params.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, auth: basicAuth }
    );

    res.json({
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      expires_in:    data.expires_in,
    });
  } catch (err) {
    console.error('❌ Refresh error:', err.response?.data || err.message);
    res.status(401).json({ error: 'Token refresh failed — user must re-login' });
  }
});

// ── Step 4: Proxy QF User API calls ───────────────────────────
app.all('/api/qf/*path', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const accessToken = authHeader.split(' ')[1];
  const qfPath = '/' + req.params.path;  // ← use params.path instead of req.path

  try {
    const { data, status } = await axios({
      method: req.method,
      url:    `${API_BASE}/auth/v1${qfPath}`,
      params: req.query,
      data:   req.method !== 'GET' ? req.body : undefined,
      headers: {
        'x-auth-token': accessToken,
        'x-client-id':  CLIENT_ID,
        'Content-Type': 'application/json',
      },
    });
    res.status(status).json(data);
  } catch (err) {
    res.status(err.response?.status ?? 500).json(
      err.response?.data ?? { error: 'Proxy error' }
    );
  }
});

// ── Utility routes ────────────────────────────────────────────
app.get('/health', (req, res) =>
  res.json({ status: 'ok', env: USE_PRELIVE ? 'prelive' : 'production' })
);
app.get('/', (req, res) => res.send('Quran Auth Backend ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));