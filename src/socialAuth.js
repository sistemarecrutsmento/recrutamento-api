'use strict';

const crypto = require('crypto');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const { pool } = require('./db');
const { criarAccessToken, criarRefreshToken, persistirRefresh } = require('./token');
const { audit } = require('./audit');

const API_PUBLIC_URL = String(process.env.API_PUBLIC_URL || 'https://recrutamento-api-novo.onrender.com').replace(/\/$/, '');
const FRONTEND_CANDIDATE_URL = String(process.env.CANDIDATE_FRONTEND_URL || `${process.env.FRONTEND_URL || 'https://vagasio.com.br'}/candidato/`).replace(/\/$/, '') + '/';
const STATE_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 2 * 60 * 1000;

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function redirectUri(provider) {
  const envKey = provider === 'google' ? 'GOOGLE_OAUTH_REDIRECT_URI' : 'APPLE_OAUTH_REDIRECT_URI';
  return process.env[envKey] || `${API_PUBLIC_URL}/api/auth/social/${provider}/callback`;
}

function config(provider) {
  if (provider === 'google') {
    return {
      clientId: process.env.GOOGLE_OAUTH_CLIENT_ID,
      clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      redirectUri: redirectUri(provider),
      missing: ['GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET'].filter(k => !process.env[k])
    };
  }
  return {
    clientId: process.env.APPLE_CLIENT_ID,
    teamId: process.env.APPLE_TEAM_ID,
    keyId: process.env.APPLE_KEY_ID,
    privateKey: String(process.env.APPLE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    redirectUri: redirectUri(provider),
    missing: ['APPLE_CLIENT_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY'].filter(k => !process.env[k])
  };
}

function providerLabel(provider) {
  return provider === 'google' ? 'Google' : 'Apple';
}

function errorRedirect(message) {
  return `${FRONTEND_CANDIDATE_URL}?social_error=${encodeURIComponent(message)}`;
}

async function start(provider, req, res) {
  const cfg = config(provider);
  if (cfg.missing.length) {
    await audit(req, 'social_auth.start_blocked', { result: 'failure', metadata: { provider, missing: cfg.missing } });
    return res.status(503).json({
      ok: false,
      code: 'social_not_configured',
      erro: `Login com ${providerLabel(provider)} ainda não está configurado neste ambiente.`
    });
  }

  const state = randomToken(32);
  const codeVerifier = randomToken(48);
  const nonce = randomToken(24);
  await pool.query(
    `INSERT INTO candidato_social_states (state_hash, provider, code_verifier, nonce, expira_em) VALUES ($1,$2,$3,$4,$5)`,
    [hash(state), provider, codeVerifier, nonce, new Date(Date.now() + STATE_TTL_MS)]
  );
  await pool.query(`DELETE FROM candidato_social_states WHERE expira_em < NOW()`);

  const challenge = b64url(crypto.createHash('sha256').update(codeVerifier).digest());
  const params = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    response_type: 'code',
    scope: provider === 'google' ? 'openid email profile' : 'name email',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    nonce
  });
  if (provider === 'apple') params.set('response_mode', 'form_post');
  const base = provider === 'google'
    ? 'https://accounts.google.com/o/oauth2/v2/auth'
    : 'https://appleid.apple.com/auth/authorize';
  return res.json({ ok: true, provider, url: `${base}?${params.toString()}` });
}

async function consumeState(provider, state) {
  if (!state || typeof state !== 'string' || state.length < 20) return null;
  const result = await pool.query(
    `DELETE FROM candidato_social_states WHERE state_hash=$1 AND provider=$2 AND expira_em > NOW() RETURNING code_verifier, nonce`,
    [hash(state), provider]
  );
  return result.rows[0] || null;
}

async function exchangeGoogle(code, verifier, cfg, expectedNonce = null) {
  const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
    code,
    client_id: cfg.clientId,
    client_secret: cfg.clientSecret,
    redirect_uri: cfg.redirectUri,
    grant_type: 'authorization_code',
    code_verifier: verifier
  }).toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  const idToken = tokenResponse.data?.id_token;
  if (!idToken) throw new Error('Google não retornou id_token');
  const client = new google.auth.OAuth2(cfg.clientId);
  const ticket = await client.verifyIdToken({ idToken, audience: cfg.clientId });
  const p = ticket.getPayload();
  if (!p?.sub || !p.email || p.email_verified !== true) throw new Error('Identidade Google não verificada');
  if (expectedNonce && p.nonce !== expectedNonce) throw new Error('Nonce Google inválido');
  return { subject: p.sub, email: p.email.toLowerCase(), emailVerified: true, name: p.name || p.given_name || 'Candidato' };
}

function appleClientSecret(cfg) {
  return jwt.sign({}, cfg.privateKey, {
    algorithm: 'ES256',
    keyid: cfg.keyId,
    issuer: cfg.teamId,
    subject: cfg.clientId,
    audience: 'https://appleid.apple.com',
    expiresIn: '5m'
  });
}

function jwkToPublicKey(jwk) {
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

async function verifyAppleIdToken(idToken, cfg, expectedNonce = null) {
  const decoded = jwt.decode(idToken, { complete: true });
  const kid = decoded?.header?.kid;
  if (!kid) throw new Error('Apple id_token sem kid');
  const keys = (await axios.get('https://appleid.apple.com/auth/keys', { timeout: 10000 })).data?.keys || [];
  const jwk = keys.find(k => k.kid === kid);
  if (!jwk) throw new Error('Chave pública Apple não encontrada');
  const p = jwt.verify(idToken, jwkToPublicKey(jwk), {
    algorithms: ['RS256'],
    issuer: 'https://appleid.apple.com',
    audience: cfg.clientId
  });
  if (!p?.sub) throw new Error('Identidade Apple inválida');
  if (expectedNonce && p.nonce !== expectedNonce) throw new Error('Nonce Apple inválido');
  return p;
}

async function exchangeApple(code, verifier, cfg, userInfo = null, expectedNonce = null) {
  const tokenResponse = await axios.post('https://appleid.apple.com/auth/token', new URLSearchParams({
    client_id: cfg.clientId,
    client_secret: appleClientSecret(cfg),
    code,
    grant_type: 'authorization_code',
    redirect_uri: cfg.redirectUri,
    code_verifier: verifier
  }).toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  const p = await verifyAppleIdToken(tokenResponse.data?.id_token, cfg, expectedNonce);
  const email = p.email ? String(p.email).toLowerCase() : null;
  const nameObj = userInfo?.name || {};
  const name = [nameObj.firstName, nameObj.lastName].filter(Boolean).join(' ').trim() || 'Candidato';
  return { subject: p.sub, email, emailVerified: p.email_verified === true || p.email_verified === 'true', name };
}

async function findOrCreateCandidate(provider, profile, req) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const linked = await client.query(
      `SELECT c.id, c.email, c.nome FROM candidato_oauth_identities i JOIN candidatos c ON c.id=i.candidato_id WHERE i.provider=$1 AND i.subject=$2 FOR UPDATE`,
      [provider, profile.subject]
    );
    let candidate = linked.rows[0] || null;

    if (!candidate && profile.email) {
      const byEmail = await client.query(`SELECT id,email,nome FROM candidatos WHERE LOWER(email)=LOWER($1) FOR UPDATE`, [profile.email]);
      candidate = byEmail.rows[0] || null;
      if (!candidate) {
        const conflicts = await client.query(
          `SELECT 1 FROM admins WHERE LOWER(email)=LOWER($1)
           UNION ALL SELECT 1 FROM recrutadores WHERE LOWER(email)=LOWER($1)
           UNION ALL SELECT 1 FROM empresas WHERE LOWER(email_principal)=LOWER($1)
           UNION ALL SELECT 1 FROM empresa_usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1`,
          [profile.email]
        );
        if (conflicts.rowCount) throw Object.assign(new Error('E-mail já pertence a outro tipo de usuário'), { code: 'EMAIL_CONFLICT' });
        const created = await client.query(
          `INSERT INTO candidatos (email,nome,email_verificado,senha_hash) VALUES ($1,$2,$3,NULL) RETURNING id,email,nome`,
          [profile.email, profile.name || 'Candidato', !!profile.emailVerified]
        );
        candidate = created.rows[0];
      }
    }
    if (!candidate) throw Object.assign(new Error('O provedor não retornou um e-mail utilizável'), { code: 'SOCIAL_EMAIL_REQUIRED' });

    await client.query(
      `INSERT INTO candidato_oauth_identities (candidato_id,provider,subject,email,atualizado_em)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (provider,subject) DO UPDATE SET email=EXCLUDED.email, atualizado_em=NOW()`,
      [candidate.id, provider, profile.subject, profile.email || candidate.email]
    );
    await client.query('COMMIT');
    return candidate;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function callback(provider, req, res) {
  const state = req.method === 'POST' ? req.body?.state : req.query?.state;
  const code = req.method === 'POST' ? req.body?.code : req.query?.code;
  const providerError = req.method === 'POST' ? req.body?.error : req.query?.error;
  if (providerError) return res.redirect(errorRedirect('Login cancelado ou recusado.'));
  const stateRow = await consumeState(provider, state);
  if (!stateRow || !code) return res.redirect(errorRedirect('Não foi possível validar o retorno do login.'));
  try {
    const cfg = config(provider);
    let appleUser = null;
    if (provider === 'apple' && req.body?.user) {
      try { appleUser = typeof req.body.user === 'string' ? JSON.parse(req.body.user) : req.body.user; } catch (_) { appleUser = null; }
    }
    const profile = provider === 'google'
      ? await exchangeGoogle(code, stateRow.code_verifier, cfg, stateRow.nonce)
      : await exchangeApple(code, stateRow.code_verifier, cfg, appleUser, stateRow.nonce);
    const candidate = await findOrCreateCandidate(provider, profile, req);
    const oneTimeCode = randomToken(32);
    await pool.query(
      `INSERT INTO candidato_social_codes (code_hash,candidato_id,expira_em) VALUES ($1,$2,$3)`,
      [hash(oneTimeCode), candidate.id, new Date(Date.now() + CODE_TTL_MS)]
    );
    await audit(req, 'social_auth.callback', { result: 'success', resource_type: 'candidato', resource_id: candidate.id, metadata: { provider } });
    return res.redirect(`${FRONTEND_CANDIDATE_URL}?social_code=${encodeURIComponent(oneTimeCode)}`);
  } catch (e) {
    console.error(`[SOCIAL ${provider}] callback falhou:`, e.message);
    await audit(req, 'social_auth.callback', { result: 'failure', metadata: { provider, motivo: e.code || 'provider_error' } });
    const msg = e.code === 'SOCIAL_EMAIL_REQUIRED'
      ? 'O provedor não compartilhou um e-mail utilizável.'
      : e.code === 'EMAIL_CONFLICT'
        ? 'Este e-mail já pertence a outro tipo de conta.'
        : 'Não foi possível concluir o login social.';
    return res.redirect(errorRedirect(msg));
  }
}

async function exchange(req, res) {
  const rawCode = req.body?.code;
  if (!rawCode || typeof rawCode !== 'string') return res.status(400).json({ erro: 'Código social ausente' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      `SELECT c.id,c.email,c.nome FROM candidato_social_codes s JOIN candidatos c ON c.id=s.candidato_id
       WHERE s.code_hash=$1 AND s.consumido_em IS NULL AND s.expira_em > NOW() FOR UPDATE`,
      [hash(rawCode)]
    );
    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(401).json({ erro: 'Código social inválido ou expirado' });
    }
    await client.query(`UPDATE candidato_social_codes SET consumido_em=NOW() WHERE code_hash=$1`, [hash(rawCode)]);
    const candidate = found.rows[0];
    const accessToken = criarAccessToken({ id: candidate.id, email: candidate.email, tipo: 'candidato' });
    const refreshToken = criarRefreshToken();
    await persistirRefresh('candidato', candidate.id, candidate.email, refreshToken, req, { user_role: 'candidato' });
    await client.query('COMMIT');
    return res.json({ ok: true, token: accessToken, refreshToken, candidato: candidate });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[SOCIAL exchange]', e.message);
    return res.status(500).json({ erro: 'Não foi possível criar sua sessão' });
  } finally {
    client.release();
  }
}

module.exports = { start, callback, exchange };
