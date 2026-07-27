// =========================================================================
// TOKENS JWT — Access + Refresh (Etapa 2, 2026-07-27)
// =========================================================================
// Access token: curta duração (15min candidato, 30min admin).
// Refresh token: longa duração (7d), armazenado como hash (sha256) no DB.
// Suporta revogação individual e por usuário.
// =========================================================================
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('./db');

// Access tokens — curta duração pra minimizar janela de uso indevido se roubado.
const ACCESS_TTL = {
  candidato: '15m',
  admin: '30m',
  recrutador: '30m',
  empresa: '30m',
};
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 dias

function criarAccessToken(payload) {
  // payload deve ter: { email, tipo, id? }
  const tipo = payload.tipo || 'candidato';
  const ttl = ACCESS_TTL[tipo] || '15m';
  return jwt.sign(payload, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: ttl,
    issuer: 'vagasio-api'
  });
}

function criarRefreshToken() {
  // Token opaco (não é JWT). 32 bytes hex = 64 chars.
  return crypto.randomBytes(32).toString('hex');
}

function hashRefresh(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function persistirRefresh(user_type, user_id, user_email, token, req) {
  const tokenHash = hashRefresh(token);
  const expiraEm = new Date(Date.now() + REFRESH_TTL_MS);
  const ip = (req && (req.ip || req.headers['x-forwarded-for'])) || null;
  const ua = (req && req.headers['user-agent']) || null;
  await pool.query(
    `INSERT INTO refresh_tokens (user_type, user_id, user_email, token_hash, expira_em, ip_criacao, user_agent_criacao)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [user_type, user_id || null, user_email, tokenHash, expiraEm, ip, (ua || '').slice(0, 250)]
  );
}

// Valida + retorna o registro. Marca revogado se inválido.
async function consumirRefresh(token) {
  const tokenHash = hashRefresh(token);
  const { rows } = await pool.query(
    `SELECT id, user_type, user_id, user_email, expira_em, revogado_em
     FROM refresh_tokens WHERE token_hash = $1`,
    [tokenHash]
  );
  if (rows.length === 0) return { valido: false, motivo: 'inexistente' };
  const t = rows[0];
  if (t.revogado_em) return { valido: false, motivo: 'revogado' };
  if (new Date(t.expira_em) < new Date()) return { valido: false, motivo: 'expirado' };
  return { valido: true, token: t };
}

async function revogarRefresh(token, motivo = 'logout') {
  const tokenHash = hashRefresh(token);
  await pool.query(
    `UPDATE refresh_tokens SET revogado_em = NOW(), revogado_motivo = $2
     WHERE token_hash = $1 AND revogado_em IS NULL`,
    [tokenHash, motivo]
  );
}

// Revoga TODOS os refresh tokens de um usuário (logout global / troca de senha).
async function revogarTodosPorUsuario(user_email, user_type, motivo = 'password_changed') {
  await pool.query(
    `UPDATE refresh_tokens SET revogado_em = NOW(), revogado_motivo = $3
     WHERE user_email = $1 AND user_type = $2 AND revogado_em IS NULL`,
    [user_email, user_type, motivo]
  );
}

module.exports = {
  criarAccessToken,
  criarRefreshToken,
  hashRefresh,
  persistirRefresh,
  consumirRefresh,
  revogarRefresh,
  revogarTodosPorUsuario,
  ACCESS_TTL,
  REFRESH_TTL_MS
};