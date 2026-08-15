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

async function persistirRefresh(user_type, user_id, user_email, token, req, opts = {}) {
  const tokenHash = hashRefresh(token);
  const expiraEm = new Date(Date.now() + REFRESH_TTL_MS);
  const ip = (req && req.ip) || null;
  const ua = (req && req.headers['user-agent']) || null;
  // user_role e user_empresa_id são OPÇÕES (default null)
  // Se não vierem, ficam null e a migração preenche quando aplicável.
  const userRole = opts.user_role || null;
  const userEmpresaId = opts.user_empresa_id || null;
  await pool.query(
    `INSERT INTO refresh_tokens (user_type, user_id, user_email, token_hash, expira_em, ip_criacao, user_agent_criacao, user_role, user_empresa_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [user_type, user_id || null, user_email, tokenHash, expiraEm, ip, (ua || '').slice(0, 250), userRole, userEmpresaId]
  );
}

// Consome o refresh token de forma atômica.
// O UPDATE condicional garante que apenas uma requisição concorrente consiga
// consumir o mesmo token. A geração do novo par acontece somente depois deste
// retorno bem-sucedido.
async function consumirRefresh(token) {
  const tokenHash = hashRefresh(token);
  const { rows } = await pool.query(
    `UPDATE refresh_tokens
     SET revogado_em = NOW(), revogado_motivo = 'rotacionado'
     WHERE token_hash = $1
       AND revogado_em IS NULL
       AND expira_em > NOW()
     RETURNING id, user_type, user_id, user_email, expira_em,
               revogado_em, user_role, user_empresa_id`,
    [tokenHash]
  );
  if (rows.length === 0) return { valido: false, motivo: 'inexistente_ou_indisponivel' };
  return { valido: true, token: rows[0] };
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

// ─── Gestão de Sessões ────────────────────────────────────────────────────

/**
 * Lista sessões ativas de um usuário (não expiradas, não revogadas).
 */
async function listarSessoes(user_email, user_type) {
  const { rows } = await pool.query(
    `SELECT id, ip_criacao, user_agent_criacao, device_name, criado_em, expira_em
     FROM refresh_tokens
     WHERE user_email = $1
       AND user_type  = $2
       AND revogado_em IS NULL
       AND expira_em > NOW()
     ORDER BY criado_em DESC`,
    [user_email, user_type]
  );
  return rows;
}

/**
 * Revoga sessão por ID — verifica ownership (isolamento por user_email/user_type).
 */
async function revogarSessaoById(sessaoId, user_email, user_type) {
  const { rowCount } = await pool.query(
    `UPDATE refresh_tokens
     SET revogado_em = NOW(), revogado_motivo = 'sessao_encerrada_usuario'
     WHERE id = $1 AND user_email = $2 AND user_type = $3 AND revogado_em IS NULL`,
    [sessaoId, user_email, user_type]
  );
  return rowCount > 0;
}

/**
 * Revoga todas as sessões EXCETO o token atual (informado raw).
 */
async function revogarOutrasSessoes(user_email, user_type, tokenAtual) {
  const hashAtual = hashRefresh(tokenAtual);
  const { rowCount } = await pool.query(
    `UPDATE refresh_tokens
     SET revogado_em = NOW(), revogado_motivo = 'outras_sessoes_encerradas'
     WHERE user_email = $1
       AND user_type  = $2
       AND token_hash != $3
       AND revogado_em IS NULL`,
    [user_email, user_type, hashAtual]
  );
  return rowCount;
}

module.exports = {
  criarAccessToken,
  criarRefreshToken,
  hashRefresh,
  persistirRefresh,
  consumirRefresh,
  revogarRefresh,
  revogarTodosPorUsuario,
  listarSessoes,
  revogarSessaoById,
  revogarOutrasSessoes,
  ACCESS_TTL,
  REFRESH_TTL_MS
};