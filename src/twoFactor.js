/**
 * Módulo 2FA para Admin/Recrutador - Vagas.io
 * 
 * Gerencia códigos de verificação de 6 dígitos com:
 * - Geração cripto-aleatória (crypto.randomInt)
 * - Armazenamento de HASH (bcrypt), nunca o código puro
 * - Validade de 10 minutos
 * - Uso único (campo usado_em)
 * - Limite de tentativas de validação (5, depois invalida)
 * - Limite de reenvio (1 a cada 30s, máx 5/hora)
 * - Novo código invalida o anterior
 * - NUNCA loga o código, NUNCA retorna pela API
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool } = require('./db');

// ===== Configurações =====
const CODE_EXPIRY_MINUTES = 10;
const MAX_TENTATIVAS = 5;
const RESEND_COOLDOWN_MS = 30_000;  // 30s entre reenvios
const MAX_RESEND_PER_HOUR = 5;

// ===== Geração de código =====

/**
 * Gera um código de 6 dígitos criptograficamente aleatório.
 * @returns {string} Código de 6 dígitos (ex: "483921")
 */
function generateCode() {
  // crypto.randomInt(0, 1000000) → 0 a 999999
  const num = crypto.randomInt(0, 1000000);
  return String(num).padStart(6, '0');
}

/**
 * Gera um codigo_id (token público) único para o frontend.
 * @returns {string} codigo_id
 */
function generateCodigoId() {
  return crypto.randomBytes(24).toString('hex');
}

// ===== Criação de código 2FA =====

/**
 * Cria um novo código 2FA para o admin/recrutador.
 * Invalida qualquer código anterior não usado do mesmo admin.
 * Salva APENAS o hash bcrypt, nunca o código puro.
 * 
 * @param {number} adminId - ID do admin ou recrutador
 * @param {string} adminTipo - 'admin' ou 'recrutador'
 * @param {string} ip - IP da requisição (opcional)
 * @returns {Promise<{codigo_id: string, code: string}>} 
 *   codigo_id: token público para o frontend
 *   code: código de 6 dígitos (para enviar por e-mail, NUNCA logar)
 */
async function create2faCode(adminId, adminTipo = 'admin', ip = '') {
  // Invalida códigos anteriores não usados deste admin
  await pool.query(
    `UPDATE admin_2fa_codes SET usado_em = NOW()
     WHERE admin_id = $1 AND admin_tipo = $2 AND usado_em IS NULL
       AND expira_em > NOW()`,
    [adminId, adminTipo]
  );

  const codigoId = generateCodigoId();
  const code = generateCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiraEm = new Date(Date.now() + CODE_EXPIRY_MINUTES * 60 * 1000);

  await pool.query(
    `INSERT INTO admin_2fa_codes (codigo_id, admin_id, admin_tipo, code_hash, expira_em, ip)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [codigoId, adminId, adminTipo, codeHash, expiraEm, ip]
  );

  return { codigo_id: codigoId, code };
}

// ===== Verificação de código 2FA =====

/**
 * Verifica um código 2FA.
 * 
 * @param {string} codigoId - Token público do código
 * @param {string} code - Código de 6 dígitos fornecido pelo usuário
 * @returns {Promise<{valido: boolean, admin_id?: number, admin_tipo?: string, motivo?: string}>}
 */
async function verify2faCode(codigoId, code) {
  if (!codigoId || !code) {
    return { valido: false, motivo: 'Código e ID são obrigatórios' };
  }

  // Busca o registro pelo codigo_id
  const { rows } = await pool.query(
    `SELECT id, admin_id, admin_tipo, code_hash, tentativas, usado_em, expira_em
     FROM admin_2fa_codes
     WHERE codigo_id = $1`,
    [codigoId]
  );

  if (rows.length === 0) {
    return { valido: false, motivo: 'Código inválido' };
  }

  const record = rows[0];

  // Verifica se já foi usado
  if (record.usado_em) {
    return { valido: false, motivo: 'Código já utilizado' };
  }

  // Verifica se expirou
  if (new Date() > new Date(record.expira_em)) {
    return { valido: false, motivo: 'Código expirado' };
  }

  // Verifica limite de tentativas
  if (record.tentativas >= MAX_TENTATIVAS) {
    // Invalida o código por excesso de tentativas
    await pool.query(
      `UPDATE admin_2fa_codes SET usado_em = NOW() WHERE id = $1`,
      [record.id]
    );
    return { valido: false, motivo: 'Muitas tentativas. Solicite um novo código.' };
  }

  // Incrementa tentativas
  await pool.query(
    `UPDATE admin_2fa_codes SET tentativas = tentativas + 1 WHERE id = $1`,
    [record.id]
  );

  // Verifica o hash
  const ok = await bcrypt.compare(code, record.code_hash);
  if (!ok) {
    return { valido: false, motivo: 'Código inválido' };
  }

  // Marca como usado
  await pool.query(
    `UPDATE admin_2fa_codes SET usado_em = NOW() WHERE id = $1`,
    [record.id]
  );

  return { valido: true, admin_id: record.admin_id, admin_tipo: record.admin_tipo };
}

// ===== Reenvio de código 2FA =====

/**
 * Reenvia um novo código 2FA, invalidando o anterior.
 * Aplica rate limit: 1 req a cada 30s, máx 5/hora.
 * 
 * @param {string} codigoId - Token público do código a ser substituído
 * @param {string} ip - IP da requisição
 * @returns {Promise<{ok: boolean, codigo_id?: string, code?: string, motivo?: string, cooldown?: number}>}
 */
async function resend2faCode(codigoId, ip = '') {
  if (!codigoId) {
    return { ok: false, motivo: 'codigo_id é obrigatório' };
  }

  // Busca o registro atual
  const { rows } = await pool.query(
    `SELECT id, admin_id, admin_tipo, criado_em
     FROM admin_2fa_codes
     WHERE codigo_id = $1`,
    [codigoId]
  );

  if (rows.length === 0) {
    return { ok: false, motivo: 'Código não encontrado. Faça login novamente.' };
  }

  const record = rows[0];

  // Rate limit: 1 requisição a cada 30s
  const msSinceCreation = Date.now() - new Date(record.criado_em).getTime();
  if (msSinceCreation < RESEND_COOLDOWN_MS) {
    const waitSec = Math.ceil((RESEND_COOLDOWN_MS - msSinceCreation) / 1000);
    return { ok: false, motivo: `Aguarde ${waitSec}s para reenviar.`, cooldown: waitSec };
  }

  // Rate limit: máx 5 reenvios por hora por admin
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const { rows: countRows } = await pool.query(
    `SELECT COUNT(*)::int as count
     FROM admin_2fa_codes
     WHERE admin_id = $1 AND admin_tipo = $2 AND criado_em > $3`,
    [record.admin_id, record.admin_tipo, oneHourAgo]
  );
  if (countRows[0].count >= MAX_RESEND_PER_HOUR) {
    return { ok: false, motivo: 'Muitos reenvios. Tente novamente em 1 hora.' };
  }

  // Gera novo código
  return create2faCode(record.admin_id, record.admin_tipo, ip);
}

module.exports = {
  generateCode,
  generateCodigoId,
  create2faCode,
  verify2faCode,
  resend2faCode
};