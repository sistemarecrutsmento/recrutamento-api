const { pool } = require('./db');

const CAMPOS_SENSIVEIS = [
  'senha', 'password', 'token', 'secret', 'refresh_token', 'codigo', '2fa',
  'cpf', 'rg', 'cnpj', 'mensagem', 'message', 'texto', 'content', 'arquivo_url'
];

function sanitizarMetadata(metadata) {
  if (typeof metadata === 'string') {
    try { metadata = JSON.parse(metadata); } catch (_) { return {}; }
  }
  if (!metadata || typeof metadata !== 'object') return {};
  const saida = {};
  for (const [chave, valor] of Object.entries(metadata)) {
    const k = String(chave).toLowerCase();
    if (CAMPOS_SENSIVEIS.some(item => k.includes(item))) continue;
    if (valor && typeof valor === 'object' && !Array.isArray(valor)) {
      saida[chave] = sanitizarMetadata(valor);
    } else {
      saida[chave] = valor;
    }
  }
  const json = JSON.stringify(saida);
  return Buffer.byteLength(json) <= 4096 ? saida : { _truncado: true };
}

/**
 * Registra um evento de auditoria no banco de dados.
 * NUNCA quebra o fluxo principal — erros são apenas logados no console.
 *
 * @param {object} req - Objeto de requisição Express (fornece ip, user-agent, user)
 * @param {string} action - Nome da ação (ex: 'login.success', 'admin.candidato.deleted')
 * @param {object} [opts={}] - Opções adicionais
 * @param {string} [opts.user_type] - Tipo do usuário (admin, recrutador, empresa, candidato)
 * @param {string} [opts.user_email] - Email do usuário (para debug)
 * @param {string} [opts.resource_type] - Tipo do recurso afetado (candidatura, vaga, etc)
 * @param {number} [opts.resource_id] - ID do recurso
 * @param {string} [opts.result] - Resultado: 'success' | 'failure' | 'blocked'
 * @param {object} [opts.metadata] - Dados adicionais (sem senhas/tokens/códigos 2FA)
 */
async function audit(req, action, opts = {}) {
  try {
    const user = req.user || {};
    await pool.query(`
      INSERT INTO audit_logs (
        user_id, user_type, user_email, action,
        resource_type, resource_id,
        ip, user_agent, result, metadata
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
      user.id || null,
      user.tipo || opts.user_type || 'anonymous',
      user.email || opts.user_email || null,
      action,
      opts.resource_type || null,
      opts.resource_id || null,
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null,
      (req.headers['user-agent'] || '').substring(0, 500),
      opts.result || 'success',
      JSON.stringify(sanitizarMetadata(opts.metadata))
    ]);
  } catch (e) {
    // NUNCA quebrar o fluxo por erro de log
    console.error('[AUDIT] erro ao registrar evento:', e.message);
  }
}

/**
 * Versão fire-and-forget para uso em middlewares síncronos (rate limit, auth).
 * Não usa await — o erro é capturado internamente.
 */
function auditFireAndForget(req, action, opts = {}) {
  audit(req, action, opts).catch(() => {});
}

module.exports = { audit, auditFireAndForget, sanitizarMetadata };