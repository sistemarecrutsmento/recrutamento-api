// Migration 007 — Fase 10: Autenticação, Sessões e 2FA Empresa
//
// Aplica:
//   1. admin_2fa_codes — garante tabela com CREATE IF NOT EXISTS (era criada via seed manual)
//   2. empresa_usuarios — colunas de 2FA (totp_secret, totp_ativo, totp_backup_codes)
//   3. refresh_tokens — coluna device_name (UX da tela de sessões)
//   4. password_resets — coluna ip_solicitacao (auditoria)
//   5. Índice performance sessões por user_id + user_type

async function ensureCol(client, tabela, coluna, def) {
  const { rowCount } = await client.query(
    `SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,
    [tabela, coluna]
  );
  if (rowCount === 0) {
    await client.query(`ALTER TABLE ${tabela} ADD COLUMN ${coluna} ${def}`);
    return true;
  }
  return false;
}

async function aplicar(client, log = console.log) {
  // ─── 1. admin_2fa_codes ─────────────────────────────────────────────────
  // Garante que a tabela existe (pode ter sido criada em versão anterior de forma
  // não rastreada). O CREATE IF NOT EXISTS é idempotente.
  await client.query(`
    CREATE TABLE IF NOT EXISTS admin_2fa_codes (
      id          SERIAL PRIMARY KEY,
      codigo_id   TEXT UNIQUE NOT NULL,
      admin_id    INTEGER NOT NULL,
      admin_tipo  TEXT NOT NULL DEFAULT 'admin',
      code_hash   TEXT NOT NULL,
      expira_em   TIMESTAMP NOT NULL,
      usado_em    TIMESTAMP,
      tentativas  INTEGER DEFAULT 0,
      ip          TEXT,
      criado_em   TIMESTAMP DEFAULT NOW()
    )
  `);
  await client.query(`
    CREATE INDEX IF NOT EXISTS idx_2fa_admin ON admin_2fa_codes(admin_id, admin_tipo, expira_em DESC)
  `);
  await client.query(`
    CREATE INDEX IF NOT EXISTS idx_2fa_codigo ON admin_2fa_codes(codigo_id)
  `);
  log('admin_2fa_codes: tabela e índices criados/confirmados');

  // ─── 2. empresa_usuarios — colunas 2FA (TOTP) ───────────────────────────
  // totp_secret: segredo base32 usado para gerar/verificar TOTP
  // totp_ativo: se 2FA está habilitado para este usuário
  // totp_backup_codes: array JSON de hashes de códigos de backup (uso único)
  const c1 = await ensureCol(client, 'empresa_usuarios', 'totp_secret', 'TEXT');
  const c2 = await ensureCol(client, 'empresa_usuarios', 'totp_ativo', 'BOOLEAN DEFAULT false');
  const c3 = await ensureCol(client, 'empresa_usuarios', 'totp_backup_codes', "TEXT DEFAULT '[]'");
  const c4 = await ensureCol(client, 'empresa_usuarios', 'totp_ativado_em', 'TIMESTAMP');
  log(`empresa_usuarios 2FA: totp_secret=${c1?'criada':'existe'} totp_ativo=${c2?'criada':'existe'} backup=${c3?'criada':'existe'} ativado_em=${c4?'criada':'existe'}`);

  // ─── 3. refresh_tokens — device_name para UX de sessões ─────────────────
  const c5 = await ensureCol(client, 'refresh_tokens', 'device_name', 'TEXT');
  log(`refresh_tokens.device_name: ${c5 ? 'criada' : 'já existia'}`);

  // ─── 4. password_resets — ip_solicitacao para auditoria ─────────────────
  const c6 = await ensureCol(client, 'password_resets', 'ip_solicitacao', 'TEXT');
  log(`password_resets.ip_solicitacao: ${c6 ? 'criada' : 'já existia'}`);

  // ─── 5. Índice de performance: refresh_tokens por user_id + user_type ────
  await client.query(`
    CREATE INDEX IF NOT EXISTS idx_refresh_userid ON refresh_tokens(user_id, user_type, expira_em DESC)
  `);
  log('refresh_tokens: índice por user_id criado/confirmado');

  return { ok: true };
}

module.exports = { aplicar };
