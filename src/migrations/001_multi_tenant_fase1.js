// =========================================================================
// Migrations multi-tenant Fase 1 (2026-07-27)
// =========================================================================
// Idempotente — checa antes de criar colunas.
// Roda no boot do servidor (chamado de db.init()).
// =========================================================================
const { pool } = require('../db');

async function colunasExistentes(client, tabela) {
  const { rows } = await client.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [tabela]
  );
  return new Set(rows.map((r) => r.column_name));
}

async function ensureColumn(client, tabela, coluna, definicao) {
  const cols = await colunasExistentes(client, tabela);
  if (cols.has(coluna)) return { coluna, criada: false };
  await client.query(`ALTER TABLE ${tabela} ADD COLUMN ${coluna} ${definicao}`);
  return { coluna, criada: true };
}

async function ensureIndex(client, sql) {
  try { await client.query(sql); }
  catch (e) { if (!/already exists/i.test(e.message)) throw e; }
}

// ──────────────────────────────────────────────────────────────────────
// Migration 001 — vagas.empresa_id (FK → empresas)
// ──────────────────────────────────────────────────────────────────────
async function m001_vagas_empresa_id(client, log) {
  const r1 = await ensureColumn(client, 'vagas', 'empresa_id',
    'INTEGER REFERENCES empresas(id) ON DELETE SET NULL');
  log(`  vagas.empresa_id: ${r1.criada ? 'criada' : 'já existia'}`);
  await ensureIndex(client,
    'CREATE INDEX IF NOT EXISTS idx_vagas_empresa_id ON vagas(empresa_id)');
  log('  idx_vagas_empresa_id: ok');
  return { criadas: [r1] };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 002 — empresa_usuarios.role
// ──────────────────────────────────────────────────────────────────────
async function m002_empresa_usuarios_role(client, log) {
  const r = await ensureColumn(client, 'empresa_usuarios', 'role',
    "TEXT DEFAULT 'membro'");
  log(`  empresa_usuarios.role: ${r.criada ? 'criada' : 'já existia'}`);
  return { criadas: [r] };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 003a — empresa_vaga_acesso: 3 novas colunas
// ──────────────────────────────────────────────────────────────────────
async function m003_empresa_vaga_acesso_cols(client, log) {
  const r1 = await ensureColumn(client, 'empresa_vaga_acesso', 'tipo',
    "TEXT DEFAULT 'propria'");
  const r2 = await ensureColumn(client, 'empresa_vaga_acesso', 'revogado_em', 'TIMESTAMP');
  const r3 = await ensureColumn(client, 'empresa_vaga_acesso', 'revogado_motivo', 'TEXT');
  log(`  empresa_vaga_acesso.tipo: ${r1.criada ? 'criada' : 'já existia'}`);
  log(`  empresa_vaga_acesso.revogado_em: ${r2.criada ? 'criada' : 'já existia'}`);
  log(`  empresa_vaga_acesso.revogado_motivo: ${r3.criada ? 'criada' : 'já existia'}`);
  await ensureIndex(client,
    'CREATE INDEX IF NOT EXISTS idx_eva_revogado ON empresa_vaga_acesso(revogado_em) WHERE revogado_em IS NULL');
  log('  idx_eva_revogado: ok');
  return { criadas: [r1, r2, r3] };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 003b — backfill tipo (propria/compartilhada)
// ──────────────────────────────────────────────────────────────────────
async function m003_backfill_tipo(client, log) {
  const up1 = await client.query(`
    UPDATE empresa_vaga_acesso
    SET tipo = 'propria'
    WHERE tipo IS NULL
  `);
  const up2 = await client.query(`
    UPDATE empresa_vaga_acesso eva
    SET tipo = 'compartilhada'
    WHERE eva.tipo = 'propria'
      AND eva.vaga_id IN (
        SELECT vaga_id FROM empresa_vaga_acesso
        GROUP BY vaga_id HAVING COUNT(DISTINCT empresa_id) > 1
      )
  `);
  log(`  backfill tipo: ${up1.rowCount} próprias + ${up2.rowCount} compartilhadas`);
  return { propria: up1.rowCount, compartilhada: up2.rowCount };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 004a — refresh_tokens: 2 novas colunas
// ──────────────────────────────────────────────────────────────────────
async function m004_refresh_tokens_cols(client, log) {
  const r1 = await ensureColumn(client, 'refresh_tokens', 'user_role', 'TEXT');
  const r2 = await ensureColumn(client, 'refresh_tokens', 'user_empresa_id', 'INTEGER');
  log(`  refresh_tokens.user_role: ${r1.criada ? 'criada' : 'já existia'}`);
  log(`  refresh_tokens.user_empresa_id: ${r2.criada ? 'criada' : 'já existia'}`);
  return { criadas: [r1, r2] };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 004b — backfill user_role e user_empresa_id em tokens antigos
// ──────────────────────────────────────────────────────────────────────
async function m004_backfill_tokens(client, log) {
  const upRole = await client.query(`
    UPDATE refresh_tokens
    SET user_role = CASE
      WHEN user_type = 'candidato' THEN 'candidato'
      WHEN user_type = 'recrutador' THEN 'recrutador'
      WHEN user_type = 'admin' THEN 'admin'
      WHEN user_type = 'empresa' THEN 'membro'
      ELSE 'desconhecido'
    END
    WHERE user_role IS NULL
  `);
  const upEmp = await client.query(`
    UPDATE refresh_tokens rt
    SET user_empresa_id = eu.empresa_id
    FROM empresa_usuarios eu
    WHERE rt.user_type = 'empresa'
      AND rt.user_empresa_id IS NULL
      AND eu.email = rt.user_email
  `);
  log(`  backfill user_role: ${upRole.rowCount} | user_empresa_id: ${upEmp.rowCount}`);
  return { role: upRole.rowCount, empresa: upEmp.rowCount };
}

// ──────────────────────────────────────────────────────────────────────
// Migration 001b — backfill vagas.empresa_id (conservador)
// ──────────────────────────────────────────────────────────────────────
async function m001_backfill_vagas(client, log) {
  const up = await client.query(`
    WITH unicas AS (
      SELECT eva.vaga_id, MIN(eva.empresa_id) AS empresa_id
      FROM empresa_vaga_acesso eva
      GROUP BY eva.vaga_id
      HAVING COUNT(DISTINCT eva.empresa_id) = 1
    )
    UPDATE vagas v
    SET empresa_id = unicas.empresa_id
    FROM unicas
    WHERE v.id = unicas.vaga_id
      AND v.empresa_id IS NULL
    RETURNING v.id
  `);
  log(`  backfill vagas.empresa_id: ${up.rowCount} vaga(s) atualizada(s)`);
  return { atualizadas: up.rowCount };
}

// ──────────────────────────────────────────────────────────────────────
// Aplicar TODAS as migrations
// ──────────────────────────────────────────────────────────────────────
async function runStep(nome, fn, log) {
  try {
    const r = await fn();
    log(`  ✅ ${nome}: ok`);
    return r;
  } catch (e) {
    log(`  ❌ ${nome} FALHOU: ${e.message}`);
    throw e;
  }
}

async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const escreve = (s) => { log.push(s); console.log('[MIGRATION]', s); };
  try {
    escreve('Iniciando Migrations Fase 1 (multi-tenant)');

    // DDL fora de transação
    await runStep('m001_cols', () => m001_vagas_empresa_id(client, escreve), escreve);
    await runStep('m002_cols', () => m002_empresa_usuarios_role(client, escreve), escreve);
    await runStep('m003_cols', () => m003_empresa_vaga_acesso_cols(client, escreve), escreve);
    await runStep('m004_cols', () => m004_refresh_tokens_cols(client, escreve), escreve);

    // DML dentro de transação
    await client.query('BEGIN');
    try {
      await runStep('m003_backfill', () => m003_backfill_tipo(client, escreve), escreve);
      await runStep('m004_backfill', () => m004_backfill_tokens(client, escreve), escreve);
      await runStep('m001_backfill', () => m001_backfill_vagas(client, escreve), escreve);
      await client.query('COMMIT');
      escreve('Backfills commitados');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    }

    // Diagnóstico final
    const dist = await client.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NOT NULL)::int AS vagas_com_dona,
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NULL)::int AS vagas_sem_dona,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE tipo = 'propria')::int AS eva_propria,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE tipo = 'compartilhada')::int AS eva_compartilhada,
        (SELECT COUNT(*) FROM refresh_tokens WHERE user_role IS NOT NULL)::int AS rt_com_role,
        (SELECT COUNT(*) FROM refresh_tokens WHERE user_empresa_id IS NOT NULL)::int AS rt_com_empresa
    `);
    escreve(`Distribuição final: ${JSON.stringify(dist.rows[0])}`);

    escreve('Migrations concluídas com sucesso');
    return { ok: true, log, resultado: dist.rows[0] };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    escreve(`ERRO FATAL: ${e.message}`);
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { aplicar };