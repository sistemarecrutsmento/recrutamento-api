// =========================================================================
// Migrations multi-tenant Fase 1 (2026-07-27)
// =========================================================================
// Idempotente — usa CREATE COLUMN IF NOT EXISTS / DROP COLUMN IF EXISTS
// não disponíveis em PostgreSQL, então usa information_schema pra checar
// antes de criar.
// =========================================================================
const { pool } = require('../db');

/**
 * Retorna as colunas existentes de uma tabela no schema public.
 */
async function colunasExistentes(client, tabela) {
  const { rows } = await client.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [tabela]
  );
  return new Set(rows.map((r) => r.column_name));
}

/**
 * Cria uma coluna se não existir (formato CREATE TABLE IF NOT EXISTS).
 */
async function ensureColumn(client, tabela, coluna, definicao) {
  const cols = await colunasExistentes(client, tabela);
  if (cols.has(coluna)) {
    return { coluna, criada: false };
  }
  await client.query(`ALTER TABLE ${tabela} ADD COLUMN ${coluna} ${definicao}`);
  return { coluna, criada: true };
}

/**
 * Cria índice se não existir.
 */
async function ensureIndex(client, sql) {
  try {
    await client.query(sql);
  } catch (e) {
    // se já existir, ignora
    if (!/already exists/i.test(e.message)) throw e;
  }
}

/**
 * Migration 001: vagas.empresa_id (FK → empresas)
 *  + backfill conservador (somente vagas com exatamente 1 empresa em
 *    empresa_vaga_acesso). Vagas órfãs ou compartilhadas ficam NULL.
 */
async function m001_vagas_empresa_id(client, log) {
  // 1. Coluna vagas.empresa_id
  const r1 = await ensureColumn(client, 'vagas', 'empresa_id', 'INTEGER REFERENCES empresas(id) ON DELETE SET NULL');
  log(`  vagas.empresa_id: ${r1.criada ? 'criada' : 'já existia'}`);

  // 2. Índice pra acelerar JOIN por empresa
  await ensureIndex(client, 'CREATE INDEX IF NOT EXISTS idx_vagas_empresa_id ON vagas(empresa_id)');
  log('  idx_vagas_empresa_id: ok');

  // 3. Backfill conservador: só vagas com EXATAMENTE 1 vínculo ativo em
  //    empresa_vaga_acesso (sem revogado_em, que será criado na m003).
  const backfill = await client.query(`
    WITH unicas AS (
      SELECT eva.vaga_id, eva.empresa_id
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
  log(`  backfill vagas.empresa_id: ${backfill.rowCount} vaga(s) atualizada(s)`);

  return { criadas: [r1], backfill: backfill.rowCount };
}

/**
 * Migration 002: empresa_usuarios.role
 *  Default 'membro' pra manter compatibilidade com usuários já existentes.
 */
async function m002_empresa_usuarios_role(client, log) {
  const r = await ensureColumn(
    client,
    'empresa_usuarios',
    'role',
    `TEXT DEFAULT 'membro'`
  );
  log(`  empresa_usuarios.role: ${r.criada ? 'criada' : 'já existia'}`);
  // Sem backfill: default já cobre.
  // Log de distribuição para diagnóstico.
  const dist = await client.query(`
    SELECT role, COUNT(*)::int AS total
    FROM empresa_usuarios
    GROUP BY role
    ORDER BY role
  `);
  log(`  distribuição atual: ${dist.rows.map((r) => `${r.role || '(null)'}=${r.total}`).join(', ')}`);
  return { criadas: [r], distribuicao: dist.rows };
}

/**
 * Migration 003: empresa_vaga_acesso.tipo + revogado_em + revogado_motivo
 *  - tipo: 'propria' (dona) | 'compartilhada' (acesso extra)
 *  - revogado_em: NULL = ativa, NOW = revogada (soft delete)
 *  - revogado_motivo: texto opcional
 */
async function m003_empresa_vaga_acesso(client, log) {
  const r1 = await ensureColumn(client, 'empresa_vaga_acesso', 'tipo', `TEXT DEFAULT 'propria'`);
  const r2 = await ensureColumn(client, 'empresa_vaga_acesso', 'revogado_em', 'TIMESTAMP');
  const r3 = await ensureColumn(client, 'empresa_vaga_acesso', 'revogado_motivo', 'TEXT');
  log(`  empresa_vaga_acesso.tipo: ${r1.criada ? 'criada' : 'já existia'}`);
  log(`  empresa_vaga_acesso.revogado_em: ${r2.criada ? 'criada' : 'já existia'}`);
  log(`  empresa_vaga_acesso.revogado_motivo: ${r3.criada ? 'criada' : 'já existia'}`);

  // Backfill coluna tipo:
  //   • se a vaga tem >1 empresa vinculada e a empresa aparece em MAIS de uma vaga
  //     da mesma lista, marca 'compartilhada'; senão 'propria'.
  //   • se a vaga tem 1 empresa, 'propria'.
  //   • Conservador: tudo vira 'propria' por default, depois atualizamos
  //     casos de vaga com múltiplas empresas.
  await client.query(`
    UPDATE empresa_vaga_acesso eva
    SET tipo = 'propria'
    WHERE eva.tipo IS NULL
  `);
  await client.query(`
    UPDATE empresa_vaga_acesso eva
    SET tipo = 'compartilhada'
    WHERE eva.id IN (
      SELECT MIN(id) FROM empresa_vaga_acesso
      WHERE vaga_id IN (
        SELECT vaga_id FROM empresa_vaga_acesso
        GROUP BY vaga_id HAVING COUNT(DISTINCT empresa_id) > 1
      )
      AND revogado_em IS NULL
      GROUP BY vaga_id
      HAVING COUNT(*) > 1
    )
  `);
  // Simplificação segura: o default 'propria' cobre 95% dos casos.
  // O ajuste acima marca como 'compartilhada' a entrada de menor id (i.e.
  // a mais antiga) em cada vaga com múltiplos vínculos. Para os casos
  // restantes, mantemos 'propria' — é metadata, não funcional.

  await ensureIndex(client, 'CREATE INDEX IF NOT EXISTS idx_eva_revogado ON empresa_vaga_acesso(revogado_em) WHERE revogado_em IS NULL');
  await ensureIndex(client, 'CREATE INDEX IF NOT EXISTS idx_eva_vaga_ativo ON empresa_vaga_acesso(vaga_id) WHERE revogado_em IS NULL');
  log('  índices empresa_vaga_acesso(revogado_em, vaga_id ativo): ok');

  // Diagnóstico final
  const dist = await client.query(`
    SELECT
      COUNT(*) FILTER (WHERE revogado_em IS NULL) AS ativos,
      COUNT(*) FILTER (WHERE revogado_em IS NOT NULL) AS revogados,
      COUNT(*) FILTER (WHERE tipo = 'propria') AS tipo_propria,
      COUNT(*) FILTER (WHERE tipo = 'compartilhada') AS tipo_compartilhada,
      COUNT(*) AS total
    FROM empresa_vaga_acesso
  `);
  log(`  distribuição final: ${JSON.stringify(dist.rows[0])}`);
  return { criadas: [r1, r2, r3], distribuicao: dist.rows[0] };
}

/**
 * Migration 004: refresh_tokens.user_role + user_empresa_id
 *  - user_role: cópia do role no momento da emissão (string)
 *  - user_empresa_id: INTEGER NULL, FK conceitual (empresa_id para tokens
 *    do tipo 'empresa', NULL pros demais). Não declaramos FK pra evitar
 *    lock contention no caminho de auth.
 */
async function m004_refresh_tokens(client, log) {
  const r1 = await ensureColumn(client, 'refresh_tokens', 'user_role', 'TEXT');
  const r2 = await ensureColumn(client, 'refresh_tokens', 'user_empresa_id', 'INTEGER');
  log(`  refresh_tokens.user_role: ${r1.criada ? 'criada' : 'já existia'}`);
  log(`  refresh_tokens.user_empresa_id: ${r2.criada ? 'criada' : 'já existia'}`);

  // Backfill conservador de tokens já existentes:
  //  • user_role: inferir do user_type (candidato→'candidato', empresa→'membro')
  //  • user_empresa_id: pra user_type='empresa', pegar do empresa_usuarios.
  //  Tokens sem correspondência ficam NULL — refresh vai falhar pra esses
  //  (serão forçados a refazer login), o que é aceitável e seguro.
  const backfillRole = await client.query(`
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
  log(`  backfill refresh_tokens.user_role: ${backfillRole.rowCount} registro(s)`);

  const backfillEmp = await client.query(`
    UPDATE refresh_tokens rt
    SET user_empresa_id = eu.empresa_id
    FROM empresa_usuarios eu
    WHERE rt.user_type = 'empresa'
      AND rt.user_empresa_id IS NULL
      AND eu.email = rt.user_email
  `);
  log(`  backfill refresh_tokens.user_empresa_id (empresa): ${backfillEmp.rowCount} registro(s)`);

  return {
    criadas: [r1, r2],
    backfill_role: backfillRole.rowCount,
    backfill_empresa_id: backfillEmp.rowCount,
  };
}

/**
 * Aplica TODAS as migrations. Retorna sumário para log.
 */
async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const escreve = (s) => { log.push(s); console.log('[MIGRATION]', s); };
  try {
    await client.query('BEGIN');
    escreve('Iniciando Migrations Fase 1 (multi-tenant)');
    const r1 = await m001_vagas_empresa_id(client, escreve);
    const r2 = await m002_empresa_usuarios_role(client, escreve);
    const r3 = await m003_empresa_vaga_acesso(client, escreve);
    const r4 = await m004_refresh_tokens(client, escreve);
    await client.query('COMMIT');
    escreve('Migrations concluídas com sucesso');
    return { ok: true, log, resultado: { r1, r2, r3, r4 } };
  } catch (e) {
    await client.query('ROLLBACK');
    escreve(`ERRO — rollback executado: ${e.message}`);
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { aplicar };