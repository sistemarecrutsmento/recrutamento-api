// =========================================================================
// Migration 003 — Portal Público das Empresas (Fase 5, 28/07/2026)
// =========================================================================
// Idempotente. Adiciona colunas públicas em `empresas` (descricao, cidade,
// estado, site, setor, tamanho) + faz backfill de `vagas.empresa_id`
// baseado em match de nome para vagas órfãs (que não tinham acesso único
// na empresa_vaga_acesso no momento do backfill da migration 001).
//
// Estes dados são OPCIONAIS no frontend: se a empresa não preencheu
// descricao/cidade/etc, a UI simplesmente não exibe.
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

async function m005_empresas_publico(client, log) {
  const c1 = await ensureColumn(client, 'empresas', 'descricao', 'TEXT');
  const c2 = await ensureColumn(client, 'empresas', 'cidade', 'TEXT');
  const c3 = await ensureColumn(client, 'empresas', 'estado', 'TEXT');
  const c4 = await ensureColumn(client, 'empresas', 'site', 'TEXT');
  const c5 = await ensureColumn(client, 'empresas', 'setor', 'TEXT');
  const c6 = await ensureColumn(client, 'empresas', 'tamanho', 'TEXT');
  log(`  empresas.descricao: ${c1.criada ? 'criada' : 'já existia'}`);
  log(`  empresas.cidade: ${c2.criada ? 'criada' : 'já existia'}`);
  log(`  empresas.estado: ${c3.criada ? 'criada' : 'já existia'}`);
  log(`  empresas.site: ${c4.criada ? 'criada' : 'já existia'}`);
  log(`  empresas.setor: ${c5.criada ? 'criada' : 'já existia'}`);
  log(`  empresas.tamanho: ${c6.criada ? 'criada' : 'já existia'}`);
  return { criadas: [c1, c2, c3, c4, c5, c6] };
}

// Backfill de vagas.empresa_id baseado em match de nome
// (para vagas que ficaram com empresa_id NULL após migration 001)
async function m005_backfill_vagas_por_nome(client, log) {
  const up = await client.query(`
    UPDATE vagas v
    SET empresa_id = (
      SELECT e.id FROM empresas e
      WHERE e.nome = v.empresa
        AND e.ativo = true
      LIMIT 1
    )
    WHERE v.empresa_id IS NULL
      AND v.empresa IS NOT NULL
    RETURNING v.id, v.empresa_id
  `);
  log(`  backfill vagas.empresa_id por nome: ${up.rowCount} vaga(s) atualizada(s)`);
  return { atualizadas: up.rowCount };
}

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
  const escreve = (s) => { log.push(s); console.log('[MIGRATION 003]', s); };
  try {
    escreve('Iniciando Migration 003 (Fase 5 — portal público)');

    // DDL fora de transação
    await runStep('m005_cols', () => m005_empresas_publico(client, escreve), escreve);

    // DML dentro de transação
    await client.query('BEGIN');
    try {
      await runStep('m005_backfill', () => m005_backfill_vagas_por_nome(client, escreve), escreve);
      await client.query('COMMIT');
      escreve('Backfill commitado');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    }

    // Diagnóstico final
    const dist = await client.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NOT NULL)::int AS vagas_com_dona,
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NULL)::int AS vagas_sem_dona,
        (SELECT COUNT(*) FROM empresas WHERE descricao IS NOT NULL)::int AS empresas_com_descricao,
        (SELECT COUNT(*) FROM empresas WHERE ativo = true)::int AS empresas_ativas
    `);
    escreve(`Distribuição final: ${JSON.stringify(dist.rows[0])}`);

    escreve('Migration 003 concluída com sucesso');
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