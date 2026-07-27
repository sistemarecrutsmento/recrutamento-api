// =========================================================================
// Migration 002: Normalização de nomenclatura RBAC (28/07/2026)
// =========================================================================
// Resolve dois problemas detectados em revisão:
// 1. empresa_vaga_acesso.tipo estava como DEFAULT 'propria' mas código
//    inseria 'proprietaria' — alinha pra 'propria' como único valor canônico.
// 2. empresa_usuarios.role tinha DEFAULT 'membro' mas a coluna nunca foi
//    populada (INSERT nunca mencionava role), e o JWT usava o campo `cargo`
//    legado como se fosse role. Normaliza role pra 3 valores RBAC planejados:
//    'admin_empresa', 'recrutador', 'viewer'. Faz backfill a partir de `cargo`.
//
// Idempotente — checa antes de aplicar.
// =========================================================================
const { pool } = require('../db');

async function colunaExiste(client, tabela, coluna) {
  const { rows } = await client.query(
    `SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,
    [tabela, coluna]
  );
  return rows.length > 0;
}

async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const w = (s) => { log.push(s); console.log('[MIGRATION 002]', s); };

  try {
    w('Iniciando Migration 002 (normalização RBAC)');

    // ─────────────────────────────────────────────────────────────────
    // PASSO A: Normalizar empresa_vaga_acesso.tipo (DDL + UPDATE + CHECK)
    // ─────────────────────────────────────────────────────────────────
    if (await colunaExiste(client, 'empresa_vaga_acesso', 'tipo')) {
      w('  → empresa_vaga_acesso.tipo existe — normalizando');

      // Atualiza registros legados com valor 'proprietaria'
      const upd1 = await client.query(
        `UPDATE empresa_vaga_acesso
         SET tipo = 'propria'
         WHERE tipo NOT IN ('propria', 'compartilhada')`
      );
      w(`    ${upd1.rowCount} registro(s) com valores estranhos → 'propria'`);

      // Garante que DEFAULT é 'propria' (não 'proprietaria')
      await client.query(
        `ALTER TABLE empresa_vaga_acesso
         ALTER COLUMN tipo SET DEFAULT 'propria'`
      );
      w(`    DEFAULT agora é 'propria'`);

      // CHECK constraint que aceita APENAS 'propria' ou 'compartilhada'
      // Remove versões antigas
      await client.query(`
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'empresa_vaga_acesso_tipo_check'
          ) THEN
            ALTER TABLE empresa_vaga_acesso DROP CONSTRAINT empresa_vaga_acesso_tipo_check;
          END IF;
        END
        $$
      `);
      await client.query(`
        ALTER TABLE empresa_vaga_acesso
        ADD CONSTRAINT empresa_vaga_acesso_tipo_check
        CHECK (tipo IN ('propria', 'compartilhada'))
      `);
      w(`    CHECK constraint aplicado (tipo IN proprietaria/compartilhada)`);
    }

    // ─────────────────────────────────────────────────────────────────
    // PASSO B: Normalizar empresa_usuarios.role
    // ─────────────────────────────────────────────────────────────────
    if (await colunaExiste(client, 'empresa_usuarios', 'role')) {
      w('  → empresa_usuarios.role existe — normalizando RBAC');

      // Backfill: preenche role baseado em cargo se role está NULL ou 'membro'
      // (que era o default legado e nunca foi intencionalmente usado)
      const backfill = await client.query(`
        UPDATE empresa_usuarios
        SET role = CASE
          WHEN LOWER(cargo) IN ('admin', 'administrador', 'admin master', 'master', 'dono', 'gerente', 'socio', 'titular', 'diretor')
            THEN 'admin_empresa'
          WHEN LOWER(cargo) IN ('recrutador', 'rh', 'analista de rh', 'analista', 'h.r.', 'hr')
            THEN 'recrutador'
          ELSE 'viewer'
        END
        WHERE role IS NULL OR role = 'membro'
      `);
      w(`    ${backfill.rowCount} usuario(s) com role backfilled`);

      // Define default como 'recrutador' (não 'membro')
      await client.query(`
        ALTER TABLE empresa_usuarios
        ALTER COLUMN role SET DEFAULT 'recrutador'
      `);
      w(`    DEFAULT agora é 'recrutador'`);

      // CHECK constraint RBAC
      await client.query(`
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'empresa_usuarios_role_check'
          ) THEN
            ALTER TABLE empresa_usuarios DROP CONSTRAINT empresa_usuarios_role_check;
          END IF;
        END
        $$
      `);
      await client.query(`
        ALTER TABLE empresa_usuarios
        ADD CONSTRAINT empresa_usuarios_role_check
        CHECK (role IN ('admin_empresa', 'recrutador', 'viewer'))
      `);
      w(`    CHECK constraint aplicado (role IN admin_empresa/recrutador/viewer)`);
    }

    // ─────────────────────────────────────────────────────────────────
    // Diagnóstico final
    // ─────────────────────────────────────────────────────────────────
    const dist = await pool.query(`
      SELECT
        (SELECT array_to_json(array_agg(t ORDER BY t))
         FROM (SELECT DISTINCT tipo AS t FROM empresa_vaga_acesso) tipo_uniq) AS tipos_eva,
        (SELECT array_to_json(array_agg(r ORDER BY r))
         FROM (SELECT DISTINCT role AS r FROM empresa_usuarios WHERE role IS NOT NULL) role_uniq) AS roles,
        (SELECT COUNT(*)::int FROM empresa_vaga_acesso WHERE tipo IS NULL) AS tipo_null
    `);
    w(`Distribuição final: ${JSON.stringify(dist.rows[0])}`);

    w('Migration 002 concluída com sucesso');
    return { ok: true, log, resultado: dist.rows[0] };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    w(`ERRO FATAL: ${e.message}`);
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { aplicar };
