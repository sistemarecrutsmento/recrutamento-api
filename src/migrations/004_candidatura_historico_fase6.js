// =========================================================================
// Migration 004 — Candidatura Histórico (Fase 6, 28/07/2026)
// =========================================================================
// Cria tabela `candidatura_historico` (append-only) para registrar
// movimentações de etapa/status com auditoria.
//
// Requisitos:
//   - Idempotente (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS).
//   - Sem DROP destrutivo.
//   - Compatível com PostgreSQL.
//   - NÃO remove a coluna `historico` (JSONB) já existente — a nova tabela
//     é uma visão desnormalizada/consultável; as duas conviverão.
//
// Schema:
//   id              BIGSERIAL PRIMARY KEY
//   candidatura_id  BIGINT NOT NULL FK -> candidaturas(id)
//   vaga_id         BIGINT NOT NULL FK -> vagas(id) (desnormalizado p/ tenant query)
//   empresa_id      BIGINT NOT NULL FK -> empresas(id) (desnormalizado p/ tenant query)
//   etapa_anterior  INT (nullable)
//   etapa_nova      INT NOT NULL
//   status_anterior VARCHAR(40)
//   status_novo     VARCHAR(40) NOT NULL
//   alterado_por_id BIGINT (NULL para sistema/automação)
//   alterado_por_tipo VARCHAR(20) NOT NULL  ('empresa' | 'admin' |
//                                            'recrutador' | 'candidato' |
//                                            'sistema')
//   alterado_por_nome VARCHAR(120)
//   alterado_por_role VARCHAR(40)
//   motivo          TEXT
//   metadata        JSONB DEFAULT '{}'::jsonb
//   criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW()
//
// Também faz backfill do JSONB legado `candidaturas.historico` para a nova
// tabela (best-effort — se o JSON for inválido, ignora e segue).
// =========================================================================
const { pool } = require('../db');

async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const escreve = (msg) => { log.push(msg); console.log('[MIG004]', msg); };

  try {
    // 1. Tabela principal (idempotente)
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidatura_historico (
        id BIGSERIAL PRIMARY KEY,
        candidatura_id BIGINT NOT NULL REFERENCES candidaturas(id) ON DELETE CASCADE,
        vaga_id BIGINT,
        empresa_id BIGINT,
        etapa_anterior INT,
        etapa_nova INT NOT NULL,
        status_anterior VARCHAR(40),
        status_novo VARCHAR(40) NOT NULL,
        alterado_por_id BIGINT,
        alterado_por_tipo VARCHAR(20) NOT NULL
          CHECK (alterado_por_tipo IN ('empresa','admin','recrutador','candidato','sistema')),
        alterado_por_nome VARCHAR(120),
        alterado_por_role VARCHAR(40),
        motivo TEXT,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    // Garante colunas vaga_id / empresa_id caso a tabela já exista sem elas
    await client.query(`ALTER TABLE candidatura_historico ADD COLUMN IF NOT EXISTS vaga_id BIGINT`);
    await client.query(`ALTER TABLE candidatura_historico ADD COLUMN IF NOT EXISTS empresa_id BIGINT`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cand_hist_vaga_id ON candidatura_historico (vaga_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cand_hist_empresa_id ON candidatura_historico (empresa_id)`);
    escreve('Tabela candidatura_historico pronta (idempotente)');

    // 2. Índices (idempotentes)
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_cand_hist_candidatura_id
        ON candidatura_historico (candidatura_id, criado_em DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_cand_hist_criado_em
        ON candidatura_historico (criado_em DESC)
    `);
    escreve('Índices criados');

    // 3. Constraint para impedir UPDATE/DELETE (append-only via trigger)
    //    Mantemos um trigger que RAISE em UPDATE/DELETE.
    await client.query(`
      CREATE OR REPLACE FUNCTION candidatura_historico_append_only()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'candidatura_historico é append-only: % não permitido', TG_OP;
      END;
      $$ LANGUAGE plpgsql;
    `);
    await client.query(`
      DROP TRIGGER IF EXISTS trg_cand_hist_no_update ON candidatura_historico;
    `);
    await client.query(`
      CREATE TRIGGER trg_cand_hist_no_update
        BEFORE UPDATE OR DELETE ON candidatura_historico
        FOR EACH ROW EXECUTE FUNCTION candidatura_historico_append_only();
    `);
    escreve('Trigger append-only instalado');

    // 4. Backfill do JSONB legado para a nova tabela (idempotente).
    //    Só insere eventos cuja (candidatura_id, etapa_nova, status_novo, criado_em)
    //    AINDA NÃO existam na nova tabela (heurística simples: ignora se já tem
    //    >=1 evento para essa candidatura criada no mesmo segundo).
    let inseridos = 0;
    let ignorados = 0;
    const candRes = await client.query(`
      SELECT id, historico, criada_em, etapa_atual, status
      FROM candidaturas
      WHERE historico IS NOT NULL
        AND jsonb_typeof(historico) = 'array'
        AND jsonb_array_length(historico) > 0
    `);

    for (const c of candRes.rows) {
      let histArr;
      try { histArr = typeof c.historico === 'string' ? JSON.parse(c.historico) : c.historico; }
      catch (_) { continue; }
      if (!Array.isArray(histArr)) continue;

      for (const h of histArr) {
        if (!h || typeof h !== 'object') continue;

        // Pega a data do evento (legado: 'data' ISO string)
        let criadoEm;
        try { criadoEm = h.data ? new Date(h.data).toISOString() : new Date(c.criada_em).toISOString(); }
        catch (_) { criadoEm = new Date(c.criada_em).toISOString(); }

        const etapaNova = Number.isInteger(h.etapa) ? h.etapa : Number(c.etapa_atual) || 0;
        const statusNovo = h.status || c.status || 'em_andamento';

        // Heurística de idempotência: já existe evento p/ essa candidatura
        // com mesma etapa+status+data? então pula (não duplica).
        const dup = await client.query(`
          SELECT 1 FROM candidatura_historico
          WHERE candidatura_id = $1
            AND etapa_nova = $2
            AND status_novo = $3
            AND criado_em = $4
          LIMIT 1
        `, [c.id, etapaNova, statusNovo, criadoEm]);
        if (dup.rows.length > 0) { ignorados++; continue; }

        await client.query(`
          INSERT INTO candidatura_historico (
            candidatura_id, etapa_anterior, etapa_nova,
            status_anterior, status_novo,
            alterado_por_tipo, alterado_por_nome,
            motivo, metadata, criado_em
          ) VALUES (
            $1, NULL, $2,
            NULL, $3,
            'sistema', COALESCE($4, 'sistema (migração JSONB)'),
            $5, $6::jsonb, $7
          )
        `, [
          c.id, etapaNova, statusNovo,
          typeof h.por === 'string' ? h.por : null,
          typeof h.mensagem === 'string' ? h.mensagem : (typeof h.motivo === 'string' ? h.motivo : null),
          JSON.stringify({ migrado_de_jsonb: true, acao: h.acao || null }),
          criadoEm
        ]);
        inseridos++;
      }
    }

    escreve(`Backfill JSONB → tabela: ${inseridos} inseridos, ${ignorados} ignorados (já existiam)`);

    // Diagnóstico final
    const dist = await client.query(`
      SELECT
        (SELECT COUNT(*) FROM candidatura_historico)::int AS total_eventos,
        (SELECT COUNT(DISTINCT candidatura_id) FROM candidatura_historico)::int AS candidaturas_com_historico,
        (SELECT COUNT(*) FROM candidaturas)::int AS total_candidaturas
    `);
    escreve(`Distribuição final: ${JSON.stringify(dist.rows[0])}`);

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