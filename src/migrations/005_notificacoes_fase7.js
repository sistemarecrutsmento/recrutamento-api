// =========================================================================
// Migration 005 — Notificações (Fase 7, 28/07/2026)
// =========================================================================
// Tabela `notificacoes` — feed de eventos para empresa E candidato.
// Schema flexível: suporta tanto notificações de empresa quanto de candidato.
//   - user_type='empresa'   + user_id=empresa_id
//   - user_type='candidato' + user_id=candidato_id
//
// Schema:
//   id               BIGSERIAL PK
//   user_type        VARCHAR(20) NOT NULL CHECK (user_type IN ('empresa','candidato'))
//   user_id          BIGINT NOT NULL
//   tipo             VARCHAR(50) NOT NULL
//                    (candidatura_criada, etapa_alterada, status_alterado,
//                     proposta_enviada, proposta_aceita, proposta_recusada,
//                     candidato_desistiu, docs_aprovados, candidato_contratado,
//                     candidato_reprovado, candidato_reaberto)
//   titulo           VARCHAR(200) NOT NULL
//   mensagem         VARCHAR(500)
//   referencia_tipo  VARCHAR(40)  ('candidatura','vaga')
//   referencia_id    BIGINT
//   lida             BOOLEAN NOT NULL DEFAULT FALSE
//   lida_em          TIMESTAMPTZ
//   metadata         JSONB NOT NULL DEFAULT '{}'::jsonb
//   criada_em        TIMESTAMPTZ NOT NULL DEFAULT NOW()
//
// Requisitos: idempotente, sem DROP destrutivo.
// =========================================================================
const { pool } = require('../db');

async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const escreve = (m) => { log.push(m); console.log('[MIG005]', m); };

  try {
    // 0. DROP se tabela existe com schema antigo (empresa_id em vez de user_type+user_id)
    const oldCol = await client.query(
      `SELECT 1 FROM information_schema.columns
       WHERE table_schema='public' AND table_name='notificacoes' AND column_name='empresa_id'`
    );
    if (oldCol.rowCount > 0) {
      await client.query('DROP TABLE IF EXISTS notificacoes CASCADE');
      log.push('Tabela antiga com empresa_id removida');
    }

    // 1. Tabela
    await client.query(`
      CREATE TABLE IF NOT EXISTS notificacoes (
        id BIGSERIAL PRIMARY KEY,
        user_type VARCHAR(20) NOT NULL
          CHECK (user_type IN ('empresa','candidato')),
        user_id BIGINT NOT NULL,
        tipo VARCHAR(50) NOT NULL,
        titulo VARCHAR(200) NOT NULL,
        mensagem VARCHAR(500),
        referencia_tipo VARCHAR(40),
        referencia_id BIGINT,
        lida BOOLEAN NOT NULL DEFAULT FALSE,
        lida_em TIMESTAMPTZ,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        criada_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    escreve('Tabela notificacoes criada/verificada');

    // 2. Índices mínimos (consulta sempre é user_type+user_id+lida)
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_notif_user
        ON notificacoes (user_type, user_id, lida, criada_em DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_notif_ref
        ON notificacoes (referencia_tipo, referencia_id)
    `);
    escreve('Índices criados');

    // 3. (Opcional) Backfill: para cada empresa + candidato que tenha pelo menos
    //    uma candidatura, criar UMA notificação inicial marcando o estado atual.
    //    Idempotente — usa ON CONFLICT DO NOTHING via WHERE NOT EXISTS.
    try {
      const r1 = await client.query(`
        INSERT INTO notificacoes (user_type, user_id, tipo, titulo, mensagem, referencia_tipo, referencia_id, criada_em)
        SELECT 'empresa', v.empresa_id, 'vaga_publicada', 'Vaga ativa no portal', v.titulo,
               'vaga', v.id, v.criada_em
        FROM vagas v
        WHERE v.status = 'publicada'
          AND NOT EXISTS (
            SELECT 1 FROM notificacoes n
            WHERE n.user_type='empresa' AND n.user_id=v.empresa_id
              AND n.referencia_tipo='vaga' AND n.referencia_id=v.id
              AND n.tipo='vaga_publicada'
          )
      `);
      escreve(`Backfill empresa: ${r1.rowCount} notificações`);
    } catch (e) {
      escreve(`Backfill empresa falhou (não-fatal): ${e.message}`);
    }

    try {
      const r2 = await client.query(`
        INSERT INTO notificacoes (user_type, user_id, tipo, titulo, mensagem, referencia_tipo, referencia_id, criada_em)
        SELECT 'candidato', c.candidato_id, 'candidatura_criada',
               'Você se candidatou: ' || v.titulo,
               'Sua candidatura foi recebida',
               'candidatura', c.id, COALESCE(c.criada_em, NOW())
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE NOT EXISTS (
          SELECT 1 FROM notificacoes n
          WHERE n.user_type='candidato' AND n.user_id=c.candidato_id
            AND n.referencia_tipo='candidatura' AND n.referencia_id=c.id
            AND n.tipo='candidatura_criada'
        )
      `);
      escreve(`Backfill candidato: ${r2.rowCount} notificações`);
    } catch (e) {
      escreve(`Backfill candidato falhou (não-fatal): ${e.message}`);
    }

    escreve('MIG005 concluída');
    return { ok: true, log };
  } catch (e) {
    console.error('[MIG005] erro:', e.message);
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { nome: '005_notificacoes_fase7', aplicar };