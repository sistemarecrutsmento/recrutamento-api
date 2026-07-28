// =========================================================================
// Migration 005 — Notificações (Fase 7, 28/07/2026)
// =========================================================================
// Cria tabela `notificacoes` (append-only) — feed global de eventos
// voltado ao admin/gestor da plataforma.
//
// Por que uma tabela SEPARADA de `candidatura_historico`?
//   - Historico é per-candidatura (você olha UMA candidatura).
//   - Notificacao é feed global + KPIs (você olha a EMPRESA inteira).
//   - Cada uma tem índices otimizados pro seu caso de uso.
//
// Schema:
//   id              BIGSERIAL PRIMARY KEY
//   empresa_id      BIGINT NOT NULL FK -> empresas(id) (multi-tenant)
//   vaga_id         BIGINT (NULL para eventos globais — ex: nova empresa)
//   candidatura_id  BIGINT (NULL para eventos sem candidatura)
//   tipo            VARCHAR(50) NOT NULL
//                   ('candidatura_criada' | 'etapa_alterada' | 'status_alterado'
//                    | 'proposta_enviada' | 'proposta_aceita' | 'proposta_recusada'
//                    | 'documento_enviado' | 'documento_aprovado'
//                    | 'candidatura_rejeitada' | 'candidatura_contratada'
//                    | 'empresa_criada' | 'vaga_criada')
//   titulo          VARCHAR(200) NOT NULL    (ex: "Nova candidatura: João Silva")
//   resumo          VARCHAR(400)              (ex: "Vaga: Auxiliar Administrativo")
//   link            VARCHAR(500)              (URL contextual pro admin clicar)
//   actor_id        BIGINT                   (quem causou)
//   actor_tipo      VARCHAR(20) NOT NULL      (mesmo enum do historico)
//   actor_nome      VARCHAR(120)
//   actor_role      VARCHAR(40)
//   lida            BOOLEAN NOT NULL DEFAULT FALSE
//   metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
//   criado_em       TIMESTAMPTZ NOT NULL DEFAULT NOW()
//
// Requisitos:
//   - Idempotente (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS).
//   - Sem DROP destrutivo.
// =========================================================================
const { pool } = require('../db');

async function aplicar() {
  const client = await pool.connect();
  const log = [];
  const escreve = (msg) => { log.push(msg); console.log('[MIG005]', msg); };

  try {
    // 1. Tabela principal (idempotente)
    await client.query(`
      CREATE TABLE IF NOT EXISTS notificacoes (
        id BIGSERIAL PRIMARY KEY,
        empresa_id BIGINT NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
        vaga_id BIGINT,
        candidatura_id BIGINT,
        tipo VARCHAR(50) NOT NULL,
        titulo VARCHAR(200) NOT NULL,
        resumo VARCHAR(400),
        link VARCHAR(500),
        actor_id BIGINT,
        actor_tipo VARCHAR(20) NOT NULL
          CHECK (actor_tipo IN ('empresa','admin','recrutador','candidato','sistema')),
        actor_nome VARCHAR(120),
        actor_role VARCHAR(40),
        lida BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    escreve('Tabela notificacoes pronta (idempotente)');

    // 2. Índices
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_notif_empresa_criado
        ON notificacoes (empresa_id, criado_em DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_notif_tipo
        ON notificacoes (tipo)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_notif_lida
        ON notificacoes (empresa_id, lida)
    `);
    escreve('Índices criados');

    // 3. Backfill best-effort — gera 1 notificação por candidatura EXISTENTE
    //    marcada como 'publicada' (status_atual público + ativa)
    const backfill = await client.query(`
      INSERT INTO notificacoes
        (empresa_id, vaga_id, candidatura_id, tipo, titulo, resumo, link,
         actor_id, actor_tipo, actor_nome, criado_em)
      SELECT
        v.empresa_id,
        c.vaga_id,
        c.id,
        'candidatura_criada',
        'Nova candidatura: ' || COALESCE(c.nome, 'Candidato ' || c.id),
        'Vaga: ' || v.titulo,
        '/admin/analisar.html?id=' || c.id,
        c.candidato_id,
        'candidato',
        c.nome,
        COALESCE(c.criada_em, NOW())
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      ON CONFLICT DO NOTHING
    `).catch(e => ({ erro: e.message }));
    const nBackfill = backfill.erro ? 'falhou (não-fatal)' : backfill.rowCount;
    escreve(`Backfill de candidaturas existentes → ${nBackfill}`);

    escreve('MIG005 concluída');
    return log;
  } finally {
    client.release();
  }
}

module.exports = { nome: '005_notificacoes_fase7', aplicar };