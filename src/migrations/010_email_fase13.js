// =============================================================================
// 010_email_fase13.js — Fase 13: E-mail transacional
// Cria: email_preferencias, email_outbox
// Idempotente (ensureColumn / CREATE TABLE IF NOT EXISTS / IF NOT EXISTS index)
// =============================================================================
'use strict';

const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  const log = (m) => console.log('[migration 010]', m);

  try {
    log('Iniciando migration 010 — e-mail transacional...');

    // ── 1. email_preferencias ────────────────────────────────────────────────
    // Opt-in/out por categoria. Sem registro = ativo (padrão).
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_preferencias (
        id          SERIAL PRIMARY KEY,
        user_type   VARCHAR(20) NOT NULL,           -- 'candidato' | 'empresa'
        user_id     INTEGER     NOT NULL,
        categoria   VARCHAR(40) NOT NULL,           -- 'candidatura' | 'etapa' | ...
        ativo       BOOLEAN     NOT NULL DEFAULT true,
        atualizado_em TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    log('email_preferencias OK');

    // Índice único (upsert seguro)
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_email_pref_usuario_cat
        ON email_preferencias (user_type, user_id, categoria)
    `);
    log('idx_email_pref_usuario_cat OK');

    // ── 2. email_outbox ──────────────────────────────────────────────────────
    // Log de todos os e-mails enviados/falhados + dedup de chat.
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_outbox (
        id           SERIAL PRIMARY KEY,
        user_type    VARCHAR(20),
        user_id      INTEGER,
        tipo         VARCHAR(60) NOT NULL,
        destinatario VARCHAR(254) NOT NULL,
        assunto      TEXT,
        payload      JSONB,
        status       VARCHAR(20) NOT NULL DEFAULT 'enviado', -- 'enviado' | 'erro'
        erro         TEXT,
        tentativas   SMALLINT DEFAULT 1,
        enviado_em   TIMESTAMPTZ,
        criado_em    TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    log('email_outbox OK');

    // Índice para dedup de chat (query: user_type + user_id + tipo + criado_em)
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_dedup
        ON email_outbox (user_type, user_id, tipo, criado_em)
        WHERE tipo = 'chat_nova_mensagem'
    `);
    // Índice geral para queries de histórico
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_email_outbox_user
        ON email_outbox (user_type, user_id, criado_em DESC)
    `);
    log('índices email_outbox OK');

    log('Migration 010 concluída ✓');
  } finally {
    client.release();
  }
}

module.exports = { up };
