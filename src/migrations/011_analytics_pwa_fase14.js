'use strict';
// Migration 011 — Fase 14: Analytics do produto
// Idempotente: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS

const { pool } = require('../db');

const EVENTOS_VALIDOS = [
  // Candidato
  'vaga_visualizada','inicio_cadastro_candidato','cadastro_candidato_concluido',
  'login_candidato','candidatura_iniciada','candidatura_enviada',
  'vaga_favoritada','vaga_desfavoritada','match_visualizado',
  'chat_aberto_candidato','mensagem_enviada_candidato',
  // Empresa
  'empresa_login','vaga_criada','vaga_publicada',
  'candidato_visualizado','candidato_contatado',
  'chat_aberto_empresa','mensagem_enviada_empresa',
  'entrevista_agendada','proposta_enviada','proposta_aceita','proposta_recusada',
];

async function up() {
  const client = await pool.connect();
  try {
    // Tabela principal de eventos
    await client.query(`
      CREATE TABLE IF NOT EXISTS analytics_eventos (
        id          BIGSERIAL PRIMARY KEY,
        evento      TEXT NOT NULL,
        user_type   TEXT,
        user_id     INTEGER,
        empresa_id  INTEGER,
        vaga_id     INTEGER,
        candidatura_id INTEGER,
        sessao_id   TEXT,
        anonimo_id  TEXT,
        metadata    JSONB DEFAULT '{}'::jsonb,
        ip_hash     TEXT,
        user_agent  TEXT,
        criado_em   TIMESTAMP DEFAULT NOW()
      )
    `);

    // Índices para consultas agregadas
    await client.query(`CREATE INDEX IF NOT EXISTS idx_ae_evento      ON analytics_eventos(evento, criado_em DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_ae_empresa     ON analytics_eventos(empresa_id, criado_em DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_ae_vaga        ON analytics_eventos(vaga_id, criado_em DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_ae_criado      ON analytics_eventos(criado_em DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_ae_user        ON analytics_eventos(user_type, user_id, criado_em DESC)`);

    // Tabela auxiliar: eventos válidos (para validação server-side)
    await client.query(`
      CREATE TABLE IF NOT EXISTS analytics_eventos_permitidos (
        evento TEXT PRIMARY KEY,
        descricao TEXT,
        requer_auth BOOLEAN DEFAULT FALSE
      )
    `);

    // Seed dos eventos válidos (upsert idempotente)
    for (const ev of EVENTOS_VALIDOS) {
      await client.query(`
        INSERT INTO analytics_eventos_permitidos (evento, requer_auth)
        VALUES ($1, $2)
        ON CONFLICT (evento) DO NOTHING
      `, [ev, !ev.includes('vaga_visualizada') && !ev.includes('anonimo')]);
    }

    console.log('[Migration 011] analytics_eventos criada/verificada OK');
  } finally {
    client.release();
  }
}

module.exports = { up, EVENTOS_VALIDOS };
