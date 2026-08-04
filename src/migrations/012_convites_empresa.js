'use strict';
// Migration 012 — Convites reais de usuários da empresa.
// Tokens são armazenados somente como SHA-256; o token puro nunca é persistido.
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS empresa_convites (
        id BIGSERIAL PRIMARY KEY,
        empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        cargo TEXT,
        role TEXT NOT NULL DEFAULT 'recrutador'
          CHECK (role IN ('admin_empresa','recrutador','viewer')),
        token_hash TEXT NOT NULL UNIQUE,
        expira_em TIMESTAMP NOT NULL,
        criado_por INTEGER,
        criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
        reenviado_em TIMESTAMP,
        aceito_em TIMESTAMP,
        cancelado_em TIMESTAMP
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresa_convites_empresa ON empresa_convites(empresa_id, criado_em DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresa_convites_email ON empresa_convites(lower(email), empresa_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresa_convites_pendentes ON empresa_convites(empresa_id, expira_em) WHERE aceito_em IS NULL AND cancelado_em IS NULL`);
    return { ok: true };
  } finally {
    client.release();
  }
}

module.exports = { up };
