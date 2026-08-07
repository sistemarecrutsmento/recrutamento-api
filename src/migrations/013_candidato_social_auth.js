'use strict';
// Migration 013 — identidades sociais e códigos de troca de sessão.
// Não armazena tokens OAuth nem refresh tokens em texto puro.
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidato_oauth_identities (
        id BIGSERIAL PRIMARY KEY,
        candidato_id INTEGER NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
        provider TEXT NOT NULL CHECK (provider IN ('google','apple')),
        subject TEXT NOT NULL,
        email TEXT,
        criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
        atualizado_em TIMESTAMP NOT NULL DEFAULT NOW(),
        UNIQUE (provider, subject),
        UNIQUE (provider, candidato_id)
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_candidato_oauth_email ON candidato_oauth_identities(lower(email))`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidato_social_states (
        id BIGSERIAL PRIMARY KEY,
        state_hash TEXT NOT NULL UNIQUE,
        provider TEXT NOT NULL CHECK (provider IN ('google','apple')),
        code_verifier TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expira_em TIMESTAMP NOT NULL,
        criado_em TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_social_states_expira ON candidato_social_states(expira_em)`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidato_social_codes (
        id BIGSERIAL PRIMARY KEY,
        code_hash TEXT NOT NULL UNIQUE,
        candidato_id INTEGER NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
        expira_em TIMESTAMP NOT NULL,
        consumido_em TIMESTAMP,
        criado_em TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_social_codes_expira ON candidato_social_codes(expira_em)`);
    return { ok: true };
  } finally {
    client.release();
  }
}

module.exports = { up };
