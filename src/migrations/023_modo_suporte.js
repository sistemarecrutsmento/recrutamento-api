const { pool } = require('../db');

// FASE 2 — sessão formal de suporte: somente leitura por padrão.
async function up() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessoes_suporte (
      id BIGSERIAL PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      iniciado_por INTEGER NOT NULL REFERENCES admins(id),
      motivo TEXT NOT NULL,
      escopo JSONB NOT NULL DEFAULT '{}'::jsonb,
      somente_leitura BOOLEAN NOT NULL DEFAULT true,
      iniciado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expira_em TIMESTAMPTZ NOT NULL,
      encerrado_em TIMESTAMPTZ,
      encerrado_por INTEGER REFERENCES admins(id)
    );
    CREATE INDEX IF NOT EXISTS idx_sessoes_suporte_ativas
      ON sessoes_suporte (token_hash, expira_em)
      WHERE encerrado_em IS NULL;
  `);
  return { ok: true, log: ['sessoes_suporte verificada/criada'] };
}

module.exports = { up };
