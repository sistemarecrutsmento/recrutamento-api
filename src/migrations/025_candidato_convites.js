'use strict';
const { pool } = require('../db');
async function up() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS candidato_convites (
      id BIGSERIAL PRIMARY KEY,
      candidato_id INTEGER NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
      empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
      vaga_id INTEGER NOT NULL REFERENCES vagas(id) ON DELETE CASCADE,
      mensagem TEXT,
      criado_por INTEGER,
      criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
      enviado_em TIMESTAMP,
      cancelado_em TIMESTAMP
    )`);
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_candidato_convite_pendente ON candidato_convites(candidato_id, vaga_id) WHERE cancelado_em IS NULL`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_candidato_convites_empresa ON candidato_convites(empresa_id, criado_em DESC)`);
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
