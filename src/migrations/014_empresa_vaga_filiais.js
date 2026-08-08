'use strict';
// Migration 014 — direcionamento de vagas para usuários Filial.
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS empresa_usuario_vagas (
        id BIGSERIAL PRIMARY KEY,
        empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
        usuario_id INTEGER NOT NULL REFERENCES empresa_usuarios(id) ON DELETE CASCADE,
        vaga_id INTEGER NOT NULL REFERENCES vagas(id) ON DELETE CASCADE,
        criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
        UNIQUE (empresa_id, usuario_id, vaga_id)
      )
    `);
    await client.query('CREATE INDEX IF NOT EXISTS idx_euv_usuario ON empresa_usuario_vagas(empresa_id, usuario_id, vaga_id)');
    await client.query('CREATE INDEX IF NOT EXISTS idx_euv_vaga ON empresa_usuario_vagas(empresa_id, vaga_id)');
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
