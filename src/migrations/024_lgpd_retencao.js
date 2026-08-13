'use strict';
const { pool } = require('../db');

async function ensureColumn(client, table, column, definition) {
  const r = await client.query(`SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, [table, column]);
  if (!r.rowCount) await client.query(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

async function up() {
  const client = await pool.connect();
  try {
    await ensureColumn(client, 'empresas', 'desativada_em', 'TIMESTAMP');
    await ensureColumn(client, 'empresas', 'retencao_ate', 'TIMESTAMP');
    await ensureColumn(client, 'empresas', 'retencao_status', "VARCHAR(30) NOT NULL DEFAULT 'active'");
    await ensureColumn(client, 'candidatos', 'anonimizado_em', 'TIMESTAMP');
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresas_retencao_ate ON empresas(retencao_ate) WHERE retencao_ate IS NOT NULL`);
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
