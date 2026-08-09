'use strict';
const { pool } = require('../db');
async function up() {
  const client = await pool.connect();
  try {
    await client.query('ALTER TABLE empresas ADD COLUMN IF NOT EXISTS asaas_checkout_id VARCHAR(120)');
    await client.query('ALTER TABLE empresas ADD COLUMN IF NOT EXISTS asaas_checkout_url TEXT');
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
