'use strict';
const { pool } = require('../db');
async function up() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS asaas_webhook_events (
      id BIGSERIAL PRIMARY KEY, event_id VARCHAR(255) NOT NULL UNIQUE,
      event VARCHAR(100) NOT NULL, payload JSONB NOT NULL,
      processado_em TIMESTAMP NOT NULL DEFAULT NOW()
    )`);
    await client.query('CREATE INDEX IF NOT EXISTS idx_asaas_webhook_event ON asaas_webhook_events(event)');
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
