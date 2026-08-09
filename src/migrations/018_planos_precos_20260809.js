'use strict';
const { pool } = require('../db');
async function up() {
  const client = await pool.connect();
  try {
    await client.query("UPDATE planos SET preco_mensal = CASE slug WHEN 'essencial' THEN 14900 WHEN 'profissional' THEN 24900 WHEN 'enterprise' THEN 39900 ELSE preco_mensal END WHERE slug IN ('essencial','profissional','enterprise')");
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
