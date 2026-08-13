const { pool } = require('../db');

// FASE 2 — impede candidatura duplicada inclusive sob concorrência.
// Não remove dados existentes: se houver duplicidades legadas, a migration falha
// explicitamente para exigir saneamento aprovado antes da criação do índice.
async function up() {
  const client = await pool.connect();
  try {
    const duplicadas = await client.query(`
      SELECT vaga_id, candidato_id, COUNT(*)::int AS quantidade
      FROM candidaturas
      GROUP BY vaga_id, candidato_id
      HAVING COUNT(*) > 1
      LIMIT 1
    `);
    if (duplicadas.rows.length) {
      throw new Error('Há candidaturas duplicadas; saneamento manual necessário antes do índice único');
    }
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_candidaturas_vaga_candidato
      ON candidaturas(vaga_id, candidato_id)
    `);
    return { ok: true, log: ['uq_candidaturas_vaga_candidato verificado/criado'] };
  } finally {
    client.release();
  }
}

module.exports = { up };
