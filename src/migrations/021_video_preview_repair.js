'use strict';
const { pool } = require('../db');

// Preview-only repair: the first bootstrap ran against the full legacy schema,
// where entrevistas.etapa and entrevistas.data_hora are NOT NULL. Keep this
// migration idempotent and never touch production (it only runs with the
// preview schema enabled).
async function up() {
  if (!process.env.VAGASIO_VIDEO_SCHEMA) return;
  await pool.query(`ALTER TABLE entrevistas ADD COLUMN IF NOT EXISTS empresa_id INTEGER REFERENCES empresas(id);`);
  const e = await pool.query(`SELECT id FROM empresas WHERE nome='Preview Synthetic Company' ORDER BY id LIMIT 1`);
  const c = await pool.query(`SELECT id FROM candidatos WHERE email='preview.candidate@vagasio.invalid' LIMIT 1`);
  if (!e.rowCount || !c.rowCount) throw new Error('preview synthetic base records missing');
  const v = await pool.query(`SELECT id FROM vagas WHERE titulo='Preview Video Interview' ORDER BY id LIMIT 1`);
  if (v.rowCount && !String(v.rows[0].empresa_id || '')) await pool.query(`UPDATE vagas SET empresa_id=$1 WHERE id=$2`, [e.rows[0].id, v.rows[0].id]);
  if (!v.rowCount) throw new Error('preview synthetic vacancy missing');
  const ca = await pool.query(`SELECT id FROM candidaturas WHERE candidato_id=$1 AND vaga_id=$2 ORDER BY id LIMIT 1`, [c.rows[0].id, v.rows[0].id]);
  if (!ca.rowCount) throw new Error('preview synthetic application missing');
  await pool.query(`INSERT INTO entrevistas(candidatura_id,empresa_id,etapa,data_hora) SELECT $1,$2,4,NOW() WHERE NOT EXISTS (SELECT 1 FROM entrevistas WHERE candidatura_id=$1)`, [ca.rows[0].id,e.rows[0].id]);
  console.log('[PREVIEW] synthetic video interview repaired');
}
module.exports = { up };
