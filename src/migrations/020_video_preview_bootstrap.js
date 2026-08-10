'use strict';
const { pool } = require('../db');

// Preview-only dependency graph. This intentionally creates no production tables;
// db.js calls it only when VAGASIO_VIDEO_SCHEMA is set.
async function up() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS empresas (id SERIAL PRIMARY KEY, nome TEXT NOT NULL, ativo BOOLEAN DEFAULT true);
    CREATE TABLE IF NOT EXISTS candidatos (id SERIAL PRIMARY KEY, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS vagas (id SERIAL PRIMARY KEY, titulo TEXT NOT NULL, empresa_id INTEGER REFERENCES empresas(id));
    CREATE TABLE IF NOT EXISTS candidaturas (id SERIAL PRIMARY KEY, candidato_id INTEGER NOT NULL REFERENCES candidatos(id), vaga_id INTEGER NOT NULL REFERENCES vagas(id));
    CREATE TABLE IF NOT EXISTS entrevistas (id SERIAL PRIMARY KEY, candidatura_id INTEGER NOT NULL REFERENCES candidaturas(id), empresa_id INTEGER REFERENCES empresas(id));
    CREATE TABLE IF NOT EXISTS empresa_usuarios (id TEXT PRIMARY KEY, empresa_id INTEGER REFERENCES empresas(id));
  `);
  await pool.query(`ALTER TABLE vagas ADD COLUMN IF NOT EXISTS empresa_id INTEGER REFERENCES empresas(id); ALTER TABLE vagas ADD COLUMN IF NOT EXISTS empresa TEXT; ALTER TABLE entrevistas ADD COLUMN IF NOT EXISTS empresa_id INTEGER REFERENCES empresas(id);`);
  const e = await pool.query(`INSERT INTO empresas(nome) VALUES ('Preview Synthetic Company') ON CONFLICT DO NOTHING RETURNING id`);
  const empresa = e.rows[0]?.id || (await pool.query(`SELECT id FROM empresas WHERE nome='Preview Synthetic Company' LIMIT 1`)).rows[0].id;
  const c = await pool.query(`INSERT INTO candidatos(nome,email) VALUES ('Preview Synthetic Candidate','preview.candidate@vagasio.invalid') ON CONFLICT(email) DO UPDATE SET nome=EXCLUDED.nome RETURNING id`);
  const candidato = c.rows[0].id;
  const v = await pool.query(`INSERT INTO vagas(titulo,empresa_id,empresa) VALUES ('Preview Video Interview', $1, 'Preview Synthetic Company') RETURNING id`, [empresa]);
  const vaga = v.rows[0].id;
  const ca = await pool.query(`INSERT INTO candidaturas(candidato_id,vaga_id) VALUES ($1,$2) RETURNING id`, [candidato,vaga]);
  const candidatura = ca.rows[0].id;
  const i = await pool.query(`INSERT INTO entrevistas(candidatura_id,empresa_id) VALUES ($1,$2) RETURNING id`, [candidatura,empresa]);
  console.log('[PREVIEW] synthetic ids', {empresa,candidato,vaga,candidatura,entrevista:i.rows[0].id});
}
module.exports = { up };
