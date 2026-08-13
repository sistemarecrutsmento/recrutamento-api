/**
 * Triagem Inteligente — estrutura de análises versionadas.
 *
 * Este módulo é idempotente e deve ser registrado no db.js somente quando
 * a funcionalidade estiver liberada no ambiente de preview.
 */
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidatura_analises_ia (
        id BIGSERIAL PRIMARY KEY,
        empresa_id INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
        vaga_id INTEGER NOT NULL REFERENCES vagas(id) ON DELETE CASCADE,
        candidatura_id INTEGER NOT NULL REFERENCES candidaturas(id) ON DELETE CASCADE,
        candidato_id INTEGER NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'pendente'
          CHECK (status IN ('pendente','processando','concluida','erro','cancelada','desatualizada')),
        versao INTEGER NOT NULL DEFAULT 1,
        analise_atual BOOLEAN NOT NULL DEFAULT true,
        score NUMERIC(5,2),
        nivel_compatibilidade TEXT,
        resultado_json JSONB,
        snapshot_vaga_json JSONB NOT NULL,
        snapshot_candidato_json JSONB NOT NULL,
        hash_entrada TEXT NOT NULL,
        modelo TEXT NOT NULL,
        versao_prompt TEXT NOT NULL,
        versao_schema TEXT NOT NULL,
        solicitada_por_id INTEGER,
        solicitada_por_tipo TEXT,
        erro_codigo TEXT,
        criada_em TIMESTAMP NOT NULL DEFAULT NOW(),
        iniciada_em TIMESTAMP,
        finalizada_em TIMESTAMP
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_triagem_ia_candidatura
      ON candidatura_analises_ia(candidatura_id, criada_em DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_triagem_ia_vaga
      ON candidatura_analises_ia(vaga_id, status)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_triagem_ia_empresa
      ON candidatura_analises_ia(empresa_id, criada_em DESC)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_triagem_ia_atual
      ON candidatura_analises_ia(candidatura_id)
      WHERE analise_atual = true
    `);

    return { ok: true, log: ['candidatura_analises_ia verificada/criada'] };
  } finally {
    client.release();
  }
}

module.exports = { up };
