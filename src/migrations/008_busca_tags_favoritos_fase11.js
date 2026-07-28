/**
 * Migration 008 — Fase 11: busca/filtros, tags de vaga, favoritos, match
 *
 * Operações (todas idempotentes):
 *  1. CREATE TABLE vaga_tags (id, vaga_id, tag, criado_em) — UNIQUE(vaga_id, tag)
 *  2. CREATE TABLE candidato_favoritos (id, candidato_id, vaga_id, criado_em) — UNIQUE
 *  3. ALTER candidatos ADD COLUMN IF NOT EXISTS nivel_experiencia TEXT
 *  4. ALTER candidatos ADD COLUMN IF NOT EXISTS competencias JSONB DEFAULT '[]'
 *  5. Índices de performance para busca, tags e favoritos
 */

const { pool } = require('../db');

async function aplicar() {
  const log = [];
  const client = await pool.connect();
  try {
    // ── 1. Tabela vaga_tags ──────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS vaga_tags (
        id        SERIAL PRIMARY KEY,
        vaga_id   INTEGER NOT NULL REFERENCES vagas(id) ON DELETE CASCADE,
        tag       TEXT    NOT NULL CHECK(length(trim(tag)) > 0 AND length(tag) <= 60),
        criado_em TIMESTAMP DEFAULT NOW(),
        CONSTRAINT vaga_tags_unique UNIQUE(vaga_id, tag)
      )
    `);
    log.push('vaga_tags criada/já existia');

    // ── 2. Tabela candidato_favoritos ────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS candidato_favoritos (
        id           SERIAL PRIMARY KEY,
        candidato_id INTEGER NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
        vaga_id      INTEGER NOT NULL REFERENCES vagas(id) ON DELETE CASCADE,
        criado_em    TIMESTAMP DEFAULT NOW(),
        CONSTRAINT candidato_favoritos_unique UNIQUE(candidato_id, vaga_id)
      )
    `);
    log.push('candidato_favoritos criada/já existia');

    // ── 3. Coluna nivel_experiencia em candidatos ────────────────────────────
    await client.query(`
      ALTER TABLE candidatos
        ADD COLUMN IF NOT EXISTS nivel_experiencia TEXT
    `);
    log.push('candidatos.nivel_experiencia OK');

    // ── 4. Coluna competencias em candidatos ─────────────────────────────────
    await client.query(`
      ALTER TABLE candidatos
        ADD COLUMN IF NOT EXISTS competencias JSONB DEFAULT '[]'::jsonb
    `);
    log.push('candidatos.competencias OK');

    // ── 5. Índices ────────────────────────────────────────────────────────────
    await client.query(`CREATE INDEX IF NOT EXISTS idx_vaga_tags_vaga_id ON vaga_tags(vaga_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_vaga_tags_tag     ON vaga_tags(tag)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_fav_candidato     ON candidato_favoritos(candidato_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_fav_vaga          ON candidato_favoritos(vaga_id)`);
    // índice para buscas de candidatos por cidade/estado
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cand_cidade_estado ON candidatos(cidade, estado)`);
    // índice para busca de candidatos por nome (ilike prefix)
    await client.query(`CREATE INDEX IF NOT EXISTS idx_cand_nome_lower   ON candidatos(lower(nome))`);
    log.push('índices OK');

    return { ok: true, log };
  } catch (e) {
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { aplicar };
