// Migration 019 — assinaturas Web Push de candidatos.
// Idempotente e sem alteração destrutiva. Ainda não é registrada no boot:
// esta fase fica isolada até a dependência e os testes locais estarem disponíveis.
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id BIGSERIAL PRIMARY KEY,
        candidato_id BIGINT NOT NULL REFERENCES candidatos(id) ON DELETE CASCADE,
        endpoint TEXT NOT NULL,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        dispositivo TEXT,
        categorias JSONB NOT NULL DEFAULT '{"candidatura":true,"entrevista":true,"mensagem":true,"documento":true,"proposta":true}'::jsonb,
        ativo BOOLEAN NOT NULL DEFAULT TRUE,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ultimo_uso_em TIMESTAMPTZ
      )
    `);
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_push_subscriptions_endpoint ON push_subscriptions(endpoint)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_push_subscriptions_candidato_ativo ON push_subscriptions(candidato_id, ativo)`);
    return { ok: true };
  } finally {
    client.release();
  }
}

module.exports = { up };
