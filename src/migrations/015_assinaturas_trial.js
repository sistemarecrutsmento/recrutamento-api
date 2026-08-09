'use strict';
// Migration 015 — período de teste e estado da assinatura da empresa.
const { pool } = require('../db');

async function up() {
  const client = await pool.connect();
  try {
    // Cada DDL é idempotente e fica fora de uma transação explícita.
    const cols = [
      ['trial_inicio', 'TIMESTAMP'],
      ['trial_fim', 'TIMESTAMP'],
      ['assinatura_status', "VARCHAR(30) NOT NULL DEFAULT 'trial'"],
      ['pagamento_configurado', 'BOOLEAN NOT NULL DEFAULT FALSE'],
      ['asaas_customer_id', 'VARCHAR(120)'],
      ['asaas_subscription_id', 'VARCHAR(120)'],
      ['assinatura_confirmada_em', 'TIMESTAMP'],
      ['assinatura_vence_em', 'TIMESTAMP'],
      ['trial_aviso_enviado_em', 'TIMESTAMP']
    ];
    for (const [col, def] of cols) {
      await client.query(`ALTER TABLE empresas ADD COLUMN IF NOT EXISTS ${col} ${def}`);
    }
    // O plano gratuito legado deixa de ser uma opção comercial de cadastro.
    await client.query(`UPDATE planos SET ativo = false WHERE slug = 'gratuito'`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresas_trial_fim ON empresas(trial_fim) WHERE trial_fim IS NOT NULL`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_empresas_assinatura_status ON empresas(assinatura_status)`);
    return { ok: true };
  } finally { client.release(); }
}
module.exports = { up };
