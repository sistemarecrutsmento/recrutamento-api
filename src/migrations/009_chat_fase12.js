/**
 * Migration 009 — Fase 12: Chat Empresa ↔ Candidato
 *
 * Operações (todas idempotentes):
 *  1. ALTER mensagens_processo ADD lida_por_candidato_em  TIMESTAMP
 *  2. ALTER mensagens_processo ADD lida_por_empresa_em    TIMESTAMP
 *  3. ALTER mensagens_processo ADD remetente_id           INTEGER  (quem enviou no lado empresa)
 *  4. CREATE TABLE chat_templates (empresa, título, texto)
 *  5. Índices de performance
 *
 * NÃO cria novas tabelas de conversa — reutiliza mensagens_processo
 * (candidatura_id = conversa_id; uma candidatura tem uma única thread).
 */

const { pool } = require('../db');

async function aplicar() {
  const log = [];
  const client = await pool.connect();
  try {
    // ── 1. lida_por_candidato_em ─────────────────────────────────────────────
    await client.query(`
      ALTER TABLE mensagens_processo
        ADD COLUMN IF NOT EXISTS lida_por_candidato_em TIMESTAMP
    `);
    log.push('mensagens_processo.lida_por_candidato_em OK');

    // ── 2. lida_por_empresa_em ───────────────────────────────────────────────
    await client.query(`
      ALTER TABLE mensagens_processo
        ADD COLUMN IF NOT EXISTS lida_por_empresa_em TIMESTAMP
    `);
    log.push('mensagens_processo.lida_por_empresa_em OK');

    // ── 3. remetente_id (FK empresa_usuarios.id para mensagens de empresa) ───
    await client.query(`
      ALTER TABLE mensagens_processo
        ADD COLUMN IF NOT EXISTS remetente_id INTEGER
    `);
    log.push('mensagens_processo.remetente_id OK');

    // ── 4. chat_encerrado_* em candidaturas ──────────────────────────────────
    await client.query(`
      ALTER TABLE candidaturas
        ADD COLUMN IF NOT EXISTS chat_encerrado_empresa_em TIMESTAMP
    `);
    await client.query(`
      ALTER TABLE candidaturas
        ADD COLUMN IF NOT EXISTS chat_encerrado_candidato_em TIMESTAMP
    `);
    log.push('candidaturas.chat_encerrado_* OK');

    // ── 4. chat_templates ────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS chat_templates (
        id         SERIAL PRIMARY KEY,
        empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
        titulo     TEXT NOT NULL CHECK(length(trim(titulo)) > 0 AND length(titulo) <= 100),
        texto      TEXT NOT NULL CHECK(length(trim(texto)) > 0 AND length(texto) <= 2000),
        criado_em  TIMESTAMP DEFAULT NOW()
      )
    `);
    log.push('chat_templates criada/já existia');

    // ── 5. Índices ────────────────────────────────────────────────────────────
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_mp_lida_cand
        ON mensagens_processo(candidatura_id, lida_por_candidato_em)
        WHERE lida_por_candidato_em IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_mp_lida_emp
        ON mensagens_processo(candidatura_id, lida_por_empresa_em)
        WHERE lida_por_empresa_em IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_chat_templates_empresa
        ON chat_templates(empresa_id)
    `);
    log.push('índices OK');

    // ── 6. Seed de templates globais (empresa_id = NULL = padrão do sistema) ─
    const { rows: existing } = await client.query(
      `SELECT id FROM chat_templates WHERE empresa_id IS NULL LIMIT 1`
    );
    if (existing.length === 0) {
      await client.query(`
        INSERT INTO chat_templates (empresa_id, titulo, texto) VALUES
          (NULL, 'Convite para entrevista',  'Olá! Gostaríamos de convidá-lo(a) para uma entrevista sobre a vaga. Poderia confirmar sua disponibilidade?'),
          (NULL, 'Atualização de candidatura','Olá! Temos uma atualização sobre sua candidatura. Por favor, verifique as informações no seu painel.'),
          (NULL, 'Confirmação de disponibilidade', 'Olá! Podemos confirmar sua disponibilidade para as próximas etapas do processo seletivo?'),
          (NULL, 'Documentação pendente',    'Olá! Para prosseguirmos com sua candidatura, precisamos de alguns documentos. Por favor, acesse o portal para envio.'),
          (NULL, 'Parabéns – próxima etapa', 'Olá! Temos o prazer de informar que você avançou para a próxima etapa do processo. Em breve entraremos em contato com mais detalhes.')
      `);
      log.push('templates padrão inseridos');
    } else {
      log.push('templates padrão já existem');
    }

    return { ok: true, log };
  } catch (e) {
    return { ok: false, erro: e.message, log };
  } finally {
    client.release();
  }
}

module.exports = { aplicar };
