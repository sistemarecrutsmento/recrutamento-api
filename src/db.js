const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  // Limites importantes pra não travar
  max: 5,                            // max 5 conexões no pool
  idleTimeoutMillis: 30_000,         // fecha conexões idle após 30s
  connectionTimeoutMillis: 10_000,   // timeout pra OBTER conexão: 10s
  statement_timeout: 15_000,         // SQL individual limitado a 15s (evita pendurar)
  query_timeout: 15_000
});

// Helper que sempre aplica statement_timeout por query (defesa em profundidade)
pool.on('connect', (client) => {
  client.query('SET statement_timeout = 15s').catch(() => {});
});

pool.on('error', (err) => {
  console.error('[DB] erro inesperado no pool:', err.message);
});

async function init() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        criado_em TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS recrutadores (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        criado_por INTEGER REFERENCES admins(id),
        ativo BOOLEAN DEFAULT true,
        role TEXT DEFAULT 'recrutador',
        primeiro_acesso BOOLEAN DEFAULT true,
        criado_em TIMESTAMP DEFAULT NOW()
      );

      -- Tabela de empresas (clientes que contratam vagas)
      CREATE TABLE IF NOT EXISTS empresas (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL,
        cnpj TEXT,
        email_principal TEXT,
        telefone TEXT,
        ativo BOOLEAN DEFAULT true,
        criado_por INTEGER REFERENCES admins(id),
        criado_em TIMESTAMP DEFAULT NOW()
      );

      -- ETAPA 3 (2026-07-27): colunas do multi-tenant / SaaS B2B.
      -- Idempotente (IF NOT EXISTS) — funciona em banco novo e em produção.
      ALTER TABLE empresas ADD COLUMN IF NOT EXISTS plano TEXT DEFAULT 'essencial';
      ALTER TABLE empresas ADD COLUMN IF NOT EXISTS slug TEXT UNIQUE;
      ALTER TABLE empresas ADD COLUMN IF NOT EXISTS cor_destaque TEXT DEFAULT '#722F37';
      ALTER TABLE empresas ADD COLUMN IF NOT EXISTS logo_url TEXT;

      -- Usuários que acessam o sistema como empresa (múltiplos por empresa)
      CREATE TABLE IF NOT EXISTS empresa_usuarios (
        id SERIAL PRIMARY KEY,
        empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
        nome TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        cargo TEXT,
        ativo BOOLEAN DEFAULT true,
        primeiro_acesso BOOLEAN DEFAULT true,
        criado_por INTEGER REFERENCES admins(id),
        criado_em TIMESTAMP DEFAULT NOW()
      );

      -- N:N — quais vagas cada empresa tem acesso
      CREATE TABLE IF NOT EXISTS empresa_vaga_acesso (
        id SERIAL PRIMARY KEY,
        empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
        vaga_id INTEGER REFERENCES vagas(id) ON DELETE CASCADE,
        concedido_por INTEGER REFERENCES admins(id),
        concedido_em TIMESTAMP DEFAULT NOW(),
        UNIQUE(empresa_id, vaga_id)
      );

      -- Log de notificações enviadas para a empresa
      CREATE TABLE IF NOT EXISTS empresa_notificacoes (
        id SERIAL PRIMARY KEY,
        empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        tipo TEXT NOT NULL,
        assunto TEXT,
        corpo TEXT,
        enviado_em TIMESTAMP DEFAULT NOW(),
        status TEXT DEFAULT 'enviado'
      );

      CREATE TABLE IF NOT EXISTS candidatos (
        id SERIAL PRIMARY KEY,
        cpf TEXT UNIQUE,
        nome TEXT NOT NULL,
        data_nascimento DATE,
        sexo TEXT,
        celular TEXT,
        email TEXT UNIQUE NOT NULL,
        email_verificado BOOLEAN DEFAULT false,
        senha_hash TEXT,
        acessibilidade TEXT,
        cep TEXT,
        estado TEXT,
        cidade TEXT,
        bairro TEXT,
        logradouro TEXT,
        numero TEXT,
        complemento TEXT,
        formacao TEXT,
        instituicao TEXT,
        curso TEXT,
        situacao TEXT,
        data_conclusao DATE,
        primeiro_emprego BOOLEAN DEFAULT false,
        banco_talentos BOOLEAN DEFAULT false,
        recebe_comunicacoes BOOLEAN DEFAULT false,
        criado_em TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS experiencias (
        id SERIAL PRIMARY KEY,
        candidato_id INTEGER REFERENCES candidatos(id) ON DELETE CASCADE,
        cargo TEXT,
        empresa TEXT,
        inicio DATE,
        fim DATE,
        emprego_atual BOOLEAN DEFAULT false,
        descricao TEXT
      );

      CREATE TABLE IF NOT EXISTS codigos_verificacao (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        codigo TEXT NOT NULL,
        expira_em TIMESTAMP NOT NULL,
        usado BOOLEAN DEFAULT false
      );

      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        user_tipo TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expira_em TIMESTAMP NOT NULL,
        usado_em TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash);
      CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, user_tipo);

      CREATE TABLE IF NOT EXISTS vagas (
        id SERIAL PRIMARY KEY,
        titulo TEXT NOT NULL,
        empresa TEXT NOT NULL,
        cidade TEXT,
        estado TEXT,
        tipo_contrato TEXT,
        nivel TEXT,
        area TEXT,
        salario_min NUMERIC,
        salario_max NUMERIC,
        descricao TEXT,
        requisitos TEXT,
        beneficios TEXT,
        etapas JSONB DEFAULT '[]',
        status TEXT DEFAULT 'publicada',
        criada_por INTEGER,
        criada_em TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS candidaturas (
        id SERIAL PRIMARY KEY,
        vaga_id INTEGER REFERENCES vagas(id) ON DELETE CASCADE,
        candidato_id INTEGER REFERENCES candidatos(id) ON DELETE CASCADE,
        status TEXT DEFAULT 'em_analise',
        etapa_atual INTEGER DEFAULT 0,
        historico JSONB DEFAULT '[]',
        observacoes_etapas JSONB DEFAULT '{}',
        criada_em TIMESTAMP DEFAULT NOW(),
        UNIQUE(vaga_id, candidato_id)
      );

      -- Adiciona colunas de proposta (se ainda não existirem)
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_texto TEXT;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_pdf_url TEXT;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_pdf_public_id TEXT;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_enviada_em TIMESTAMP;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_aceita_em TIMESTAMP;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_recusada_em TIMESTAMP;
      ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS proposta_motivo_recusa TEXT;

      CREATE TABLE IF NOT EXISTS mensagens_processo (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        autor_tipo TEXT,
        autor_nome TEXT,
        texto TEXT,
        contexto TEXT,
        criado_em TIMESTAMP DEFAULT NOW()
      );

      -- Arquivos anexados em mensagens de chat
      CREATE TABLE IF NOT EXISTS chat_arquivos (
        id SERIAL PRIMARY KEY,
        mensagem_id INTEGER REFERENCES mensagens_processo(id) ON DELETE CASCADE,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        nome_original TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        tamanho_bytes INTEGER NOT NULL,
        base64_data TEXT NOT NULL,
        criado_em TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_chat_arquivos_msg ON chat_arquivos(mensagem_id);
      CREATE INDEX IF NOT EXISTS idx_chat_arquivos_cand ON chat_arquivos(candidatura_id);

      CREATE TABLE IF NOT EXISTS documentos_candidatura (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        tipo TEXT NOT NULL,
        categoria TEXT NOT NULL,
        valor_texto TEXT,
        arquivo_url TEXT,
        arquivo_public_id TEXT,
        arquivo_nome TEXT,
        arquivo_tipo TEXT,
        arquivo_tamanho INTEGER,
        status TEXT DEFAULT 'pendente',
        justificativa_admin TEXT,
        enviado_em TIMESTAMP DEFAULT NOW(),
        revisado_em TIMESTAMP
      );

      -- Entrevistas agendadas (jul/2026 - dashboard profissional)
      CREATE TABLE IF NOT EXISTS entrevistas (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        etapa INTEGER NOT NULL,
        data_hora TIMESTAMP NOT NULL,
        duracao_minutos INTEGER DEFAULT 60,
        local TEXT,
        link_reuniao TEXT,
        google_event_id TEXT,
        observacoes TEXT,
        status TEXT DEFAULT 'agendada',
        criado_por INTEGER REFERENCES admins(id),
        criado_em TIMESTAMP DEFAULT NOW(),
        atualizado_em TIMESTAMP DEFAULT NOW()
      );
      ALTER TABLE entrevistas ADD COLUMN IF NOT EXISTS google_event_id TEXT;

      -- Chat Empresa <-> RH/Recrutador (jul/2026)
      CREATE TABLE IF NOT EXISTS empresa_chat (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        remetente_tipo TEXT NOT NULL, -- 'empresa' | 'rh'
        remetente_id INTEGER,
        remetente_nome TEXT,
        mensagem TEXT NOT NULL,
        lida_em TIMESTAMP,
        criado_em TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_empresa_chat_cand ON empresa_chat(candidatura_id, criado_em);
    `);

    // Tabela de logs de auditoria (jul/2026)
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        created_at TIMESTAMP DEFAULT NOW(),
        user_id INTEGER,
        user_type TEXT,
        user_email TEXT,
        action TEXT NOT NULL,
        resource_type TEXT,
        resource_id INTEGER,
        ip TEXT,
        user_agent TEXT,
        result TEXT,
        metadata JSONB DEFAULT '{}'::jsonb
      );
    `);
    // Índices da tabela de auditoria
    await client.query(`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, created_at DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type, resource_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);`);

    // Tabela de refresh tokens (Etapa 2, 2026-07-27)
    // Token armazenado como hash (sha256) — nunca em texto puro.
    // Suporta revogação individual (revoked_at) e por usuário (revoked_all).
    await client.query(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_type TEXT NOT NULL,
        user_id INTEGER,
        user_email TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        criado_em TIMESTAMP DEFAULT NOW(),
        expira_em TIMESTAMP NOT NULL,
        revogado_em TIMESTAMP,
        revogado_motivo TEXT,
        ip_criacao TEXT,
        user_agent_criacao TEXT
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_email, expira_em DESC);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_refresh_token ON refresh_tokens(token_hash);`);

    // Garantir colunas em tabelas já criadas (idempotente)
    await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS criada_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS atualizada_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
    // Migração: tabela documentos_candidatura pode ter sido criada com arquivo_base64 (versão antiga)
    await client.query(`ALTER TABLE documentos_candidatura ADD COLUMN IF NOT EXISTS arquivo_url TEXT;`);
    await client.query(`ALTER TABLE documentos_candidatura ADD COLUMN IF NOT EXISTS arquivo_public_id TEXT;`);
    await client.query(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
    // 🐛 BUG FIX (jul/2026): coluna role faltava em bancos antigos (a rota /auth/login-recrutador dava 500)
    await client.query(`ALTER TABLE recrutadores ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'recrutador';`);
    await client.query(`ALTER TABLE recrutadores ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;`);
    await client.query(`ALTER TABLE recrutadores ADD COLUMN IF NOT EXISTS primeiro_acesso BOOLEAN DEFAULT true;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS senha_hash TEXT;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS email_verificado BOOLEAN DEFAULT false;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS foto_url TEXT;`);
    // Campos adicionados em jul/2026
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS sobre_voce TEXT;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS experiencia TEXT;`);
    // Áreas de interesse (Banco de Talentos) — array JSON
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS areas_interesse JSONB DEFAULT '[]'::jsonb;`);
  // Mensagens de processo podem ter contexto (ex: 'documento_retornado') para filtrar no painel do candidato
  await client.query(`ALTER TABLE mensagens_processo ADD COLUMN IF NOT EXISTS contexto TEXT;`);
  // Comentários internos do admin por etapa (entrevista RH, entrevista gestor, etc.)
  // Estrutura: { "1": "obs etapa 1", "2": "obs etapa 2", ... }
  await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS observacoes_etapas JSONB DEFAULT '{}'::jsonb;`);

    // ──────────────────────────────────────────────────────────────────
    // Migrations Fase 1 (multi-tenant, jul/2026) — idempotente
    //   • vagas.empresa_id
    //   • empresa_usuarios.role
    //   • empresa_vaga_acesso.tipo + revogado_em + revogado_motivo
    //   • refresh_tokens.user_role + user_empresa_id
    // Importante: se a migration falhar, REGISTRAMOS e seguimos.
    // O boot do container NÃO deve abortar por causa de migration —
    // caso contrário o app fica indisponível até o dev corrigir manualmente.
    // ──────────────────────────────────────────────────────────────────
    try {
      const { aplicar: aplicarMigracoesFase1 } = require('./migrations/001_multi_tenant_fase1');
      const r1 = await aplicarMigracoesFase1();
      if (!r1.ok) {
        console.error('[MIGRATION FASE 1] Falha (mas segui):', r1.erro);
      }
    } catch (migrationErr) {
      console.error('[MIGRATION FASE 1] Erro não tratado (mas segui):', migrationErr.message);
    }

    // Migration 002 (28/07/2026) — normalização de nomenclatura RBAC.
    // Idempotente; corrige inconsistências detectadas na revisão:
    //  • empresa_vaga_acesso.tipo: alinha default + atualiza 'proprietaria' legacy → 'propria'
    //  • empresa_usuarios.role:    popula pendentes + adiciona CHECK constraint RBAC
    //    Valores canônicos: admin_empresa | recrutador | viewer
    try {
      const { aplicar: aplicarMigration002 } = require('./migrations/002_normalizar_rbac');
      const r2 = await aplicarMigration002();
      if (!r2.ok) {
        console.error('[MIGRATION 002] Falha (mas segui):', r2.erro);
      }
    } catch (migrationErr) {
      console.error('[MIGRATION 002] Erro não tratado (mas segui):', migrationErr.message);
    }

    // Migration 003 (28/07/2026) — portal público das empresas (Fase 5).
    // Idempotente; adiciona colunas públicas em `empresas` + backfill vagas.empresa_id
    // por match de nome (para vagas órfãs que ficaram sem empresa_id após Fase 1).
    try {
      const { aplicar: aplicarMigration003 } = require('./migrations/003_portal_publico_fase5');
      const r3 = await aplicarMigration003();
      if (!r3.ok) {
        console.error('[MIGRATION 003] Falha (mas segui):', r3.erro);
      }
    } catch (migrationErr) {
      console.error('[MIGRATION 003] Erro não tratado (mas segui):', migrationErr.message);
    }

    // Migration 004 (28/07/2026) — tabela append-only `candidatura_historico`
    // (Fase 6 — fluxo completo + histórico de etapas).
    try {
      const { aplicar: aplicarMigration004 } = require('./migrations/004_candidatura_historico_fase6');
      const r4 = await aplicarMigration004();
      if (!r4.ok) {
        console.error('[MIGRATION 004] Falha (mas segui):', r4.erro);
      }
    } catch (migrationErr) {
      console.error('[MIGRATION 004] Erro não tratado (mas segui):', migrationErr.message);
    }

    console.log('Tabelas criadas/verificadas + migrations Fase 1 + 002 + 003 + 004 aplicadas');
  } finally {
    client.release();
  }
}

module.exports = { pool, init };
// (redeploy trigger 23:30)
