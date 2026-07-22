const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
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
        observacoes TEXT,
        status TEXT DEFAULT 'agendada',
        criado_por INTEGER REFERENCES admins(id),
        criado_em TIMESTAMP DEFAULT NOW(),
        atualizado_em TIMESTAMP DEFAULT NOW()
      );

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

    // Garantir colunas em tabelas já criadas (idempotente)
    await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS criada_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS atualizada_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
    // Migração: tabela documentos_candidatura pode ter sido criada com arquivo_base64 (versão antiga)
    await client.query(`ALTER TABLE documentos_candidatura ADD COLUMN IF NOT EXISTS arquivo_url TEXT;`);
    await client.query(`ALTER TABLE documentos_candidatura ADD COLUMN IF NOT EXISTS arquivo_public_id TEXT;`);
    await client.query(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
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

    console.log('Tabelas criadas/verificadas + colunas garantidas');
  } finally {
    client.release();
  }
}

module.exports = { pool, init };
