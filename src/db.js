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
        criado_em TIMESTAMP DEFAULT NOW()
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
