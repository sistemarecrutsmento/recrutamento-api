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
        criada_em TIMESTAMP DEFAULT NOW(),
        UNIQUE(vaga_id, candidato_id)
      );

      CREATE TABLE IF NOT EXISTS mensagens_processo (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        autor_tipo TEXT,
        autor_nome TEXT,
        texto TEXT,
        criado_em TIMESTAMP DEFAULT NOW()
      );

      -- Documentos da etapa "Coleta de Documentos"
      -- Pode ser campo de texto (cpf, rg, pis) OU arquivo (foto do RG, PDF)
      CREATE TABLE IF NOT EXISTS documentos_candidatura (
        id SERIAL PRIMARY KEY,
        candidatura_id INTEGER REFERENCES candidaturas(id) ON DELETE CASCADE,
        tipo TEXT NOT NULL,            -- 'cpf', 'rg_foto', 'pis', 'foto_3x4', etc
        categoria TEXT NOT NULL,       -- 'texto' ou 'arquivo'
        valor_texto TEXT,              -- preenchido quando categoria='texto'
        url_arquivo TEXT,              -- preenchido quando categoria='arquivo' (link Cloudinary)
        public_id TEXT,                -- public_id do Cloudinary (pra deletar depois)
        nome_arquivo TEXT,             -- nome original (ex: 'rg-frente.jpg')
        status TEXT DEFAULT 'pendente',-- 'pendente' | 'aprovado' | 'reprovado'
        justificativa_admin TEXT,      -- quando reprovado, o admin justifica
        justificativa_candidato TEXT,  -- candidato pode escrever obs (ex: 'substituindo por CNH')
        revisado_em TIMESTAMP,
        revisado_por TEXT,             -- nome do admin que revisou
        criado_em TIMESTAMP DEFAULT NOW(),
        UNIQUE(candidatura_id, tipo)
      );
    `);

    // Garantir colunas em tabelas já criadas (idempotente)
    await client.query(`ALTER TABLE candidaturas ADD COLUMN IF NOT EXISTS criada_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE admins ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW();`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS senha_hash TEXT;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS email_verificado BOOLEAN DEFAULT false;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS foto_url TEXT;`);
    // Campos adicionados em jul/2026
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS sobre_voce TEXT;`);
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS experiencia TEXT;`);
    // Áreas de interesse (Banco de Talentos) — array JSON
    await client.query(`ALTER TABLE candidatos ADD COLUMN IF NOT EXISTS areas_interesse JSONB DEFAULT '[]'::jsonb;`);

    console.log('Tabelas criadas/verificadas + colunas garantidas');
  } finally {
    client.release();
  }
}

module.exports = { pool, init };
