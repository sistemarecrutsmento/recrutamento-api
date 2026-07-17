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

    console.log('Tabelas criadas/verificadas + colunas garantidas');
  } finally {
    client.release();
  }
}

module.exports = { pool, init };
