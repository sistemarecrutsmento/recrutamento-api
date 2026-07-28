// Migration 006 — Fase 9: Planos + Onboarding steps + drop empresa_notificacoes (órfã)

const PLANOS_SEED = [
  {
    slug: 'gratuito',
    nome: 'Gratuito',
    descricao: 'Para testar a plataforma. Ideal para MEI e freelancers.',
    preco_mensal: 0,
    limite_vagas: 1,
    limite_usuarios: 1,
    limite_candidaturas_mes: 50,
    destaque: false,
    ativo: true,
  },
  {
    slug: 'essencial',
    nome: 'Essencial',
    descricao: 'Para pequenas empresas que estão começando a estruturar o RH.',
    preco_mensal: 9700,  // R$ 97,00 em centavos
    limite_vagas: 5,
    limite_usuarios: 3,
    limite_candidaturas_mes: 300,
    destaque: false,
    ativo: true,
  },
  {
    slug: 'profissional',
    nome: 'Profissional',
    descricao: 'Para empresas em crescimento com múltiplos processos simultâneos.',
    preco_mensal: 24700,  // R$ 247,00
    limite_vagas: 20,
    limite_usuarios: 10,
    limite_candidaturas_mes: 1000,
    destaque: true,
    ativo: true,
  },
  {
    slug: 'enterprise',
    nome: 'Enterprise',
    descricao: 'Para grandes empresas com volume alto de contratações.',
    preco_mensal: 69700,  // R$ 697,00
    limite_vagas: 999,
    limite_usuarios: 999,
    limite_candidaturas_mes: 99999,
    destaque: false,
    ativo: true,
  },
];

async function ensureCol(client, tabela, coluna, def) {
  const { rowCount } = await client.query(
    `SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,
    [tabela, coluna]
  );
  if (rowCount === 0) {
    await client.query(`ALTER TABLE ${tabela} ADD COLUMN ${coluna} ${def}`);
    return true;
  }
  return false;
}

async function aplicar(client, log = console.log) {
  // ─── 1. Criar tabela planos ─────────────────────────────────────────────
  await client.query(`
    CREATE TABLE IF NOT EXISTS planos (
      id                      SERIAL PRIMARY KEY,
      slug                    TEXT UNIQUE NOT NULL,
      nome                    TEXT NOT NULL,
      descricao               TEXT,
      preco_mensal            INTEGER NOT NULL DEFAULT 0,  -- em centavos (BRL)
      limite_vagas            INTEGER NOT NULL DEFAULT 1,
      limite_usuarios         INTEGER NOT NULL DEFAULT 1,
      limite_candidaturas_mes INTEGER NOT NULL DEFAULT 50,
      destaque                BOOLEAN DEFAULT false,
      ativo                   BOOLEAN DEFAULT true,
      criado_em               TIMESTAMP DEFAULT NOW()
    )
  `);
  log('planos: tabela criada/confirmada');

  // ─── 2. Seed de planos (upsert por slug) ────────────────────────────────
  for (const p of PLANOS_SEED) {
    await client.query(
      `INSERT INTO planos (slug, nome, descricao, preco_mensal,
                           limite_vagas, limite_usuarios, limite_candidaturas_mes,
                           destaque, ativo)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (slug) DO UPDATE SET
         nome                    = EXCLUDED.nome,
         descricao               = EXCLUDED.descricao,
         preco_mensal            = EXCLUDED.preco_mensal,
         limite_vagas            = EXCLUDED.limite_vagas,
         limite_usuarios         = EXCLUDED.limite_usuarios,
         limite_candidaturas_mes = EXCLUDED.limite_candidaturas_mes,
         destaque                = EXCLUDED.destaque,
         ativo                   = EXCLUDED.ativo`,
      [p.slug, p.nome, p.descricao, p.preco_mensal,
       p.limite_vagas, p.limite_usuarios, p.limite_candidaturas_mes,
       p.destaque, p.ativo]
    );
  }
  log('planos: 4 planos seed aplicados (upsert)');

  // ─── 3. Coluna plano_id em empresas (FK para planos) ────────────────────
  const addedPlanoId = await ensureCol(client, 'empresas', 'plano_id', 'INTEGER REFERENCES planos(id)');
  if (addedPlanoId) log('empresas: coluna plano_id adicionada');

  // Backfill: empresas com plano TEXT → migra para plano_id
  await client.query(`
    UPDATE empresas e
    SET plano_id = (SELECT id FROM planos p WHERE p.slug = e.plano OR p.slug = 'essencial' LIMIT 1)
    WHERE e.plano_id IS NULL
  `);
  log('empresas: backfill plano_id concluído');

  // ─── 4. Coluna onboarding_step em empresas ──────────────────────────────
  const addedOEmp = await ensureCol(client, 'empresas', 'onboarding_step', 'INTEGER DEFAULT 0');
  if (addedOEmp) log('empresas: coluna onboarding_step adicionada');

  // Empresas com vagas publicadas já estão além do onboarding
  await client.query(`
    UPDATE empresas SET onboarding_step = 3
    WHERE onboarding_step = 0
      AND id IN (SELECT DISTINCT empresa_id FROM vagas WHERE empresa_id IS NOT NULL AND status = 'publicada')
  `);
  log('empresas: backfill onboarding_step para empresas com vagas publicadas');

  // ─── 5. Coluna onboarding_step em candidatos ────────────────────────────
  const addedOCand = await ensureCol(client, 'candidatos', 'onboarding_step', 'INTEGER DEFAULT 0');
  if (addedOCand) log('candidatos: coluna onboarding_step adicionada');

  // Candidatos com candidatura já estão além do onboarding
  await client.query(`
    UPDATE candidatos SET onboarding_step = 4
    WHERE onboarding_step = 0
      AND id IN (SELECT DISTINCT candidato_id FROM candidaturas)
  `);
  log('candidatos: backfill onboarding_step para candidatos com candidatura');

  // ─── 6. Drop empresa_notificacoes (tabela órfã) ─────────────────────────
  const hasEmpNotif = await client.query(`
    SELECT 1 FROM information_schema.tables
    WHERE table_schema='public' AND table_name='empresa_notificacoes'
  `);
  if (hasEmpNotif.rowCount > 0) {
    await client.query('DROP TABLE empresa_notificacoes CASCADE');
    log('empresa_notificacoes: dropada (era órfã — sem INSERTs nem SELECTs)');
  } else {
    log('empresa_notificacoes: já não existe');
  }
}

module.exports = { aplicar };
