const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

const { pool, init } = require('./db');
const { enviarCodigo, enviarNotificacaoStatus, enviarEmailProposta, enviarEmailBg, enviarEmailAtualizacao, enviarEmail, enviarEmailInscricao } = require('./email');

// Email do admin pra receber notificações de ação do candidato
const ADMIN_NOTIF_EMAIL = process.env.ADMIN_NOTIF_EMAIL || process.env.ADMIN_EMAIL || 'fabio08dejesusjunior@gmail.com';
const { authMiddleware, authCandidato, authAdmin } = require('./auth');

// Cloudinary: aceita CLOUDINARY_URL no formato cloudinary://key:secret@cloud_name
if (process.env.CLOUDINARY_URL) cloudinary.config({ url: process.env.CLOUDINARY_URL, secure: true });
else if (process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '100mb' }));

// log toda requisição
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// handler de erro global
app.use((err, req, res, next) => {
  console.error('ERRO GLOBAL:', err);
  res.status(500).json({ erro: err.message || 'Erro interno' });
});

// ============= SAÚDE =============
app.get('/api/saude', (req, res) => res.json({ ok: true, sistema: process.env.SISTEMA_NOME, hora: new Date().toISOString() }));

// ============= DEBUG TEMPORÁRIO (remover depois) =============
// Tenta enviar e-mail de teste via Resend e mostra erro/sucesso
app.get('/api/_debug-email-teste', async (req, res) => {
  const to = req.query.to || 'fabio08dejesusjunior@gmail.com';
  const hasResend = !!process.env.RESEND_API_KEY;
  const hasFrom = !!process.env.EMAIL_FROM;
  // Lista todas as env vars relacionadas (mascaradas)
  const envRelacionadas = {};
  for (const k of Object.keys(process.env)) {
    if (/RESEND|EMAIL|SISTEMA|MAIL|SMTP|NODE_ENV|DEBUG|RENDER/i.test(k)) {
      const v = process.env[k];
      envRelacionadas[k] = v && v.length > 12 ? v.substring(0, 6) + '...' + v.substring(v.length - 4) : v;
    }
  }
  const info = {
    hasResendApiKey: hasResend,
    hasEmailFrom: hasFrom,
    emailFrom: process.env.EMAIL_FROM || null,
    resendKeyPreview: hasResend ? process.env.RESEND_API_KEY.substring(0, 8) + '...' : null,
    nodeEnv: process.env.NODE_ENV || 'sem',
    sistemaUrl: process.env.SISTEMA_URL || 'default',
    envRelacionadas,
    processUptimeSeg: Math.round(process.uptime())
  };
  try {
    const result = await enviarEmail({
      to,
      subject: 'Teste de e-mail - Vagas.io',
      html: '<p>Se você está lendo isso, o sistema de e-mail tá funcionando! ✅</p>'
    });
    res.json({ ok: true, info, result });
  } catch (e) {
    res.json({ ok: false, info, erro: e.message, code: e.code, response: e.response?.data });
  }
});

// Debug: testa bcrypt isolado
// =========================================================================
// ROTAS DE DEBUG (APENAS DESENVOLVIMENTO)
// =========================================================================
// Em produção, só funciona se DEBUG_API=1 estiver setado no env
const DEBUG = process.env.DEBUG_API === '1';

if (DEBUG) {
  // Teste de bcrypt
  app.get('/api/_debug/bcrypt', async (req, res) => {
    try {
      const hash = await bcrypt.hash('089339', 10);
      const ok = await bcrypt.compare('089339', hash);
      const ok2 = await bcrypt.compare('errado', hash);
      res.json({ ok, ok2, hashInicio: hash.substring(0, 7), node: process.version });
    } catch (e) {
      res.status(500).json({ erro: e.message, stack: e.stack?.substring(0, 500) });
    }
  });

  // Resetar senha do admin
  app.post('/api/_debug/reset-admin', async (req, res) => {
    try {
      const email = (req.body.email || process.env.EMAIL_FROM || '').toLowerCase();
      const senha = req.body.senha || process.env.ADMIN_SENHA || '089339';
      if (!email) return res.status(400).json({ erro: 'email obrigatório' });
      const hash = await bcrypt.hash(senha, 10);
      const { rows } = await pool.query(
        `UPDATE admins SET senha_hash = $1 WHERE email = $2 RETURNING id, email`,
        [hash, email]
      );
      res.json({ ok: true, atualizado: rows.length, hashInicio: hash.substring(0, 7) });
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // Estado do admin (SEM hash da senha — só id/nome/email)
  app.get('/api/_debug/admin-info', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, nome, email, criado_em FROM admins`
      );
      res.json({ admins: rows });
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  app.get('/api/_debug/config', async (req, res) => {
    res.json({
      hasDb: !!process.env.DATABASE_URL,
      hasEmail: !!process.env.EMAIL_FROM,
      hasEmailPwd: !!process.env.EMAIL_APP_PASSWORD,
      hasJwt: !!process.env.JWT_SECRET,
      smtpDebug: process.env.SMTP_DEBUG || '0',
      nodeEnv: process.env.NODE_ENV || 'sem'
    });
  });

  // Teste dashboard SEM auth (público)
  app.get('/api/_debug/dashboard', async (req, res) => {
    try {
      const stats = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM vagas WHERE status = 'publicada') as vagas_ativas,
          (SELECT COUNT(*) FROM candidatos) as total_candidatos,
          (SELECT COUNT(*) FROM candidaturas WHERE status = 'em_analise') as candidaturas_pendentes,
          (SELECT COUNT(*) FROM vagas) as total_vagas
      `);
      res.json({ stats: stats.rows[0] });
    } catch (e) {
      res.status(500).json({ erro: e.message, stack: e.stack?.substring(0, 300) });
    }
  });

  app.get('/api/_debug/ultimo-codigo/:email', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT codigo, expira_em, usado FROM codigos_verificacao
         WHERE email = $1 ORDER BY id DESC LIMIT 1`,
        [req.params.email.toLowerCase()]
      );
      if (rows.length === 0) return res.status(404).json({ erro: 'Nenhum código para esse e-mail' });
      res.json({ codigo: rows[0].codigo, expira_em: rows[0].expira_em, usado: rows[0].usado });
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // Migração manual via API
  app.post('/api/_debug/migrar', async (req, res) => {
    try {
      const cols = await pool.query(`
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE column_name ILIKE '%criad%'
      `);
      const sp = await pool.query(`SHOW search_path`);
      res.json({ ok: true, schemas: sp.rows, colunas_criadas: cols.rows });
    } catch (e) {
      res.status(500).json({ erro: e.message });
    }
  });

  // ===== Debug: ajustar etapas de uma vaga =====
  app.post('/api/_debug/vaga-etapas', async (req, res) => {
    try {
      const { vaga_id, substituir } = req.body;
      if (!vaga_id || !Array.isArray(substituir)) {
        return res.status(400).json({ erro: 'vaga_id e substituir[] são obrigatórios' });
      }
      const { rows: v } = await pool.query('SELECT id, etapas FROM vagas WHERE id = $1', [vaga_id]);
      if (v.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
      let etapas = v[0].etapas;
      if (typeof etapas === 'string') { try { etapas = JSON.parse(etapas); } catch (e) { etapas = []; } }
      let alterado = false;
      for (const e of (etapas || [])) {
        for (const s of substituir) {
          const nome = (typeof e === 'string' ? e : e.nome);
          if (nome === s.de) {
            if (typeof e === 'string') {
              const idx = etapas.indexOf(e);
              etapas[idx] = s.para;
            } else {
              e.nome = s.para;
            }
            alterado = true;
          }
        }
      }
      if (!alterado) return res.json({ ok: false, msg: 'Nenhuma etapa correspondia', etapas });
      const upd = await pool.query(
        'UPDATE vagas SET etapas = $1 WHERE id = $2 RETURNING etapas',
        [JSON.stringify(etapas), vaga_id]
      );
      res.json({ ok: true, etapas: upd.rows[0].etapas });
    } catch (e) {
      console.error(e);
      res.status(500).json({ erro: e.message });
    }
  });
} else {
  // Em produção, todas as rotas de debug retornam 404
  app.all('/api/_debug/*', (req, res) => res.status(404).json({ erro: 'Not found' }));
}

// ============= CEP (ViaCEP) =============
app.get('/api/cep/:cep', async (req, res) => {
  const cep = req.params.cep.replace(/\D/g, '');
  if (cep.length !== 8) return res.status(400).json({ erro: 'CEP inválido' });
  try {
    const { data } = await axios.get(`https://viacep.com.br/ws/${cep}/json/`);
    if (data.erro) return res.status(404).json({ erro: 'CEP não encontrado' });
    res.json(data);
  } catch {
    res.status(500).json({ erro: 'Erro ao buscar CEP' });
  }
});

// Cache de falhas de SMTP: se Gmail falhou, devolvemos codigo_debug
let smtpFalhando = false;
async function enviarCodigoSeguro(email, codigo) {
  if (smtpFalhando) return false;
  try {
    await enviarCodigo(email, codigo);
    console.log(`[EMAIL OK] Código enviado para ${email}`);
    return true;
  } catch (e) {
    console.error(`[EMAIL FAIL] ${email}: ${e.message}`);
    smtpFalhando = true;
    return false;
  }
}

// ============= CANDIDATO - CADASTRO =============
app.post('/api/candidato/iniciar', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: 'E-mail obrigatório' });

  const codigo = String(Math.floor(100000 + Math.random() * 900000));
  const expira = new Date(Date.now() + 10 * 60 * 1000);

  // Apaga códigos antigos não usados para esse e-mail
  await pool.query('DELETE FROM codigos_verificacao WHERE email = $1 AND usado = false', [email.toLowerCase()]);

  await pool.query(
    'INSERT INTO codigos_verificacao (email, codigo, expira_em) VALUES ($1, $2, $3)',
    [email.toLowerCase(), codigo, expira]
  );

  // SEMPRE devolve o codigo_debug para o front mostrar (já que o SMTP do Gmail
  // tem bloqueios contra IPs do Render). O front exibe um box amarelo com o código.
  // O e-mail real TAMBÉM é disparado em background (caso funcione).
  const resposta = {
    ok: true,
    mensagem: 'Código gerado',
    codigo_debug: codigo
  };

  // Tenta enviar em background (NUNCA bloqueia a resposta)
  setImmediate(async () => {
    await enviarCodigoSeguro(email, codigo);
  });

  res.json(resposta);
});

app.post('/api/candidato/verificar', async (req, res) => {
  const { email, codigo } = req.body;
  if (!email || !codigo) return res.status(400).json({ erro: 'E-mail e código obrigatórios' });

  const { rows } = await pool.query(
    `SELECT * FROM codigos_verificacao
     WHERE email = $1 AND codigo = $2 AND usado = false AND expira_em > NOW()
     ORDER BY id DESC LIMIT 1`,
    [email.toLowerCase(), codigo]
  );
  if (rows.length === 0) return res.status(400).json({ erro: 'Código inválido ou expirado' });

  await pool.query('UPDATE codigos_verificacao SET usado = true WHERE id = $1', [rows[0].id]);

  // marca e-mail como verificado se já existir candidato
  await pool.query('UPDATE candidatos SET email_verificado = true WHERE email = $1', [email.toLowerCase()]);

  const token = jwt.sign({ email: email.toLowerCase(), tipo: 'candidato' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ ok: true, token, email: email.toLowerCase() });
});

// ============= CANDIDATO - CADASTRO COM SENHA (NOVO) =============
// Cria conta nova com email+senha (sem código de verificação).
// Recebe dados básicos; o resto do perfil (endereço, formação, etc.) pode ser completado depois em /api/candidato/cadastrar.
app.post('/api/candidato/cadastro', async (req, res) => {
  const { email, senha, nome, cpf, celular, data_nascimento, sexo, cidade, estado, formacao } = req.body;
  if (!email || !senha || !nome) {
    return res.status(400).json({ erro: 'E-mail, senha e nome são obrigatórios' });
  }
  if (senha.length < 6) {
    return res.status(400).json({ erro: 'A senha deve ter no mínimo 6 caracteres' });
  }

  const emailLower = email.toLowerCase();

  // Verifica se já existe candidato com esse e-mail
  const { rows: existe } = await pool.query('SELECT id, senha_hash FROM candidatos WHERE email = $1', [emailLower]);
  if (existe.length > 0) {
    return res.status(400).json({ erro: 'Já existe uma conta com esse e-mail. Faça login.' });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const { rows } = await pool.query(
      `INSERT INTO candidatos (email, senha_hash, nome, cpf, celular, data_nascimento, sexo, cidade, estado, formacao, email_verificado)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
       RETURNING id, email, nome`,
      [emailLower, senhaHash, nome, cpf || null, celular || null, data_nascimento || null, sexo || null, cidade || null, estado || null, formacao || null]
    );

    const token = jwt.sign({ email: emailLower, tipo: 'candidato' }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ ok: true, token, candidato: rows[0] });
  } catch (e) {
    console.error('[CADASTRO ERRO]', e);
    if (e.code === '23505') return res.status(400).json({ erro: 'CPF ou e-mail já cadastrado' });
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

// ============= CANDIDATO - LOGIN COM SENHA (NOVO) =============
app.post('/api/candidato/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });

  const emailLower = email.toLowerCase();
  const { rows } = await pool.query('SELECT * FROM candidatos WHERE email = $1', [emailLower]);
  if (rows.length === 0) {
    return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
  }
  const cand = rows[0];

  // Se o candidato foi criado pelo fluxo antigo (sem senha), o hash é null
  if (!cand.senha_hash) {
    return res.status(401).json({ erro: 'Sua conta foi criada antes do login com senha. Cadastre-se novamente ou use o código de acesso.' });
  }

  const ok = await bcrypt.compare(senha, cand.senha_hash);
  if (!ok) {
    return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
  }

  const token = jwt.sign({ email: emailLower, tipo: 'candidato' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({
    ok: true,
    token,
    candidato: { id: cand.id, email: cand.email, nome: cand.nome }
  });
});

app.post('/api/candidato/cadastrar', authCandidato, async (req, res) => {
  const d = req.body;
  if (!d.nome) return res.status(400).json({ erro: 'Nome obrigatório' });

  const email = (d.email || req.user.email).toLowerCase();
  const areasInteresse = Array.isArray(d.areas_interesse) ? d.areas_interesse.slice(0, 5) : [];

  try {
    // Primeiro: UPDATE o candidato existente (por email) — o "cadastrar" agora é completar perfil
    const upd = await pool.query(
      `UPDATE candidatos SET
        cpf = COALESCE($1, cpf),
        nome = $2,
        data_nascimento = $3,
        sexo = $4,
        celular = $5,
        acessibilidade = $6,
        cep = $7,
        estado = $8,
        cidade = $9,
        bairro = $10,
        logradouro = $11,
        numero = $12,
        complemento = $13,
        formacao = $14,
        instituicao = $15,
        curso = $16,
        situacao = $17,
        data_conclusao = $18,
        primeiro_emprego = $19,
        banco_talentos = $20,
        recebe_comunicacoes = $21,
        sobre_voce = $22,
        experiencia = $23,
        areas_interesse = $24,
        email_verificado = true
      WHERE email = $25
      RETURNING id, nome, email, cpf`,
      [
        d.cpf || null, d.nome, d.data_nascimento || null, d.sexo || null, d.celular || null, d.acessibilidade || null,
        d.cep || null, d.estado || null, d.cidade || null, d.bairro || null,
        d.logradouro || null, d.numero || null, d.complemento || null,
        d.formacao || null, d.instituicao || null, d.curso || null,
        d.situacao || null, d.data_conclusao || null,
        !!d.primeiro_emprego, !!d.banco_talentos, !!d.recebe_comunicacoes,
        d.sobre_voce || null, d.experiencia || null,
        JSON.stringify(areasInteresse),
        email
      ]
    );

    let candidatoId;
    let result = upd;
    if (upd.rowCount === 0) {
      // Não existe — INSERT
      try {
        const ins = await pool.query(
          `INSERT INTO candidatos (
            cpf, nome, data_nascimento, sexo, celular, email, email_verificado,
            acessibilidade, cep, estado, cidade, bairro, logradouro, numero, complemento,
            formacao, instituicao, curso, situacao, data_conclusao,
            primeiro_emprego, banco_talentos, recebe_comunicacoes,
            sobre_voce, experiencia, areas_interesse
          ) VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)
          RETURNING id, nome, email, cpf`,
          [
            d.cpf || null, d.nome, d.data_nascimento || null, d.sexo || null, d.celular || null, email,
            d.acessibilidade || null,
            d.cep || null, d.estado || null, d.cidade || null, d.bairro || null,
            d.logradouro || null, d.numero || null, d.complemento || null,
            d.formacao || null, d.instituicao || null, d.curso || null,
            d.situacao || null, d.data_conclusao || null,
            !!d.primeiro_emprego, !!d.banco_talentos, !!d.recebe_comunicacoes,
            d.sobre_voce || null, d.experiencia || null,
            JSON.stringify(areasInteresse)
          ]
        );
        candidatoId = ins.rows[0].id;
        result = ins;
      } catch (e2) {
        if (e2.code === '23505') return res.status(400).json({ erro: 'CPF já cadastrado em outra conta' });
        throw e2;
      }
    } else {
      candidatoId = upd.rows[0].id;
    }

    // experiencias - apaga e recria
    if (candidatoId) {
      await pool.query('DELETE FROM experiencias WHERE candidato_id = $1', [candidatoId]);
      if (Array.isArray(d.experiencias)) {
        for (const exp of d.experiencias) {
          await pool.query(
            `INSERT INTO experiencias (candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [candidatoId, exp.cargo, exp.empresa, exp.inicio || null, exp.fim || null, !!exp.emprego_atual, exp.descricao || null]
          );
        }
      }
    }

    res.json({ ok: true, candidato: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar cadastro' });
  }
});

app.get('/api/candidato/perfil', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query('SELECT * FROM candidatos WHERE email = $1', [req.user.email]);
  if (c.length === 0) return res.json({ candidato: null });
  const { rows: ex } = await pool.query('SELECT * FROM experiencias WHERE candidato_id = $1 ORDER BY id DESC', [c[0].id]);
  res.json({ candidato: c[0], experiencias: ex });
});

app.put('/api/candidato/perfil', authCandidato, async (req, res) => {
  const d = req.body;
  const areasInteresse = Array.isArray(d.areas_interesse) ? d.areas_interesse.slice(0, 5) : null;
  try {
    const { rows } = await pool.query(
      `UPDATE candidatos SET
        nome = COALESCE($1, nome),
        cpf = COALESCE($2, cpf),
        data_nascimento = COALESCE($3, data_nascimento),
        sexo = COALESCE($4, sexo),
        celular = COALESCE($5, celular),
        cep = COALESCE($6, cep),
        estado = COALESCE($7, estado),
        cidade = COALESCE($8, cidade),
        bairro = COALESCE($9, bairro),
        logradouro = COALESCE($10, logradouro),
        numero = COALESCE($11, numero),
        complemento = COALESCE($12, complemento),
        formacao = COALESCE($13, formacao),
        instituicao = COALESCE($14, instituicao),
        curso = COALESCE($15, curso),
        situacao = COALESCE($16, situacao),
        data_conclusao = COALESCE($17, data_conclusao),
        acessibilidade = COALESCE($18, acessibilidade),
        sobre_voce = COALESCE($19, sobre_voce),
        experiencia = COALESCE($20, experiencia),
        primeiro_emprego = COALESCE($21, primeiro_emprego),
        areas_interesse = COALESCE($22, areas_interesse)
       WHERE email = $23 RETURNING *`,
      [
        d.nome, d.cpf, d.data_nascimento, d.sexo, d.celular,
        d.cep, d.estado, d.cidade, d.bairro, d.logradouro, d.numero, d.complemento,
        d.formacao, d.instituicao, d.curso, d.situacao, d.data_conclusao,
        d.acessibilidade, d.sobre_voce, d.experiencia,
        d.primeiro_emprego === undefined ? null : !!d.primeiro_emprego,
        areasInteresse ? JSON.stringify(areasInteresse) : null,
        req.user.email
      ]
    );

    // Sincronizar experiencias (se enviadas)
    if (rows.length > 0 && Array.isArray(d.experiencias)) {
      const candidatoId = rows[0].id;
      await pool.query('DELETE FROM experiencias WHERE candidato_id = $1', [candidatoId]);
      for (const exp of d.experiencias) {
        await pool.query(
          `INSERT INTO experiencias (candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [candidatoId, exp.cargo, exp.empresa, exp.inicio || null, exp.fim || null, !!exp.emprego_atual, exp.descricao || null]
        );
      }
    }

    res.json({ ok: true, candidato: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao atualizar perfil' });
  }
});

app.post('/api/candidato/trocar-senha', authCandidato, async (req, res) => {
  const { senha_atual, senha_nova } = req.body;
  if (!senha_atual || !senha_nova) {
    return res.status(400).json({ erro: 'Informe a senha atual e a nova senha' });
  }
  if (senha_nova.length < 6) {
    return res.status(400).json({ erro: 'A nova senha deve ter no mínimo 6 caracteres' });
  }
  try {
    const { rows } = await pool.query('SELECT id, senha_hash FROM candidatos WHERE email = $1', [req.user.email]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Conta não encontrada' });
    if (!rows[0].senha_hash) return res.status(400).json({ erro: 'Conta sem senha definida (legado)' });
    const ok = await bcrypt.compare(senha_atual, rows[0].senha_hash);
    if (!ok) return res.status(401).json({ erro: 'Senha atual incorreta' });
    const novoHash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE candidatos SET senha_hash = $1 WHERE id = $2', [novoHash, rows[0].id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao trocar senha' });
  }
});

app.get('/api/candidato/candidaturas', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
  if (c.length === 0) return res.json({ candidaturas: [] });
  const { rows } = await pool.query(
    `SELECT cand.*, v.titulo, v.empresa, v.cidade, v.estado
     FROM candidaturas cand
     JOIN vagas v ON v.id = cand.vaga_id
     WHERE cand.candidato_id = $1
     ORDER BY cand.criada_em DESC`,
    [c[0].id]
  );
  res.json({ candidaturas: rows });
});

app.post('/api/candidato/candidatar/:vagaId', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
  if (c.length === 0) return res.status(400).json({ erro: 'Complete seu cadastro antes de se candidatar' });

  try {
    const { rows } = await pool.query(
      `INSERT INTO candidaturas (vaga_id, candidato_id, status, etapa_atual, historico)
       VALUES ($1, $2, 'em_andamento', 1, $3)
       RETURNING *`,
      [req.params.vagaId, c[0].id, JSON.stringify([
        { etapa: 0, status: 'concluida', acao: 'inscricao', data: new Date().toISOString(), mensagem: 'Inscrição realizada' }
      ])]
    );
    // E-mail de boas-vindas: inscrição recebida (em background, não trava a response)
    try {
      const { rows: vd } = await pool.query(
        'SELECT v.titulo, v.empresa, cd.nome FROM vagas v, candidatos cd WHERE v.id = $1 AND cd.id = $2',
        [req.params.vagaId, c[0].id]
      );
      if (vd.length > 0) {
        enviarEmailBg(enviarEmailInscricao, req.user.email, vd[0].nome, vd[0].titulo, vd[0].empresa);
      }
    } catch (e) {
      console.error('[candidatar] Falha ao enviar e-mail de inscrição:', e.message);
    }
    res.json({ ok: true, candidatura: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'Você já se candidatou a esta vaga' });
    console.error(e);
    res.status(500).json({ erro: 'Erro ao se candidatar' });
  }
});

// Upload / atualização da foto de perfil (base64 inline — sem storage externo)
app.put('/api/candidato/foto', authCandidato, async (req, res) => {
  const { foto_url } = req.body;
  if (!foto_url) return res.status(400).json({ erro: 'foto_url é obrigatório' });
  if (typeof foto_url !== 'string' || !foto_url.startsWith('data:image/')) {
    return res.status(400).json({ erro: 'Formato inválido (esperado data:image/...)' });
  }
  // Limite ~6.7MB encoded (5MB original)
  if (foto_url.length > 7 * 1024 * 1024) {
    return res.status(413).json({ erro: 'Imagem muito grande (máx ~5MB)' });
  }
  try {
    const { rows } = await pool.query(
      'UPDATE candidatos SET foto_url = $1 WHERE email = $2 RETURNING foto_url',
      [foto_url, req.user.email]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Candidato não encontrado' });
    res.json({ ok: true, foto_url: rows[0].foto_url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao salvar foto' });
  }
});

app.delete('/api/candidato/foto', authCandidato, async (req, res) => {
  try {
    await pool.query('UPDATE candidatos SET foto_url = NULL WHERE email = $1', [req.user.email]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao remover foto' });
  }
});

// ============= VAGAS (PÚBLICO) =============
app.get('/api/vagas', async (req, res) => {
  const { cidade, area, tipo, nivel, busca } = req.query;
  let sql = `SELECT * FROM vagas WHERE status = 'publicada'`;
  const params = [];
  if (cidade) { params.push(`%${cidade}%`); sql += ` AND cidade ILIKE $${params.length}`; }
  if (area) { params.push(area); sql += ` AND area = $${params.length}`; }
  if (tipo) { params.push(tipo); sql += ` AND tipo_contrato = $${params.length}`; }
  if (nivel) { params.push(nivel); sql += ` AND nivel = $${params.length}`; }
  if (busca) { params.push(`%${busca}%`); sql += ` AND (titulo ILIKE $${params.length} OR empresa ILIKE $${params.length})`; }
  sql += ' ORDER BY criada_em DESC';
  const { rows } = await pool.query(sql, params);
  res.json({ vagas: rows });
});

app.get('/api/vagas/:id', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vagas WHERE id = $1', [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
  res.json({ vaga: rows[0] });
});

// ============= ADMIN/RECRUTADOR =============
app.post('/api/admin/login', async (req, res) => {
  try {
    console.log('[LOGIN] body recebido:', JSON.stringify(req.body));
    const { email, senha } = req.body;
    if (!email || !senha) {
      console.log('[LOGIN] campos faltando');
      return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
    }
    // tolerar tabela sem coluna 'role' (caso o init() tenha rodado antes dela existir)
    let rows;
    try {
      const r = await pool.query(
        'SELECT id, nome, email, senha_hash, role FROM admins WHERE email = $1',
        [email.toLowerCase()]
      );
      rows = r.rows;
    } catch (e1) {
      const r = await pool.query(
        'SELECT id, nome, email, senha_hash FROM admins WHERE email = $1',
        [email.toLowerCase()]
      );
      rows = r.rows.map(x => ({ ...x, role: 'admin' }));
    }
    console.log('[LOGIN] rows encontrados:', rows.length);
    if (rows.length === 0) return res.status(401).json({ erro: 'Credenciais inválidas' });
    console.log('[LOGIN] hash começa com:', rows[0].senha_hash?.substring(0, 7));
    const ok = await bcrypt.compare(senha, rows[0].senha_hash);
    console.log('[LOGIN] compare result:', ok);
    if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas' });

    const token = jwt.sign(
      { id: rows[0].id, email: rows[0].email, nome: rows[0].nome, tipo: 'admin' },
      process.env.JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ ok: true, token, usuario: { id: rows[0].id, nome: rows[0].nome, email: rows[0].email, role: rows[0].role || 'admin' } });
  } catch (e) {
    console.error('[LOGIN ERRO]', e);
    res.status(500).json({ erro: e.message });
  }
});

// USARÁ O E-MAIL DO ADMIN COMO LOGIN (fabio08dejesusjunior@gmail.com)

app.get('/api/admin/dashboard', authAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada') as vagas_ativas,
        (SELECT COUNT(*) FROM candidatos) as total_candidatos,
        (SELECT COUNT(*) FROM candidaturas WHERE status NOT IN ('reprovado','contratado')) as processos_ativos,
        (SELECT COUNT(*) FROM candidaturas WHERE criada_em > NOW() - INTERVAL '7 days') as novos_7d
    `);
    const processos = await pool.query(`
      SELECT c.*, v.titulo, v.empresa, cd.nome as candidato_nome
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE c.status NOT IN ('reprovado','contratado')
      ORDER BY c.criada_em DESC LIMIT 20
    `);
    const ranking = await pool.query(`
      SELECT v.titulo, v.empresa, COUNT(c.id) as total
      FROM vagas v
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE v.status = 'publicada'
      GROUP BY v.id
      ORDER BY total DESC LIMIT 5
    `);
    res.json({ stats: stats.rows[0], processos: processos.rows, ranking: ranking.rows });
  } catch (e) {
    console.error('[DASHBOARD ERRO]', e);
    res.status(500).json({ erro: e.message });
  }
});

app.post('/api/admin/vagas', authAdmin, async (req, res) => {
  try {
    const v = req.body;
    if (!v.titulo) return res.status(400).json({ erro: 'Título é obrigatório' });
    const etapas = v.etapas || [
      { nome: 'Inscrição' },
      { nome: 'Triagem curricular' },
      { nome: 'Entrevista RH' },
      { nome: 'Entrevista gestor' },
      { nome: 'Teste prático' },
      { nome: 'Contratação' }
    ];
    const { rows } = await pool.query(
      `INSERT INTO vagas (titulo, empresa, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, criada_por)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area, v.salario_min, v.salario_max, v.descricao, v.requisitos, v.beneficios, JSON.stringify(etapas), req.user.id]
    );
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[CRIAR VAGA ERRO]', e);
    res.status(500).json({ erro: 'Erro ao criar vaga' });
  }
});

app.get('/api/admin/vagas', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vagas ORDER BY criada_em DESC');
  res.json({ vagas: rows });
});

app.put('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  const v = req.body;
  // Monta query dinâmica para permitir atualizar etapas opcionalmente
  const updates = [];
  const values = [];
  const push = (col, val) => { values.push(val); updates.push(`${col} = $${values.length}`); };
  if (v.titulo !== undefined) push('titulo', v.titulo);
  if (v.empresa !== undefined) push('empresa', v.empresa);
  if (v.cidade !== undefined) push('cidade', v.cidade);
  if (v.estado !== undefined) push('estado', v.estado);
  if (v.tipo_contrato !== undefined) push('tipo_contrato', v.tipo_contrato);
  if (v.nivel !== undefined) push('nivel', v.nivel);
  if (v.area !== undefined) push('area', v.area);
  if (v.salario_min !== undefined) push('salario_min', v.salario_min);
  if (v.salario_max !== undefined) push('salario_max', v.salario_max);
  if (v.descricao !== undefined) push('descricao', v.descricao);
  if (v.requisitos !== undefined) push('requisitos', v.requisitos);
  if (v.beneficios !== undefined) push('beneficios', v.beneficios);
  if (v.status !== undefined) push('status', v.status);
  if (v.etapas !== undefined && Array.isArray(v.etapas)) push('etapas', JSON.stringify(v.etapas));
  if (updates.length === 0) return res.status(400).json({ erro: 'Nenhum campo para atualizar' });
  values.push(req.params.id);
  const { rows } = await pool.query(
    `UPDATE vagas SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
    values
  );
  if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
  res.json({ ok: true, vaga: rows[0] });
});

app.delete('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM vagas WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('[DELETE VAGA]', e);
    res.status(500).json({ erro: 'Erro ao deletar vaga' });
  }
});

app.get('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM vagas WHERE id = $1', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
    res.json({ vaga: rows[0] });
  } catch (e) {
    console.error('[GET VAGA]', e);
    res.status(500).json({ erro: 'Erro ao buscar vaga' });
  }
});

app.get('/api/admin/candidatos', authAdmin, async (req, res) => {
  try {
    const { area } = req.query;
    let sql = `SELECT id, nome, email, cpf, celular, cidade, estado, areas_interesse, banco_talentos, criado_em FROM candidatos`;
    const params = [];
    if (area) {
      params.push(JSON.stringify([area]));
      sql += ` WHERE areas_interesse @> $${params.length}::jsonb`;
    }
    sql += ' ORDER BY criado_em DESC';
    const { rows } = await pool.query(sql, params);
    res.json({ candidatos: rows });
  } catch (e) {
    console.error('[LIST CANDIDATOS]', e);
    res.status(500).json({ erro: 'Erro ao listar candidatos' });
  }
});

// Retorna os dados completos de um candidato (currículo) para o admin
app.get('/api/admin/candidato/:id', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, nome, email, cpf, celular, data_nascimento, sexo,
              acessibilidade, cep, estado, cidade, bairro, logradouro, numero, complemento,
              formacao, instituicao, curso, situacao, data_conclusao,
              primeiro_emprego, banco_talentos, areas_interesse, sobre_voce, experiencia,
              criado_em
       FROM candidatos WHERE id = $1`, [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Candidato não encontrado' });
    res.json({ candidato: rows[0] });
  } catch (e) {
    console.error('[GET CANDIDATO]', e);
    res.status(500).json({ erro: 'Erro ao buscar candidato' });
  }
});

app.get('/api/admin/candidaturas', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, v.titulo, v.empresa, cd.nome as candidato_nome, cd.email as candidato_email
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      ORDER BY c.criada_em DESC
    `);
    res.json({ candidaturas: rows });
  } catch (e) {
    console.error('[LIST CANDIDATURAS]', e);
    res.status(500).json({ erro: 'Erro ao listar candidaturas' });
  }
});

// Lista de vagas com contagem de candidaturas (p/ painel admin)
app.get('/api/admin/vagas-com-candidaturas', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
             COUNT(c.id) FILTER (WHERE c.status NOT IN ('rejeitado','reprovado')) AS total_ativas,
             COUNT(c.id) AS total_geral,
             COUNT(c.id) FILTER (WHERE c.status = 'em_analise') AS em_analise,
             COUNT(c.id) FILTER (WHERE c.status = 'em_andamento') AS em_andamento,
             COUNT(c.id) FILTER (WHERE c.status = 'contratado') AS contratados
      FROM vagas v
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      GROUP BY v.id
      HAVING COUNT(c.id) > 0
      ORDER BY v.criada_em DESC
    `);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[VAGAS COM CANDIDATURAS]', e);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

// Candidatos de uma vaga específica
app.get('/api/admin/vagas/:id/candidaturas', authAdmin, async (req, res) => {
  try {
    const vagaId = req.params.id;
    const { rows: vagaRows } = await pool.query('SELECT * FROM vagas WHERE id = $1', [vagaId]);
    if (vagaRows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
    const vaga = vagaRows[0];
    const { rows } = await pool.query(`
      SELECT c.*, cd.nome, cd.email, cd.celular, cd.cidade, cd.estado
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE c.vaga_id = $1
      ORDER BY c.criada_em DESC
    `, [vagaId]);
    res.json({ vaga, candidaturas: rows });
  } catch (e) {
    console.error('[VAGA CANDIDATURAS]', e);
    res.status(500).json({ erro: 'Erro ao listar candidatos da vaga' });
  }
});

app.get('/api/admin/candidatura/:id', authAdmin, async (req, res) => {
  try {
    const { rows: cand } = await pool.query(`
      SELECT c.*, v.titulo, v.empresa, v.etapas, v.cidade as v_cidade, v.estado as v_estado, v.descricao, v.requisitos,
             cd.id as candidato_id_full, cd.nome, cd.email, cd.celular, cd.cpf, cd.data_nascimento,
             cd.acessibilidade, cd.cep, cd.estado as cd_estado, cd.cidade as cd_cidade, cd.bairro,
             cd.logradouro, cd.numero, cd.complemento,
             cd.formacao, cd.instituicao, cd.curso, cd.situacao, cd.data_conclusao,
             cd.primeiro_emprego, cd.sobre_voce, cd.experiencia, cd.foto_url,
             cd.areas_interesse, cd.banco_talentos,
             cd.criado_em as candidato_criado_em
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE c.id = $1`, [req.params.id]);
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const candidatura = cand[0];

    // Buscar experiencias do candidato
    const { rows: exps } = await pool.query(
      'SELECT * FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC',
      [candidatura.candidato_id]
    );
    candidatura.experiencias = exps;

    res.json({ candidatura });
  } catch (e) {
    console.error('[GET CANDIDATURA]', e);
    res.status(500).json({ erro: 'Erro ao buscar candidatura' });
  }
});

// ============= DOCUMENTOS DO CANDIDATO (etapa "Coleta de documentos") =============

// Lista dos 14 documentos exigidos (categoria + tipo + label)
const DOCUMENTOS_OBRIGATORIOS = [
  // Campos de texto
  { categoria: 'texto', tipo: 'cpf', label: 'CPF' },
  { categoria: 'texto', tipo: 'rg', label: 'RG' },
  { categoria: 'texto', tipo: 'pis_pasep', label: 'Número do PIS/PASEP' },
  { categoria: 'texto', tipo: 'titulo_eleitor', label: 'Título de Eleitor' },
  { categoria: 'texto', tipo: 'reservista', label: 'Certificado de Reservista' },
  { categoria: 'texto', tipo: 'conta_bancaria', label: 'Conta bancária (agência e conta)' },
  // Anexos
  { categoria: 'arquivo', tipo: 'rg_foto', label: 'RG (frente/verso) ou CNH' },
  { categoria: 'arquivo', tipo: 'cpf_foto', label: 'CPF (ou CNH substituindo)' },
  { categoria: 'arquivo', tipo: 'ctps', label: 'Carteira de Trabalho Digital (CTPS)' },
  { categoria: 'arquivo', tipo: 'comprovante_residencia', label: 'Comprovante de residência atualizado' },
  { categoria: 'arquivo', tipo: 'titulo_eleitor_foto', label: 'Título de Eleitor (foto)' },
  { categoria: 'arquivo', tipo: 'certidao_nascimento', label: 'Certidão de nascimento ou casamento' },
  { categoria: 'arquivo', tipo: 'reservista_foto', label: 'Certificado de Reservista (foto)' },
  { categoria: 'arquivo', tipo: 'escolaridade', label: 'Comprovante de escolaridade' },
  { categoria: 'arquivo', tipo: 'foto_3x4', label: 'Foto 3x4' },
  { categoria: 'arquivo', tipo: 'aso', label: 'Atestado de Saúde Ocupacional (ASO)' }
];

// Candidato envia documentos da sua candidatura
app.post('/api/candidatura/:id/documentos', async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    const { documentos } = req.body; // [{tipo, valor_texto, arquivo_base64, arquivo_nome, arquivo_tipo}]
    if (!Array.isArray(documentos) || documentos.length === 0) {
      return res.status(400).json({ erro: 'Nenhum documento enviado' });
    }
    // Limite: 5MB em base64 (~3.7MB binário)
    const MAX = 5 * 1024 * 1024;
    for (const d of documentos) {
      if (d.arquivo_base64 && d.arquivo_base64.length > MAX) {
        return res.status(413).json({ erro: `Arquivo "${d.arquivo_nome || d.tipo}" passa de 5MB.` });
      }
    }
    // Apaga envios anteriores do mesmo tipo (candidato pode reenviar)
    const tipos = documentos.map(d => d.tipo).filter(Boolean);
    if (tipos.length) {
      // Antes de apagar, tenta remover do Cloudinary também (best effort)
      const { rows: antigos } = await pool.query(
        `SELECT id, arquivo_public_id FROM documentos_candidatura WHERE candidatura_id = $1 AND tipo = ANY($2)`,
        [candidaturaId, tipos]
      );
      for (const a of antigos) {
        if (a.arquivo_public_id) {
          cloudinary.uploader.destroy(a.arquivo_public_id).catch(() => {});
        }
      }
      await pool.query('DELETE FROM documentos_candidatura WHERE candidatura_id = $1 AND tipo = ANY($2)', [candidaturaId, tipos]);
    }
    // Insere os novos
    let salvos = 0;
    for (const d of documentos) {
      let arquivoUrl = null, arquivoPublicId = null;
      if (d.arquivo_base64) {
        // Sobe pro Cloudinary via data URI
        const dataUri = d.arquivo_base64.startsWith('data:') ? d.arquivo_base64 : `data:${d.arquivo_tipo || 'application/octet-stream'};base64,${d.arquivo_base64}`;
        try {
          const r = await cloudinary.uploader.upload(dataUri, {
            folder: `vagas-io/candidatura-${candidaturaId}`,
            public_id: `${candidaturaId}_${d.tipo}_${Date.now()}`,
            resource_type: 'auto'
          });
          arquivoUrl = r.secure_url;
          arquivoPublicId = r.public_id;
        } catch (upErr) {
          console.error('[DOCS] cloudinary upload erro:', upErr.message);
          return res.status(500).json({ erro: `Falha no upload do arquivo "${d.arquivo_nome || d.tipo}": ${upErr.message}` });
        }
      }
      await pool.query(
        `INSERT INTO documentos_candidatura
         (candidatura_id, tipo, categoria, valor_texto, arquivo_url, arquivo_public_id, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, enviado_em)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pendente', NOW())`,
        [candidaturaId, d.tipo, d.categoria || 'arquivo', d.valor_texto || null, arquivoUrl, arquivoPublicId, d.arquivo_nome || null, d.arquivo_tipo || null, d.arquivo_tamanho || null]
      );
      salvos++;
    }
    // Marca a etapa como "em_andamento" (candidato enviou) — admin ainda precisa revisar
    await pool.query(
      `UPDATE candidaturas SET etapa_atual = GREATEST(etapa_atual, $1) WHERE id = $2`,
      [5, candidaturaId] // etapa 5 = coleta de documentos
    );

    // Notifica o admin que documentos foram enviados (em background)
    try {
      if (ADMIN_NOTIF_EMAIL) {
        const { rows: candRows } = await pool.query(
          `SELECT c.id, cand.email, cand.nome, v.titulo
           FROM candidaturas c
           JOIN candidatos cand ON cand.id = c.candidato_id
           JOIN vagas v ON v.id = c.vaga_id
           WHERE c.id = $1`,
          [candidaturaId]
        );
        if (candRows.length > 0) {
          const cr = candRows[0];
          enviarEmailBg(enviarEmailAtualizacao, ADMIN_NOTIF_EMAIL, 'Admin', cr.titulo, {
            etapaNum: 6,
            etapaNome: 'Coleta de Documentos',
            acao: 'admin_docs_recebidos',
            status: 'em_andamento',
            mensagemAdmin: `Candidato ${cr.nome} (${cr.email}) enviou ${salvos} documento(s) na etapa de Coleta. Acesse o painel admin para revisar.`
          });
        }
      }
    } catch (e) {
      console.error('Falha ao notificar admin sobre documentos:', e.message);
    }

    res.json({ ok: true, salvos });
  } catch (e) {
    console.error('[DOCS] erro ao enviar:', e);
    res.status(500).json({ erro: e.message });
  }
});

// Candidato vê seus próprios documentos
app.get('/api/candidatura/:id/documentos', async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows, obrigatorios: DOCUMENTOS_OBRIGATORIOS });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Admin lista documentos de uma candidatura
app.get('/api/admin/candidatura/:id/documentos', authAdmin, async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows, obrigatorios: DOCUMENTOS_OBRIGATORIOS });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

// Admin aprova ou reprova um documento (com justificativa)
app.post('/api/admin/documento/:id/revisar', authAdmin, async (req, res) => {
  try {
    const docId = Number(req.params.id);
    // Aceita tanto {status: 'aprovado'|'reprovado'|'retornado'|'pendente'}
    // quanto {acao: 'aprovar'|'reprovar'|'retornar'|'reverter'}
    let { status, justificativa, acao } = req.body;
    if (acao && !status) {
      if (acao === 'aprovar') status = 'aprovado';
      else if (acao === 'reprovar') status = 'reprovado';
      else if (acao === 'retornar') status = 'retornado';
      else if (acao === 'reverter') status = 'pendente';
    }
    if (!['aprovado', 'reprovado', 'retornado', 'pendente'].includes(status)) {
      return res.status(400).json({ erro: 'status/acao inválido (use aprovado, reprovado, retornar ou reverter)' });
    }
    if ((status === 'reprovado' || status === 'retornado') && !justificativa) {
      return res.status(400).json({ erro: 'Justificativa obrigatória para retornar/reprovar' });
    }

    // Busca dados do doc + candidatura + candidato (pra notificar e salvar na timeline)
    const { rows: docRows } = await pool.query(
      `SELECT dc.*, cand.id as cand_id, cand.nome as cand_nome, cand.email as cand_email,
              v.titulo as vaga_titulo, c.id as candidatura_id
       FROM documentos_candidatura dc
       JOIN candidaturas c ON c.id = dc.candidatura_id
       JOIN candidatos cand ON cand.id = c.candidato_id
       JOIN vagas v ON v.id = c.vaga_id
       WHERE dc.id = $1`,
      [docId]
    );
    if (docRows.length === 0) return res.status(404).json({ erro: 'Documento não encontrado' });
    const docInfo = docRows[0];

    // Quando "retornado" é uma ação que LIBERA reenvio:
    // - Se o doc tem arquivo, marcamos o antigo como "tombstone" (status='retornado', justificativa com msg)
    //   e o CANDIDATO poderá enviar um novo doc (que vira um NOVO registro no banco).
    await pool.query(
      `UPDATE documentos_candidatura SET status = $1, justificativa_admin = $2, revisado_em = NOW() WHERE id = $3`,
      [status, justificativa || null, docId]
    );

    // Se for "retornado", adiciona uma mensagem na timeline da candidatura (aparece pro candidato no painel)
    if (status === 'retornado' && justificativa) {
      await pool.query(
        `INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto)
         VALUES ($1, 'admin', $2, $3, $4)`,
        [docInfo.candidatura_id, req.user.nome, '📄 ' + (docInfo.tipo || 'documento') + ': ' + justificativa, 'documento_retornado']
      );
      // Volta a candidatura pra status "em_andamento" na etapa atual (pra liberar reenvio)
      await pool.query(
        `UPDATE candidaturas SET status = 'em_andamento' WHERE id = $1`,
        [docInfo.candidatura_id]
      );

      // Notifica o candidato por e-mail (em background)
      try {
        const { rows: candRows } = await pool.query(
          'SELECT c.id, c.etapa_atual, c.etapas, cand.email, cand.nome, v.titulo FROM candidaturas c JOIN candidatos cand ON cand.id = c.candidato_id JOIN vagas v ON v.id = c.vaga_id WHERE c.id = $1',
          [docInfo.candidatura_id]
        );
        if (candRows.length > 0) {
          const cr = candRows[0];
          const etapaNum = cr.etapa_atual;
          let etapaNome = null;
          try {
            const arr = typeof cr.etapas === 'string' ? JSON.parse(cr.etapas) : cr.etapas;
            if (Array.isArray(arr) && arr[etapaNum - 1]) {
              etapaNome = typeof arr[etapaNum - 1] === 'string' ? arr[etapaNum - 1] : arr[etapaNum - 1].nome;
            }
          } catch (e) {}
          enviarEmailBg(enviarEmailAtualizacao, cr.email, cr.nome, cr.titulo, {
            etapaNum,
            etapaNome,
            acao: 'documento_retornado',
            status: 'em_andamento',
            mensagemAdmin: '📄 ' + (docInfo.tipo || 'documento') + ': ' + justificativa
          });
        }
      } catch (e) {
        console.error('Falha ao notificar retorno de documento:', e.message);
      }
    } else if (status === 'aprovado' || status === 'reprovado') {
      // Aprovação ou reprovação de um documento individual (sem mudar etapa)
      // Notifica o candidato em ambos os casos (aprovação E reprovação)
      const tipoDoc = docInfo.tipo || 'documento';
      const acaoDoc = status === 'aprovado' ? 'documento_aprovado' : 'documento_reprovado';
      const justificativaDoc = status === 'reprovado' ? (justificativa || 'Documento reprovado') : tipoDoc;
      try {
        const { rows: candRows } = await pool.query(
          'SELECT c.id, c.etapa_atual, c.etapas, cand.email, cand.nome, v.titulo FROM candidaturas c JOIN candidatos cand ON cand.id = c.candidato_id JOIN vagas v ON v.id = c.vaga_id WHERE c.id = $1',
          [docInfo.candidatura_id]
        );
        if (candRows.length > 0) {
          const cr = candRows[0];
          const etapaNum = cr.etapa_atual;
          let etapaNome = null;
          try {
            const arr = typeof cr.etapas === 'string' ? JSON.parse(cr.etapas) : cr.etapas;
            if (Array.isArray(arr) && arr[etapaNum - 1]) {
              etapaNome = typeof arr[etapaNum - 1] === 'string' ? arr[etapaNum - 1] : arr[etapaNum - 1].nome;
            }
          } catch (e) {}
          enviarEmailBg(enviarEmailAtualizacao, cr.email, cr.nome, cr.titulo, {
            etapaNum,
            etapaNome,
            acao: acaoDoc,
            status: 'em_andamento',
            mensagemAdmin: status === 'aprovado' ? tipoDoc : (tipoDoc + ': ' + justificativa)
          });
        }
      } catch (e) {
        console.error('Falha ao notificar ' + (status === 'aprovado' ? 'aprovação' : 'reprovação') + ' de documento:', e.message);
      }
    }

    res.json({ ok: true, status, documento: { id: docId, status, justificativa_admin: justificativa || null } });
  } catch (e) {
    console.error('[DOC REVISAR]', e);
    res.status(500).json({ erro: e.message });
  }
});

// Admin: APROVAR TODOS os documentos pendentes de uma candidatura e AVANÇAR etapa de uma vez
app.post('/api/admin/candidatura/:id/aprovar-documentos', authAdmin, async (req, res) => {
  try {
    const candId = Number(req.params.id);
    // 1) Buscar candidatura + vaga + candidato
    const { rows: cRows } = await pool.query(
      `SELECT c.*, v.titulo, v.etapas, cd.nome, cd.email
       FROM candidaturas c
       JOIN vagas v ON v.id = c.vaga_id
       JOIN candidatos cd ON cd.id = c.candidato_id
       WHERE c.id = $1`, [candId]);
    if (cRows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const cand = cRows[0];

    // 2) Listar docs da candidatura e checar quais foram ENVIADOS
    const { rows: docs } = await pool.query(
      `SELECT id, tipo, status FROM documentos_candidatura WHERE candidatura_id = $1`,
      [candId]
    );
    const tiposObrig = (DOCUMENTOS_OBRIGATORIOS || []).map(d => d.tipo);
    // Falta enviar: tipos obrigatórios que nem têm linha no banco
    const tiposEnviados = new Set(docs.map(d => d.tipo));
    const tiposFaltando = tiposObrig.filter(t => !tiposEnviados.has(t));
    if (tiposFaltando.length > 0) {
      return res.status(400).json({
        erro: 'Candidato ainda não enviou todos os documentos obrigatórios.',
        detalhes: { faltando: tiposFaltando }
      });
    }
    // Bloqueia só se há docs "retornado" (candidato precisa reenviar) ou "reprovado" (precisa reverter)
    const bloqueia = docs.filter(d =>
      tiposObrig.includes(d.tipo) && (d.status === 'retornado' || d.status === 'reprovado')
    );
    if (bloqueia.length > 0) {
      return res.status(400).json({
        erro: 'Há documentos marcados para reenviar/reprovados. Aguarde o candidato regularizar.',
        detalhes: { bloqueados: bloqueia.length }
      });
    }
    if (docs.length === 0) {
      return res.status(400).json({ erro: 'Nenhum documento enviado ainda.' });
    }

    // 3) Marcar TODOS os docs como aprovados
    await pool.query(
      `UPDATE documentos_candidatura SET status = 'aprovado', justificativa_admin = 'Aprovado em lote', revisado_em = NOW()
       WHERE candidatura_id = $1 AND status != 'aprovado'`,
      [candId]
    );

    // 4) Avançar etapa
    const novaEtapa = (cand.etapa_atual || 0) + 1;
    let totalEtapas = 7;
    try {
      const etapasArr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
      if (Array.isArray(etapasArr) && etapasArr.length) totalEtapas = etapasArr.length;
    } catch (e) {}
    const novoStatus = (novaEtapa >= totalEtapas) ? 'contratado' : 'em_andamento';

    // 5) Adicionar ao histórico
    const historico = Array.isArray(cand.historico) ? cand.historico : [];
    historico.push({
      etapa: novaEtapa,
      status: novoStatus,
      acao: 'aprovar_docs',
      mensagem: 'Documentação aprovada e processo avançado',
      data: new Date().toISOString(),
      por: req.user.nome
    });
    await pool.query(
      'UPDATE candidaturas SET status = $1, etapa_atual = $2, historico = $3 WHERE id = $4',
      [novoStatus, novaEtapa, JSON.stringify(historico), candId]
    );

    // 6) Notificar candidato (em background — não trava a resposta)
    try {
      // Pega o nome da etapa atual da vaga
      const etapaNome = (() => {
        try {
          const arr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
          if (Array.isArray(arr) && arr[novaEtapa - 1]) {
            return typeof arr[novaEtapa - 1] === 'string' ? arr[novaEtapa - 1] : arr[novaEtapa - 1].nome;
          }
        } catch (e) {}
        return null;
      })();
      enviarEmailBg(enviarEmailAtualizacao, cand.email, cand.nome, cand.titulo, {
        etapaNum: novaEtapa,
        etapaNome,
        acao: novoStatus === 'contratado' ? null : 'avancar',
        status: novoStatus
      });
    } catch (e) {
      console.error('Falha ao agendar notificação:', e.message);
    }

    res.json({
      ok: true,
      novaEtapa,
      novoStatus,
      totalEtapas,
      contratados: novoStatus === 'contratado'
    });
  } catch (e) {
    console.error('[APROVAR DOCS E AVANCAR]', e);
    res.status(500).json({ erro: e.message });
  }
});

// Admin: salva APENAS um comentário interno da etapa (sem mexer em status/etapa/historico)
app.post('/api/admin/candidatura/:id/comentario', authAdmin, async (req, res) => {
  const { etapa, comentario } = req.body;
  if (etapa == null || !comentario || !String(comentario).trim()) {
    return res.status(400).json({ erro: 'etapa e comentario são obrigatórios' });
  }
  const { rows: c } = await pool.query(
    'SELECT observacoes_etapas FROM candidaturas WHERE id = $1',
    [req.params.id]
  );
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const obs = (c[0].observacoes_etapas && typeof c[0].observacoes_etapas === 'object') ? { ...c[0].observacoes_etapas } : {};
  obs[String(etapa)] = String(comentario).trim();
  await pool.query(
    'UPDATE candidaturas SET observacoes_etapas = $1 WHERE id = $2',
    [JSON.stringify(obs), req.params.id]
  );
  res.json({ ok: true });
});

app.post('/api/admin/candidatura/:id/status', authAdmin, async (req, res) => {
  const { status, etapa, mensagem, acao, comentario } = req.body;
  // acao: 'avancar' = incrementa etapa_atual, 'reprovar' = marca rejeitado, 'aprovar' = aprova atual
  // comentario: observação interna do admin sobre a etapa atual (não vai pro candidato, fica em observacoes_etapas[etapa])
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, v.etapas, cd.nome, cd.email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });

  const cand = c[0];
  const historico = Array.isArray(cand.historico) ? cand.historico : [];
  const observacoes = (cand.observacoes_etapas && typeof cand.observacoes_etapas === 'object') ? { ...cand.observacoes_etapas } : {};
  let novoStatus = status;
  let novaEtapa = etapa ?? cand.etapa_atual;

  if (acao === 'avancar') {
    // Trava: se a etapa atual for a "Coleta de Documentos" (índice 4) e a vaga tiver 5 etapas
    // (inscrição + 4 = total 5), só avança se todos os docs obrigatórios estiverem aprovados.
    // Detectamos pelo nome da etapa, não por número fixo.
    let nomeEtapaAtual = '';
    try {
      const etapasArr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
      if (Array.isArray(etapasArr) && etapasArr.length > (cand.etapa_atual || 0)) {
        const e = etapasArr[cand.etapa_atual || 0];
        nomeEtapaAtual = (typeof e === 'string' ? e : (e?.nome || '')).toLowerCase();
      }
    } catch (e) {}
    if (nomeEtapaAtual.includes('documento') || nomeEtapaAtual.includes('document')) {
      const tiposObrig = (DOCUMENTOS_OBRIGATORIOS || []).map(d => d.tipo);
      if (tiposObrig.length > 0) {
        const { rows: docsCand } = await pool.query(
          `SELECT tipo, status FROM documentos_candidatura WHERE candidatura_id = $1 AND tipo = ANY($2)`,
          [cand.id, tiposObrig]
        );
        const enviadosTipos = new Set(docsCand.map(d => d.tipo));
        const todosEnviados = tiposObrig.every(t => enviadosTipos.has(t));
        const todosAprovados = docsCand.length === tiposObrig.length && docsCand.every(d => d.status === 'aprovado');
        if (!todosEnviados || !todosAprovados) {
          return res.status(400).json({
            erro: 'Não é possível avançar: há documentos pendentes ou reprovados.',
            detalhes: {
              obrigatorios: tiposObrig.length,
              enviados: docsCand.length,
              aprovados: docsCand.filter(d => d.status === 'aprovado').length,
              reprovados: docsCand.filter(d => d.status === 'reprovado').length,
              pendentes: tiposObrig.length - docsCand.length
            }
          });
        }
      }
    }
    novaEtapa = (cand.etapa_atual || 0) + 1;
    novoStatus = 'em_andamento';
    // Calcular total de etapas (do JSON etapas da vaga, ou usar padrão 7)
    let totalEtapas = 7;
    try {
      const etapasArr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
      if (Array.isArray(etapasArr) && etapasArr.length) totalEtapas = etapasArr.length;
    } catch (e) {}

    // (Sem trava ao entrar na etapa 5: o admin envia a proposta via botão 📨 Enviar Proposta
    //  que aparece quando o candidato já está na etapa 5. Ao aceitar, o candidato
    //  avança automaticamente pra etapa 6 - sem precisar de nova ação do admin.)

    if (novaEtapa >= totalEtapas) {
      novoStatus = 'contratado';
    }
  } else if (acao === 'reprovar') {
    novoStatus = 'rejeitado';
  } else if (acao === 'reabrir') {
    novoStatus = 'em_analise';
  }

  historico.push({ etapa: novaEtapa, status: novoStatus, mensagem, acao, data: new Date().toISOString(), por: req.user.nome });

  // Se o admin mandou um comentário, salva no índice da etapa ATUAL (a que ele tava atuando)
  // Quando avançar, vai pra próxima etapa e a próxima observação será salva lá.
  if (comentario && String(comentario).trim()) {
    observacoes[String(cand.etapa_atual || 0)] = String(comentario).trim();
  }

  await pool.query(
    'UPDATE candidaturas SET status = $1, etapa_atual = $2, historico = $3, observacoes_etapas = $4 WHERE id = $5',
    [novoStatus, novaEtapa, JSON.stringify(historico), JSON.stringify(observacoes), req.params.id]
  );

  if (mensagem) {
    await pool.query(
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto) VALUES ($1,$2,$3,$4)',
      [req.params.id, 'admin', req.user.nome, mensagem]
    );
  }

  // Notifica o candidato por e-mail (em background — não trava a resposta)
  try {
    // Pega o nome da etapa atual da vaga
    const etapaNome = (() => {
      try {
        const arr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
        if (Array.isArray(arr) && arr[(novaEtapa || 1) - 1]) {
          return typeof arr[(novaEtapa || 1) - 1] === 'string' ? arr[(novaEtapa || 1) - 1] : arr[(novaEtapa || 1) - 1].nome;
        }
      } catch (e) {}
      return null;
    })();
    enviarEmailBg(enviarEmailAtualizacao, cand.email, cand.nome, cand.titulo, {
      etapaNum: novaEtapa,
      etapaNome,
      acao,
      status: novoStatus,
      mensagemAdmin: mensagem || null
    });
  } catch (e) {
    console.error('Falha ao agendar notificação:', e.message);
  }

  res.json({ ok: true });
});

// ===== Admin: enviar proposta ao candidato (etapa 5 - Proposta) =====
// Recebe texto da proposta + opcional PDF (data URL base64) ou já com URL pública
app.post('/api/admin/candidatura/:id/enviar-proposta', authAdmin, async (req, res) => {
  const { texto, pdf_url, pdf_public_id } = req.body;
  if (!texto && !pdf_url) return res.status(400).json({ erro: 'Envie um texto ou um PDF da proposta' });

  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, cd.nome, cd.email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];

  // Se veio PDF em base64 (data URL), faz upload pro Cloudinary
  let pdfFinalUrl = pdf_url || null;
  let pdfFinalId = pdf_public_id || null;
  if (pdf_url && String(pdf_url).startsWith('data:application/pdf')) {
    if (!process.env.CLOUDINARY_URL && !process.env.CLOUDINARY_CLOUD_NAME) {
      return res.status(500).json({ erro: 'Cloudinary não configurado para receber PDF' });
    }
    try {
      const up = await cloudinary.uploader.upload(pdf_url, {
        folder: 'propostas',
        resource_type: 'raw',
        public_id: `proposta_${cand.id}_${Date.now()}`
      });
      pdfFinalUrl = up.secure_url;
      pdfFinalId = up.public_id;
    } catch (e) {
      console.error('Erro upload PDF proposta:', e);
      return res.status(500).json({ erro: 'Falha ao enviar PDF: ' + e.message });
    }
  }

  // Monta entrada no histórico
  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: cand.etapa_atual,
    status: 'proposta_enviada',
    acao: 'enviar_proposta',
    mensagem: 'Proposta enviada ao candidato',
    data: new Date().toISOString(),
    por: req.user.nome
  });

  await pool.query(
    `UPDATE candidaturas
     SET proposta_texto = $1,
         proposta_pdf_url = $2,
         proposta_pdf_public_id = $3,
         proposta_enviada_em = NOW(),
         historico = $4
     WHERE id = $5`,
    [texto || null, pdfFinalUrl, pdfFinalId, JSON.stringify(historico), req.params.id]
  );

  // Notifica o candidato por e-mail (em background — não trava a resposta)
  try {
    enviarEmailBg(enviarEmailProposta, cand.email, cand.nome, cand.titulo, pdfFinalUrl);
  } catch (e) {
    console.error('Falha ao agendar e-mail de proposta:', e.message);
  }

  res.json({ ok: true, proposta: { texto, pdf_url: pdfFinalUrl } });
});

// ===== Admin: visualizar proposta enviada (pra imprimir/baixar de novo) =====
app.get('/api/admin/candidatura/:id/proposta', authAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT proposta_texto, proposta_pdf_url, proposta_enviada_em, proposta_aceita_em, proposta_recusada_em, proposta_motivo_recusa FROM candidaturas WHERE id = $1',
    [req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  res.json({ ok: true, proposta: rows[0] });
});

// ===== Candidato: aceitar proposta =====
app.post('/api/candidato/aceitar-proposta/:candidaturaId', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, v.etapas, cd.email as cand_email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.candidaturaId]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];

  // Garante que o candidato é o dono da candidatura
  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });

  // Só pode aceitar se estiver na etapa 5 (Proposta)
  // (etapa_atual é 1-indexed: etapa 5 = Proposta)
  if ((cand.etapa_atual || 0) !== 5) {
    return res.status(400).json({ erro: 'Você só pode aceitar a proposta quando estiver na etapa "Proposta"' });
  }
  if (!cand.proposta_enviada_em) {
    return res.status(400).json({ erro: 'Nenhuma proposta foi enviada ainda' });
  }
  if (cand.proposta_aceita_em) {
    return res.status(400).json({ erro: 'Proposta já foi aceita' });
  }

  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: 6, // próxima etapa = Coleta de documentos (etapa 6)
    status: 'em_andamento',
    acao: 'aceitar_proposta',
    mensagem: 'Candidato aceitou a proposta',
    data: new Date().toISOString(),
    por: cand.cand_email
  });

  await pool.query(
    `UPDATE candidaturas
     SET proposta_aceita_em = NOW(),
         etapa_atual = 6,
         status = 'em_andamento',
         historico = $1
     WHERE id = $2`,
    [JSON.stringify(historico), req.params.candidaturaId]
  );

  // Notifica o candidato por e-mail (em background)
  try {
    enviarEmailBg(enviarEmailAtualizacao, cand.cand_email, 'Candidato', cand.titulo, {
      etapaNum: 6,
      etapaNome: 'Coleta de Documentos',
      acao: 'avancar',
      status: 'em_andamento',
      mensagemAdmin: 'Você aceitou a proposta! Agora é só enviar os documentos solicitados.'
    });
    // Notifica o admin também
    if (ADMIN_NOTIF_EMAIL) {
      enviarEmailBg(enviarEmailAtualizacao, ADMIN_NOTIF_EMAIL, 'Admin', cand.titulo, {
        etapaNum: 6,
        etapaNome: 'Coleta de Documentos',
        acao: 'admin_candidato_aceitou',
        status: 'em_andamento',
        mensagemAdmin: `Candidato ${cand.cand_email} ACEITOU a proposta. Próxima etapa: Coleta de Documentos.`
      });
    }
  } catch (e) {
    console.error('Falha ao notificar aceite de proposta:', e.message);
  }

  res.json({ ok: true, msg: 'Proposta aceita! Próxima etapa: Coleta de documentos.' });
});

// ===== Candidato: recusar proposta =====
app.post('/api/candidato/recusar-proposta/:candidaturaId', authCandidato, async (req, res) => {
  const { motivo } = req.body;
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, cd.email as cand_email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.candidaturaId]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];

  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });
  if ((cand.etapa_atual || 0) !== 5) {
    return res.status(400).json({ erro: 'Você só pode recusar a proposta quando estiver na etapa "Proposta"' });
  }

  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: 5,
    status: 'rejeitado',
    acao: 'recusar_proposta',
    mensagem: 'Candidato recusou a proposta' + (motivo ? `: ${motivo}` : ''),
    data: new Date().toISOString(),
    por: cand.cand_email
  });

  await pool.query(
    `UPDATE candidaturas
     SET proposta_recusada_em = NOW(),
         proposta_motivo_recusa = $1,
         status = 'rejeitado',
         historico = $2
     WHERE id = $3`,
    [motivo || null, JSON.stringify(historico), req.params.candidaturaId]
  );

  // Notifica o candidato por e-mail (em background)
  try {
    enviarEmailBg(enviarEmailAtualizacao, cand.cand_email, 'Candidato', cand.titulo, {
      etapaNum: 5,
      etapaNome: 'Proposta',
      acao: 'recusar_proposta',
      status: 'rejeitado',
      mensagemAdmin: 'Você recusou a proposta. O processo foi encerrado. Obrigado por participar!'
    });
    // Notifica o admin
    if (ADMIN_NOTIF_EMAIL) {
      enviarEmailBg(enviarEmailAtualizacao, ADMIN_NOTIF_EMAIL, 'Admin', cand.titulo, {
        etapaNum: 5,
        etapaNome: 'Proposta',
        acao: 'admin_candidato_recusou',
        status: 'rejeitado',
        mensagemAdmin: `Candidato ${cand.cand_email} RECUSOU a proposta${motivo ? '. Motivo: ' + motivo : ''}.`
      });
    }
  } catch (e) {
    console.error('Falha ao notificar recusa de proposta:', e.message);
  }

  res.json({ ok: true, msg: 'Proposta recusada.' });
});

// ===== Candidato: ver proposta pendente (pra aceitar/recusar) =====
app.get('/api/candidato/candidatura/:id/proposta', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query(`
    SELECT c.id, c.etapa_atual, c.status, c.proposta_texto, c.proposta_pdf_url,
           c.proposta_enviada_em, c.proposta_aceita_em, c.proposta_recusada_em,
           v.titulo, cd.email as cand_email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];
  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });

  res.json({
    ok: true,
    proposta: {
      texto: cand.proposta_texto,
      pdf_url: cand.proposta_pdf_url,
      enviada_em: cand.proposta_enviada_em,
      aceita_em: cand.proposta_aceita_em,
      recusada_em: cand.proposta_recusada_em,
      etapa_atual: cand.etapa_atual,
      status: cand.status
    }
  });
});

app.post('/api/admin/recrutadores', authAdmin, async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Nome, e-mail e senha obrigatórios' });
  const hash = await bcrypt.hash(senha, 10);
  try {
    const { rows } = await pool.query(
      'INSERT INTO recrutadores (nome, email, senha_hash, criado_por) VALUES ($1,$2,$3,$4) RETURNING id, nome, email',
      [nome, email.toLowerCase(), hash, req.user.id]
    );
    res.json({ ok: true, recrutador: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'E-mail já cadastrado' });
    res.status(500).json({ erro: 'Erro ao criar recrutador' });
  }
});

app.get('/api/admin/recrutadores', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, nome, email, ativo, criado_em FROM recrutadores ORDER BY criado_em DESC');
  res.json({ recrutadores: rows });
});

// ============= INIT =============
process.on('uncaughtException', (e) => {
  console.error('[UNCAUGHT EXCEPTION]', e);
});
process.on('unhandledRejection', (e) => {
  console.error('[UNHANDLED REJECTION]', e);
});

(async () => {
  try {
    await init();
    console.log('Banco inicializado com sucesso');

    // Endpoint pra testar email em produção (sem auth, mas com token simples)
  // GET /api/_teste/email?to=email@x.com
  app.get('/api/_teste/email', async (req, res) => {
    const to = req.query.to;
    if (!to) return res.status(400).json({ erro: 'Passe ?to=email@dominio.com' });
    if (!process.env.EMAIL_FROM && !process.env.RESEND_API_KEY) {
      return res.status(500).json({
        erro: 'Nenhum provedor de e-mail configurado',
        hasEmailFrom: !!process.env.EMAIL_FROM,
        hasResend: !!process.env.RESEND_API_KEY
      });
    }
    try {
      const result = await enviarEmail({
        to,
        subject: '🧪 Teste de envio - Recrutamento',
        html: '<h1>Funcionando! ✅</h1><p>Este é um teste do Zapia. Se você recebeu, o e-mail tá ok.</p>',
        text: 'Teste Zapia OK'
      });
      res.json({ ok: true, provedor: process.env.RESEND_API_KEY ? 'Resend' : 'Gmail SMTP', result });
    } catch (e) {
      console.error('[teste-email] ERRO:', e.message);
      res.status(500).json({
        erro: e.message,
        code: e.code,
        command: e.command,
        responseCode: e.responseCode,
        response: e.response
      });
    }
  });

  // ========== SEED DEMO: Importa 6 vagas de exemplo (apenas admin) ==========
  // Idempotente: se a vaga já existe (mesmo título+empresa), não duplica.
  app.post('/api/admin/seed-vagas-demo', authAdmin, async (req, res) => {
    try {
      const vagasDemo = [
        {
          titulo: 'Atendente de Sorveteria',
          empresa: 'Gelateria Bom Gosto',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'CLT', nivel: 'Operacional', area: 'Atendimento / Vendas',
          salario_min: 1518, salario_max: 1800,
          descricao: 'Atender clientes com simpatia e agilidade, servir sorvetes, preparar milk-shakes, açaís e demais produtos do cardápio, operar máquina de sorvete expresso, manter o balcão e a vitrine sempre organizados e limpos, controlar estoque de insumos (caldas, copos, coberturas), receber pagamentos (dinheiro, PIX e cartão) e apoiar no fechamento de caixa. Vaga perfeita para quem gosta de servir, trabalhar em equipe e tem energia para lidar com movimento nos fins de semana e alta temporada.',
          requisitos: 'Ensino médio completo. Experiência anterior em atendimento (sorveteria, cafeteria, lanchonete) será um diferencial. Simpatia, agilidade, organização e responsabilidade. Disponibilidade para finais de semana, feriados e para trabalhar em escala.',
          beneficios: 'Salário fixo + vale-refeição + vale-transporte + gorjeta + uniforme + possibilidade de efetivação + crescimento para líder de turno.',
          etapas: [{nome:'Inscrição'},{nome:'Triagem'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Teste Prático (montagem de sundae)'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        },
        {
          titulo: 'Gerente Administrativo',
          empresa: 'Distribuidora Prime Aracaju',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'CLT', nivel: 'Pleno', area: 'Administração / Gestão',
          salario_min: 3500, salario_max: 4800,
          descricao: 'Planejar, coordenar e supervisionar as rotinas administrativas da empresa (compras, financeiro, RH e facilities). Gerenciar equipe de auxiliares e assistentes, fazer controle de fluxo de caixa, contas a pagar e a receber, conciliação bancária, fechamento mensal, compras, contratos com fornecedores e relacionamento com a contabilidade. Reportar resultados direto à diretoria e propor melhorias de processo.',
          requisitos: 'Ensino superior completo em Administração, Contábeis, Gestão Comercial ou áreas afins. Experiência comprovada em gestão administrativa (mínimo 2 anos). Domínio de Excel avançado, ERP (preferencialmente Omie, Conta Azul ou similar) e rotinas financeiras. Liderança, organização, visão estratégica e boa comunicação.',
          beneficios: 'Salário fixo + bônus por performance + vale-refeição + vale-transporte + plano de saúde + plano odontológico + participação nos lucros + horário comercial (segunda a sexta).',
          etapas: [{nome:'Inscrição'},{nome:'Triagem Curricular'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Case Prático (gestão)'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        },
        {
          titulo: 'Farmacêutico(a)',
          empresa: 'Drogaria Bem Estar',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'CLT', nivel: 'Pleno', area: 'Saúde / Farmácia',
          salario_min: 3200, salario_max: 4200,
          descricao: 'Atuar como responsável técnico da drogaria, realizar dispensação de medicamentos (incluindo controlados), orientar pacientes sobre posologia e interações, supervisionar balconistas e caixas, controlar estoque e validade, realizar compra junto a distribuidores, emitir relatórios para a vigilância sanitária e cuidar do SNGPC (Sistema Nacional de Gerenciamento de Produtos Controlados).',
          requisitos: 'Graduação completa em Farmácia. CRF/SE ativo e regular. Experiência em drogaria será um diferencial. Conhecimento em SNGPC, controle de psicotrópicos e boas práticas de dispensação. Proatividade, ética, responsabilidade técnica e boa comunicação.',
          beneficios: 'Salário fixo + insalubridade (se aplicável) + vale-refeição + vale-transporte + participação nos lucros + plano de saúde + horário em escala.',
          etapas: [{nome:'Inscrição'},{nome:'Triagem Curricular'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Validação de Registro (CRF)'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        },
        {
          titulo: 'Garçom / Garçonete',
          empresa: 'Restaurante Sabor do Nordeste',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'CLT', nivel: 'Operacional', area: 'Atendimento / Hospitalidade',
          salario_min: 1518, salario_max: 2200,
          descricao: 'Receber clientes, apresentar o cardápio, anotar pedidos, servir pratos e bebidas com atenção e cordialidade, montar e desmontar mesas, manter o salão limpo e organizado, conferir comandas, operar sistema de PDV e apoiar no fechamento do caixa quando necessário. Trabalho dinâmico, com bastante contato com o público. Especialidade da casa: frutos do mar e culinária regional nordestina.',
          requisitos: 'Ensino médio completo. Experiência anterior em restaurante, bar ou cafeteria será um diferencial. Boa apresentação, simpatia, agilidade, trabalho sob pressão e em equipe. Disponibilidade para noites, finais de semana e feriados.',
          beneficios: 'Salário fixo + gorjeta garantida + vale-refeição + vale-transporte + uniforme + possibilidade de efetivação + crescimento para maître.',
          etapas: [{nome:'Inscrição'},{nome:'Triagem'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Teste Prático (simulação de atendimento)'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        },
        {
          titulo: 'Auxiliar de Escritório',
          empresa: 'Contábil Sergipe Assessoria',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'CLT', nivel: 'Júnior', area: 'Administrativo / Apoio',
          salario_min: 1518, salario_max: 1900,
          descricao: 'Apoiar as rotinas do escritório: receber e organizar documentos, protocolar entregas, digitalizar e arquivar, atender clientes no balcão e por telefone/WhatsApp, lançar dados em planilhas e sistema, emitir recibos e boletos, controlar agenda de reuniões e prestar suporte geral aos setores administrativo e contábil.',
          requisitos: 'Ensino médio completo (cursando superior será um diferencial). Boa digitação, organização, atenção a detalhes, noções de Excel/Google Sheets e pacote Office. Comunicativa, proativa e com vontade de aprender. Não exigimos experiência prévia.',
          beneficios: 'Salário compatível + vale-refeição + vale-transporte + plano odontológico + horário comercial (segunda a sexta, sem plantão) + oportunidade de efetivação e crescimento.',
          etapas: [{nome:'Inscrição'},{nome:'Triagem'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Teste Prático (digitação e planilha)'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        },
        {
          titulo: 'Estagiário(a) de Administração',
          empresa: 'Grupo Vértice Empreendimentos',
          cidade: 'Aracaju', estado: 'SE',
          tipo_contrato: 'Estágio', nivel: 'Estágio', area: 'Administração / Aprendizagem',
          salario_min: 900, salario_max: 1200,
          descricao: 'Apoiar o time administrativo em rotinas de controle financeiro, organização de documentos, atendimento a clientes internos e externos, atualização de planilhas, controle de estoque, apoio em eventos e projetos especiais. Vaga com mentoria, foco em desenvolvimento e aprendizado prático na área.',
          requisitos: 'Cursando Ensino Superior em Administração, Contábeis, Gestão Comercial ou áreas afins (a partir do 2º semestre). Conhecimento básico em Excel e Google Workspace. Vontade de aprender, organização, responsabilidade e comprometimento com o horário (6h/dia).',
          beneficios: 'Bolsa-auxílio + vale-transporte + vale-refeição + seguro de vida + chance de efetivação ao final do estágio + certificado + mentoria semanal com gestor.',
          etapas: [{nome:'Inscrição'},{nome:'Triagem Curricular'},{nome:'Entrevista RH'},{nome:'Entrevista Gestor'},{nome:'Dinâmica em Grupo'},{nome:'Proposta'},{nome:'Coleta Documentos'},{nome:'Contratação'}]
        }
      ];

      const criadas = [];
      const jaExistiam = [];
      for (const v of vagasDemo) {
        // Verifica duplicidade por título + empresa
        const dup = await pool.query(
          'SELECT id FROM vagas WHERE LOWER(titulo) = LOWER($1) AND LOWER(empresa) = LOWER($2)',
          [v.titulo, v.empresa]
        );
        if (dup.rows.length > 0) {
          jaExistiam.push({ id: dup.rows[0].id, titulo: v.titulo, empresa: v.empresa });
          continue;
        }
        const { rows } = await pool.query(
          `INSERT INTO vagas (titulo, empresa, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id, titulo, empresa`,
          [v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area, v.salario_min, v.salario_max, v.descricao, v.requisitos, v.beneficios, JSON.stringify(v.etapas), 'publicada', req.user.id]
        );
        criadas.push(rows[0]);
      }
      res.json({ ok: true, criadas: criadas.length, jaExistiam: jaExistiam.length, detalhes: { criadas, jaExistiam } });
    } catch (e) {
      console.error('[SEED VAGAS DEMO ERRO]', e);
      res.status(500).json({ erro: e.message });
    }
  });

  const port = process.env.PORT || 10000;
    app.listen(port, () => console.log(`API rodando na porta ${port}`));
  } catch (e) {
    console.error('Erro ao iniciar:', e);
    process.exit(1);
  }
})();
