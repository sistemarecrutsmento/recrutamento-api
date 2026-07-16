const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const { pool, init } = require('./db');
const { enviarCodigo, enviarNotificacaoStatus } = require('./email');
const { authMiddleware, authCandidato, authAdmin } = require('./auth');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '5mb' }));

// ============= SAÚDE =============
app.get('/api/saude', (req, res) => res.json({ ok: true, sistema: process.env.SISTEMA_NOME, hora: new Date().toISOString() }));

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

// ============= CANDIDATO - CADASTRO =============
app.post('/api/candidato/iniciar', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: 'E-mail obrigatório' });

  const codigo = String(Math.floor(100000 + Math.random() * 900000));
  const expira = new Date(Date.now() + 10 * 60 * 1000);

  await pool.query(
    'INSERT INTO codigos_verificacao (email, codigo, expira_em) VALUES ($1, $2, $3)',
    [email.toLowerCase(), codigo, expira]
  );

  try {
    await enviarCodigo(email, codigo);
    res.json({ ok: true, mensagem: 'Código enviado para o e-mail' });
  } catch (e) {
    console.error('Erro ao enviar e-mail:', e.message);
    res.status(500).json({ erro: 'Falha ao enviar e-mail. Verifique as credenciais.' });
  }
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

app.post('/api/candidato/cadastrar', authCandidato, async (req, res) => {
  const d = req.body;
  if (!d.nome || !d.cpf) return res.status(400).json({ erro: 'Nome e CPF obrigatórios' });

  try {
    const result = await pool.query(
      `INSERT INTO candidatos (
        cpf, nome, data_nascimento, sexo, celular, email, email_verificado,
        acessibilidade, cep, estado, cidade, bairro, logradouro, numero, complemento,
        formacao, instituicao, curso, situacao, data_conclusao,
        primeiro_emprego, banco_talentos, recebe_comunicacoes
      ) VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
      ON CONFLICT (cpf) DO UPDATE SET
        nome = EXCLUDED.nome,
        data_nascimento = EXCLUDED.data_nascimento,
        sexo = EXCLUDED.sexo,
        celular = EXCLUDED.celular,
        email = EXCLUDED.email,
        acessibilidade = EXCLUDED.acessibilidade,
        cep = EXCLUDED.cep, estado = EXCLUDED.estado, cidade = EXCLUDED.cidade,
        bairro = EXCLUDED.bairro, logradouro = EXCLUDED.logradouro, numero = EXCLUDED.numero, complemento = EXCLUDED.complemento,
        formacao = EXCLUDED.formacao, instituicao = EXCLUDED.instituicao, curso = EXCLUDED.curso,
        situacao = EXCLUDED.situacao, data_conclusao = EXCLUDED.data_conclusao,
        primeiro_emprego = EXCLUDED.primeiro_emprego, banco_talentos = EXCLUDED.banco_talentos, recebe_comunicacoes = EXCLUDED.recebe_comunicacoes
      RETURNING id, nome, email`,
      [
        d.cpf, d.nome, d.data_nascimento || null, d.sexo || null, d.celular || null, d.email.toLowerCase(),
        d.acessibilidade || null,
        d.cep || null, d.estado || null, d.cidade || null, d.bairro || null,
        d.logradouro || null, d.numero || null, d.complemento || null,
        d.formacao || null, d.instituicao || null, d.curso || null,
        d.situacao || null, d.data_conclusao || null,
        !!d.primeiro_emprego, !!d.banco_talentos, !!d.recebe_comunicacoes
      ]
    );

    const candidatoId = result.rows[0].id;

    // experiencias - apaga e recria
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

    res.json({ ok: true, candidato: result.rows[0] });
  } catch (e) {
    console.error(e);
    if (e.code === '23505') return res.status(400).json({ erro: 'CPF já cadastrado' });
    res.status(500).json({ erro: 'Erro ao salvar cadastro' });
  }
});

app.get('/api/candidato/perfil', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query('SELECT * FROM candidatos WHERE email = $1', [req.user.email]);
  if (c.length === 0) return res.json({ candidato: null });
  const { rows: ex } = await pool.query('SELECT * FROM experiencias WHERE candidato_id = $1 ORDER BY id DESC', [c[0].id]);
  res.json({ candidato: c[0], experiencias: ex });
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
       VALUES ($1, $2, 'em_analise', 0, $3)
       RETURNING *`,
      [req.params.vagaId, c[0].id, JSON.stringify([{ etapa: 0, status: 'em_analise', data: new Date().toISOString() }])]
    );
    res.json({ ok: true, candidatura: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'Você já se candidatou a esta vaga' });
    console.error(e);
    res.status(500).json({ erro: 'Erro ao se candidatar' });
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
  const { email, senha } = req.body;
  const { rows } = await pool.query(
    'SELECT * FROM admins WHERE email = $1 UNION SELECT * FROM recrutadores WHERE email = $1 AND ativo = true',
    [email.toLowerCase()]
  );
  if (rows.length === 0) return res.status(401).json({ erro: 'Credenciais inválidas' });
  const ok = await bcrypt.compare(senha, rows[0].senha_hash);
  if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas' });

  const token = jwt.sign(
    { id: rows[0].id, email: rows[0].email, nome: rows[0].nome, tipo: 'admin' },
    process.env.JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({ ok: true, token, usuario: { id: rows[0].id, nome: rows[0].nome, email: rows[0].email, role: rows[0].role || 'recrutador' } });
});

// USARÁ O E-MAIL DO ADMIN COMO LOGIN (fabio08dejesusjunior@gmail.com)

app.get('/api/admin/dashboard', authAdmin, async (req, res) => {
  const stats = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM vagas WHERE status = 'publicada') as vagas_ativas,
      (SELECT COUNT(*) FROM candidatos) as total_candidatos,
      (SELECT COUNT(*) FROM candidaturas WHERE status NOT IN ('reprovado','contratado')) as processos_ativos,
      (SELECT COUNT(*) FROM candidaturas WHERE criado_em > NOW() - INTERVAL '7 days') as novos_7d
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
});

app.post('/api/admin/vagas', authAdmin, async (req, res) => {
  const v = req.body;
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
});

app.get('/api/admin/vagas', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vagas ORDER BY criada_em DESC');
  res.json({ vagas: rows });
});

app.get('/api/admin/candidatos', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, nome, email, cpf, cidade, estado, criado_em FROM candidatos ORDER BY criado_em DESC');
  res.json({ candidatos: rows });
});

app.get('/api/admin/candidaturas', authAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.*, v.titulo, v.empresa, cd.nome as candidato_nome, cd.email as candidato_email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    ORDER BY c.criada_em DESC
  `);
  res.json({ candidaturas: rows });
});

app.get('/api/admin/candidatura/:id', authAdmin, async (req, res) => {
  const { rows: cand } = await pool.query(`
    SELECT c.*, v.titulo, v.empresa, v.etapas, cd.nome, cd.email, cd.celular, cd.cpf
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  res.json({ candidatura: cand[0] });
});

app.post('/api/admin/candidatura/:id/status', authAdmin, async (req, res) => {
  const { status, etapa, mensagem } = req.body;
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, v.etapas, cd.nome, cd.email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });

  const cand = c[0];
  const historico = Array.isArray(cand.historico) ? cand.historico : [];
  historico.push({ etapa: etapa ?? cand.etapa_atual, status, mensagem, data: new Date().toISOString(), por: req.user.nome });

  await pool.query(
    'UPDATE candidaturas SET status = $1, etapa_atual = $2, historico = $3 WHERE id = $4',
    [status, etapa ?? cand.etapa_atual, JSON.stringify(historico), req.params.id]
  );

  if (mensagem) {
    await pool.query(
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto) VALUES ($1,$2,$3,$4)',
      [req.params.id, 'admin', req.user.nome, mensagem]
    );
  }

  try {
    await enviarNotificacaoStatus(cand.email, cand.nome, cand.titulo, status);
  } catch (e) {
    console.error('Falha ao notificar candidato:', e.message);
  }

  res.json({ ok: true });
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
(async () => {
  try {
    await init();

    // cria admin padrão se não existir
    const emailAdmin = process.env.EMAIL_FROM || process.env.ADMIN_EMAIL;
    if (emailAdmin) {
      const { rows } = await pool.query('SELECT id FROM admins WHERE email = $1', [emailAdmin]);
      if (rows.length === 0) {
        const hash = await bcrypt.hash(process.env.ADMIN_SENHA || '089339', 10);
        await pool.query(
          'INSERT INTO admins (nome, email, senha_hash, role) VALUES ($1,$2,$3,$4)',
          ['Fabio Junior', emailAdmin, hash, 'superadmin']
        );
        console.log('Admin criado:', emailAdmin);
      } else {
        console.log('Admin já existe:', emailAdmin);
      }
    } else {
      console.warn('AVISO: EMAIL_FROM não definido. Crie o admin manualmente pelo endpoint /api/admin/criar-inicial.');
    }

    const port = process.env.PORT || 10000;
    app.listen(port, () => console.log(`API rodando na porta ${port}`));
  } catch (e) {
    console.error('Erro ao iniciar:', e);
    process.exit(1);
  }
})();
