const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const { pool, init } = require('./db');
const { enviarCodigo, enviarNotificacaoStatus } = require('./email');
const { authMiddleware, authCandidato, authAdmin } = require('./auth');

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));

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

// Debug: testa bcrypt isolado
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

// Resetar senha do admin (não usa bcrypt no compare, só cria novo hash)
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

// Ver estado do admin
app.get('/api/_debug/admin-info', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, nome, email, substring(senha_hash, 1, 10) as hash_inicio, length(senha_hash) as hash_len FROM admins`
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

// Migração manual via API (cria coluna criado_em em todas as tabelas)
app.post('/api/_debug/migrar', async (req, res) => {
  try {
    // Procurar a coluna em todos os schemas
    const cols = await pool.query(`
      SELECT table_schema, table_name, column_name 
      FROM information_schema.columns 
      WHERE column_name ILIKE '%criad%'
    `);
    // Ver o search_path
    const sp = await pool.query(`SHOW search_path`);
    res.json({ ok: true, schemas: sp.rows, colunas_criadas: cols.rows });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

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
       VALUES ($1, $2, 'em_andamento', 2, $3)
       RETURNING *`,
      [req.params.vagaId, c[0].id, JSON.stringify([
        { etapa: 0, status: 'em_analise', acao: 'inscricao', data: new Date().toISOString() },
        { etapa: 1, status: 'em_andamento', acao: 'avancar', data: new Date().toISOString(), mensagem: 'Inscrição realizada — aguardando triagem curricular' },
        { etapa: 2, status: 'em_andamento', acao: 'avancar', data: new Date().toISOString(), mensagem: 'Encaminhado para triagem curricular' }
      ])]
    );
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

app.put('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  const v = req.body;
  const { rows } = await pool.query(
    `UPDATE vagas SET
      titulo = COALESCE($1, titulo),
      empresa = COALESCE($2, empresa),
      cidade = COALESCE($3, cidade),
      estado = COALESCE($4, estado),
      tipo_contrato = COALESCE($5, tipo_contrato),
      nivel = COALESCE($6, nivel),
      area = COALESCE($7, area),
      salario_min = COALESCE($8, salario_min),
      salario_max = COALESCE($9, salario_max),
      descricao = COALESCE($10, descricao),
      requisitos = COALESCE($11, requisitos),
      beneficios = COALESCE($12, beneficios),
      status = COALESCE($13, status)
     WHERE id = $14 RETURNING *`,
    [v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area,
     v.salario_min, v.salario_max, v.descricao, v.requisitos, v.beneficios, v.status, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
  res.json({ ok: true, vaga: rows[0] });
});

app.delete('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  await pool.query('DELETE FROM vagas WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM vagas WHERE id = $1', [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
  res.json({ vaga: rows[0] });
});

app.get('/api/admin/candidatos', authAdmin, async (req, res) => {
  const { area } = req.query;
  let sql = `SELECT id, nome, email, cpf, celular, cidade, estado, areas_interesse, banco_talentos, criado_em FROM candidatos`;
  const params = [];
  if (area) {
    // Filtra candidatos que tenham a área no array areas_interesse (JSONB array)
    // Wraps a string em ["..."] pra fazer match exato via @>
    params.push(JSON.stringify([area]));
    sql += ` WHERE areas_interesse @> $${params.length}::jsonb`;
  }
  sql += ' ORDER BY criado_em DESC';
  const { rows } = await pool.query(sql, params);
  res.json({ candidatos: rows });
});

// Retorna os dados completos de um candidato (currículo) para o admin
app.get('/api/admin/candidato/:id', authAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, nome, email, cpf, celular, data_nascimento, sexo,
            acessibilidade, cep, estado, cidade, bairro, logradouro, numero, complemento,
            formacao, instituicao, curso, situacao, data_conclusao,
            primeiro_emprego, banco_talentos, areas_interesse, sobre_voce, experiencia,
            criado_em
     FROM candidatos WHERE id = $1`, [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ erro: 'Candidato não encontrado' });
  res.json({ candidato: rows[0] });
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

// Lista de vagas com contagem de candidaturas (p/ painel admin)
app.get('/api/admin/vagas-com-candidaturas', authAdmin, async (req, res) => {
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
});

// Candidatos de uma vaga específica
app.get('/api/admin/vagas/:id/candidaturas', authAdmin, async (req, res) => {
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
});

app.get('/api/admin/candidatura/:id', authAdmin, async (req, res) => {
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
    const { documentos } = req.body; // [{tipo, valor_texto, arquivo_base64, arquivo_nome, arquivo_tipo, arquivo_tamanho}]
    if (!Array.isArray(documentos) || documentos.length === 0) {
      return res.status(400).json({ erro: 'Nenhum documento enviado' });
    }
    // Limite: 2MB por arquivo em base64 (~1.5MB binário)
    const MAX = 2 * 1024 * 1024;
    for (const d of documentos) {
      if (d.arquivo_base64 && d.arquivo_base64.length > MAX) {
        return res.status(413).json({ erro: `Arquivo "${d.arquivo_nome || d.tipo}" passa de 2MB.` });
      }
    }
    // Apaga envios anteriores do mesmo tipo (mantém histórico de revisões)
    const tipos = documentos.map(d => d.tipo).filter(Boolean);
    if (tipos.length) {
      await pool.query('DELETE FROM documentos_candidatura WHERE candidatura_id = $1 AND tipo = ANY($2)', [candidaturaId, tipos]);
    }
    // Insere os novos
    for (const d of documentos) {
      await pool.query(
        `INSERT INTO documentos_candidatura
         (candidatura_id, tipo, categoria, valor_texto, arquivo_base64, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, enviado_em)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pendente', NOW())`,
        [candidaturaId, d.tipo, d.categoria || 'arquivo', d.valor_texto || null, d.arquivo_base64 || null, d.arquivo_nome || null, d.arquivo_tipo || null, d.arquivo_tamanho || null]
      );
    }
    // Marca a etapa como "em_andamento" (candidato enviou) — admin ainda precisa revisar
    await pool.query(
      `UPDATE candidaturas SET etapa_atual = GREATEST(etapa_atual, $1) WHERE id = $2`,
      [5, candidaturaId] // etapa 5 = coleta de documentos (índice 4 nas 6 etapas)
    );
    res.json({ ok: true, salvos: documentos.length });
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
      `SELECT id, tipo, categoria, valor_texto, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
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
    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [Number(req.params.id)]
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
    const { status, justificativa } = req.body;
    if (!['aprovado', 'reprovado'].includes(status)) {
      return res.status(400).json({ erro: 'status deve ser aprovado ou reprovado' });
    }
    if (status === 'reprovado' && !justificativa) {
      return res.status(400).json({ erro: 'Justificativa obrigatória ao reprovar' });
    }
    await pool.query(
      `UPDATE documentos_candidatura SET status = $1, justificativa_admin = $2, revisado_em = NOW() WHERE id = $3`,
      [status, justificativa || null, docId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: e.message });
  }
});

app.post('/api/admin/candidatura/:id/status', authAdmin, async (req, res) => {
  const { status, etapa, mensagem, acao } = req.body;
  // acao: 'avancar' = incrementa etapa_atual, 'reprovar' = marca rejeitado, 'aprovar' = aprova atual
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, v.etapas, cd.nome, cd.email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });

  const cand = c[0];
  const historico = Array.isArray(cand.historico) ? cand.historico : [];
  let novoStatus = status;
  let novaEtapa = etapa ?? cand.etapa_atual;

  if (acao === 'avancar') {
    novaEtapa = (cand.etapa_atual || 0) + 1;
    novoStatus = 'em_andamento';
    // Calcular total de etapas (do JSON etapas da vaga, ou usar padrão 7)
    let totalEtapas = 7;
    try {
      const etapasArr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
      if (Array.isArray(etapasArr) && etapasArr.length) totalEtapas = etapasArr.length;
    } catch (e) {}
    if (novaEtapa >= totalEtapas) {
      novoStatus = 'contratado';
    }
  } else if (acao === 'reprovar') {
    novoStatus = 'rejeitado';
  } else if (acao === 'reabrir') {
    novoStatus = 'em_analise';
  }

  historico.push({ etapa: novaEtapa, status: novoStatus, mensagem, acao, data: new Date().toISOString(), por: req.user.nome });

  await pool.query(
    'UPDATE candidaturas SET status = $1, etapa_atual = $2, historico = $3 WHERE id = $4',
    [novoStatus, novaEtapa, JSON.stringify(historico), req.params.id]
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

    const port = process.env.PORT || 10000;
    app.listen(port, () => console.log(`API rodando na porta ${port}`));
  } catch (e) {
    console.error('Erro ao iniciar:', e);
    process.exit(1);
  }
})();

