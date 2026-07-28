const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { pool } = require('./db');
const { enviarEmailBg } = require('./email');
const { audit } = require('./audit');

// Tempo de expiração do token (1 hora)
const TOKEN_EXPIRY_HOURS = 1;

// ===== Gerar token seguro =====
function gerarToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ===== Templates de e-mail =====
function emailRedefinicaoHtml({ nome, link, minutos }) {
  return `
  <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 560px; margin: 0 auto; padding: 24px;">
    <div style="text-align: center; padding: 20px 0;">
      <h1 style="color: #722F37; font-size: 24px; margin: 0;">Vagas.io</h1>
    </div>
    <div style="background: #fff; padding: 28px 24px; border-radius: 8px; border: 1px solid #E5E5E5;">
      <p style="color: #1A1A1A; font-size: 16px; line-height: 1.5;">Olá, <strong>${nome || ''}</strong>!</p>
      <p style="color: #1A1A1A; font-size: 15px; line-height: 1.5;">Recebemos um pedido pra redefinir a senha da sua conta. Se foi você, clique no botão abaixo:</p>
      <div style="text-align: center; margin: 28px 0;">
        <a href="${link}" style="background: #722F37; color: #fff; padding: 14px 32px; border-radius: 6px; text-decoration: none; font-weight: 700; display: inline-block; font-size: 15px;">Redefinir minha senha</a>
      </div>
      <p style="color: #6B6B6B; font-size: 14px; line-height: 1.5;">Este link é válido por <strong>${minutos} minutos</strong>.</p>
      <p style="color: #6B6B6B; font-size: 14px; line-height: 1.5;">Se você <strong>não fez</strong> esse pedido, é só ignorar este e-mail — sua senha continua a mesma.</p>
      <hr style="border: none; border-top: 1px solid #E5E5E5; margin: 20px 0;" />
      <p style="color: #999; font-size: 12px; line-height: 1.4;">Ou copie e cole este link no navegador:<br /><a href="${link}" style="color: #722F37; word-break: break-all;">${link}</a></p>
    </div>
    <div style="text-align: center; padding: 14px 8px 0; color: #999; font-size: 11px;">
      Você está recebendo este e-mail porque um pedido de redefinição foi feito em vagasio.com.br.
    </div>
  </div>
  `;
}

// ===== Buscar usuário em qualquer tabela =====
async function buscarUsuarioPorEmail(email, tipoHint = null) {
  const emailNorm = email.trim().toLowerCase();
  // Tenta em cada tabela (candidatos, admins, recrutadores, empresa_usuarios)
  const tabelas = [
    { nome: 'candidatos', tipo: 'candidato' },
    { nome: 'admins', tipo: 'admin' },
    { nome: 'recrutadores', tipo: 'recrutador' },
    { nome: 'empresa_usuarios', tipo: 'empresa' }
  ];
  // Se tipoHint for fornecido, prioriza a tabela correspondente
  if (tipoHint) {
    tabelas.sort((a, b) => (a.tipo === tipoHint ? -1 : b.tipo === tipoHint ? 1 : 0));
  }
  for (const t of tabelas) {
    const r = await pool.query(
      `SELECT id, email, nome, senha_hash FROM ${t.nome} WHERE LOWER(email) = $1 LIMIT 1`,
      [emailNorm]
    );
    if (r.rows.length > 0) {
      return {
        id: r.rows[0].id,
        email: r.rows[0].email,
        nome: r.rows[0].nome,
        tabela: t.nome,
        tipo: t.tipo
      };
    }
  }
  return null;
}

// ===== POST /api/auth/esqueci-senha =====
async function esqueciSenha(req, res) {
  const { email, frontendUrl, _user_tipo_hint } = req.body || {};
  if (!email) return res.status(400).json({ erro: 'E-mail é obrigatório' });

  // SEMPRE responde 200 (não revela se o e-mail existe)
  const respostaOk = { ok: true, mensagem: 'Se o e-mail estiver cadastrado, você receberá o link de redefinição.' };

  try {
    const usuario = await buscarUsuarioPorEmail(email, _user_tipo_hint || null);
    if (!usuario) {
      console.log(`[esqueci-senha] e-mail não encontrado: ${email}`);
      await audit(req, 'password.reset_requested', { result: 'failure', metadata: { email, motivo: 'email_nao_encontrado' } });
      return res.json(respostaOk);
    }

    // Gerar token, salvar hash
    const token = gerarToken();
    const tokenH = hashToken(token);
    const expira = new Date(Date.now() + TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);

    await pool.query(
      `INSERT INTO password_resets (user_id, user_tipo, token_hash, expira_em) VALUES ($1, $2, $3, $4)`,
      [usuario.id, usuario.tipo, tokenH, expira]
    );

    // Link de redefinição
    const base = (frontendUrl || process.env.FRONTEND_URL || 'https://sistemarecrutsmento.github.io/vagas').replace(/\/$/, '');
    const link = `${base}/redefinir-senha.html?token=${token}`;

    // Enviar e-mail em background
    const html = emailRedefinicaoHtml({
      nome: usuario.nome,
      link,
      minutos: TOKEN_EXPIRY_HOURS * 60
    });

    enviarEmailBg({
      to: usuario.email,
      subject: 'Redefinição de senha — Vagas.io',
      html
    });

    console.log(`[esqueci-senha] token gerado pra ${email} (id=${usuario.id}, tipo=${usuario.tipo})`);
    await audit(req, 'password.reset_requested', { result: 'success', metadata: { email, user_tipo: usuario.tipo } });
    return res.json(respostaOk);
  } catch (err) {
    console.error('[esqueci-senha] erro:', err);
    // Mesmo com erro, não vaza info
    return res.json(respostaOk);
  }
}

// ===== POST /api/auth/redefinir-senha =====
async function redefinirSenha(req, res) {
  const { token, novaSenha } = req.body || {};
  if (!token || !novaSenha) {
    return res.status(400).json({ erro: 'Token e nova senha são obrigatórios' });
  }
  if (novaSenha.length < 6) {
    await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'senha_curta' } });
    return res.status(400).json({ erro: 'Senha deve ter no mínimo 6 caracteres' });
  }

  try {
    const tokenH = hashToken(token);
    const r = await pool.query(
      `SELECT * FROM password_resets WHERE token_hash = $1 AND usado_em IS NULL AND expira_em > NOW() ORDER BY created_at DESC LIMIT 1`,
      [tokenH]
    );
    if (r.rows.length === 0) {
      await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'token_invalido_expirado' } });
      return res.status(400).json({ erro: 'Token inválido ou expirado' });
    }
    const reset = r.rows[0];

    // Mapear tipo → tabela
    const tipoParaTabela = {
      candidato: 'candidatos',
      admin: 'admins',
      recrutador: 'recrutadores',
      empresa: 'empresa_usuarios'
    };
    const tabela = tipoParaTabela[reset.user_tipo];
    if (!tabela) {
      await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'tipo_invalido', user_tipo: reset.user_tipo } });
      return res.status(500).json({ erro: 'Tipo de usuário inválido' });
    }

    // Atualizar senha
    const novoHash = await bcrypt.hash(novaSenha, 10);
    await pool.query(
      `UPDATE ${tabela} SET senha_hash = $1 WHERE id = $2`,
      [novoHash, reset.user_id]
    );

    // Marcar token como usado
    await pool.query(
      `UPDATE password_resets SET usado_em = NOW() WHERE id = $1`,
      [reset.id]
    );

    // Revogar todos os refresh tokens do usuário (sessões antigas invalidadas)
    try {
      const { revogarTodosPorUsuario } = require('./token');
      // user_type nos refresh_tokens usa o nome do tipo
      const tipoRefresh = reset.user_tipo === 'admin' ? 'admin' : reset.user_tipo;
      // Buscar email do usuário para revogar
      const { rows: emailRows } = await pool.query(
        `SELECT email FROM ${tabela} WHERE id = $1`, [reset.user_id]
      );
      if (emailRows.length) {
        await revogarTodosPorUsuario(emailRows[0].email, tipoRefresh, 'password_reset');
      }
    } catch (revokeErr) {
      console.error('[redefinir-senha] revogação de refresh tokens falhou (não crítico):', revokeErr.message);
    }

    console.log(`[redefinir-senha] senha atualizada: user_id=${reset.user_id}, tipo=${reset.user_tipo}`);
    await audit(req, 'password.changed', { result: 'success', metadata: { user_tipo: reset.user_tipo } });
    return res.json({ ok: true, mensagem: 'Senha redefinida com sucesso' });
  } catch (err) {
    console.error('[redefinir-senha] erro:', err);
    return res.status(500).json({ erro: 'Erro ao redefinir senha' });
  }
}

// ===== GET /api/auth/validar-token (opcional, pra UX da tela de redefinir) =====
async function validarToken(req, res) {
  const { token } = req.query;
  if (!token) return res.status(400).json({ valido: false, erro: 'Token ausente' });
  try {
    const tokenH = hashToken(token);
    const r = await pool.query(
      `SELECT pr.expira_em, pr.usado_em, u.nome
       FROM password_resets pr
       LEFT JOIN LATERAL (
         SELECT nome FROM candidatos WHERE id = pr.user_id AND pr.user_tipo = 'candidato'
         UNION ALL SELECT nome FROM admins WHERE id = pr.user_id AND pr.user_tipo = 'admin'
         UNION ALL SELECT nome FROM recrutadores WHERE id = pr.user_id AND pr.user_tipo = 'recrutador'
         UNION ALL SELECT nome FROM empresa_usuarios WHERE id = pr.user_id AND pr.user_tipo = 'empresa'
       ) u ON true
       WHERE pr.token_hash = $1
       LIMIT 1`,
      [tokenH]
    );
    if (r.rows.length === 0) {
      return res.json({ valido: false, erro: 'Token inválido' });
    }
    const row = r.rows[0];
    if (row.usado_em) {
      return res.json({ valido: false, erro: 'Token já foi utilizado' });
    }
    if (new Date(row.expira_em) < new Date()) {
      return res.json({ valido: false, erro: 'Token expirado' });
    }
    return res.json({ valido: true, nome: row.nome });
  } catch (err) {
    console.error('[validar-token] erro:', err);
    return res.status(500).json({ valido: false, erro: 'Erro ao validar token' });
  }
}

module.exports = { esqueciSenha, redefinirSenha, validarToken };
