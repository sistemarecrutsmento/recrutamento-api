const nodemailer = require('nodemailer');
const axios = require('axios');

// ===== Resolver chave do provedor de e-mail =====
function getResendKey() {
  return process.env.RESEND_API_KEY
      || process.env.RESEND_KEY
      || process.env.ResendApiKey
      || process.env.RESENDAPIKEY
      || null;
}
function getWeb3FormsKey() {
  return process.env.WEB3FORMS_ACCESS_KEY
      || process.env.WEB3FORMS_KEY
      || process.env.WEB3FORMS_API_KEY
      || null;
}

let transporter = null;
function getTransporter() {
  if (transporter) return transporter;
  if (!process.env.EMAIL_FROM || !process.env.EMAIL_APP_PASSWORD) return null;
  // Usa Gmail SMTP com SSL porta 465 (mais confiável em ambientes como Render)
  transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // usa SSL
    auth: {
      user: process.env.EMAIL_FROM,
      pass: process.env.EMAIL_APP_PASSWORD
    },
    // Timeout agressivo: não deixa o SMTP pendurar
    connectionTimeout: 6000,
    socketTimeout: 6000,
    greetingTimeout: 4000
  });
  return transporter;
}

// Helper: dispara e-mail em BACKGROUND. NÃO bloqueia a resposta da API.
// Falha silenciosa (loga, mas o sistema continua). Ideal p/ notificações secundárias.
function enviarEmailBg(fn, ...args) {
  // Dispara em próximo tick (não trava a response)
  setImmediate(() => {
    Promise.resolve()
      .then(() => fn(...args))
      .catch((e) => console.error('[email-bg] Falha ao enviar e-mail:', e.message, '| code:', e.code));
  });
}

// Envia via Resend (HTTP API — funciona onde SMTP tá bloqueado, tipo Render)
async function enviarViaResend({ from, to, subject, html, text }) {
  const apiKey = getResendKey();
  if (!apiKey) {
    throw new Error('RESEND_API_KEY não configurada');
  }
  const r = await axios.post(
    'https://api.resend.com/emails',
    {
      from: from || `${process.env.SISTEMA_NOME || 'Recrutamento'} <onboarding@resend.dev>`,
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
      text: text || ''
    },
    {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      timeout: 8000
    }
  );
  return r.data;
}

// Envia via Web3Forms (HTTP POST simples — não precisa de SMTP)
// Plano grátis: 250 e-mails/mês. API key é vinculada ao email do destinatário.
async function enviarViaWeb3Forms({ from, to, subject, html, text }) {
  const accessKey = getWeb3FormsKey();
  if (!accessKey) {
    throw new Error('WEB3FORMS_ACCESS_KEY não configurada');
  }
  const r = await axios.post(
    'https://api.web3forms.com/submit',
    {
      access_key: accessKey,
      from_name: from || (process.env.SISTEMA_NOME || 'Recrutamento'),
      from_email: process.env.EMAIL_FROM || 'noreply@recrutamento.local',
      to: Array.isArray(to) ? to.join(',') : to,
      subject: subject || '(sem assunto)',
      // Web3Forms aceita HTML no campo "message" e manda como HTML
      message: html || text || '',
      replyto: process.env.EMAIL_FROM || 'noreply@recrutamento.local'
    },
    {
      headers: { 'Content-Type': 'application/json' },
      timeout: 8000
    }
  );
  return r.data;
}

const SISTEMA = process.env.SISTEMA_NOME || 'Recrutamento e Seleção';

// ===== Estratégia de envio =====
// Prioridade: Resend (HTTP API) > Web3Forms (HTTP API) > Gmail SMTP
// HTTP APIs funcionam onde SMTP tá bloqueado, tipo Render
async function enviarEmail({ to, subject, html, text, from }) {
  // 1ª opção: Resend (se configurado)
  if (getResendKey()) {
    console.log('[email] Enviando via Resend para:', to, '| subject:', subject);
    return enviarViaResend({ from, to, subject, html, text });
  }
  // 2ª opção: Web3Forms (se configurado)
  if (getWeb3FormsKey()) {
    console.log('[email] Enviando via Web3Forms para:', to, '| subject:', subject);
    return enviarViaWeb3Forms({ from, to, subject, html, text });
  }
  console.log('[email] Nenhum provedor HTTP configurado, tentando Gmail SMTP (fallback)...');
  // 3ª opção: Gmail SMTP (fallback final)
  const t = getTransporter();
  if (!t) throw new Error('Nenhum provedor de e-mail configurado (RESEND_API_KEY, WEB3FORMS_ACCESS_KEY ou EMAIL_FROM/EMAIL_APP_PASSWORD)');
  return t.sendMail({
    from: from || `"${SISTEMA}" <${process.env.EMAIL_FROM}>`,
    to,
    subject,
    html,
    text
  });
}

async function enviarCodigo(email, codigo) {
  return enviarEmail({
    to: email,
    subject: `Seu código de verificação - ${SISTEMA}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
        <div style="background: #7a1f3d; color: #fff; padding: 20px; border-radius: 8px; text-align: center;">
          <h2 style="margin: 0;">${SISTEMA}</h2>
        </div>
        <div style="background: #fff; padding: 28px; border-radius: 8px; margin-top: 16px;">
          <p style="color: #2b2b2b; font-size: 15px;">Use o código abaixo para confirmar seu e-mail:</p>
          <div style="text-align: center; margin: 24px 0;">
            <div style="display: inline-block; background: #111; color: #fff; font-size: 32px; font-weight: 800; letter-spacing: 6px; padding: 16px 28px; border-radius: 10px;">${codigo}</div>
          </div>
          <p style="color: #6b6b6b; font-size: 13px;">Este código expira em <strong>10 minutos</strong>.</p>
          <p style="color: #6b6b6b; font-size: 13px;">Se você não fez essa solicitação, ignore este e-mail.</p>
        </div>
      </div>
    `
  });
}

async function enviarNotificacaoStatus(email, nome, vaga, novoStatus) {
  const statusTexto = {
    'em_analise': 'em análise',
    'entrevista': 'avançou para etapa de entrevista',
    'aprovado': 'foi aprovado(a) 🎉',
    'reprovado': 'foi reprovado(a) neste processo',
    'contratado': 'foi contratado(a) 🎉'
  }[novoStatus] || novoStatus;

  return enviarEmail({
    to: email,
    subject: `Atualização do seu processo - ${vaga}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
        <div style="background: #7a1f3d; color: #fff; padding: 20px; border-radius: 8px; text-align: center;">
          <h2 style="margin: 0;">${SISTEMA}</h2>
        </div>
        <div style="background: #fff; padding: 28px; border-radius: 8px; margin-top: 16px;">
          <p style="color: #2b2b2b; font-size: 15px;">Olá, <strong>${nome}</strong>!</p>
          <p style="color: #2b2b2b; font-size: 15px;">Sua candidatura para a vaga <strong>${vaga}</strong> ${statusTexto}.</p>
          <p style="color: #6b6b6b; font-size: 13px;">Acesse seu painel para ver mais detalhes.</p>
        </div>
      </div>
    `
  });
}

// ===== E-mail rico de atualização do processo =====
// Disparado em cada mudança de etapa/status. Inclui nome da etapa, número, e link pro painel.
const NOMES_ETAPAS = {
  1: 'Inscrição',
  2: 'Triagem',
  3: 'RH',
  4: 'Gestor',
  5: 'Proposta',
  6: 'Coleta de Documentos',
  7: 'Contratação'
};

async function enviarEmailAtualizacao(email, nome, vaga, { etapaNum, etapaNome, acao, status, mensagemAdmin }) {
  // Monta assunto e copy baseado na ação
  let subject, intro, corHeader, emoji, detalhe = '';
  const linkPainel = (process.env.SISTEMA_URL || 'https://sistemarecrutsmento.github.io/vagas') + '/painel.html';

  if (acao === 'avancar') {
    const prox = (etapaNum && NOMES_ETAPAS[etapaNum + 1]) ? NOMES_ETAPAS[etapaNum + 1] : 'próxima etapa';
    subject = `Você avançou para ${etapaNome || prox} - ${vaga}`;
    intro = `Boa notícia! Você avançou para a etapa <strong>${etapaNome || prox}</strong> no processo da vaga <strong>${vaga}</strong>.`;
    corHeader = '#7a1f3d';
    emoji = '🚀';
    detalhe = 'Continue acompanhando seu painel para os próximos passos.';
  } else if (acao === 'reabrir') {
    subject = `Seu processo foi reaberto - ${vaga}`;
    intro = `Seu processo para a vaga <strong>${vaga}</strong> foi reaberto e voltou para a etapa <strong>${etapaNome || 'inicial'}</strong>.`;
    corHeader = '#0c5a8a';
    emoji = '🔄';
    detalhe = 'Acesse seu painel para ver os detalhes.';
  } else if (acao === 'reprovar' || status === 'rejeitado' || status === 'reprovado') {
    subject = `Atualização do seu processo - ${vaga}`;
    intro = `Infelizmente, seu processo para a vaga <strong>${vaga}</strong> não seguiu adiante nesta etapa.`;
    corHeader = '#8a3a3a';
    emoji = '😔';
    detalhe = 'Agradecemos sua participação e desejamos sucesso em outras oportunidades.';
  } else if (status === 'contratado') {
    subject = `Parabéns! Você foi contratado - ${vaga}`;
    intro = `Que ótima notícia! Você foi contratado(a) para a vaga <strong>${vaga}</strong>. 🎉`;
    corHeader = '#0a6e2e';
    emoji = '🎉';
    detalhe = 'Em breve o RH entrará em contato com os próximos passos da sua contratação.';
  } else if (acao === 'documento_aprovado') {
    subject = `Documento aprovado - ${vaga}`;
    intro = `Seu documento <strong>${mensagemAdmin || 'enviado'}</strong> foi aprovado pelo recrutador na vaga <strong>${vaga}</strong>.`;
    corHeader = '#0a6e2e';
    emoji = '✅';
    detalhe = 'Continue acompanhando seu painel para mais atualizações.';
  } else if (acao === 'documentos_aprovados_massa') {
    subject = `Documentos aprovados! - ${vaga}`;
    intro = `Todos os seus documentos da vaga <strong>${vaga}</strong> foram aprovados!`;
    corHeader = '#0a6e2e';
    emoji = '🎉';
    detalhe = 'Acesse seu painel para ver o andamento do processo.';
  } else if (acao === 'inscricao_recebida') {
    subject = `Inscrição recebida - ${vaga}`;
    intro = `Recebemos sua inscrição para a vaga <strong>${vaga}</strong>. A partir de agora, você pode acompanhar cada etapa do processo pelo seu painel.`;
    corHeader = '#7a1f3d';
    emoji = '📝';
    detalhe = 'Fique de olho no seu e-mail e no painel. A cada nova etapa, avisaremos você!';
  } else {
    subject = `Atualização do seu processo - ${vaga}`;
    intro = `Houve uma atualização no seu processo para a vaga <strong>${vaga}</strong>.`;
    corHeader = '#7a1f3d';
    emoji = '📋';
    detalhe = 'Acesse seu painel para ver os detalhes.';
  }

  // Monta a parte da etapa atual (se conhecida)
  let etapaBloco = '';
  if (etapaNum && NOMES_ETAPAS[etapaNum]) {
    etapaBloco = `
      <div style="background:#f3f0f5;border-left:4px solid ${corHeader};padding:14px 16px;margin:18px 0;border-radius:6px">
        <div style="color:#6b6b6b;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600">Etapa atual</div>
        <div style="color:#1f1f1f;font-size:18px;font-weight:700;margin-top:4px">${etapaNum}. ${NOMES_ETAPAS[etapaNum]}</div>
      </div>`;
  }

  // Bloco de mensagem do admin (se tiver)
  let msgAdminBloco = '';
  if (mensagemAdmin && String(mensagemAdmin).trim()) {
    msgAdminBloco = `
      <div style="background:#fff8e6;border:1px solid #f0d770;padding:14px 16px;margin:18px 0;border-radius:6px">
        <div style="color:#7a5a00;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;margin-bottom:6px">💬 Mensagem do recrutador</div>
        <div style="color:#3a2e00;font-size:14px;line-height:1.5;white-space:pre-wrap">${String(mensagemAdmin).replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>
      </div>`;
  }

  return enviarEmail({
    to: email,
    subject,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
        <div style="background: ${corHeader}; color: #fff; padding: 22px 20px; border-radius: 8px; text-align: center;">
          <div style="font-size:32px;margin-bottom:6px">${emoji}</div>
          <h2 style="margin:0;font-size:20px">${SISTEMA}</h2>
        </div>
        <div style="background: #fff; padding: 28px 24px; border-radius: 8px; margin-top: 16px;">
          <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${nome}</strong>!</p>
          <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">${intro}</p>
          ${etapaBloco}
          ${msgAdminBloco}
          <p style="color: #6b6b6b; font-size: 13px; line-height: 1.5;">${detalhe}</p>
          <div style="text-align:center;margin:24px 0 8px">
            <a href="${linkPainel}" style="background:${corHeader};color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block">Acessar meu painel</a>
          </div>
        </div>
        <div style="text-align:center;padding:14px 8px 0;color:#999;font-size:11px">
          Você está recebendo este e-mail porque se candidatou à vaga ${vaga}.
        </div>
      </div>
    `
  });
}

async function enviarEmailProposta(email, nome, vaga, pdfUrl) {
  return enviarEmail({
    to: email,
    subject: `Você recebeu uma proposta - ${vaga}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
        <div style="background: #7a1f3d; color: #fff; padding: 20px; border-radius: 8px; text-align: center;">
          <h2 style="margin: 0;">${SISTEMA}</h2>
        </div>
        <div style="background: #fff; padding: 28px; border-radius: 8px; margin-top: 16px;">
          <p style="color: #2b2b2b; font-size: 15px;">Olá, <strong>${nome}</strong>!</p>
          <p style="color: #2b2b2b; font-size: 15px;">Você recebeu uma proposta para a vaga <strong>${vaga}</strong>.</p>
          ${pdfUrl ? `<p style="text-align:center;margin:20px 0"><a href="${pdfUrl}" style="background:#7a1f3d;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">📄 Baixar proposta (PDF)</a></p>` : ''}
          <p style="color: #2b2b2b; font-size: 15px;">Acesse seu painel para visualizar a proposta completa e dar o seu aceite.</p>
        </div>
      </div>
    `
  });
}

// ===== E-mail de inscrição recebida (boas-vindas ao candidato) =====
async function enviarEmailInscricao(email, nome, vaga, empresa) {
  const linkPainel = (process.env.SISTEMA_URL || 'https://sistemarecrutsmento.github.io/vagas') + '/painel.html';
  return enviarEmail({
    to: email,
    subject: `Inscrição recebida - ${vaga}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
        <div style="background: #7a1f3d; color: #fff; padding: 22px 20px; border-radius: 8px; text-align: center;">
          <div style="font-size:32px;margin-bottom:6px">📝</div>
          <h2 style="margin:0;font-size:20px">${SISTEMA}</h2>
        </div>
        <div style="background: #fff; padding: 28px 24px; border-radius: 8px; margin-top: 16px;">
          <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${nome}</strong>!</p>
          <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Recebemos sua inscrição para a vaga <strong>${vaga}</strong>${empresa ? ' na <strong>' + empresa + '</strong>' : ''}.</p>
          <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">A partir de agora, você pode acompanhar cada etapa do processo pelo seu painel. A cada avanço, reprovação ou necessidade de documento, avisaremos você por aqui.</p>
          <div style="text-align:center;margin:24px 0 8px">
            <a href="${linkPainel}" style="background:#7a1f3d;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block">Acessar meu painel</a>
          </div>
        </div>
        <div style="text-align:center;padding:14px 8px 0;color:#999;font-size:11px">
          Você está recebendo este e-mail porque se candidatou à vaga ${vaga}.
        </div>
      </div>
    `
  });
}

module.exports = {
  getResendKey,
  enviarCodigo,
  enviarNotificacaoStatus,
  enviarEmailProposta,
  enviarEmailBg,
  enviarEmailAtualizacao,
  enviarViaResend,
  enviarEmail,
  enviarEmailInscricao
};
