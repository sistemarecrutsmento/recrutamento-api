const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_FROM,
    pass: process.env.EMAIL_APP_PASSWORD
  }
});

const SISTEMA = process.env.SISTEMA_NOME || 'Recrutamento e Seleção';

async function enviarCodigo(email, codigo) {
  return transporter.sendMail({
    from: `"${SISTEMA}" <${process.env.EMAIL_FROM}>`,
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

  return transporter.sendMail({
    from: `"${SISTEMA}" <${process.env.EMAIL_FROM}>`,
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

module.exports = { enviarCodigo, enviarNotificacaoStatus };

