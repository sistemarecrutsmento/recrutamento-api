// =============================================================================
// emailService.js — Serviço central de e-mail Vagas.io (Fase 13)
// =============================================================================
// Reutiliza enviarEmail() do ../email.js (Resend > Web3Forms > SMTP)
// Acrescenta: templates visuais unificados, preferências, dedup de chat,
//   boas-vindas candidato/empresa, entrevista, digest, outbox log.
// =============================================================================
'use strict';

const { pool } = require('../db');
const { enviarEmail, enviarEmailBg, getResendKey } = require('../email');
const { wrap, esc, p, box, badge, aviso, BASE_URL, VINHO } = require('./templates');

const ADMIN_EMAIL = process.env.ADMIN_NOTIF_EMAIL
                 || process.env.ADMIN_EMAIL
                 || 'fabio08dejesusjunior@gmail.com';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers internos
// ─────────────────────────────────────────────────────────────────────────────

/** Formata data/hora pt-BR. */
function fmtDt(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('pt-BR', {
    timeZone: 'America/Sao_Paulo',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

/** Envia em background sem travar resposta. Nunca joga para cima. */
function bg(fn, ...args) {
  setImmediate(() =>
    Promise.resolve().then(() => fn(...args)).catch(e =>
      console.error('[emailService bg]', e.message)
    )
  );
}

/** Log na tabela email_outbox. Não falha silenciosamente — erros são logados. */
async function registrarOutbox({ user_type, user_id, tipo, destinatario, assunto, payload, status, erro }) {
  try {
    await pool.query(
      `INSERT INTO email_outbox
         (user_type, user_id, tipo, destinatario, assunto, payload, status, enviado_em)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        user_type || null, user_id || null, tipo || 'geral',
        destinatario, assunto, payload ? JSON.stringify(payload) : null,
        status || 'enviado', status === 'enviado' ? new Date() : null
      ]
    );
  } catch (e) {
    console.error('[emailService outbox]', e.message);
  }
}

/** Envia e registra no outbox. */
async function enviar({ to, subject, html, tipo, user_type, user_id, payload }) {
  try {
    const result = await enviarEmail({ to, subject, html });
    await registrarOutbox({ user_type, user_id, tipo, destinatario: to, assunto: subject, payload, status: 'enviado' });
    console.log(`[emailService] ✓ ${tipo} → ${to}`);
    return { ok: true, result };
  } catch (e) {
    console.error(`[emailService] ✗ ${tipo} → ${to}:`, e.message);
    await registrarOutbox({ user_type, user_id, tipo, destinatario: to, assunto: subject, payload,
      status: 'erro', erro: e.message });
    return { ok: false, erro: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verificar preferências de e-mail
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifica se o usuário aceitou receber e-mail dessa categoria.
 * Retorna true se não há registro (opt-out não feito = opt-in padrão).
 * Categorias obrigatórias (segurança): 'seguranca' sempre retorna true.
 */
async function podeEnviar(user_type, user_id, categoria) {
  if (categoria === 'seguranca') return true; // nunca bloquear
  try {
    const { rows } = await pool.query(
      `SELECT ativo FROM email_preferencias
       WHERE user_type = $1 AND user_id = $2 AND categoria = $3 LIMIT 1`,
      [user_type, user_id, categoria]
    );
    if (rows.length === 0) return true; // padrão: ativo
    return rows[0].ativo;
  } catch (e) {
    // Se tabela não existe ainda (rollout), permite por segurança
    return true;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dedup de e-mail de chat (anti-spam)
// ─────────────────────────────────────────────────────────────────────────────

const CHAT_DEDUP_MIN = parseInt(process.env.CHAT_EMAIL_DEDUP_MIN || '15');

/**
 * Verifica se já enviamos e-mail de chat para este destinatário sobre
 * esta candidatura nos últimos CHAT_DEDUP_MIN minutos.
 */
async function chatJaNotificado(user_type, user_id, candidatura_id) {
  try {
    const { rows } = await pool.query(
      `SELECT 1 FROM email_outbox
       WHERE user_type = $1 AND user_id = $2 AND tipo = 'chat_nova_mensagem'
         AND payload::text LIKE $3
         AND criado_em > NOW() - INTERVAL '${CHAT_DEDUP_MIN} minutes'
       LIMIT 1`,
      [user_type, user_id, `%"candidatura_id":${candidatura_id}%`]
    );
    return rows.length > 0;
  } catch (e) {
    return false; // Se falhar, permite enviar
  }
}

// =============================================================================
// TEMPLATES DE E-MAIL
// =============================================================================

// ─── 1. Boas-vindas Candidato ────────────────────────────────────────────────
async function boasVindasCandidato({ nome, email, candidato_id }) {
  const pode = await podeEnviar('candidato', candidato_id, 'marketing');
  // boas-vindas é transacional — envia mesmo se marketing desligado
  const html = wrap({
    titulo: '🎉 Bem-vindo à Vagas.io!',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p('Sua conta foi criada com sucesso. Agora você tem acesso à plataforma de recrutamento mais moderna do Brasil.')}
      ${box(`
        <b>O que fazer agora?</b><br>
        <ol style="margin:10px 0 0 16px;padding:0;color:#333;line-height:2">
          <li>Complete seu perfil para se destacar</li>
          <li>Explore as vagas disponíveis</li>
          <li>Candidate-se em segundos</li>
        </ol>
      `)}
      ${p('Mantenha seu perfil atualizado — empresas buscam por candidatos com perfis completos.')}
    `,
    cta_link: `${BASE_URL}/candidato/painel.html`,
    cta_texto: 'Acessar meu painel',
    rodape: 'Você recebeu este e-mail por ter criado uma conta na Vagas.io.'
  });
  return enviar({
    to: email, subject: '🎉 Bem-vindo à Vagas.io!', html,
    tipo: 'boas_vindas_candidato', user_type: 'candidato', user_id: candidato_id,
    payload: { nome }
  });
}

// ─── 2. Boas-vindas Empresa ──────────────────────────────────────────────────
async function boasVindasEmpresa({ empresa_nome, admin_nome, admin_email, empresa_id }) {
  const html = wrap({
    titulo: '🚀 Sua empresa está na Vagas.io!',
    conteudo: `
      ${p(`Olá, <strong>${esc(admin_nome)}</strong>!`)}
      ${p(`A empresa <strong>${esc(empresa_nome)}</strong> foi cadastrada com sucesso na plataforma.`)}
      ${box(`
        <b>Primeiros passos:</b><br>
        <ol style="margin:10px 0 0 16px;padding:0;color:#333;line-height:2">
          <li>Acesse o painel da empresa</li>
          <li>Crie sua primeira vaga</li>
          <li>Receba candidatos qualificados</li>
        </ol>
      `)}
      ${p('Nossa plataforma já tem candidatos aguardando oportunidades. Publique sua primeira vaga e comece a receber currículos hoje.')}
    `,
    cta_link: `${BASE_URL}/empresa/vagas-todas.html`,
    cta_texto: 'Criar primeira vaga',
    rodape: `Você recebeu este e-mail por cadastrar a empresa ${esc(empresa_nome)} na Vagas.io.`
  });
  return enviar({
    to: admin_email, subject: `🚀 ${esc(empresa_nome)} está na Vagas.io!`, html,
    tipo: 'boas_vindas_empresa', user_type: 'empresa', user_id: empresa_id,
    payload: { empresa_nome, admin_nome }
  });
}

// ─── 3. Candidatura confirmada (para o candidato) ───────────────────────────
async function candidaturaConfirmadaCandidato({ nome, email, candidato_id, vaga_titulo, empresa_nome, candidatura_id }) {
  const pode = await podeEnviar('candidato', candidato_id, 'candidatura');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '✅ Candidatura enviada com sucesso!',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`Sua candidatura para a vaga <strong>${esc(vaga_titulo)}</strong>${empresa_nome ? ` na <strong>${esc(empresa_nome)}</strong>` : ''} foi enviada com sucesso.`)}
      ${box(`Agora é aguardar. Você será notificado por e-mail em cada atualização do processo.`)}
      ${p('Enquanto isso, você pode acompanhar o status da sua candidatura pelo painel.')}
    `,
    cta_link: `${BASE_URL}/candidato/candidaturas.html`,
    cta_texto: 'Acompanhar candidatura',
    rodape: `Você se candidatou à vaga ${esc(vaga_titulo)}. Se não foi você, entre em contato.`
  });
  return enviar({
    to: email, subject: `✅ Candidatura enviada — ${esc(vaga_titulo)}`, html,
    tipo: 'candidatura_confirmada', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, empresa_nome, candidatura_id }
  });
}

// ─── 4. Nova candidatura recebida (para a empresa) ──────────────────────────
async function novaCandidaturaEmpresa({ empresa_email, empresa_id, candidato_nome, vaga_titulo, candidatura_id, data }) {
  // Busca email da empresa se não fornecido
  if (!empresa_email && empresa_id) {
    try {
      const { rows } = await pool.query(
        `SELECT e.email_principal, u.email
         FROM empresas e
         LEFT JOIN empresa_usuarios u ON u.empresa_id = e.id AND u.role = 'admin_empresa' AND u.ativo = true
         WHERE e.id = $1 LIMIT 1`,
        [empresa_id]
      );
      empresa_email = rows[0]?.email_principal || rows[0]?.email || null;
    } catch (e) { /* sem email, skip */ }
  }
  if (!empresa_email) return { ok: true, skip: true };
  const pode = await podeEnviar('empresa', empresa_id, 'candidatura');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '📥 Nova candidatura recebida',
    conteudo: `
      ${p(`<strong>${esc(candidato_nome)}</strong> se candidatou à vaga <strong>${esc(vaga_titulo)}</strong>.`)}
      ${box(`
        <b>Candidato:</b> ${esc(candidato_nome)}<br>
        <b>Vaga:</b> ${esc(vaga_titulo)}<br>
        <b>Data:</b> ${fmtDt(data)}
      `)}
      ${p('Acesse o painel para visualizar o perfil completo e iniciar a triagem.')}
    `,
    cta_link: `${BASE_URL}/empresa/candidatos.html?vaga=${candidatura_id}`,
    cta_texto: 'Ver candidatura',
    rodape: 'Você recebe este e-mail por ser responsável pela vaga na plataforma Vagas.io.'
  });
  return enviar({
    to: empresa_email, subject: `📥 Nova candidatura — ${esc(vaga_titulo)}`, html,
    tipo: 'nova_candidatura_empresa', user_type: 'empresa', user_id: empresa_id,
    payload: { candidato_nome, vaga_titulo, candidatura_id }
  });
}

// ─── 5. Mudança de etapa (para o candidato) ─────────────────────────────────
async function mudancaEtapaCandidato({ nome, email, candidato_id, vaga_titulo, etapa_num, etapa_nome, status, mensagem_extra }) {
  const pode = await podeEnviar('candidato', candidato_id, 'etapa');
  if (!pode) return { ok: true, skip: true };

  let titulo, intro, cor;
  if (status === 'contratado') {
    titulo = '🎉 Parabéns! Você foi contratado!';
    intro = `Sua candidatura para <strong>${esc(vaga_titulo)}</strong> chegou ao final com sucesso. Você foi <strong>contratado</strong>! 🎉`;
    cor = '#1B5E20';
  } else if (status === 'reprovado' || status === 'rejeitado') {
    titulo = 'Atualização sobre sua candidatura';
    intro = `Agradecemos seu interesse na vaga <strong>${esc(vaga_titulo)}</strong>. Infelizmente, você não avançou neste processo seletivo.`;
    cor = '#616161';
  } else {
    titulo = '📊 Sua candidatura avançou!';
    intro = `Boa notícia! Sua candidatura para a vaga <strong>${esc(vaga_titulo)}</strong> avançou no processo seletivo.`;
    cor = VINHO;
  }

  const etapaBloco = (etapa_nome && status !== 'reprovado' && status !== 'rejeitado' && status !== 'contratado')
    ? box(`<b>Etapa atual:</b> ${etapa_num ? `${etapa_num}. ` : ''}${esc(etapa_nome)}`)
    : '';

  const html = wrap({
    titulo,
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(intro)}
      ${etapaBloco}
      ${mensagem_extra ? aviso(`<b>Mensagem da empresa:</b> ${esc(mensagem_extra)}`) : ''}
      ${p('Acesse seu painel para ver mais detalhes e próximas orientações.')}
    `,
    cta_link: `${BASE_URL}/candidato/candidaturas.html`,
    cta_texto: 'Ver minha candidatura',
    rodape: `Você está recebendo este e-mail porque se candidatou à vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `${titulo} — ${esc(vaga_titulo)}`, html,
    tipo: 'mudanca_etapa', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, etapa_num, etapa_nome, status }
  });
}

// ─── 6. Entrevista agendada ──────────────────────────────────────────────────
async function entrevistaAgendadaCandidato({ nome, email, candidato_id, vaga_titulo, empresa_nome,
  data_hora, modalidade, local_link, observacoes, entrevista_id, candidatura_id }) {
  const pode = await podeEnviar('candidato', candidato_id, 'entrevista');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '📅 Entrevista agendada!',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`Você tem uma entrevista agendada para a vaga <strong>${esc(vaga_titulo)}</strong>${empresa_nome ? ` — <strong>${esc(empresa_nome)}</strong>` : ''}.`)}
      ${box(`
        <b>Data e hora:</b> ${fmtDt(data_hora)}<br>
        ${modalidade ? `<b>Modalidade:</b> ${esc(modalidade)}<br>` : ''}
        ${local_link ? `<b>Local/Link:</b> <a href="${esc(local_link)}" style="color:${VINHO}">${esc(local_link)}</a><br>` : ''}
        ${observacoes ? `<b>Observações:</b> ${esc(observacoes)}` : ''}
      `)}
      ${p('Acesse seu painel para ver todos os detalhes e confirmar presença.')}
    `,
    cta_link: `${BASE_URL}/candidato/entrevistas.html`,
    cta_texto: 'Ver entrevista',
    rodape: `Você recebeu este e-mail sobre a vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `📅 Entrevista agendada — ${esc(vaga_titulo)}`, html,
    tipo: 'entrevista_agendada', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, data_hora, modalidade, entrevista_id, candidatura_id }
  });
}

async function entrevistaCanceladaCandidato({ nome, email, candidato_id, vaga_titulo, data_hora, motivo }) {
  const pode = await podeEnviar('candidato', candidato_id, 'entrevista');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '❌ Entrevista cancelada',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`A entrevista agendada para a vaga <strong>${esc(vaga_titulo)}</strong> em ${fmtDt(data_hora)} foi cancelada.`)}
      ${motivo ? aviso(`<b>Motivo:</b> ${esc(motivo)}`) : ''}
      ${p('Em breve você pode receber um novo agendamento. Acompanhe seu painel.')}
    `,
    cta_link: `${BASE_URL}/candidato/entrevistas.html`,
    cta_texto: 'Ver entrevistas',
    rodape: `Você recebeu este e-mail sobre a vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `❌ Entrevista cancelada — ${esc(vaga_titulo)}`, html,
    tipo: 'entrevista_cancelada', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, data_hora, motivo }
  });
}

async function entrevistaAlteradaCandidato({ nome, email, candidato_id, vaga_titulo, data_hora, modalidade, local_link, observacoes }) {
  const pode = await podeEnviar('candidato', candidato_id, 'entrevista');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '🔄 Entrevista atualizada',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`Os detalhes da sua entrevista para <strong>${esc(vaga_titulo)}</strong> foram atualizados.`)}
      ${box(`
        <b>Nova data/hora:</b> ${fmtDt(data_hora)}<br>
        ${modalidade ? `<b>Modalidade:</b> ${esc(modalidade)}<br>` : ''}
        ${local_link ? `<b>Local/Link:</b> <a href="${esc(local_link)}" style="color:${VINHO}">${esc(local_link)}</a><br>` : ''}
        ${observacoes ? `<b>Observações:</b> ${esc(observacoes)}` : ''}
      `)}
    `,
    cta_link: `${BASE_URL}/candidato/entrevistas.html`,
    cta_texto: 'Ver entrevista',
    rodape: `Você recebeu este e-mail sobre a vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `🔄 Entrevista atualizada — ${esc(vaga_titulo)}`, html,
    tipo: 'entrevista_alterada', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, data_hora }
  });
}

// ─── 7. Proposta ─────────────────────────────────────────────────────────────
async function propostaEnviadaCandidato({ nome, email, candidato_id, vaga_titulo, empresa_nome,
  resumo_proposta, prazo, candidatura_id }) {
  const pode = await podeEnviar('candidato', candidato_id, 'proposta');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: '📨 Você recebeu uma proposta!',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`A empresa <strong>${esc(empresa_nome || 'contratante')}</strong> enviou uma proposta para você sobre a vaga <strong>${esc(vaga_titulo)}</strong>.`)}
      ${resumo_proposta ? box(`<b>Resumo:</b> ${esc(resumo_proposta)}`) : ''}
      ${prazo ? aviso(`Você tem até <strong>${fmtDt(prazo)}</strong> para responder.`) : ''}
      ${p('Acesse seu painel para visualizar todos os detalhes e aceitar ou recusar a proposta.')}
    `,
    cta_link: `${BASE_URL}/candidato/inscricao.html?id=${candidatura_id}`,
    cta_texto: 'Ver proposta',
    rodape: `Este e-mail é referente à vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `📨 Proposta recebida — ${esc(vaga_titulo)}`, html,
    tipo: 'proposta_enviada', user_type: 'candidato', user_id: candidato_id,
    payload: { vaga_titulo, empresa_nome, candidatura_id }
  });
}

async function propostaRespondidaEmpresa({ empresa_email, empresa_id, candidato_nome, vaga_titulo,
  aceita, resposta, motivo, candidatura_id }) {
  // Aceita 'resposta' como alias de 'aceita' para compatibilidade com server.js
  const aceitou = aceita !== undefined ? aceita : (resposta === 'aceita');
  // Busca email da empresa se não fornecido
  if (!empresa_email && empresa_id) {
    try {
      const { rows } = await pool.query(
        `SELECT e.email_principal, u.email
         FROM empresas e
         LEFT JOIN empresa_usuarios u ON u.empresa_id = e.id AND u.role = 'admin_empresa'
         WHERE e.id = $1 LIMIT 1`,
        [empresa_id]
      );
      empresa_email = rows[0]?.email_principal || rows[0]?.email || null;
    } catch (e) { /* segue sem email */ }
  }
  if (!empresa_email) return { ok: true, skip: true };
  const pode = await podeEnviar('empresa', empresa_id, 'proposta');
  if (!pode) return { ok: true, skip: true };
  const html = wrap({
    titulo: aceitou ? '✅ Proposta aceita!' : '❌ Proposta recusada',
    conteudo: `
      ${p(`<strong>${esc(candidato_nome)}</strong> ${aceitou ? 'aceitou' : 'recusou'} a proposta para a vaga <strong>${esc(vaga_titulo)}</strong>.`)}
      ${!aceitou && motivo ? aviso(`<b>Motivo:</b> ${esc(motivo)}`) : ''}
      ${aceitou ? box('O candidato avançou para a etapa de Coleta de Documentos. Acompanhe o processo pelo painel.') : ''}
    `,
    cta_link: `${BASE_URL}/empresa/analisar.html?id=${candidatura_id}`,
    cta_texto: 'Ver candidatura',
    rodape: 'Você recebeu este e-mail como responsável pela vaga na plataforma Vagas.io.'
  });
  return enviar({
    to: empresa_email, subject: `${aceitou ? '✅' : '❌'} Proposta ${aceitou ? 'aceita' : 'recusada'} — ${esc(vaga_titulo)}`, html,
    tipo: aceitou ? 'proposta_aceita' : 'proposta_recusada',
    user_type: 'empresa', user_id: empresa_id,
    payload: { candidato_nome, vaga_titulo, aceita: aceitou, candidatura_id }
  });
}

// ─── 8. Chat — nova mensagem ─────────────────────────────────────────────────
async function chatNovaMensagemCandidato({ candidato_id, email, nome, vaga_titulo, empresa_nome,
  remetente_nome, candidatura_id }) {
  const pode = await podeEnviar('candidato', candidato_id, 'chat');
  if (!pode) return { ok: true, skip: true };
  const jaNotif = await chatJaNotificado('candidato', candidato_id, candidatura_id);
  if (jaNotif) return { ok: true, skip: true, motivo: 'dedup' };
  const html = wrap({
    titulo: '💬 Nova mensagem recebida',
    conteudo: `
      ${p(`Olá, <strong>${esc(nome)}</strong>!`)}
      ${p(`<strong>${esc(remetente_nome || empresa_nome || 'Recrutador')}</strong> enviou uma mensagem sobre a vaga <strong>${esc(vaga_titulo)}</strong>.`)}
      ${box('Acesse o chat para ver a mensagem e responder.')}
    `,
    cta_link: `${BASE_URL}/candidato/chat.html?cid=${candidatura_id}`,
    cta_texto: 'Abrir conversa',
    rodape: `Você recebeu este e-mail porque tem uma candidatura ativa na vaga ${esc(vaga_titulo)}.`
  });
  return enviar({
    to: email, subject: `💬 Nova mensagem — ${esc(vaga_titulo)}`, html,
    tipo: 'chat_nova_mensagem', user_type: 'candidato', user_id: candidato_id,
    payload: { candidatura_id, vaga_titulo, empresa_nome }
  });
}

async function chatNovaMensagemEmpresa({ empresa_id, empresa_email, vaga_titulo, candidato_nome,
  candidatura_id }) {
  // Busca email da empresa se não fornecido
  if (!empresa_email && empresa_id) {
    try {
      const { rows } = await pool.query(
        `SELECT e.email_principal, u.email
         FROM empresas e
         LEFT JOIN empresa_usuarios u ON u.empresa_id = e.id AND u.role = 'admin_empresa' AND u.ativo = true
         WHERE e.id = $1 LIMIT 1`,
        [empresa_id]
      );
      empresa_email = rows[0]?.email_principal || rows[0]?.email || null;
    } catch (e) { /* sem email, skip */ }
  }
  if (!empresa_email) return { ok: true, skip: true };
  const pode = await podeEnviar('empresa', empresa_id, 'chat');
  if (!pode) return { ok: true, skip: true };
  const jaNotif = await chatJaNotificado('empresa', empresa_id, candidatura_id);
  if (jaNotif) return { ok: true, skip: true, motivo: 'dedup' };
  const html = wrap({
    titulo: '💬 Nova mensagem de candidato',
    conteudo: `
      ${p(`<strong>${esc(candidato_nome)}</strong> enviou uma mensagem sobre a vaga <strong>${esc(vaga_titulo)}</strong>.`)}
      ${box('Acesse o chat para ver e responder.')}
    `,
    cta_link: `${BASE_URL}/empresa/chat.html?cid=${candidatura_id}`,
    cta_texto: 'Abrir conversa',
    rodape: 'Você recebeu este e-mail como responsável pela vaga na plataforma Vagas.io.'
  });
  return enviar({
    to: empresa_email, subject: `💬 ${esc(candidato_nome)} enviou uma mensagem — ${esc(vaga_titulo)}`, html,
    tipo: 'chat_nova_mensagem', user_type: 'empresa', user_id: empresa_id,
    payload: { candidatura_id, vaga_titulo, candidato_nome }
  });
}

// ─── 9. Digest diário empresa ─────────────────────────────────────────────────
async function digestDiarioEmpresa({ empresa_id, empresa_email, empresa_nome, kpis, data }) {
  if (!empresa_email) return { ok: true, skip: true };
  const { candidaturas = 0, avancos = 0, entrevistas = 0, propostas = 0, mensagens = 0 } = kpis || {};
  if (candidaturas + avancos + entrevistas + propostas + mensagens === 0) {
    return { ok: true, skip: true, motivo: 'sem_atividade' };
  }
  const html = wrap({
    titulo: `📊 Resumo do dia — ${esc(empresa_nome)}`,
    conteudo: `
      ${p(`Aqui está o resumo das atividades de hoje na sua empresa:`)}
      ${box(`
        📥 <b>${candidaturas}</b> nova${candidaturas !== 1 ? 's' : ''} candidatura${candidaturas !== 1 ? 's' : ''}<br>
        📊 <b>${avancos}</b> candidato${avancos !== 1 ? 's' : ''} avançou de etapa<br>
        📅 <b>${entrevistas}</b> entrevista${entrevistas !== 1 ? 's' : ''} agendada${entrevistas !== 1 ? 's' : ''}<br>
        📨 <b>${propostas}</b> proposta${propostas !== 1 ? 's' : ''} enviada${propostas !== 1 ? 's' : ''}<br>
        💬 <b>${mensagens}</b> mensagem${mensagens !== 1 ? 'ns' : ''} nova${mensagens !== 1 ? 's' : ''}
      `)}
    `,
    cta_link: `${BASE_URL}/empresa/index.html`,
    cta_texto: 'Ver painel',
    rodape: `Resumo diário da empresa ${esc(empresa_nome)} na plataforma Vagas.io.`
  });
  return enviar({
    to: empresa_email, subject: `📊 Resumo do dia — ${esc(empresa_nome)}`, html,
    tipo: 'digest_diario', user_type: 'empresa', user_id: empresa_id,
    payload: { data, kpis }
  });
}

// ─── 10. Aviso de fim do período de teste ────────────────────────────────────
async function avisoFimTrial({ empresa_id, empresa_nome, empresa_email, trial_fim, plano }) {
  const dataFim = new Date(trial_fim).toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  const html = wrap({
    titulo: 'Seu período gratuito está terminando',
    conteudo: `${p(`Olá, ${esc(empresa_nome)}!`)}${p('Seu período gratuito de 30 dias termina em 5 dias. Até lá, você continua usando os recursos do plano ' + esc(plano) + ' sem cobrança.')}${aviso('Para continuar usando o sistema após o período gratuito, cadastre uma forma de pagamento e confirme sua assinatura. Você poderá manter o plano atual ou escolher outro plano disponível.')}${p('<b>Data de encerramento do teste:</b> ' + dataFim)}`,
    cta_link: `${BASE_URL}/empresa/index.html?page=planos`,
    cta_texto: 'Configurar assinatura',
    rodape: 'Aviso automático do Vagas.io sobre o seu período de teste.'
  });
  return enviar({
    to: empresa_email,
    subject: 'Seu período gratuito do Vagas.io termina em 5 dias',
    html, tipo: 'trial_5_dias', user_type: 'empresa', user_id: empresa_id,
    payload: { trial_fim, plano }
  });
}

// ─── 11. Recuperação de senha ─────────────────────────────────────────────────
// (Já implementada em passwordReset.js — re-exportamos para uso via emailService)
// O emailService não reimplementa; apenas expõe a bridge se precisar de logística extra.

// =============================================================================
// PREFERÊNCIAS (CRUD)
// =============================================================================

const CATEGORIAS_VALIDAS = ['candidatura', 'etapa', 'entrevista', 'proposta', 'chat', 'marketing'];
const CATEGORIAS_OBRIGATORIAS = ['seguranca']; // nunca podem ser desligadas

async function getPreferencias(user_type, user_id) {
  const defaults = CATEGORIAS_VALIDAS.map(c => ({ categoria: c, ativo: c !== 'marketing' }));
  try {
    const { rows } = await pool.query(
      `SELECT categoria, ativo FROM email_preferencias WHERE user_type = $1 AND user_id = $2`,
      [user_type, user_id]
    );
    // Merge: usa DB se existe, senão usa default
    return defaults.map(d => {
      const dbRow = rows.find(r => r.categoria === d.categoria);
      return dbRow ? { categoria: d.categoria, ativo: dbRow.ativo } : d;
    });
  } catch (e) {
    return defaults;
  }
}

async function setPreferencia(user_type, user_id, categoria, ativo) {
  if (!CATEGORIAS_VALIDAS.includes(categoria)) {
    throw new Error(`Categoria inválida: ${categoria}`);
  }
  await pool.query(
    `INSERT INTO email_preferencias (user_type, user_id, categoria, ativo)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (user_type, user_id, categoria)
     DO UPDATE SET ativo = EXCLUDED.ativo, atualizado_em = NOW()`,
    [user_type, user_id, categoria, !!ativo]
  );
  return { ok: true };
}

// =============================================================================
// Wrappers bg (para chamar em handlers sem await)
// =============================================================================
const bgBoasVindasCandidato    = (...a) => bg(boasVindasCandidato, ...a);
const bgBoasVindasEmpresa      = (...a) => bg(boasVindasEmpresa, ...a);
const bgCandidaturaConfirmada  = (...a) => bg(candidaturaConfirmadaCandidato, ...a);
const bgNovaCandidaturaEmpresa = (...a) => bg(novaCandidaturaEmpresa, ...a);
const bgMudancaEtapa           = (...a) => bg(mudancaEtapaCandidato, ...a);
const bgEntrevistaAgendada     = (...a) => bg(entrevistaAgendadaCandidato, ...a);
const bgEntrevistaCancelada    = (...a) => bg(entrevistaCanceladaCandidato, ...a);
const bgEntrevistaAlterada     = (...a) => bg(entrevistaAlteradaCandidato, ...a);
const bgPropostaEnviada        = (...a) => bg(propostaEnviadaCandidato, ...a);
const bgPropostaRespondida     = (...a) => bg(propostaRespondidaEmpresa, ...a);
// bgChatEmpresa = empresa enviou msg → notifica CANDIDATO
// bgChatCandidato = candidato enviou msg → notifica EMPRESA
const bgChatCandidato          = (...a) => bg(chatNovaMensagemEmpresa, ...a);
const bgChatEmpresa            = (...a) => bg(chatNovaMensagemCandidato, ...a);
const bgDigestDiario           = (...a) => bg(digestDiarioEmpresa, ...a);

module.exports = {
  // Diretos (await)
  boasVindasCandidato,
  boasVindasEmpresa,
  candidaturaConfirmadaCandidato,
  novaCandidaturaEmpresa,
  mudancaEtapaCandidato,
  entrevistaAgendadaCandidato,
  entrevistaCanceladaCandidato,
  entrevistaAlteradaCandidato,
  propostaEnviadaCandidato,
  propostaRespondidaEmpresa,
  chatNovaMensagemCandidato,
  chatNovaMensagemEmpresa,
  digestDiarioEmpresa,
  avisoFimTrial,
  // Background (setImmediate, sem await)
  bgBoasVindasCandidato,
  bgBoasVindasEmpresa,
  bgCandidaturaConfirmada,
  bgNovaCandidaturaEmpresa,
  bgMudancaEtapa,
  bgEntrevistaAgendada,
  bgEntrevistaCancelada,
  bgEntrevistaAlterada,
  bgPropostaEnviada,
  bgPropostaRespondida,
  bgChatCandidato,
  bgChatEmpresa,
  bgDigestDiario,
  // Preferências
  getPreferencias,
  setPreferencia,
  podeEnviar,
  CATEGORIAS_VALIDAS,
};
