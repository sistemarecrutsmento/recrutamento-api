'use strict';
// analyticsService.js — Fase 14: registra eventos e consolida métricas
// Nunca quebra o fluxo principal (fire-and-forget seguro)

const { pool } = require('./db');
const { EVENTOS_VALIDOS } = require('./migrations/011_analytics_pwa_fase14');
const crypto = require('crypto');

// Limite máximo de metadata (bytes JSON serializado)
const METADATA_MAX_BYTES = 2048;

// Campos proibidos em metadata (dados sensíveis)
const CAMPOS_PROIBIDOS = [
  'senha','password','token','refresh_token','codigo_2fa','code','secret',
  'cpf','rg','cnpj','curriculo','content','texto','mensagem','message'
];

/** Sanitiza metadata: remove campos sensíveis, trunca se muito grande */
function sanitizarMetadata(meta) {
  if (!meta || typeof meta !== 'object') return {};
  const limpo = {};
  for (const [k, v] of Object.entries(meta)) {
    if (CAMPOS_PROIBIDOS.some(p => k.toLowerCase().includes(p))) continue;
    limpo[k] = v;
  }
  const serializado = JSON.stringify(limpo);
  if (Buffer.byteLength(serializado) > METADATA_MAX_BYTES) {
    return { _truncado: true };
  }
  return limpo;
}

/** Hash de IP para privacidade (não armazenamos IP bruto em analytics) */
function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHash('sha256').update(ip + (process.env.IP_HASH_SALT || 'v14salt')).digest('hex').slice(0, 16);
}

/** Registra um evento de analytics (fire-and-forget — nunca lança exceção) */
async function registrar({
  evento, user_type = null, user_id = null, empresa_id = null,
  vaga_id = null, candidatura_id = null, sessao_id = null, anonimo_id = null,
  metadata = {}, ip = null, user_agent = null
}) {
  try {
    if (!EVENTOS_VALIDOS.includes(evento)) return; // silencioso
    const meta = sanitizarMetadata(metadata);
    const ip_hash = hashIp(ip);
    const ua = user_agent ? String(user_agent).slice(0, 300) : null;
    await pool.query(`
      INSERT INTO analytics_eventos
        (evento, user_type, user_id, empresa_id, vaga_id, candidatura_id,
         sessao_id, anonimo_id, metadata, ip_hash, user_agent)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    `, [evento, user_type, user_id || null, empresa_id || null,
        vaga_id || null, candidatura_id || null,
        sessao_id || null, anonimo_id || null,
        JSON.stringify(meta), ip_hash, ua]);
  } catch (e) {
    console.error('[ANALYTICS] erro ao registrar:', evento, e.message);
  }
}

/** Fire-and-forget: usa setImmediate para não bloquear a resposta */
function bg(params) {
  setImmediate(() => registrar(params).catch(() => {}));
}

/** Extrai parâmetros de analytics de um req Express */
function fromReq(req, extra = {}) {
  const user = req.user || {};
  return {
    user_type: user.tipo || null,
    user_id: user.id || user.candidato_id || null,
    empresa_id: user.empresa_id || extra.empresa_id || null,
    sessao_id: req.headers['x-sessao-id'] || null,
    ip: req.ip || req.socket?.remoteAddress || null,
    user_agent: req.headers['user-agent'] || null,
    ...extra
  };
}

// =============================================================================
// MÉTRICAS AGREGADAS
// =============================================================================

/** Período padrão: últimos 30 dias */
function periodoDefault() {
  const fim = new Date();
  const ini = new Date();
  ini.setDate(ini.getDate() - 30);
  return { ini: ini.toISOString(), fim: fim.toISOString() };
}

/** Métricas SaaS globais */
async function metricasSaas({ periodo_inicio, periodo_fim, vaga_id } = {}) {
  const { ini, fim } = {
    ini: periodo_inicio || periodoDefault().ini,
    fim: periodo_fim   || periodoDefault().fim
  };

  const base = `FROM analytics_eventos WHERE criado_em BETWEEN $1 AND $2`;
  const args = [ini, fim];
  const vagaFilter = vaga_id ? ` AND vaga_id = $3` : '';
  const argsVaga = vaga_id ? [...args, vaga_id] : args;

  const [
    totVisual, totCandIni, totCandEnv, totLogin,
    vagasTop, periodoEvs, funil, empresasAtivas
  ] = await Promise.all([
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'vaga_visualizada'${vagaFilter}`, argsVaga),
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'candidatura_iniciada'${vagaFilter}`, argsVaga),
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'candidatura_enviada'${vagaFilter}`, argsVaga),
    pool.query(`SELECT COUNT(*) c ${base} AND evento IN ('login_candidato','empresa_login')${vagaFilter}`, argsVaga),
    pool.query(`
      SELECT vaga_id, COUNT(*) cnt
      ${base} AND evento = 'vaga_visualizada' AND vaga_id IS NOT NULL${vagaFilter}
      GROUP BY vaga_id ORDER BY cnt DESC LIMIT 10
    `, argsVaga),
    pool.query(`
      SELECT DATE_TRUNC('day', criado_em) dia,
             evento, COUNT(*) cnt
      ${base} AND evento IN ('vaga_visualizada','candidatura_enviada','entrevista_agendada','proposta_enviada','proposta_aceita')
      GROUP BY dia, evento ORDER BY dia DESC
    `, args),
    pool.query(`
      SELECT evento, COUNT(*) cnt
      ${base} AND evento IN (
        'vaga_visualizada','candidatura_iniciada','candidatura_enviada',
        'entrevista_agendada','proposta_enviada','proposta_aceita'
      )
      GROUP BY evento
    `, args),
    pool.query(`SELECT COUNT(DISTINCT empresa_id) c ${base} AND empresa_id IS NOT NULL`, args),
  ]);

  const funnelMap = {};
  for (const r of funil.rows) funnelMap[r.evento] = parseInt(r.cnt);

  return {
    visualizacoes:       parseInt(totVisual.rows[0].c),
    candidaturas_ini:    parseInt(totCandIni.rows[0].c),
    candidaturas_env:    parseInt(totCandEnv.rows[0].c),
    logins:              parseInt(totLogin.rows[0].c),
    empresas_ativas:     parseInt(empresasAtivas.rows[0].c),
    taxa_conversao: totVisual.rows[0].c > 0
      ? ((totCandEnv.rows[0].c / totVisual.rows[0].c) * 100).toFixed(1) + '%'
      : '0%',
    vagas_top: vagasTop.rows.map(r => ({ vaga_id: r.vaga_id, visualizacoes: parseInt(r.cnt) })),
    evolucao: periodoEvs.rows.map(r => ({ dia: r.dia, evento: r.evento, cnt: parseInt(r.cnt) })),
    funil: {
      vaga_visualizada:    funnelMap['vaga_visualizada']    || 0,
      candidatura_iniciada:funnelMap['candidatura_iniciada']|| 0,
      candidatura_enviada: funnelMap['candidatura_enviada'] || 0,
      entrevista_agendada: funnelMap['entrevista_agendada'] || 0,
      proposta_enviada:    funnelMap['proposta_enviada']    || 0,
      proposta_aceita:     funnelMap['proposta_aceita']     || 0,
    },
    periodo: { inicio: ini, fim }
  };
}

/** Métricas por empresa (isoladas ao tenant) */
async function metricasEmpresa({ empresa_id, periodo_inicio, periodo_fim, vaga_id } = {}) {
  if (!empresa_id) throw new Error('empresa_id obrigatório');
  const { ini, fim } = {
    ini: periodo_inicio || periodoDefault().ini,
    fim: periodo_fim   || periodoDefault().fim
  };

  const base = `FROM analytics_eventos WHERE empresa_id = $1 AND criado_em BETWEEN $2 AND $3`;
  const args = [empresa_id, ini, fim];
  const vagaFilter = vaga_id ? ` AND vaga_id = $4` : '';
  const argsVaga = vaga_id ? [...args, vaga_id] : args;

  const [totVisual, totCandIni, totCandEnv, vagasTop, funil, evolucao] = await Promise.all([
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'vaga_visualizada'${vagaFilter}`, argsVaga),
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'candidatura_iniciada'${vagaFilter}`, argsVaga),
    pool.query(`SELECT COUNT(*) c ${base} AND evento = 'candidatura_enviada'${vagaFilter}`, argsVaga),
    pool.query(`
      SELECT ae.vaga_id, v.titulo, COUNT(*) cnt
      FROM analytics_eventos ae
      LEFT JOIN vagas v ON v.id = ae.vaga_id
      WHERE ae.empresa_id = $1 AND ae.criado_em BETWEEN $2 AND $3
        AND v.empresa_id = $1
        AND ae.evento = 'vaga_visualizada' AND ae.vaga_id IS NOT NULL${vagaFilter}
      GROUP BY ae.vaga_id, v.titulo ORDER BY cnt DESC LIMIT 10
    `, argsVaga),
    pool.query(`
      SELECT evento, COUNT(*) cnt
      ${base} AND evento IN (
        'vaga_visualizada','candidatura_iniciada','candidatura_enviada',
        'entrevista_agendada','proposta_enviada','proposta_aceita'
      )
      GROUP BY evento
    `, args),
    pool.query(`
      SELECT DATE_TRUNC('day', criado_em) dia,
             evento, COUNT(*) cnt
      ${base} AND evento IN ('vaga_visualizada','candidatura_enviada','entrevista_agendada','proposta_aceita')
      GROUP BY dia, evento ORDER BY dia DESC LIMIT 90
    `, args),
  ]);

  const funnelMap = {};
  for (const r of funil.rows) funnelMap[r.evento] = parseInt(r.cnt);

  return {
    visualizacoes:    parseInt(totVisual.rows[0].c),
    candidaturas_ini: parseInt(totCandIni.rows[0].c),
    candidaturas_env: parseInt(totCandEnv.rows[0].c),
    taxa_conversao: totVisual.rows[0].c > 0
      ? ((totCandEnv.rows[0].c / totVisual.rows[0].c) * 100).toFixed(1) + '%'
      : '0%',
    vagas_ranking: vagasTop.rows.map(r => ({
      vaga_id: r.vaga_id, titulo: r.titulo, visualizacoes: parseInt(r.cnt)
    })),
    funil: {
      vaga_visualizada:    funnelMap['vaga_visualizada']    || 0,
      candidatura_iniciada:funnelMap['candidatura_iniciada']|| 0,
      candidatura_enviada: funnelMap['candidatura_enviada'] || 0,
      entrevista_agendada: funnelMap['entrevista_agendada'] || 0,
      proposta_enviada:    funnelMap['proposta_enviada']    || 0,
      proposta_aceita:     funnelMap['proposta_aceita']     || 0,
    },
    evolucao: evolucao.rows.map(r => ({ dia: r.dia, evento: r.evento, cnt: parseInt(r.cnt) })),
    periodo: { inicio: ini, fim }
  };
}

module.exports = {
  registrar, bg, fromReq,
  metricasSaas, metricasEmpresa,
  EVENTOS_VALIDOS, sanitizarMetadata
};
