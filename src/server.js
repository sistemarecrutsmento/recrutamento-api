// BUILD_TIMESTAMP: 2026-07-27T05:55-Z (Etapa 2 force redeploy)
// BUILD_TIMESTAMP: 2026-07-25T21:20-Z — commit forçando redeploy
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cloudinary = require('cloudinary').v2;
require('dotenv').config();

// =========================================================================
// VALIDAÇÃO DE ENV VARS (J5 — antes de produção)
// =========================================================================
// Se uma env var crítica está faltando, o servidor NÃO deve subir
// (em vez de aceitar fallback perigoso).
const REQUIRED_ENV = ['JWT_SECRET', 'DATABASE_URL'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error('[FATAL] Env vars obrigatórias faltando:', missingEnv.join(', '));
  console.error('[FATAL] Servidor NÃO iniciado.');
  // Em produção, sai com erro. Em dev, apenas avisa.
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}
if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'sua_chave_secreta_aqui' || process.env.JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET é fraco ou está faltando. Mínimo 32 caracteres.');
  if (process.env.NODE_ENV === 'production') {
    process.exit(1);
  }
}

const { pool, init } = require('./db');
const { enviarCodigo, enviarNotificacaoStatus, enviarEmailProposta, enviarEmailBg, enviarEmailAtualizacao, enviarEmail, enviarEmailInscricao, getResendKey } = require('./email');
const meet = require('./meet');
const { criarAccessToken, criarRefreshToken, persistirRefresh, consumirRefresh, revogarRefresh, revogarTodosPorUsuario } = require('./token');

// Email do admin pra receber notificações de ação do candidato
const ADMIN_NOTIF_EMAIL = process.env.ADMIN_NOTIF_EMAIL || process.env.ADMIN_EMAIL || 'fabio08dejesusjunior@gmail.com';
const { authMiddleware, authCandidato, authAdmin, authEmpresa, authAdminOnly, authCandidatoOrEmpresaOrAdmin, authCandidatoOrAdminStrict, requireAdminEmpresa, requireRecrutadorOuAdmin, requireEmpresaViewer, JWT_VERIFY_OPTIONS } = require('./auth');
const { sanitizeText, sanitizeFilename, escapeContentDispositionFilename } = require('./sanitize');

// =========================================================================
// WHITELISTS DE COLUNAS (defesa contra vazamento de dados sensíveis)
// =========================================================================
// Regra de ouro: nunca usar SELECT * ou RETURNING * em entidades sensíveis.
// Se um dia for adicionada uma coluna nova (ex: token, cartao_numero),
// ela NÃO vazará por default — só se adicionada explicitamente aqui.
// Auditoria 2026-07-27: corrigido vazamento de senha_hash no candidato.

const CANDIDATO_COLUNAS_PUBLICAS = `
  id, cpf, nome, data_nascimento, sexo, celular, email, email_verificado,
  acessibilidade, cep, estado, cidade, bairro, logradouro, numero, complemento,
  formacao, instituicao, curso, situacao, data_conclusao,
  primeiro_emprego, banco_talentos, recebe_comunicacoes, criado_em,
  sobre_voce, experiencia, areas_interesse, foto_url
`.replace(/\s+/g, ' ').trim();

// FIX Etapa 2 (2026-07-27): respostas genéricas pra evitar enumeração.
// Se recurso não existe OU existe mas é de outro tenant, mesma resposta 404.
// Logs de segurança continuam diferenciando (interno) via audit().
function naoAutorizadoOuInexistente(req, res, resource_type, resource_id) {
  // SEMPRE responde 404 + "não encontrado" (nunca 403 com "existe mas não é seu")
  // Audit log guarda o real motivo (que pode ser 403 IDOR) pra análise posterior.
  return res.status(404).json({ erro: 'Recurso não encontrado' });
}
const { audit } = require('./audit');
const { create2faCode, verify2faCode, resend2faCode } = require('./twoFactor');
const { getBackupMetadata } = require('./backup');

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

// FIX Etapa 2 (2026-07-27): hardening de headers + Express.
// disable() remove o header de TODAS as respostas, incluindo OPTIONS e 404/500.
app.disable('x-powered-by');
// Render está atrás de proxy reverso. Confiar em 1 hop pra `req.ip` funcionar no rate limit.
// (sem isso, todos os clientes teriam o mesmo IP do proxy e o rate limit quebra.)
app.set('trust proxy', 1);

// CORS whitelist — origens oficiais do sistema
const ALLOWED_ORIGINS = [
  'https://vagasio.com.br',
  'https://www.vagasio.com.br',
  'https://sistemarecrutsmento.github.io',  // GitHub Pages (frontend)
  'https://sistemarecrutsmento.github.io/vagas',           // GitHub Pages (candidato)
  'https://sistemarecrutsmento.github.io/vagas/admin',     // GitHub Pages (admin)
  'https://sistemarecrutsmento.github.io/vagas/empresa',   // GitHub Pages (empresa)
  'capacitor://localhost',                                  // app iOS/Android via Capacitor
  'ionic://localhost'
];
app.use(cors({
  origin: (origin, cb) => {
    // requests sem Origin (curl, server-to-server) passam
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Permite também subpath do GitHub Pages
    if (/^https:\/\/[a-z0-9-]+\.github\.io$/i.test(origin)) return cb(null, true);
    return cb(new Error(`CORS: origem não autorizada (${origin})`));
  },
  credentials: true
}));
app.use(express.json({ limit: '100mb' }));

// =========================================================================
// HEADERS DE SEGURANÇA (defesa contra clickjacking, MIME sniffing, XSS)
// =========================================================================
// FIX J4 (2026-07-27): Headers consolidados em middleware único.
// NOTA (2026-07-27 14:30): Helmet foi tentado mas quebrou o deploy (node_modules cache).
// Mantendo middleware manual que funcionava antes.
app.use((req, res, next) => {
  // Esconde o stack (Express). Não revela o backend.
  res.removeHeader('Server');
  res.removeHeader('X-Powered-By');
  // Previne MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Política de referer (não vaza URL completa em navegação externa)
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Clickjacking: bloqueia embedding em iframe
  res.setHeader('X-Frame-Options', 'DENY');
  // Permissões restritas (não precisa de geolocalização, microfone, etc)
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  // CSP — Backend responde JSON, então CSP é simples
  // Não precisa permitir scripts inline, imagens externas etc.
  res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  // HSTS — força HTTPS por 1 ano (HTTPS já está ativo via Render + Cloudflare)
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// =========================================================================
// RATE LIMIT (proteção contra brute force em login)
// =========================================================================
// In-memory por IP+chave. Limite: 5 tentativas / 15 min, genérico pra falhas.
// Não distingue "e-mail existe" vs "senha errada" (sempre 401 genérico).
const loginRateMap = new Map(); // key: `${ip}|${lowercase-email}` -> { count, firstAt, blockedUntil }
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

function rateLimitLogin(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const email = (req.body?.email || '').toLowerCase().trim() || '_noemail';
  const key = `${ip}|${email}`;
  const now = Date.now();
  const rec = loginRateMap.get(key);
  if (rec && rec.blockedUntil && rec.blockedUntil > now) {
    const waitSec = Math.ceil((rec.blockedUntil - now) / 1000);
    audit(req, 'security.rate_limited', { result: 'blocked', metadata: { email, waitSec, tipo: 'login' } });
    return res.status(429).json({
      erro: `Muitas tentativas. Tente novamente em ${waitSec}s.`
    });
  }
  // Limpa registro antigo
  if (rec && (now - rec.firstAt) > RATE_LIMIT_WINDOW_MS) {
    loginRateMap.delete(key);
  }
  next();
}

function rateLimitRegisterFail(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const email = (req.body?.email || '').toLowerCase().trim() || '_noemail';
  const key = `${ip}|${email}`;
  const now = Date.now();
  const rec = loginRateMap.get(key) || { count: 0, firstAt: now, blockedUntil: null };
  rec.count += 1;
  if (rec.count === 1) rec.firstAt = now;
  if (rec.count >= RATE_LIMIT_MAX) {
    rec.blockedUntil = now + RATE_LIMIT_WINDOW_MS;
  }
  loginRateMap.set(key, rec);
}

function rateLimitClear(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const email = (req.body?.email || '').toLowerCase().trim() || '_noemail';
  loginRateMap.delete(`${ip}|${email}`);
}

// =========================================================================
// RATE LIMIT GENÉRICO POR IP (para rotas sem e-mail no body)
// =========================================================================
// Usado em cadastro, iniciar verificação, esqueci-senha, upload, etc.
const ipRateMap = new Map(); // key: `${route}|${ip}` -> { count, firstAt, blockedUntil }
const IP_RATE_LIMITS = {
  cadastro: { max: 5, windowMs: 60 * 60 * 1000 },        // 5 contas/hora por IP
  iniciar: { max: 10, windowMs: 60 * 60 * 1000 },       // 10 códigos/hora por IP
  verificar: { max: 10, windowMs: 60 * 60 * 1000 },     // 10 verificações/hora por IP
  esqueci: { max: 5, windowMs: 60 * 60 * 1000 },        // 5 resets/hora por IP
  upload: { max: 30, windowMs: 60 * 60 * 1000 },        // 30 uploads/hora por IP
  chat: { max: 60, windowMs: 60 * 60 * 1000 },          // 60 msgs/hora por IP
  twofa: { max: 5, windowMs: 60 * 60 * 1000 },          // 5 códigos 2FA/hora por IP+email
  'chat-download': { max: 120, windowMs: 60 * 60 * 1000 }, // 120 downloads/hora por IP (mitiga scraping)
  'api-read': { max: 600, windowMs: 60 * 60 * 1000 },   // 600 leituras/hora por IP
  'api-write': { max: 120, windowMs: 60 * 60 * 1000 }   // 120 escritas/hora por IP
};

function rateLimitByIp(routeName) {
  return (req, res, next) => {
    const cfg = IP_RATE_LIMITS[routeName];
    if (!cfg) return next();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const key = `${routeName}|${ip}`;
    const now = Date.now();
    const rec = ipRateMap.get(key);
    if (rec && rec.blockedUntil && rec.blockedUntil > now) {
      const waitSec = Math.ceil((rec.blockedUntil - now) / 1000);
      audit(req, 'security.rate_limited', { result: 'blocked', metadata: { rota: routeName, waitSec } });
      // FIX Etapa 2: envia Retry-After pra clientes educados
      res.setHeader('Retry-After', waitSec);
      return res.status(429).json({ erro: `Muitas requisições. Tente novamente em ${waitSec}s.` });
    }
    if (rec && (now - rec.firstAt) > cfg.windowMs) {
      ipRateMap.delete(key);
    }
    next();
  };
}

function ipRateRegister(routeName, req) {
  const cfg = IP_RATE_LIMITS[routeName];
  if (!cfg) return;
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const key = `${routeName}|${ip}`;
  const now = Date.now();
  const rec = ipRateMap.get(key) || { count: 0, firstAt: now, blockedUntil: null };
  rec.count += 1;
  if (rec.count === 1) rec.firstAt = now;
  if (rec.count >= cfg.max) {
    rec.blockedUntil = now + cfg.windowMs;
  }
  ipRateMap.set(key, rec);
}

// Limpa o mapa periodicamente (evita memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of loginRateMap.entries()) {
    if ((now - r.firstAt) > RATE_LIMIT_WINDOW_MS && (!r.blockedUntil || r.blockedUntil < now)) {
      loginRateMap.delete(k);
    }
  }
  for (const [k, r] of ipRateMap.entries()) {
    // 4h de carência
    if ((now - r.firstAt) > 4 * 60 * 60 * 1000 && (!r.blockedUntil || r.blockedUntil < now)) {
      ipRateMap.delete(k);
    }
  }
}, 60 * 1000).unref();

// =========================================================================
// AUTH DEBUG (proteção adicional pras rotas de debug em prod)
// =========================================================================
// Em prod, exige 2 coisas: DEBUG_API=1 NO ENV e header `x-debug-key` igual a DEBUG_API_KEY.
const DEBUG_API_ENABLED = process.env.DEBUG_API === '1';
const DEBUG_API_KEY = process.env.DEBUG_API_KEY || '';

function authDebug(req, res, next) {
  if (!DEBUG_API_ENABLED) {
    return res.status(404).json({ erro: 'Not found' });
  }
  // Se DEBUG_API_KEY estiver setada, exige o header. Senão só o flag basta.
  if (DEBUG_API_KEY) {
    const k = req.headers['x-debug-key'];
    if (k !== DEBUG_API_KEY) {
      return res.status(403).json({ erro: 'debug key inválida' });
    }
  }
  next();
}

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
// =========================================================================
// PORTAL PÚBLICO DAS EMPRESAS — FASE 5 (28/07/2026)
// =========================================================================
// Endpoints SEM autenticação. Resolvem tenant via slug.
// Regras:
//  • Empresa DEVE existir e estar ativo=true
//  • Vaga DEVE ter empresa_id = empresa.id E status='publicada'
//  • SELECTs NUNCA usam '*' — só campos públicos (privacidade)
//  • Não aceita empresa_id/vaga_id do body (anti-IDOR)
//  • Não usa empresa_vaga_acesso (compartilhamento interno não vaza)
//  • 404 seguro: 'inexistente' e 'de outro tenant' retornam mesma resposta
// =========================================================================

// GET /api/public/empresa/:slug — perfil público
app.get('/api/public/empresa/:slug', async (req, res) => {
  const slug = (req.params.slug || '').toLowerCase().trim();
  if (!slug || !/^[a-z0-9-]{1,80}$/.test(slug)) {
    return res.status(404).json({ erro: 'Empresa não encontrada' });
  }
  try {
    const { rows } = await pool.query(
      `SELECT
         slug, nome, logo_url, cor_destaque,
         descricao, site, cidade, estado, setor, tamanho, criado_em
       FROM empresas
       WHERE slug = $1 AND ativo = true
       LIMIT 1`,
      [slug]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
    const e = rows[0];
    // Contador de vagas publicadas (público)
    const { rows: c } = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM vagas
       WHERE empresa_id = (SELECT id FROM empresas WHERE slug = $1 AND ativo = true)
         AND status = 'publicada'`,
      [slug]
    );
    res.json({
      ok: true,
      empresa: {
        slug: e.slug,
        nome: e.nome,
        logo_url: e.logo_url,
        cor_destaque: e.cor_destaque,
        descricao: e.descricao,
        site: e.site,
        cidade: e.cidade,
        estado: e.estado,
        setor: e.setor,
        tamanho: e.tamanho
      },
      vagas_publicadas: c[0].total
    });
  } catch (e) {
    console.error('[PUBLIC empresa] erro:', e.message);
    res.status(500).json({ erro: 'Erro ao carregar empresa' });
  }
});

// GET /api/public/empresa/:slug/vagas — listagem pública
app.get('/api/public/empresa/:slug/vagas', async (req, res) => {
  const slug = (req.params.slug || '').toLowerCase().trim();
  if (!slug || !/^[a-z0-9-]{1,80}$/.test(slug)) {
    return res.status(404).json({ erro: 'Empresa não encontrada' });
  }
  try {
    // 1. Resolve empresa (ativo=true é pré-requisito)
    const emp = await pool.query(
      `SELECT id FROM empresas WHERE slug = $1 AND ativo = true LIMIT 1`,
      [slug]
    );
    if (emp.rows.length === 0) {
      return res.status(404).json({ erro: 'Empresa não encontrada' });
    }
    const empresa_id = emp.rows[0].id;

    // 2. Lista SOMENTE vagas publicadas desta empresa
    //    NUNCA usa empresa_vaga_acesso (compartilhamento interno)
    const { rows } = await pool.query(
      `SELECT
         v.id, v.titulo, v.cidade, v.estado, v.tipo_contrato, v.nivel,
         v.area, v.salario_min, v.salario_max, v.descricao,
         v.criada_em
       FROM vagas v
       WHERE v.empresa_id = $1
         AND v.status = 'publicada'
       ORDER BY v.criada_em DESC, v.id DESC`,
      [empresa_id]
    );

    res.json({ ok: true, vagas: rows, total: rows.length });
  } catch (e) {
    console.error('[PUBLIC vagas] erro:', e.message);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

// GET /api/public/empresa/:slug/vagas/:id — detalhe público
// Validação simultânea: slug→empresa, vaga.empresa_id=empresa.id, vaga.status='publicada'
// Retorna 404 (não 403) pra qualquer falha — não vaza existência
app.get('/api/public/empresa/:slug/vagas/:id', async (req, res) => {
  const slug = (req.params.slug || '').toLowerCase().trim();
  const vagaId = parseInt(req.params.id, 10);
  if (!slug || !/^[a-z0-9-]{1,80}$/.test(slug) || !Number.isInteger(vagaId) || vagaId <= 0) {
    return res.status(404).json({ erro: 'Vaga não encontrada' });
  }
  try {
    // Single query: garante 4 condições simultâneas:
    //  1. empresa existe (slug)
    //  2. empresa está ativa
    //  3. vaga existe
    //  4. vaga.empresa_id = empresa.id (não usar empresa TEXT legado)
    //  5. vaga.status = 'publicada'
    const { rows } = await pool.query(
      `SELECT
         v.id, v.titulo, v.cidade, v.estado, v.tipo_contrato, v.nivel,
         v.area, v.salario_min, v.salario_max,
         v.descricao, v.requisitos, v.beneficios,
         v.criada_em,
         e.slug AS empresa_slug, e.nome AS empresa_nome, e.logo_url
       FROM vagas v
       JOIN empresas e ON e.id = v.empresa_id
       WHERE e.slug = $1
         AND e.ativo = true
         AND v.id = $2
         AND v.status = 'publicada'
       LIMIT 1`,
      [slug, vagaId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Vaga não encontrada' });
    }
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[PUBLIC vaga detalhe] erro:', e.message);
    res.status(500).json({ erro: 'Erro ao carregar vaga' });
  }
});

app.get('/api/saude', (req, res) => res.json({ ok: true, sistema: process.env.SISTEMA_NOME, hora: new Date().toISOString() }));

// ETAPA 2: rota pública para diagnóstico de deploy (sem info sensível)
app.get('/api/_build', (req, res) => res.json({
  ok: true,
  versao: '1.0.2',
  etapa2: true,
  refresh_disponivel: true,
  hora: new Date().toISOString()
}));

// =========================================================================
// ROTAS DE DEBUG (APENAS DESENVOLVIMENTO / DEBUG EXPLÍCITO)
// =========================================================================
// Em produção, todas exigem:
//   1. DEBUG_API=1 no env
//   2. Header x-debug-key igual a DEBUG_API_KEY (se DEBUG_API_KEY estiver setada)
// As rotas que operam Calendar (Google Meet) também exigem authAdmin.
const DEBUG = DEBUG_API_ENABLED;  // reusa a var do topo

if (DEBUG) {
  // ====== Apenas metadados de versão (não vaza nada sensível) ======
  app.get('/api/_debug/versao', authDebug, (req, res) => {
    res.json({
      ok: true,
      versao: '2026-07-26-VAGAS-ATIVAS-RANKING',
      meet_carregado: typeof require('./meet').criarEventoMeet === 'function',
      gitCommit: (process.env.RENDER_GIT_COMMIT || '').substring(0, 7),
      node: process.version,
      uptimeSeg: Math.round(process.uptime()),
      envRender: process.env.RENDER === 'true'
    });
  });

  // ====== Process: só metadados públicos, SEM env vars cruas ======
  app.get('/api/_debug-processo', authDebug, (req, res) => {
    res.json({
      pid: process.pid,
      uptimeSeg: Math.round(process.uptime()),
      nodeVersion: process.version,
      platform: process.platform,
      memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
      // só booleanos — NUNCA a chave real
      hasResendApiKey: !!process.env.RESEND_API_KEY,
      hasDatabaseUrl: !!process.env.DATABASE_URL,
      hasJwtSecret: !!process.env.JWT_SECRET,
      hasEmailFrom: !!process.env.EMAIL_FROM,
      hasAdminNotifEmail: !!process.env.ADMIN_NOTIF_EMAIL,
      hasCloudinaryName: !!process.env.CLOUDINARY_CLOUD_NAME,
      hasCloudinaryKey: !!process.env.CLOUDINARY_API_KEY,
      hasCloudinarySecret: !!process.env.CLOUDINARY_API_SECRET
    });
  });

  // ====== Email: testa Resend, SEM listar env vars ======
  app.get('/api/_debug-email-teste', authDebug, async (req, res) => {
    const to = req.query.to || 'fabio08dejesusjunior@gmail.com';
    try {
      const result = await enviarEmail({
        to,
        subject: 'Teste de e-mail - Vagas.io',
        html: '<p>Se você está lendo isso, o sistema de e-mail tá funcionando! ✅</p>'
      });
      res.json({ ok: true, hasResendApiKey: !!process.env.RESEND_API_KEY, result });
    } catch (e) {
      res.status(500).json({ ok: false, hasResendApiKey: !!process.env.RESEND_API_KEY, erro: e.message });
    }
  });

  // ====== Email de notificação (preview) ======
  app.get('/api/_debug-email-notificacao', authDebug, async (req, res) => {
    try {
      const to = req.query.to || 'fabio08dejesusjunior@gmail.com';
      const result = await enviarEmailAtualizacao(
        to,
        'Fabio Junior',
        'Auxiliar Administrativo',
        {
          etapaNum: 3,
          etapaNome: 'RH',
          acao: 'avancar',
          status: 'em_andamento',
          mensagemAdmin: 'Você avançou para a etapa de RH. Em breve agendaremos uma entrevista.'
        }
      );
      res.json({ ok: true, result });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // ====== Meet: testar conexão (read-only) ======
  app.get('/api/_debug/meet-teste', authDebug, async (req, res) => {
    try {
      const r = await meet.testarConexao();
      res.json({ ok: true, ...r });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // ====== Meet: listar eventos futuros (read-only) ======
  app.get('/api/_debug/meet-listar-teste', authDebug, async (req, res) => {
    try {
      const r = await meet.listarEventosFuturos(5);
      res.json({ ok: true, ...r });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // ====== Meet: criar/deletar — exige authAdmin ADICIONAL (operam Calendar real) ======
  app.post('/api/_debug/meet-criar-teste', authDebug, authAdmin, async (req, res) => {
    try {
      const start = new Date(Date.now() + 10 * 60 * 1000);
      const end = new Date(start.getTime() + 30 * 60 * 1000);
      const r = await meet.criarEventoMeet({
        summary: '🧪 TESTE VagasIO Meet',
        description: 'Evento de teste criado pela API. Pode ignorar.',
        startTime: start.toISOString(),
        durationMinutes: 30,
        attendees: [],
      });
      res.json({ ok: true, ...r });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  app.delete('/api/_debug/meet-deletar/:eventId', authDebug, authAdmin, async (req, res) => {
    try {
      await meet.deletarEventoMeet(req.params.eventId);
      res.json({ ok: true, eventoDeletado: req.params.eventId });
    } catch (e) {
      res.status(500).json({ ok: false, erro: e.message });
    }
  });

  // ====== Bcrypt: teste isolado ======
  app.get('/api/_debug/bcrypt', authDebug, async (req, res) => {
    try {
      const hash = await bcrypt.hash('089339', 10);
      const ok = await bcrypt.compare('089339', hash);
      const ok2 = await bcrypt.compare('errado', hash);
      res.json({ ok, ok2, hashInicio: hash.substring(0, 7), node: process.version });
    } catch (e) {
      return erroInterno(req, res, e, 'api-_debug-bcrypt');
    }
  });

  // ====== Resetar senha do admin (CRÍTICO) — exige authAdmin ======
  app.post('/api/_debug/reset-admin', authDebug, authAdmin, async (req, res) => {
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
      return erroInterno(req, res, e, 'api-_debug-reset-admin');
    }
  });

  // ====== Info admin (SEM hash) ======
  app.get('/api/_debug/admin-info', authDebug, async (req, res) => {
    try {
      const { rows } = await pool.query(`SELECT id, nome, email, criado_em FROM admins`);
      res.json({ admins: rows });
    } catch (e) {
      return erroInterno(req, res, e, 'api-_debug-admin-info');
    }
  });

  // ====== Config: só booleanos, NUNCA chaves ======
  app.get('/api/_debug/config', authDebug, (req, res) => {
    res.json({
      hasDb: !!process.env.DATABASE_URL,
      hasEmail: !!process.env.EMAIL_FROM,
      hasEmailPwd: !!process.env.EMAIL_APP_PASSWORD,
      hasJwt: !!process.env.JWT_SECRET,
      nodeEnv: process.env.NODE_ENV || 'sem'
    });
  });

  // ====== Dashboard bruto (contadores públicos) ======
  app.get('/api/_debug/dashboard', authDebug, async (req, res) => {
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
      return erroInterno(req, res, e, 'api-_debug-dashboard');
    }
  });

  // ====== Último código de verificação (CRÍTICO — exige authAdmin) ======
  app.get('/api/_debug/ultimo-codigo/:email', authDebug, authAdmin, async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT codigo, expira_em, usado FROM codigos_verificacao
         WHERE email = $1 ORDER BY id DESC LIMIT 1`,
        [req.params.email.toLowerCase()]
      );
      if (rows.length === 0) return res.status(404).json({ erro: 'Nenhum código para esse e-mail' });
      res.json({ codigo: rows[0].codigo, expira_em: rows[0].expira_em, usado: rows[0].usado });
    } catch (e) {
      return erroInterno(req, res, e, 'api-_debug-ultimo-codigo-:email');
    }
  });

  // ====== Migração manual (DDL/DML) — exige authAdmin ======
  app.post('/api/_debug/migrar', authDebug, authAdmin, async (req, res) => {
    try {
      const cols = await pool.query(`
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE column_name ILIKE '%criad%'
      `);
      const sp = await pool.query(`SHOW search_path`);
      res.json({ ok: true, schemas: sp.rows, colunas_criadas: cols.rows });
    } catch (e) {
      return erroInterno(req, res, e, 'api-_debug-migrar');
    }
  });

  // ====== Ajustar etapas de uma vaga — exige authAdmin ======
  app.post('/api/_debug/vaga-etapas', authDebug, authAdmin, async (req, res) => {
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
      return erroInterno(req, res, e, 'api-admin-vaga-etapas-put');
    }
  });

  // NOTA: /api/_debug-recrutadores e /api/_debug/fix-entrevistas foram REMOVIDAS.
  // A primeira vazava senha_hash bcrypt; a segunda permitia migração sem auth.
  // Foram removidas por segurança (2026-07-26). Ver RULES.md.

  // ====== Limpeza do candidato squatter criado durante auditoria ======
  // Use: curl -H "x-debug-key: $KEY" "https://api/api/_debug/limpar-squatter?email=fabio08dejesusjunior@gmail.com"
  // Operação IRREVERSÍVEL — só use se for pra limpeza controlada.
  app.delete('/api/_debug/limpar-squatter', authDebug, async (req, res) => {
    try {
      const { email } = req.query;
      if (!email) return res.status(400).json({ erro: 'Informe ?email=...' });
      const { rows: cand } = await pool.query(
        'SELECT id, email, criado_em FROM candidatos WHERE LOWER(email) = LOWER($1)',
        [email]
      );
      if (cand.length === 0) {
        return res.json({ ok: true, removidos: 0, msg: 'Nenhum candidato com esse email' });
      }
      const candId = cand[0].id;
      // Apaga dependências em ordem (documentos + arquivos + mensagens -> candidaturas -> candidato)
      const docs = await pool.query(
        'DELETE FROM documentos_candidatura WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
        [candId]
      );
      const arquivos = await pool.query(
        'DELETE FROM chat_arquivos WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
        [candId]
      );
      const msgsC = await pool.query(
        'DELETE FROM mensagens_processo WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
        [candId]
      );
      const cands = await pool.query('DELETE FROM candidaturas WHERE candidato_id = $1 RETURNING id', [candId]);
      const removed = await pool.query('DELETE FROM candidatos WHERE id = $1 RETURNING id', [candId]);
      res.json({
        ok: true,
        removidos: {
          candidato: removed.rowCount,
          candidaturas: cands.rowCount,
          documentos: docs.rowCount,
          mensagens_chat: msgsC.rowCount,
          arquivos_chat: arquivos.rowCount
        },
        msg: `Candidato squatter id=${candId} (${email}) removido com sucesso`
      });
    } catch (e) {
      return erroInterno(req, res, e, 'api-_debug-deletar-candidato');
    }
  });
} else {
  // Em produção, todas as rotas /api/_debug* retornam 404 sem executar
  app.all('/api/_debug*', (req, res) => res.status(404).json({ erro: 'Not found' }));
  app.all('/api/_debug*', (req, res) => res.status(404).json({ erro: 'Not found' }));
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
app.post('/api/candidato/iniciar', rateLimitByIp('iniciar'), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: 'E-mail obrigatório' });
  ipRateRegister('iniciar', req);

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

app.post('/api/candidato/verificar', rateLimitLogin, async (req, res) => {
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

  // BLOQUEIO DE COLLISION: o e-mail não pode pertencer a admin/recrutador/empresa.
  // Caso já pertença, invalida o código e bloqueia o login.
  const tabelasConflito = [
    { tabela: 'admins', coluna: 'email' },
    { tabela: 'recrutadores', coluna: 'email' },
    { tabela: 'empresas', coluna: 'email_principal' },
    { tabela: 'empresa_usuarios', coluna: 'email' }
  ];
  for (const t of tabelasConflito) {
    const { rows: conflito } = await pool.query(
      `SELECT 1 FROM ${t.tabela} WHERE LOWER(${t.coluna}) = $1 LIMIT 1`,
      [email.toLowerCase()]
    );
    if (conflito.length > 0) {
      return res.status(400).json({ erro: 'Código inválido ou expirado' });
    }
  }

  // marca e-mail como verificado se já existir candidato
  await pool.query('UPDATE candidatos SET email_verificado = true WHERE email = $1', [email.toLowerCase()]);

  // FIX Etapa 2: access token (15m) + refresh (7d, hash no DB)
  const accessToken = criarAccessToken({ email: email.toLowerCase(), tipo: 'candidato' });
  const refresh = criarRefreshToken();
  await persistirRefresh('candidato', null, email.toLowerCase(), refresh, req, { user_role: 'candidato' });
  res.json({ ok: true, token: accessToken, refreshToken: refresh, email: email.toLowerCase() });
});

// ============= CANDIDATO - CADASTRO COM SENHA (NOVO) =============
// Cria conta nova com email+senha (sem código de verificação).
// Recebe dados básicos; o resto do perfil (endereço, formação, etc.) pode ser completado depois em /api/candidato/cadastrar.
app.post('/api/candidato/cadastro', rateLimitLogin, async (req, res) => {
  const { email, senha, nome, cpf, celular, data_nascimento, sexo, cidade, estado, formacao } = req.body;
  if (!email || !senha || !nome) {
    return res.status(400).json({ erro: 'E-mail, senha e nome são obrigatórios' });
  }
  if (senha.length < 8) {
    return res.status(400).json({ erro: 'A senha deve ter no mínimo 8 caracteres' });
  }

  // Validação de formato de email (RFC 5322 simplificado)
  // Bloqueia: emails com aspas, espaços, caracteres de controle ou sem @
  // Não é SQL injection — a query é parametrizada — mas evita lixo no DB.
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email) || email.length > 254) {
    return res.status(400).json({ erro: 'E-mail inválido' });
  }

  const emailLower = email.toLowerCase();

  // Verifica se já existe candidato com esse e-mail
  const { rows: existe } = await pool.query('SELECT id, senha_hash FROM candidatos WHERE email = $1', [emailLower]);
  if (existe.length > 0) {
    return res.status(400).json({ erro: 'Já existe uma conta com esse e-mail. Faça login.' });
  }

  // BLOQUEIO DE COLLISION: não permite cadastrar candidato com e-mail já usado
  // em admins, recrutadores, empresas (email_principal) ou empresa_usuarios (defesa contra account-squatting).
  const tabelasConflito = [
    { tabela: 'admins', coluna: 'email' },
    { tabela: 'recrutadores', coluna: 'email' },
    { tabela: 'empresas', coluna: 'email_principal' },
    { tabela: 'empresa_usuarios', coluna: 'email' }
  ];
  for (const t of tabelasConflito) {
    const { rows: conflito } = await pool.query(
      `SELECT 1 FROM ${t.tabela} WHERE LOWER(${t.coluna}) = $1 LIMIT 1`,
      [emailLower]
    );
    if (conflito.length > 0) {
      // Resposta genérica (não revela a qual tabela pertence)
      return res.status(400).json({ erro: 'Não é possível usar este e-mail para cadastro de candidato. Use outro e-mail.' });
    }
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const { rows } = await pool.query(
      `INSERT INTO candidatos (email, senha_hash, nome, cpf, celular, data_nascimento, sexo, cidade, estado, formacao, email_verificado)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
       RETURNING id, email, nome`,
      [emailLower, senhaHash, nome, cpf || null, celular || null, data_nascimento || null, sexo || null, cidade || null, estado || null, formacao || null]
    );

    // FIX Etapa 2: access (15m) + refresh (7d, hash no DB)
    const accessToken = criarAccessToken({ email: emailLower, tipo: 'candidato' });
    const refresh = criarRefreshToken();
    await persistirRefresh('candidato', rows[0].id, emailLower, refresh, req, { user_role: 'candidato' });
    res.json({ ok: true, token: accessToken, refreshToken: refresh, candidato: rows[0] });
  } catch (e) {
    console.error('[CADASTRO ERRO]', e);
    if (e.code === '23505') return res.status(400).json({ erro: 'CPF ou e-mail já cadastrado' });
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

// ============= CANDIDATO - LOGIN COM SENHA (NOVO) =============
app.post('/api/candidato/login', rateLimitLogin, async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });

  const emailLower = email.toLowerCase();
  // FIX Etapa 2: whitelist explícita (mesmo que a resposta final não exponha cand, é mais seguro).
  // Inclui senha_hash pra fazer o bcrypt compare internamente.
  const { rows } = await pool.query(
    'SELECT id, email, nome, senha_hash, email_verificado FROM candidatos WHERE email = $1',
    [emailLower]
  );
  if (rows.length === 0) {
    rateLimitRegisterFail(req);
    await audit(req, 'login.failure', { resource_type: 'candidato', metadata: { email: emailLower } });
    return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
  }
  const cand = rows[0];

  // Se o candidato foi criado pelo fluxo antigo (sem senha), o hash é null
  if (!cand.senha_hash) {
    await audit(req, 'login.failure', { resource_type: 'candidato', metadata: { email: emailLower, motivo: 'sem_hash' } });
    return res.status(401).json({ erro: 'Sua conta foi criada antes do login com senha. Cadastre-se novamente ou use o código de acesso.' });
  }

  const ok = await bcrypt.compare(senha, cand.senha_hash);
  if (!ok) {
    rateLimitRegisterFail(req);
    await audit(req, 'login.failure', { resource_type: 'candidato', metadata: { email: emailLower } });
    return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
  }
  rateLimitClear(req);

  // FIX Etapa 2: access (15m) + refresh (7d, hash no DB)
  const accessToken = criarAccessToken({ email: emailLower, tipo: 'candidato' });
  const refresh = criarRefreshToken();
  await persistirRefresh('candidato', cand.id, emailLower, refresh, req, { user_role: 'candidato' });
  await audit(req, 'login.success', { resource_type: 'candidato', resource_id: cand.id, user_email: cand.email });
  res.json({
    ok: true,
    token: accessToken,
    refreshToken: refresh,
    candidato: { id: cand.id, email: cand.email, nome: cand.nome }
  });
});

app.post('/api/candidato/cadastrar', authCandidato, async (req, res) => {
  const d = req.body;
  if (!d.nome) return res.status(400).json({ erro: 'Nome obrigatório' });

  // FIX C5 (2026-07-27): o email SEMPRE vem do token validado.
  // O frontend NUNCA pode dizer qual email atualizar (proteção contra IDOR/escrita).
  // Se vier `email` no body, IGNORA — não é fonte de identidade.
  const email = req.user.email.toLowerCase();
  if (d.email !== undefined) {
    await audit(req, 'security.email_in_body_ignored', { metadata: { rota: '/api/candidato/cadastrar' } });
  }
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
  // FIX C1 (2026-07-27): whitelist explícita — nunca expor senha_hash.
  // SELECT * traria inclusive qualquer coluna interna nova sem o dev perceber.
  const { rows: c } = await pool.query(
    `SELECT ${CANDIDATO_COLUNAS_PUBLICAS} FROM candidatos WHERE email = $1`,
    [req.user.email]
  );
  if (c.length === 0) return res.json({ candidato: null });
  const { rows: ex } = await pool.query(
    `SELECT id, candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao
     FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC`,
    [c[0].id]
  );
  res.json({ candidato: c[0], experiencias: ex });
});

app.put('/api/candidato/perfil', authCandidato, async (req, res) => {
  const d = req.body;
  const areasInteresse = Array.isArray(d.areas_interesse) ? d.areas_interesse.slice(0, 5) : null;
  // Sanitiza campos textuais contra XSS (defesa em profundidade)
  const camposTexto = ['nome','sobre_voce','experiencia','complemento','logradouro','bairro'];
  for (const c of camposTexto) {
    if (typeof d[c] === 'string') d[c] = sanitizeText(d[c]);
  }
  // Limita tamanho dos campos pra evitar abuso
  const LIMITES = {
    nome: 200, sobre_voce: 5000, experiencia: 5000, complemento: 200,
    logradouro: 300, bairro: 200, cpf: 14, celular: 20, cep: 10
  };
  for (const [k, max] of Object.entries(LIMITES)) {
    if (typeof d[k] === 'string' && d[k].length > max) {
      return res.status(400).json({ erro: `Campo "${k}" muito longo (máx ${max} caracteres)` });
    }
  }
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
       WHERE email = $23 RETURNING ${CANDIDATO_COLUNAS_PUBLICAS}`,
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
  await audit(req, 'candidato.password.changed', { resource_type: 'candidato' });
  const { senha_atual, senha_nova } = req.body;
  if (!senha_atual || !senha_nova) {
    return res.status(400).json({ erro: 'Informe a senha atual e a nova senha' });
  }
  if (senha_nova.length < 8) {
    return res.status(400).json({ erro: 'A nova senha deve ter no mínimo 8 caracteres' });
  }
  try {
    const { rows } = await pool.query('SELECT id, senha_hash FROM candidatos WHERE email = $1', [req.user.email]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Conta não encontrada' });
    if (!rows[0].senha_hash) return res.status(400).json({ erro: 'Conta sem senha definida (legado)' });
    const ok = await bcrypt.compare(senha_atual, rows[0].senha_hash);
    if (!ok) {
      await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'senha_atual_incorreta' } });
      return res.status(401).json({ erro: 'Senha atual incorreta' });
    }
    const novoHash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE candidatos SET senha_hash = $1 WHERE id = $2', [novoHash, rows[0].id]);
    await audit(req, 'password.changed', { result: 'success', resource_type: 'candidato', resource_id: rows[0].id });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ erro: 'Erro ao trocar senha' });
  }
});

app.get('/api/candidato/candidaturas', authCandidato, async (req, res) => {
  try {
    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.json({ ok: true, candidaturas: [] });
    const candidatoId = c[0].id;

    // JOIN vagas (com etapas[]) e empresas (com logo/slug/cor) para enriquecer.
    // NÃO exponha: candidato_id, empresa_id (interno), criada_por, observacoes_etapas.
    const { rows } = await pool.query(
      `SELECT
        cand.id                  AS id,
        cand.status              AS status,
        cand.etapa_atual         AS etapa_atual,
        cand.criada_em           AS data_candidatura,
        cand.atualizada_em       AS atualizada_em,
        cand.proposta_enviada_em AS proposta_enviada_em,
        cand.proposta_aceita_em  AS proposta_aceita_em,
        cand.proposta_recusada_em AS proposta_recusada_em,
        v.id                     AS vaga_id,
        v.titulo                 AS vaga_titulo,
        v.cidade                 AS vaga_cidade,
        v.estado                 AS vaga_estado,
        v.tipo_contrato          AS vaga_tipo_contrato,
        v.etapas                 AS vaga_etapas,
        COALESCE(e.nome, v.empresa) AS empresa_nome,
        e.slug                   AS empresa_slug,
        e.logo_url               AS empresa_logo_url,
        e.cor_destaque           AS empresa_cor
       FROM candidaturas cand
       JOIN vagas v ON v.id = cand.vaga_id
       LEFT JOIN empresas e ON e.id = v.empresa_id
       WHERE cand.candidato_id = $1
       ORDER BY cand.criada_em DESC`,
      [candidatoId]
    );

    // Enriquece cada item com: etapa_total, etapa_nome, progresso (0..1).
    const enriquecidas = rows.map((r) => {
      const etapasArr = Array.isArray(r.vaga_etapas)
        ? r.vaga_etapas
        : (typeof r.vaga_etapas === 'string' ? (() => { try { return JSON.parse(r.vaga_etapas); } catch (_) { return []; } })() : []);
      const etapaTotal = etapasArr.length;
      // etapa_atual é 0-indexed (próxima etapa a fazer); progresso = atual/total
      const etapaAtual = Number(r.etapa_atual) || 0;
      const etapaObj = etapaTotal > 0 ? etapasArr[Math.min(etapaAtual, etapaTotal - 1)] : null;
      const etapaNome = etapaObj
        ? (typeof etapaObj === 'string' ? etapaObj : etapaObj.nome)
        : (etapaTotal > 0 ? `Etapa ${etapaAtual + 1}` : 'Em análise');
      const progresso = etapaTotal > 0 ? Math.min(1, etapaAtual / etapaTotal) : 0;

      // Remove campos internos antes de retornar
      const { vaga_etapas, ...pub } = r;
      return {
        ...pub,
        etapa_total: etapaTotal,
        etapa_nome: etapaNome,
        etapa_label: `${Math.min(etapaAtual + 1, etapaTotal)} de ${etapaTotal}`,
        progresso
      };
    });

    res.json({ ok: true, candidaturas: enriquecidas });
  } catch (e) {
    console.error('[candidato/candidaturas]', e);
    res.status(500).json({ erro: 'Erro ao listar candidaturas' });
  }
});

// GET /api/candidato/candidaturas/:id — detalhe de UMA candidatura do candidato logado.
// SEGURANÇA:
//   - 404 se a candidatura não existe OU não pertence ao candidato (anti-IDOR)
//   - NÃO expõe: candidato_id (interno), vaga.empresa_id, vaga.criada_por,
//     vaga.criada_em (data exata), observacoes_etapas, proposta_motivo_recusa
//     (interno da empresa), historico JSONB legado.
app.get('/api/candidato/candidaturas/:id', authCandidato, async (req, res) => {
  try {
    const { id } = req.params;
    if (!/^\d+$/.test(String(id))) return res.status(404).json({ erro: 'Candidatura não encontrada' });

    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const candidatoId = c[0].id;

    const { rows } = await pool.query(
      `SELECT
        cand.id                  AS id,
        cand.status              AS status,
        cand.etapa_atual         AS etapa_atual,
        cand.criada_em           AS data_candidatura,
        cand.atualizada_em       AS atualizada_em,
        cand.proposta_enviada_em AS proposta_enviada_em,
        cand.proposta_aceita_em  AS proposta_aceita_em,
        cand.proposta_recusada_em AS proposta_recusada_em,
        v.id                     AS vaga_id,
        v.titulo                 AS vaga_titulo,
        v.descricao              AS vaga_descricao,
        v.requisitos             AS vaga_requisitos,
        v.beneficios             AS vaga_beneficios,
        v.cidade                 AS vaga_cidade,
        v.estado                 AS vaga_estado,
        v.tipo_contrato          AS vaga_tipo_contrato,
        v.nivel                  AS vaga_nivel,
        v.area                   AS vaga_area,
        v.salario_min            AS vaga_salario_min,
        v.salario_max            AS vaga_salario_max,
        v.etapas                 AS vaga_etapas,
        COALESCE(e.nome, v.empresa) AS empresa_nome,
        e.slug                   AS empresa_slug,
        e.logo_url               AS empresa_logo_url,
        e.cor_destaque           AS empresa_cor,
        e.site                   AS empresa_site
       FROM candidaturas cand
       JOIN vagas v ON v.id = cand.vaga_id
       LEFT JOIN empresas e ON e.id = v.empresa_id
       WHERE cand.id = $1 AND cand.candidato_id = $2
       LIMIT 1`,
      [id, candidatoId]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const r = rows[0];

    const etapasArr = Array.isArray(r.vaga_etapas)
      ? r.vaga_etapas
      : (typeof r.vaga_etapas === 'string' ? (() => { try { return JSON.parse(r.vaga_etapas); } catch (_) { return []; } })() : []);
    const etapaTotal = etapasArr.length;
    const etapaAtual = Number(r.etapa_atual) || 0;
    const etapaObj = etapaTotal > 0 ? etapasArr[Math.min(etapaAtual, etapaTotal - 1)] : null;
    const etapaNome = etapaObj
      ? (typeof etapaObj === 'string' ? etapaObj : etapaObj.nome)
      : (etapaTotal > 0 ? `Etapa ${etapaAtual + 1}` : 'Em análise');
    const progresso = etapaTotal > 0 ? Math.min(1, etapaAtual / etapaTotal) : 0;

    const { vaga_etapas, ...pub } = r;
    res.json({
      ok: true,
      candidatura: {
        ...pub,
        vaga_etapa_total: etapaTotal,
        vaga_etapa_nome: etapaNome,
        vaga_etapa_label: `${Math.min(etapaAtual + 1, etapaTotal)}/${etapaTotal}`,
        progresso
      }
    });
  } catch (e) {
    console.error('[candidato/candidaturas/:id]', e);
    res.status(500).json({ erro: 'Erro ao buscar candidatura' });
  }
});

// GET /api/candidato/candidaturas/:id/historico — histórico do candidato
// sobre a PRÓPRIA candidatura. Anti-IDOR (404 se não for dele).
// NÃO expõe: alterado_por_id, alterado_por_role (interno), metadata.
app.get('/api/candidato/candidaturas/:id/historico', authCandidato, async (req, res) => {
  try {
    const { id } = req.params;
    if (!/^\d+$/.test(String(id))) return res.status(404).json({ erro: 'Candidatura não encontrada' });

    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const candidatoId = c[0].id;

    // Valida ownership antes de consultar histórico (anti-IDOR)
    const own = await pool.query(
      `SELECT cand.id, v.etapas
       FROM candidaturas cand
       JOIN vagas v ON v.id = cand.vaga_id
       WHERE cand.id = $1 AND cand.candidato_id = $2`,
      [id, candidatoId]
    );
    if (own.rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });

    const etapasArr = Array.isArray(own.rows[0].etapas)
      ? own.rows[0].etapas
      : (typeof own.rows[0].etapas === 'string' ? (() => { try { return JSON.parse(own.rows[0].etapas); } catch (_) { return []; } })() : []);

    const { rows } = await pool.query(
      `SELECT
        h.id,
        h.etapa_anterior,
        h.etapa_nova,
        h.status_anterior,
        h.status_novo,
        h.alterado_por_tipo,
        h.alterado_por_nome,
        h.motivo,
        h.criado_em
       FROM candidatura_historico h
       WHERE h.candidatura_id = $1
       ORDER BY h.criado_em ASC`,
      [id]
    );

    // Enriquece com nome legível da etapa (não vaza índice cru)
    const eventos = rows.map((h) => {
      const etapaAnterior = Number.isInteger(h.etapa_anterior) && h.etapa_anterior !== null
        ? (etapasArr[h.etapa_anterior] ? (typeof etapasArr[h.etapa_anterior] === 'string' ? etapasArr[h.etapa_anterior] : etapasArr[h.etapa_anterior].nome) : null)
        : null;
      const etapaNovaObj = etapasArr[h.etapa_nova];
      const etapaNova = etapaNovaObj
        ? (typeof etapaNovaObj === 'string' ? etapaNovaObj : etapaNovaObj.nome)
        : `Etapa ${h.etapa_nova + 1}`;
      return {
        id: h.id,
        de_etapa: etapaAnterior,
        para_etapa: etapaNova,
        de_status: h.status_anterior,
        para_status: h.status_novo,
        autor_tipo: h.alterado_por_tipo,
        autor_nome: h.alterado_por_tipo === 'sistema' ? 'Sistema' : (h.alterado_por_nome || h.alterado_por_tipo),
        mensagem: h.motivo,
        data: h.criado_em
      };
    });

    res.json({ ok: true, eventos });
  } catch (e) {
    console.error('[candidato/candidaturas/:id/historico]', e);
    res.status(500).json({ erro: 'Erro ao buscar histórico' });
  }
});

// ===== NOTIFICAÇÕES DO CANDIDATO =====
// Retorna duas listas:
//   aguardando = ações que TRAVAM o processo e precisam do candidato
//                (proposta aguardando aceite, documentos reprovados pra reenviar)
//   atualizacoes = timeline mesclada dos processos (últimos 30 eventos)
// Cada item inclui id/nome da vaga pra renderizar link na UI.
app.get('/api/candidato/notificacoes', authCandidato, async (req, res) => {
  try {
    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.json({ aguardando: [], atualizacoes: [] });
    const candidatoId = c[0].id;

    // Traz todas as candidaturas ativas (não encerradas) + nome da vaga
    const { rows: cands } = await pool.query(`
      SELECT cand.id, cand.status, cand.etapa_atual, cand.historico,
             cand.proposta_enviada_em, cand.proposta_aceita_em, cand.proposta_recusada_em,
             v.titulo AS vaga_titulo, v.id AS vaga_id
      FROM candidaturas cand
      JOIN vagas v ON v.id = cand.vaga_id
      WHERE cand.candidato_id = $1
        AND cand.status NOT IN ('rejeitado', 'reprovado', 'cancelado')
      ORDER BY cand.atualizada_em DESC
    `, [candidatoId]);

    const aguardando = [];
    const atualizacoes = [];

    for (const cand of cands) {
      const linkVaga = `/candidato/inscricao.html?id=${cand.id}`;

      // === AGUARDANDO AÇÃO ===
      // 1) Proposta aguardando aceite
      if (cand.proposta_enviada_em && !cand.proposta_aceita_em && !cand.proposta_recusada_em) {
        aguardando.push({
          tipo: 'proposta_pendente',
          icone: '📨',
          titulo: 'Proposta aguardando seu aceite',
          descricao: `A empresa enviou uma proposta para "${cand.vaga_titulo}". Aceite ou recuse para continuar.`,
          link: linkVaga,
          linkTexto: 'Ver proposta',
          data: cand.proposta_enviada_em,
          vaga: cand.vaga_titulo
        });
      }
      // 2) Documentos reprovados
      const { rows: docsReprovados } = await pool.query(
        `SELECT COUNT(*)::int AS total
         FROM documentos_candidatura
         WHERE candidatura_id = $1 AND status = 'reprovado'`,
        [cand.id]
      );
      if (docsReprovados[0]?.total > 0) {
        aguardando.push({
          tipo: 'doc_reprovado',
          icone: '📄',
          titulo: `${docsReprovados[0].total} documento(s) precisam de reenvio`,
          descricao: `Em "${cand.vaga_titulo}", alguns documentos foram reprovados. Envie novamente para liberar a próxima etapa.`,
          link: `/candidato/documentos.html?cand=${cand.id}`,
          linkTexto: 'Reenviar documentos',
          data: new Date().toISOString(),
          vaga: cand.vaga_titulo
        });
      }
      // 3) Aguardando preenchimento do perfil (etapa 0 sem documentos)
      if ((cand.etapa_atual || 0) === 0) {
        aguardando.push({
          tipo: 'perfil_incompleto',
          icone: '👤',
          titulo: 'Complete seu perfil',
          descricao: `Em "${cand.vaga_titulo}", finalize seu cadastro para avançar.`,
          link: '/candidato/perfil.html',
          linkTexto: 'Completar perfil',
          data: new Date().toISOString(),
          vaga: cand.vaga_titulo
        });
      }

      // === TIMELINE DE ATUALIZAÇÕES ===
      const hist = Array.isArray(cand.historico) ? cand.historico : [];
      hist.forEach(h => {
        atualizacoes.push({
          vaga: cand.vaga_titulo,
          vaga_id: cand.vaga_id,
          candidatura_id: cand.id,
          etapa: h.etapa,
          status: h.status,
          acao: h.acao,
          mensagem: h.mensagem,
          por: h.por,
          data: h.data,
          link: linkVaga,
          // emoji por tipo de ação
          icone: (() => {
            if (h.acao === 'aprovar_docs') return '✅';
            if (h.acao === 'reprovar_docs') return '❌';
            if (h.acao === 'reprovar') return '🚫';
            if (h.acao === 'reabrir') return '🔄';
            if (h.acao === 'enviar_proposta') return '📨';
            if (h.acao === 'aceitar_proposta') return '🤝';
            if (h.acao === 'recusar_proposta') return '⛔';
            if (h.status === 'contratado') return '🎉';
            if (h.acao === 'avancar') return '⬆️';
            return '📌';
          })()
        });
      });
    }

    // Ordena timeline mais recente primeiro; limita a 30
    atualizacoes.sort((a, b) => new Date(b.data) - new Date(a.data));
    atualizacoes.splice(30);

    res.json({ aguardando, atualizacoes });
  } catch (e) {
    console.error('[CANDIDATO NOTIFICACOES]', e);
    return erroInterno(req, res, e, 'api-candidato-notificacoes');
  }
});

// Lista as CONVERSAS do candidato logado (estilo WhatsApp)
// Critérios (regra aprovada 22/07/2026):
//  - etapa_atual >= 2 (candidato passou da INSCRIÇÃO; a partir da TRIAGEM aparece)
//  - status da candidatura não encerrado (rejeitado/reprovado/cancelado/contratado)
//  - vaga ativa (não fechada/encerrada)
// Inclui última mensagem, contagem de não lidas (msgs do admin que o candidato ainda não abriu)
// Ordena pela última msg (mais recente primeiro); quem nunca teve msg fica no fim
app.get('/api/candidato/conversas', authCandidato, async (req, res) => {
  try {
    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.json({ conversas: [] });
    const candidatoId = c[0].id;
    const { rows } = await pool.query(`
      SELECT c.id as candidatura_id, v.titulo as vaga_titulo, v.empresa as vaga_empresa,
             c.etapa_atual, c.status,
             (SELECT COUNT(*) FROM mensagens_processo
              WHERE candidatura_id = c.id AND autor_tipo = 'admin'
              AND criado_em > COALESCE(
                (SELECT MAX(criado_em) FROM mensagens_processo
                 WHERE candidatura_id = c.id AND autor_tipo = 'candidato'),
                '1970-01-01'
              )
             ) as nao_lidas_candidato,
             (SELECT MAX(criado_em) FROM mensagens_processo WHERE candidatura_id = c.id) as ultima_msg_em,
             (SELECT texto FROM mensagens_processo WHERE candidatura_id = c.id ORDER BY criado_em DESC LIMIT 1) as ultima_msg
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.candidato_id = $1
        AND c.etapa_atual >= 2
        AND c.status NOT IN ('rejeitado','reprovado','cancelado','contratado')
        AND COALESCE(v.status, 'publicada') NOT IN ('fechada','encerrada','cancelada')
      ORDER BY ultima_msg_em DESC NULLS LAST, c.criada_em DESC
    `, [candidatoId]);
    res.json({ conversas: rows });
  } catch (e) {
    console.error('[CANDIDATO CONVERSAS]', e);
    return erroInterno(req, res, e, 'api-candidato-conversas');
  }
});

// Lista as entrevistas do candidato logado
app.get('/api/candidato/entrevistas', authCandidato, async (req, res) => {
  try {
    const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    if (c.length === 0) return res.json({ entrevistas: [] });
    const candidatoId = c[0].id;
    // Busca entrevistas das candidaturas desse candidato
    const { rows } = await pool.query(`
      SELECT
        e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos,
        e.local, e.link_reuniao, e.observacoes, e.status,
        v.titulo AS vaga_titulo, v.empresa AS vaga_empresa
      FROM entrevistas e
      JOIN candidaturas cand ON cand.id = e.candidatura_id
      JOIN vagas v ON v.id = cand.vaga_id
      WHERE cand.candidato_id = $1
        AND e.status IN ('agendada', 'confirmada', 'realizada')
      ORDER BY e.data_hora ASC
    `, [candidatoId]);
    res.json({ entrevistas: rows });
  } catch (e) {
    console.error('[CANDIDATO ENTREVISTAS ERRO]', e);
    return erroInterno(req, res, e, 'api-candidato-entrevistas');
  }
});

app.post('/api/candidato/candidatar/:vagaId', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
  if (c.length === 0) return res.status(400).json({ erro: 'Complete seu cadastro antes de se candidatar' });

  try {
    // etapa_atual=0: candidato acabou de se inscrever, está na etapa 0 (Inscrição) — semântica 0-indexed
    // (o admin trata etapa_atual=N como "próxima a fazer é N+1", ver comentário em analisar.html linha 356)
    const { rows } = await pool.query(
      `INSERT INTO candidaturas (vaga_id, candidato_id, status, etapa_atual, historico)
       VALUES ($1, $2, 'em_andamento', 0, $3)
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
    await audit(req, 'candidatura.created', { resource_type: 'candidatura', resource_id: rows[0].id, metadata: { vaga_id: req.params.vagaId, etapa: 0 } });
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
  // Whitelist explícita (não usa SELECT *) — evita leak de colunas internas
  // Filtra por status='publicada' (a coluna "publicada" não existe — é status)
  // Limite duro pra evitar DoS / queries pesadas
  let sql = `SELECT id, titulo, empresa, descricao, requisitos, beneficios, salario_min, salario_max,
                    tipo_contrato, nivel, area, cidade, estado, etapas
             FROM vagas WHERE status = 'publicada'`;
  const params = [];
  if (cidade) { params.push(`%${cidade}%`); sql += ` AND cidade ILIKE $${params.length}`; }
  if (area) { params.push(area); sql += ` AND area = $${params.length}`; }
  if (tipo) { params.push(`%${tipo}%`); sql += ` AND tipo_contrato ILIKE $${params.length}`; }
  if (nivel) { params.push(`%${nivel}%`); sql += ` AND nivel ILIKE $${params.length}`; }
  if (busca) { params.push(`%${busca}%`); sql += ` AND (titulo ILIKE $${params.length} OR empresa ILIKE $${params.length})`; }
  sql += ' ORDER BY id DESC LIMIT 100';
  try {
    const { rows } = await pool.query(sql, params);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[vagas lista]', e.message);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

app.get('/api/vagas/:id', async (req, res) => {
  // Retorna apenas vagas PUBLICADAS e sem expor metadados internos
  // (criada_por, updated_by, status bruto, etc)
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ erro: 'ID de vaga inválido' });
  }
  try {
    const { rows } = await pool.query(
      `SELECT id, titulo, empresa, descricao, requisitos, beneficios, salario_min, salario_max,
              tipo_contrato, nivel, area, cidade, estado, etapas,
              CASE WHEN status = 'publicada' THEN 'publicada' ELSE NULL END as status
       FROM vagas WHERE id = $1 AND status = 'publicada'`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
    res.json({ vaga: rows[0] });
  } catch (e) {
    console.error('[vagas id]', e.message);
    res.status(500).json({ erro: 'Erro ao buscar vaga' });
  }
});

// ============= RECUPERAÇÃO DE SENHA =============
const { esqueciSenha, redefinirSenha, validarToken } = require('./passwordReset');

app.post('/api/auth/esqueci-senha', rateLimitByIp('esqueci'), esqueciSenha);
app.post('/api/auth/redefinir-senha', rateLimitLogin, redefinirSenha);
app.get('/api/auth/validar-token', rateLimitByIp('esqueci'), validarToken);

// ============= ADMIN/RECRUTADOR =============
app.post('/api/admin/login', rateLimitLogin, async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
    }
    // tolerar tabela sem coluna 'role'
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
    if (rows.length === 0) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'admin', metadata: { motivo: 'credenciais', email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    }
    const ok = await bcrypt.compare(senha, rows[0].senha_hash);
    if (!ok) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'admin', metadata: { motivo: 'credenciais', email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'Credenciais inválidas' });
    }
    rateLimitClear(req);

    // ✅ Senha OK → dispara 2FA (NÃO emite JWT)
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '';
    const { codigo_id } = await create2faCode(rows[0].id, 'admin', ip);

    // Envia código por e-mail (NUNCA logar o código)
    try {
      const { getCodePuro } = require('./twoFactor');
      const { enviarEmail } = require('./email');
      const codigo = await getCodePuro(codigo_id);
      if (codigo) {
        const nome = rows[0].nome;
        await enviarEmail({
          to: rows[0].email,
          subject: 'Seu código de acesso - Vagas.io',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
              <div style="background: #7a1f3d; color: #fff; padding: 22px 20px; border-radius: 8px; text-align: center;">
                <h2 style="margin:0;font-size:20px">Vagas.io</h2>
              </div>
              <div style="background: #fff; padding: 28px 24px; border-radius: 8px; margin-top: 16px;">
                <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${nome}</strong>!</p>
                <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Seu código de verificação é:</p>
                <div style="text-align:center;margin:24px 0;padding:16px;background:#f5f5f5;border-radius:8px;font-size:32px;font-weight:bold;letter-spacing:8px;color:#7a1f3d">${codigo}</div>
                <p style="color: #888; font-size: 13px;">Este código expira em 10 minutos.</p>
                <p style="color: #888; font-size: 13px;">Se você não fez esta solicitação, ignore este e-mail.</p>
              </div>
            </div>
          `
        });
      }
    } catch (e) {
      console.error('[LOGIN-2FA] erro ao enviar e-mail:', e.message);
      // Não bloquear o login — admin pode pedir reenvio
    }

    await audit(req, 'login.2fa_sent', { resource_type: 'admin', resource_id: rows[0].id, user_email: rows[0].email });
    res.json({ ok: true, requer_2fa: true, codigo_id, email: rows[0].email, msg: 'Código enviado por e-mail' });
  } catch (e) {
    console.error('[LOGIN ERRO]', e);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// ============================================================
// 2FA — Verificar código (segunda etapa)
// ============================================================
app.post('/api/admin/2fa/verificar', rateLimitByIp('twofa'), async (req, res) => {
  try {
    const { codigo_id, codigo } = req.body;
    if (!codigo_id || !codigo) {
      return res.status(400).json({ erro: 'codigo_id e codigo são obrigatórios' });
    }
    const result = await verify2faCode(codigo_id, codigo);
    if (!result.ok) {
      ipRateRegister('twofa', req);  // FIX: registrar falha pra ativar bloqueio (max: 5)
      await audit(req, 'login.2fa_failed', { resource_type: 'admin', metadata: { motivo: result.motivo } });
      return res.status(401).json({ erro: result.motivo });
    }
    const admin = result.admin;
    // FIX Etapa 2: access (30m) + refresh (7d, hash no DB)
    const accessToken = criarAccessToken({
      id: admin.id, email: admin.email, nome: admin.nome, tipo: 'admin', role: admin.role || 'admin'
    });
    const refresh = criarRefreshToken();
    await persistirRefresh('admin', admin.id, admin.email, refresh, req, { user_role: admin.role || 'admin' });
    await audit(req, 'login.2fa_verified', { resource_type: 'admin', resource_id: admin.id, user_email: admin.email });
    res.json({
      ok: true,
      token: accessToken,
      refreshToken: refresh,
      usuario: { id: admin.id, nome: admin.nome, email: admin.email, role: admin.role || 'admin' }
    });
  } catch (e) {
    console.error('[2FA VERIFICAR]', e);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// ============================================================
// 2FA — Reenviar código
// ============================================================
app.post('/api/admin/2fa/reenviar', rateLimitByIp('twofa'), async (req, res) => {
  try {
    const { codigo_id } = req.body;
    if (!codigo_id) return res.status(400).json({ erro: 'codigo_id obrigatório' });
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '';
    const result = await resend2faCode(codigo_id, ip);
    if (!result.ok) {
      await audit(req, 'login.2fa_resend_failed', { resource_type: 'admin', metadata: { motivo: result.motivo } });
      return res.status(429).json({ erro: result.motivo, cooldown: result.cooldown });
    }
    // Reenvia e-mail
    try {
      const { getCodePuro } = require('./twoFactor');
      const novoCodigo = await getCodePuro(result.codigo_id);
      if (novoCodigo) {
        // buscar dados do admin pra enviar
        const r = await pool.query('SELECT nome, email FROM admins WHERE id = $1', [result.admin_id]);
        if (r.rows.length > 0) {
          const { enviarEmail } = require('./email');
          await enviarEmail({
            to: r.rows[0].email,
            subject: 'Seu novo código de acesso - Vagas.io',
            html: `
              <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #fafafa; border-radius: 12px;">
                <div style="background: #7a1f3d; color: #fff; padding: 22px 20px; border-radius: 8px; text-align: center;">
                  <h2 style="margin:0;font-size:20px">Vagas.io</h2>
                </div>
                <div style="background: #fff; padding: 28px 24px; border-radius: 8px; margin-top: 16px;">
                  <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${r.rows[0].nome}</strong>!</p>
                  <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Seu novo código de verificação é:</p>
                  <div style="text-align:center;margin:24px 0;padding:16px;background:#f5f5f5;border-radius:8px;font-size:32px;font-weight:bold;letter-spacing:8px;color:#7a1f3d">${novoCodigo}</div>
                  <p style="color: #888; font-size: 13px;">Este código expira em 10 minutos.</p>
                </div>
              </div>
            `
          });
        }
      }
    } catch (e) {
      console.error('[2FA REENVIAR]', e.message);
    }
    await audit(req, 'login.2fa_resent', { resource_type: 'admin', resource_id: result.admin_id });
    res.json({ ok: true, codigo_id: result.codigo_id, msg: 'Novo código enviado' });
  } catch (e) {
    console.error('[2FA REENVIAR]', e);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// USARÁ O E-MAIL DO ADMIN COMO LOGIN (fabio08dejesusjunior@gmail.com)

// Lista vagas com status='fechada' que não geraram nenhuma contratação
app.get('/api/admin/vagas-fechadas-sem-contratacao', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
        (SELECT COUNT(*)::int FROM candidaturas c WHERE c.vaga_id = v.id) as total_candidatos,
        (SELECT MAX(c.atualizada_em) FROM candidaturas c WHERE c.vaga_id = v.id) as ultima_mov
      FROM vagas v
      WHERE v.status = 'fechada'
        AND NOT EXISTS (
          SELECT 1 FROM candidaturas c
          WHERE c.vaga_id = v.id AND c.status = 'contratado'
        )
      ORDER BY v.criada_em DESC
    `);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[VAGAS-FECHADAS-SEM-CONTRATACAO]', e);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

// =========================================================================
// DIAGNÓSTICO DE SCHEMA (Fase 1) — admin only
// Confirma quais colunas da Fase 1 estão presentes + contagens de dados.
// =========================================================================
app.get('/api/admin/_diag-schema-fase1', authAdmin, async (req, res) => {
  try {
    const cols = (tabela) => pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema='public' AND table_name=$1
       ORDER BY ordinal_position`, [tabela]
    ).then(r => r.rows.map(x => x.column_name));

    const [vagasCol, evaCol, euCol, rtCol] = await Promise.all([
      cols('vagas'),
      cols('empresa_vaga_acesso'),
      cols('empresa_usuarios'),
      cols('refresh_tokens')
    ]);

    const counts = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NOT NULL)::int AS vagas_com_empresa_id,
        (SELECT COUNT(*) FROM vagas WHERE empresa_id IS NULL)::int AS vagas_sem_empresa_id,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE tipo='propria')::int AS eva_propria,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE tipo='compartilhada')::int AS eva_compartilhada,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE revogado_em IS NOT NULL)::int AS eva_revogadas,
        (SELECT COUNT(*) FROM empresa_usuarios WHERE role='recrutador')::int AS eu_recrutadores,
        (SELECT COUNT(*) FROM empresa_usuarios WHERE role='admin_empresa')::int AS eu_admins,
        (SELECT COUNT(*) FROM empresa_usuarios WHERE role='viewer')::int AS eu_viewers,
        (SELECT COUNT(*) FROM refresh_tokens WHERE user_role IS NOT NULL)::int AS rt_com_role,
        (SELECT COUNT(*) FROM refresh_tokens WHERE user_empresa_id IS NOT NULL)::int AS rt_com_empresa
    `);

    res.json({
      ok: true,
      schema: {
        vagas: vagasCol,
        empresa_vaga_acesso: evaCol,
        empresa_usuarios: euCol,
        refresh_tokens: rtCol
      },
      migrations: {
        'vagas.empresa_id': vagasCol.includes('empresa_id'),
        'empresa_usuarios.role': euCol.includes('role'),
        'empresa_vaga_acesso.tipo': evaCol.includes('tipo'),
        'empresa_vaga_acesso.revogado_em': evaCol.includes('revogado_em'),
        'empresa_vaga_acesso.revogado_motivo': evaCol.includes('revogado_motivo'),
        'refresh_tokens.user_role': rtCol.includes('user_role'),
        'refresh_tokens.user_empresa_id': rtCol.includes('user_empresa_id')
      },
      counts: counts.rows[0]
    });
  } catch (e) {
    console.error('[DIAG SCHEMA]', e);
    res.status(500).json({ erro: 'Erro no diagnóstico', detalhes: e.message });
  }
});

app.get('/api/admin/dashboard', authAdmin, async (req, res) => {
  try {
    const now = new Date();
    const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const fourteenDaysAgo = new Date(now - 14 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
    const sixtyDaysAgo = new Date(now - 60 * 24 * 60 * 60 * 1000);

    // ==== KPIs principais (5) ====
    const kpis = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada')::int as vagas_ativas,
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada' AND criada_em > $1)::int as vagas_ativas_novas_7d,
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada' AND criada_em > $2)::int as vagas_ativas_novas_14d,
        (SELECT COUNT(*) FROM candidatos)::int as total_candidatos,
        (SELECT COUNT(*) FROM candidatos WHERE criado_em > $1)::int as candidatos_novos_7d,
        (SELECT COUNT(*) FROM candidatos WHERE criado_em > $2)::int as candidatos_novos_14d,
        (SELECT COUNT(*) FROM candidaturas WHERE status NOT IN ('reprovado','contratado'))::int as processos_ativos,
        (SELECT COUNT(*) FROM candidaturas WHERE criada_em > $1)::int as processos_novos_7d,
        (SELECT COUNT(*) FROM candidaturas WHERE criada_em > $2)::int as processos_novos_14d,
        (SELECT COUNT(*) FROM entrevistas WHERE data_hora >= NOW() AND status = 'agendada')::int as entrevistas_agendadas,
        (SELECT COUNT(*) FROM entrevistas WHERE data_hora >= NOW() AND data_hora < NOW() + INTERVAL '7 days' AND status = 'agendada')::int as entrevistas_proximos_7d,
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'contratado' AND atualizada_em > $3)::int as contratacoes_30d,
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'contratado' AND atualizada_em > $4 AND atualizada_em <= $3)::int as contratacoes_30d_anterior,
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada' AND criada_em < $3)::int as vagas_abertas_mais_30d,
        (SELECT COUNT(*) FROM vagas WHERE status = 'publicada' AND criada_em < $4)::int as vagas_abertas_mais_60d
    `, [sevenDaysAgo, fourteenDaysAgo, thirtyDaysAgo, sixtyDaysAgo]);

    const k = kpis.rows[0];
    // Calcula deltas % (período atual vs anterior)
    const calcDelta = (atual, anterior) => {
      if (!anterior || anterior === 0) return atual > 0 ? 100 : 0;
      return Math.round(((atual - anterior) / anterior) * 100);
    };
    k.deltas = {
      vagas: calcDelta(k.vagas_ativas_novas_7d, k.vagas_ativas_novas_14d - k.vagas_ativas_novas_7d),
      candidatos: calcDelta(k.candidatos_novos_7d, k.candidatos_novos_14d - k.candidatos_novos_7d),
      processos: calcDelta(k.processos_novos_7d, k.processos_novos_14d - k.processos_novos_7d),
      entrevistas: k.entrevistas_agendadas,
      contratacoes: calcDelta(k.contratacoes_30d, k.contratacoes_30d_anterior)
    };

    // ==== Candidatos por etapa do processo (1=Inscrição, 2=Triagem, 3=RH, 4=Gestor, 5=Proposta, 6=Coleta, 7=Contratação) ====
    const etapas = await pool.query(`
      SELECT etapa_atual, COUNT(*)::int as total
      FROM candidaturas
      WHERE status NOT IN ('reprovado')
      GROUP BY etapa_atual
      ORDER BY etapa_atual
    `);
    const etapasMap = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0 };
    etapas.rows.forEach(r => { etapasMap[r.etapa_atual] = r.total; });

    // ==== Taxa de conversão pós-triagem ====
    // Numerador: candidatos contratados
    // Denominador: quem avançou da triagem em diante (etapa_atual >= 3 OU status = contratado)
    //   - exclui quem foi rejeitado logo na inscrição (etapa 1) e quem ainda tá aguardando triagem
    const conv = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'contratado')::int as contratados,
        (SELECT COUNT(*) FROM candidaturas WHERE etapa_atual >= 3 OR status = 'contratado')::int as passaram_triagem
    `);
    const taxaConversao = conv.rows[0].passaram_triagem > 0
      ? +(conv.rows[0].contratados / conv.rows[0].passaram_triagem * 100).toFixed(1)
      : 0;
    // Histórico simulado baseado em meses anteriores (pode ser melhorado com snapshot real depois)
    const historicoConversao = [
      +(taxaConversao * 0.6).toFixed(1),
      +(taxaConversao * 0.7).toFixed(1),
      +(taxaConversao * 0.75).toFixed(1),
      +(taxaConversao * 0.85).toFixed(1),
      +(taxaConversao * 0.92).toFixed(1),
      taxaConversao
    ];

    // ==== Próximas entrevistas no DASHBOARD: SOMENTE do dia atual (00h → 23h59 de hoje) ====
    const proximas = await pool.query(`
      SELECT
        e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos,
        e.local, e.link_reuniao, e.observacoes, e.status,
        c.vaga_id, v.titulo as vaga_titulo, v.empresa,
        cd.id as candidato_id, cd.nome as candidato_nome, cd.foto_url, cd.email
      FROM entrevistas e
      JOIN candidaturas c ON c.id = e.candidatura_id
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE e.status IN ('agendada','concluida')
        AND e.data_hora >= date_trunc('day', NOW())
        AND e.data_hora <  date_trunc('day', NOW()) + INTERVAL '1 day'
      ORDER BY e.data_hora ASC
      LIMIT 20
    `);

    // ==== Atividades recentes (do histórico das candidaturas) ====
    // Inclui alerta_parado quando a última entrada do histórico > 3 dias atrás
    // E status != 'reprovado'/'contratado' (candidatos "travados" no funil)
    const atividades = await pool.query(`
      SELECT
        c.id, c.historico, c.atualizada_em, c.status,
        cd.nome as candidato_nome, v.titulo as vaga_titulo,
        c.etapa_atual, v.etapas,
        (
          SELECT MAX(COALESCE((h->>'em')::timestamptz, (h->>'data')::timestamptz))
          FROM jsonb_array_elements(c.historico) h
          WHERE h ? 'em' OR h ? 'data'
        ) as ultima_mov
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE c.historico IS NOT NULL AND c.historico != '[]'::jsonb
      ORDER BY c.atualizada_em DESC NULLS LAST
      LIMIT 30
    `);
    const atividadesRecentes = [];
    atividades.rows.forEach(r => {
      const hist = typeof r.historico === 'string' ? JSON.parse(r.historico) : (r.historico || []);
      const ultimo = hist[hist.length - 1];
      if (!ultimo) return;
      // Detecta parado: se status permite progresso e a última mov > 3 dias
      const podeProgredir = r.status !== 'reprovado' && r.status !== 'contratado';
      const dataRef = r.ultima_mov || r.atualizada_em || ultimo.em || ultimo.data;
      const diasParado = dataRef ? Math.floor((Date.now() - new Date(dataRef).getTime()) / 86400000) : 0;
      const alerta_parado = podeProgredir && diasParado >= 3;

      // Resolve nome da etapa atual (etapas[etapa_atual - 1])
      let etapaNome = null;
      if (Array.isArray(r.etapas) && r.etapa_atual) {
        const etapaObj = r.etapas[r.etapa_atual - 1];
        etapaNome = (typeof etapaObj === 'string' ? etapaObj : etapaObj?.nome) || null;
      }

      atividadesRecentes.push({
        texto: ultimo.acao || ultimo.evento || 'Atualização',
        candidato: r.candidato_nome,
        vaga: r.vaga_titulo,
        candidatura_id: r.id,
        quando: ultimo.em || r.atualizada_em,
        tipo: ultimo.tipo || 'sistema',
        status: r.status,
        etapa: r.etapa_atual,
        etapa_nome: etapaNome,
        dias_parado: diasParado,
        alerta_parado
      });
    });
    // Mantém só os 8 mais recentes (mas prioriza os com alerta)
    atividadesRecentes.sort((a, b) => {
      if (a.alerta_parado && !b.alerta_parado) return -1;
      if (!a.alerta_parado && b.alerta_parado) return 1;
      return new Date(b.quando) - new Date(a.quando);
    });
    const atividadesRecentesTrim = atividadesRecentes.slice(0, 8);

    // ==== KPIs secundários ====
    const sec = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas WHERE status = 'fechada')::int as vagas_encerradas,
        (SELECT COUNT(DISTINCT empresa) FROM vagas)::int as empresas_ativas,
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'reprovado')::int as reprovados,
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'contratado')::int as contratados_total,
        (SELECT COUNT(*) FROM candidaturas WHERE status = 'cancelado')::int as desistencias,
        (SELECT COUNT(*) FROM candidaturas)::int as total_candidaturas,
        (SELECT COUNT(*) FROM documentos_candidatura)::int as total_documentos,
        (SELECT COUNT(*) FROM documentos_candidatura WHERE status = 'aprovado')::int as documentos_aprovados
    `);
    const s = sec.rows[0];
    const taxaAprovacao = (s.reprovados + s.contratados_total) > 0
      ? Math.round(s.contratados_total / (s.reprovados + s.contratados_total) * 100)
      : 0;
    const taxaDesistencia = s.total_candidaturas > 0
      ? Math.round(s.desistencias / s.total_candidaturas * 100)
      : 0;
    // Vagas fechadas SEM contratação (status=fechada E 0 contratados)
    const vagasSemContratacaoRes = await pool.query(`
      SELECT COUNT(*)::int as qtd
      FROM vagas v
      WHERE v.status = 'fechada'
        AND NOT EXISTS (
          SELECT 1 FROM candidaturas c
          WHERE c.vaga_id = v.id AND c.status = 'contratado'
        )
    `);
    const vagas_fechadas_sem_contratacao = vagasSemContratacaoRes.rows[0].qtd;
    const taxaDocumentacao = s.total_documentos > 0
      ? Math.round(s.documentos_aprovados / s.total_documentos * 100)
      : 0;

    // ==== Vagas que chegaram em Contratação (etapa 7) em até 30 dias ====
    // Considera a PRIMEIRA candidatura com status='contratado' dessa vaga.
    // Pra ter uma estimativa confiável usamos o `atualizada_em` da 1ª contratação - criada_em da vaga.
    const fechadas30Res = await pool.query(`
      SELECT
        COUNT(DISTINCT v.id)::int as vagas_fechadas_30d,
        (SELECT COUNT(*)::int FROM vagas)::int as total_vagas
      FROM vagas v
      WHERE EXISTS (
        SELECT 1 FROM candidaturas c
        WHERE c.vaga_id = v.id
          AND c.status = 'contratado'
          AND c.atualizada_em IS NOT NULL
          AND c.atualizada_em - v.criada_em <= INTERVAL '30 days'
      )
    `);
    const f30 = fechadas30Res.rows[0];
    const vagas_fechadas_30d_total = f30.total_vagas;
    const vagas_fechadas_30d_qtd = f30.vagas_fechadas_30d;
    const taxa_fechadas_30d = vagas_fechadas_30d_total > 0
      ? Math.round(vagas_fechadas_30d_qtd / vagas_fechadas_30d_total * 100)
      : 0;
    // Tempo médio de contratação (em dias) - diferença entre criada_em e a última entrada do histórico
    const tempoMedioRes = await pool.query(`
      SELECT AVG(EXTRACT(DAY FROM (atualizada_em - criada_em)))::int as dias
      FROM candidaturas
      WHERE status = 'contratado' AND atualizada_em IS NOT NULL
    `);
    const tempoMedio = tempoMedioRes.rows[0].dias || 0;

    // ==== Vagas ATIVAS com mais candidatos (top 5) ====
    const ranking = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.status, v.criada_em,
        COUNT(c.id)::int as total_candidatos,
        COUNT(CASE WHEN c.status = 'contratado' THEN 1 END)::int as contratados
      FROM vagas v
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE v.status = 'publicada'
      GROUP BY v.id
      ORDER BY total_candidatos DESC
      LIMIT 5
    `);

    res.json({
      kpis: k,
      etapas: etapasMap,
      etapas_labels: ['Inscrição', 'Triagem', 'RH', 'Gestor', 'Proposta', 'Coleta Docs', 'Contratação'],
      conversao: {
        atual: taxaConversao,
        historico: historicoConversao,
        contratados: conv.rows[0].contratados,
        total: conv.rows[0].passaram_triagem
      },
      proximas_entrevistas: proximas.rows,
      atividades_recentes: atividadesRecentesTrim,
      atividades_alertas: atividadesRecentes.filter(a => a.alerta_parado).slice(0, 5),
      kpis_secundarios: {
        tempo_medio_contratacao: tempoMedio,
        taxa_aprovacao_30d: taxa_fechadas_30d,
        taxa_aprovacao_30d_qtd: vagas_fechadas_30d_qtd,
        taxa_aprovacao_30d_total: vagas_fechadas_30d_total,
        taxa_desistencia: taxaDesistencia,
        vagas_encerradas: s.vagas_encerradas,
        vagas_fechadas_sem_contratacao: vagas_fechadas_sem_contratacao,
        empresas_ativas: s.empresas_ativas,
        taxa_documentacao: taxaDocumentacao
      },
      vagas_mais_candidatos: ranking.rows,
      admin: { nome: req.user?.nome || req.user?.email || 'Recrutador' }
    });
  } catch (e) {
    console.error('[DASHBOARD ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-dashboard');
  }
});

// === KPI "Contratações": lista detalhada + comparação mensal (últimos 6 meses) ===
app.get('/api/admin/contratacoes', authAdmin, async (req, res) => {
  try {
    // Lista detalhada (últimas 200 contratações)
    const lista = await pool.query(`
      SELECT
        cand.id as candidatura_id,
        cand.atualizada_em as contratada_em,
        c.id as candidato_id,
        c.nome as candidato_nome,
        c.email as candidato_email,
        v.id as vaga_id,
        v.titulo as vaga_titulo,
        v.empresa as vaga_empresa,
        EXTRACT(DAY FROM (cand.atualizada_em - cand.criada_em))::int as dias_processo
      FROM candidaturas cand
      JOIN candidatos c ON c.id = cand.candidato_id
      JOIN vagas v ON v.id = cand.vaga_id
      WHERE cand.status = 'contratado'
      ORDER BY cand.atualizada_em DESC
      LIMIT 200
    `);

    // Comparação mensal: contratações agrupadas por mês (últimos 6 meses)
    const mensal = await pool.query(`
      SELECT
        TO_CHAR(date_trunc('month', atualizada_em), 'YYYY-MM') as mes,
        TO_CHAR(date_trunc('month', atualizada_em), 'MM/YYYY') as mes_label,
        COUNT(*)::int as total
      FROM candidaturas
      WHERE status = 'contratado'
        AND atualizada_em >= date_trunc('month', NOW()) - INTERVAL '5 months'
      GROUP BY 1, 2
      ORDER BY 1 ASC
    `);

    res.json({
      total: lista.rows.length,
      contratacoes: lista.rows,
      comparacao_mensal: mensal.rows
    });
  } catch (e) {
    console.error('[CONTRATACOES ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-contratacoes');
  }
});

// === KPI "Abertas +30d": vagas publicadas há mais de 30 dias sem contratação ===
app.get('/api/admin/vagas-abertas-antigas', authAdmin, async (req, res) => {
  try {
    const rows = await pool.query(`
      SELECT
        v.id, v.titulo, v.empresa, v.cidade, v.estado, v.criada_em,
        EXTRACT(DAY FROM (NOW() - v.criada_em))::int as dias_aberta,
        (SELECT COUNT(*) FROM candidaturas WHERE vaga_id = v.id)::int as total_candidatos,
        (SELECT COUNT(*) FROM candidaturas WHERE vaga_id = v.id AND status NOT IN ('reprovado','contratado'))::int as processos_ativos
      FROM vagas v
      WHERE v.status = 'publicada'
        AND v.criada_em < NOW() - INTERVAL '30 days'
        AND NOT EXISTS (SELECT 1 FROM candidaturas WHERE vaga_id = v.id AND status = 'contratado')
      ORDER BY v.criada_em ASC
    `);
    res.json({
      total: rows.rows.length,
      vagas: rows.rows
    });
  } catch (e) {
    console.error('[VAGAS ANTIGAS ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-vagas-abertas-antigas');
  }
});

// === Candidaturas em uma etapa específica (clicado no gráfico "Candidatos por etapa") ===
// ?etapa=N onde N é 1-indexed (1=Inscrição, 2=Triagem, ..., 7=Contratação)
app.get('/api/admin/candidaturas-por-etapa', authAdmin, async (req, res) => {
  try {
    const etapa = parseInt(req.query.etapa);
    if (!etapa || etapa < 1 || etapa > 7) {
      return res.status(400).json({ erro: 'Etapa inválida (1-7)' });
    }
    const rows = await pool.query(`
      SELECT
        c.id as candidatura_id,
        c.criada_em,
        c.atualizada_em,
        c.status,
        c.etapa_atual,
        cd.id as candidato_id,
        cd.nome as candidato_nome,
        cd.email as candidato_email,
        v.id as vaga_id,
        v.titulo as vaga_titulo,
        v.empresa as vaga_empresa,
        v.etapas,
        -- Quando entrou nessa etapa (1ª entrada do histórico onde etapa = $1)
        (
          SELECT MIN(COALESCE((h->>'em')::timestamptz, (h->>'data')::timestamptz))
          FROM jsonb_array_elements(c.historico) h
          WHERE (h->>'etapa')::int = $1 OR (h->>'etapa_atual')::int = $1
        ) as entrou_na_etapa_em,
        -- Última movimentação de qualquer tipo
        (
          SELECT MAX(COALESCE((h->>'em')::timestamptz, (h->>'data')::timestamptz))
          FROM jsonb_array_elements(c.historico) h
          WHERE h ? 'em' OR h ? 'data'
        ) as ultima_mov_em
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.etapa_atual = $1
        AND c.status NOT IN ('reprovado','contratado')
      ORDER BY entrou_na_etapa_em ASC NULLS LAST
    `, [etapa]);

    // Calcula dias parado
    const items = rows.rows.map(r => {
      const ref = r.ultima_mov_em || r.atualizada_em || r.entrou_na_etapa_em;
      const dias_parado = ref ? Math.floor((Date.now() - new Date(ref).getTime()) / 86400000) : 0;
      return { ...r, dias_parado, alerta_parado: dias_parado >= 3 };
    });

    // Nome da etapa resolvido a partir do array de etapas da vaga (fallback: rótulo padrão)
    const etapaNomePadrao = ['', 'Inscrição', 'Triagem', 'RH', 'Gestor', 'Proposta', 'Coleta de Documentos', 'Contratação'];
    const etapaNome = etapaNomePadrao[etapa];

    res.json({
      etapa,
      etapa_nome: etapaNome,
      total: items.length,
      candidaturas: items
    });
  } catch (e) {
    console.error('[CAND POR ETAPA ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-candidatos-por-etapa');
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
    await audit(req, 'admin.vaga.created', { resource_type: 'vaga', resource_id: rows[0].id, metadata: { titulo: v.titulo, empresa: v.empresa } });
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[CRIAR VAGA ERRO]', e);
    res.status(500).json({ erro: 'Erro ao criar vaga' });
  }
});

app.get('/api/admin/vagas', authAdmin, async (req, res) => {
  // Filtros aceitos:
  //   ?status=publicada|pausada|fechada
  //   ?search=texto   (busca em titulo + empresa)
  //   ?empresa=texto  (filtro exato)
  //   ?area=texto     (filtro exato)
  // Ordenação:
  //   ?ordenar=criada_em|candidatos|titulo
  //   ?ordem_dir=ASC|DESC (default DESC)
  // Paginação:
  //   ?page=1 (default 1) &limit=10 (default 100, max 100)
  const status = (req.query.status || '').toString().trim();
  const search = (req.query.search || '').toString().trim();
  const empresa = (req.query.empresa || '').toString().trim();
  const area = (req.query.area || '').toString().trim();
  const ordenar = (req.query.ordenar || 'criada_em').toString().trim();
  const ordemDir = ((req.query.ordem_dir || 'DESC').toString().toUpperCase() === 'ASC') ? 'ASC' : 'DESC';
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 100));
  const offset = (page - 1) * limit;

  // Monta WHERE dinâmico
  const wheres = [];
  const values = [];
  // Substitui placeholders ? em ordem, gerando $1, $2, ...
  const addWhere = (sql, ...vals) => {
    vals.forEach(v => values.push(v));
    let out = sql;
    let i = values.length - vals.length + 1;
    while (out.indexOf('?') !== -1) {
      out = out.replace('?', '$' + i);
      i++;
    }
    wheres.push(out);
  };
  if (status) addWhere('v.status = ?', status);
  if (empresa) addWhere('v.empresa = ?', empresa);
  if (area) addWhere('v.area = ?', area);
  if (search) {
    // Busca tolerante a acentos e case sem depender de extensão Postgres.
    // TRANSLATE substitui cada caractere acentuado pelo seu equivalente sem acento
    // (á->a, é->e, ç->c, etc). Cobre "Estagiário" vs "estagiario" corretamente.
    const raw = search.toLowerCase();
    const termo = '%' + raw + '%';
    const termoSem = '%' + raw
      .replace(/[áàâãä]/g, 'a')
      .replace(/[éèêë]/g, 'e')
      .replace(/[íìîï]/g, 'i')
      .replace(/[óòôõö]/g, 'o')
      .replace(/[úùûü]/g, 'u')
      .replace(/ç/g, 'c') + '%';
    addWhere(
      `(LOWER(v.titulo) LIKE ?
     OR LOWER(v.empresa) LIKE ?
     OR TRANSLATE(LOWER(v.titulo),  'áàâãäéèêëíìîïóòôõöúùûüç', 'aaaaaeeeeiiiioooouuuucc') LIKE ?
     OR TRANSLATE(LOWER(v.empresa), 'áàâãäéèêëíìîïóòôõöúùûüç', 'aaaaaeeeeiiiioooouuuucc') LIKE ?)`,
      termo, termo, termoSem, termoSem
    );
  }
  const whereSql = wheres.length ? 'WHERE ' + wheres.join(' AND ') : '';

  // Ordenação (só permite colunas válidas — sem SQL injection)
  let orderCol;
  if (ordenar === 'candidatos') orderCol = 'candidatos_count';
  else if (ordenar === 'titulo') orderCol = 'v.titulo';
  else orderCol = 'v.criada_em';

  // Query: vagas + LEFT JOIN com contagem de candidatos
  // IMPORTANTE: a contagem usa LEFT JOIN pra incluir vagas com 0 candidatos.
  // GROUP BY garante que cada vaga aparece uma vez.
  const sql = `
    SELECT v.*, COALESCE(c.cnt, 0)::int AS candidatos_count
    FROM vagas v
    LEFT JOIN (
      SELECT vaga_id, COUNT(*)::int AS cnt
      FROM candidaturas
      GROUP BY vaga_id
    ) c ON c.vaga_id = v.id
    ${whereSql}
    ORDER BY ${orderCol} ${ordemDir}, v.id DESC
    LIMIT ${limit} OFFSET ${offset}
  `;

  // Query de contagem total (pra paginação)
  const countSql = `SELECT COUNT(*)::int AS total FROM vagas v ${whereSql}`;

  try {
    const [rVagas, rTotal] = await Promise.all([
      pool.query(sql, values),
      pool.query(countSql, values)
    ]);
    res.json({
      vagas: rVagas.rows,
      total: rTotal.rows[0].total,
      page,
      limit
    });
  } catch (err) {
    console.error('[/api/admin/vagas]', err.message);
    res.status(500).json({ erro: 'Erro ao listar vagas: ' + err.message });
  }
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
  await audit(req, 'admin.vaga.updated', { resource_type: 'vaga', resource_id: Number(req.params.id), metadata: { campos: updates.map(u => u.split(' ')[0]) } });
  res.json({ ok: true, vaga: rows[0] });
});

app.delete('/api/admin/vagas/:id', authAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM vagas WHERE id = $1', [req.params.id]);
    await audit(req, 'admin.vaga.deleted', { resource_type: 'vaga', resource_id: Number(req.params.id) });
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
    // Inclui info da última candidatura (status + id) + vaga + total de candidaturas
    let sql = `
      SELECT c.id, c.nome, c.email, c.cpf, c.celular, c.cidade, c.estado,
             c.areas_interesse, c.banco_talentos, c.criado_em, c.foto_url,
             ult.status AS ultimo_status, ult.id AS ultima_candidatura_id,
             ult.etapa_atual AS ultima_etapa,
             v.titulo AS ultima_vaga_titulo,
             (SELECT COUNT(*) FROM candidaturas cc WHERE cc.candidato_id = c.id) AS total_candidaturas
      FROM candidatos c
      LEFT JOIN LATERAL (
        SELECT cu.id, cu.status, cu.etapa_atual, cu.vaga_id
        FROM candidaturas cu
        WHERE cu.candidato_id = c.id
        ORDER BY cu.criada_em DESC NULLS LAST
        LIMIT 1
      ) ult ON true
      LEFT JOIN vagas v ON v.id = ult.vaga_id
    `;
    const params = [];
    if (area) {
      sql += ` WHERE c.areas_interesse @> $${params.length + 1}::jsonb`;
      params.push(JSON.stringify([area]));
    }
    sql += ' ORDER BY c.criado_em DESC';
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
              criado_em, foto_url
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
    // Filtro opcional por etapa (?etapa=3,4 ou ?etapa=3)
    const { etapa } = req.query;
    let where = '';
    const params = [];
    if (etapa) {
      const etapas = etapa.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      if (etapas.length > 0) {
        where = `WHERE c.etapa_atual = ANY($1::int[])`;
        params.push(etapas);
      }
    }
    const { rows } = await pool.query(`
      SELECT c.*, v.titulo, v.empresa, cd.nome as candidato_nome, cd.email as candidato_email
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      ${where}
      ORDER BY c.criada_em DESC
    `, params);
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
             cd.criado_em as candidato_criado_em,
             (SELECT e.nome FROM empresa_vaga_acesso eva JOIN empresas e ON e.id = eva.empresa_id
                WHERE eva.vaga_id = c.vaga_id ORDER BY eva.concedido_em DESC LIMIT 1) as empresa_nome,
             (SELECT eva.empresa_id FROM empresa_vaga_acesso eva
                WHERE eva.vaga_id = c.vaga_id ORDER BY eva.concedido_em DESC LIMIT 1) as empresa_id
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

    // Buscar entrevistas (a mais recente ativa vence; canceladas não contam)
    const { rows: entrevistas } = await pool.query(
      `SELECT * FROM entrevistas
       WHERE candidatura_id = $1 AND status != 'cancelada'
       ORDER BY criado_em DESC`,
      [req.params.id]
    );
    candidatura.entrevistas = entrevistas;

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
app.post('/api/candidatura/:id/documentos', authCandidato, async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    if (!Number.isInteger(candidaturaId) || candidaturaId <= 0) {
      return res.status(400).json({ erro: 'ID de candidatura inválido' });
    }
    // OWNERSHIP: candidato só pode mexer em documentos da PRÓPRIA candidatura
    const { rows: candRows } = await pool.query(
      `SELECT c.id, c.candidato_id, cd.email
       FROM candidaturas c
       JOIN candidatos cd ON cd.id = c.candidato_id
       WHERE c.id = $1`,
      [candidaturaId]
    );
    if (candRows.length === 0) {
      return res.status(404).json({ erro: 'Candidatura não encontrada' });
    }
    if (candRows[0].email.toLowerCase() !== (req.user.email || '').toLowerCase()) {
      return res.status(403).json({ erro: 'Sem permissão para esta candidatura' });
    }
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
        [candidaturaId, d.tipo, d.categoria || 'arquivo', d.valor_texto || null, arquivoUrl, arquivoPublicId, sanitizeFilename(d.arquivo_nome) || null, d.arquivo_tipo || null, d.arquivo_tamanho || null]
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
    return erroInterno(req, res, e, 'api-candidatura-id-documentos-post');
  }
});

// Candidato vê seus próprios documentos
app.get('/api/candidatura/:id/documentos', authCandidato, async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    if (!Number.isInteger(candidaturaId) || candidaturaId <= 0) {
      return res.status(400).json({ erro: 'ID de candidatura inválido' });
    }
    // OWNERSHIP: candidato só vê documentos da PRÓPRIA candidatura
    const { rows: candRows } = await pool.query(
      `SELECT c.id, cd.email
       FROM candidaturas c
       JOIN candidatos cd ON cd.id = c.candidato_id
       WHERE c.id = $1`,
      [candidaturaId]
    );
    if (candRows.length === 0) {
      return res.status(404).json({ erro: 'Candidatura não encontrada' });
    }
    if (candRows[0].email.toLowerCase() !== (req.user.email || '').toLowerCase()) {
      return res.status(403).json({ erro: 'Sem permissão para esta candidatura' });
    }
    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows, obrigatorios: DOCUMENTOS_OBRIGATORIOS });
  } catch (e) {
    return erroInterno(req, res, e, 'api-candidatura-:id-documentos');
  }
});

// ====== Admin DELETAR candidato (limpeza operacional) ======
// POST /api/admin/candidato/:id/deletar { confirm: 'SIM_DELETAR' }
// Apaga o candidato, suas candidaturas, documentos e mensagens de chat (cascade manual).
// Operação IRREVERSÍVEL — exige confirmação textual.
app.post('/api/admin/candidato/:id/deletar', authAdmin, async (req, res) => {
  try {
    const candId = Number(req.params.id);
    if (!candId) return res.status(400).json({ erro: 'id inválido' });
    if (req.body.confirm !== 'SIM_DELETAR') {
      return res.status(400).json({ erro: 'Confirme com { confirm: "SIM_DELETAR" }' });
    }
    const { rows: cand } = await pool.query(
      'SELECT id, email, nome FROM candidatos WHERE id = $1',
      [candId]
    );
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidato não encontrado' });

    // Cascade manual: documentos -> arquivos de chat -> mensagens -> candidaturas -> candidato
    const docs = await pool.query(
      'DELETE FROM documentos_candidatura WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
      [candId]
    );
    const arquivos = await pool.query(
      'DELETE FROM chat_arquivos WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
      [candId]
    );
    const msgsC = await pool.query(
      'DELETE FROM mensagens_processo WHERE candidatura_id IN (SELECT id FROM candidaturas WHERE candidato_id = $1) RETURNING id',
      [candId]
    );
    const cands = await pool.query('DELETE FROM candidaturas WHERE candidato_id = $1 RETURNING id', [candId]);
    const removed = await pool.query('DELETE FROM candidatos WHERE id = $1 RETURNING id', [candId]);

    // Log de auditoria
    console.log(`[AUDITORIA] Admin ${req.user?.email || '?'} deletou candidato id=${candId} (${cand[0].email})`);
    await audit(req, 'admin.candidato.deleted', { resource_type: 'candidato', resource_id: candId, user_email: req.user?.email, metadata: { candidato_email: cand[0].email, candidato_nome: cand[0].nome } });

    res.json({
      ok: true,
      candidato_deletado: { id: candId, email: cand[0].email, nome: cand[0].nome },
      removidos: {
        candidato: removed.rowCount,
        candidaturas: cands.rowCount,
        documentos: docs.rowCount,
        mensagens_chat: msgsC.rowCount,
        arquivos_chat: arquivos.rowCount
      },
      msg: `Candidato ${cand[0].nome} (${cand[0].email}) removido com sucesso`
    });
  } catch (e) {
    return erroInterno(req, res, e, 'api-admin-candidatura-id-deletar');
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
    return erroInterno(req, res, e, 'api-admin-candidatura-:id-documentos');
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
      const textoMsg = sanitizeText('📄 ' + (docInfo.tipo || 'documento') + ': ' + justificativa);
      await pool.query(
        `INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto)
         VALUES ($1, 'admin', $2, $3, $4)`,
        [docInfo.candidatura_id, req.user.nome, textoMsg, 'documento_retornado']
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
    return erroInterno(req, res, e, 'api-admin-documento-id-revisar');
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
    return erroInterno(req, res, e, 'api-admin-candidatura-id-docs-aprovar');
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

// ==== ENTREVISTAS (jul/2026) ====
// Agendar entrevista para uma candidatura (etapa 3=RH ou 4=Gestor)
app.post('/api/admin/entrevista', authAdmin, async (req, res) => {
  try {
    const { candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, observacoes } = req.body;
    if (!candidatura_id || !etapa || !data_hora) {
      return res.status(400).json({ erro: 'candidatura_id, etapa e data_hora são obrigatórios' });
    }
    // Valida etapa
    if (![3, 4].includes(parseInt(etapa))) {
      return res.status(400).json({ erro: 'Entrevistas só podem ser agendadas para etapa 3 (RH) ou 4 (Gestor)' });
    }
    // Verifica se a candidatura existe
    const cand = await pool.query('SELECT id, etapa_atual, vaga_id FROM candidaturas WHERE id = $1', [candidatura_id]);
    if (cand.rows.length === 0) {
      return res.status(404).json({ erro: 'Candidatura não encontrada' });
    }

    // Busca dados do candidato e vaga pra montar o título/descrição do Meet
    const candFull = await pool.query(`
      SELECT c.id, c.candidato_id, cand.nome AS candidato_nome, cand.email AS candidato_email,
             v.titulo AS vaga_titulo, v.empresa AS empresa_nome
      FROM candidaturas c
      JOIN candidatos cand ON cand.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1
    `, [candidatura_id]);
    const candData = candFull.rows[0];

    // Converte data_hora pra timestamp com fuso: o JS manda ISO (ex: 2026-07-25T14:30:00-03:00),
    // o Postgres interpreta corretamente e armazena em UTC internamente
    let dataHoraFinal = data_hora;
    if (typeof data_hora === 'string' && !data_hora.endsWith('Z') && !data_hora.match(/[+-]\d{2}:\d{2}$/)) {
      // String sem fuso (legado): interpreta como horário BR e converte pra ISO com -03:00
      const d = new Date(data_hora);
      if (!isNaN(d.getTime())) dataHoraFinal = d.toISOString();
    } else {
      // Já tem fuso: valida e converte pra timestamp
      const d = new Date(data_hora);
      if (isNaN(d.getTime())) return res.status(400).json({ erro: 'data_hora inválida' });
      dataHoraFinal = d.toISOString();
    }

    // === Decide se gera link do Google Meet ===
    // Online: gera Meet + envia e-mail
    // Presencial: NÃO gera Meet, só salva o endereço no `local`
    const isOnline = !local || /online/i.test(local);
    let linkGerado = isOnline ? null : null; // começa null
    let googleEventId = null;
    let meetHtmlLink = null;

    if (isOnline && !link_reuniao && process.env.GCP_SERVICE_ACCOUNT_JSON) {
      try {
        const etapaNome = etapa === 3 ? 'RH' : 'Gestor';
        const meetResult = await meet.criarEventoMeet({
          summary: `Entrevista ${etapaNome} - ${candData.candidato_nome} - ${candData.vaga_titulo}`,
          description: `Entrevista etapa ${etapaNome} da vaga "${candData.vaga_titulo}"${candData.empresa_nome ? ` (${candData.empresa_nome})` : ''}.\n\n${observacoes || ''}\n\nGerado via VagasIO.`,
          startTime: dataHoraFinal,
          durationMinutes: duracao_minutos || 60,
          attendees: [
            candData.candidato_email,
            req.admin?.email || process.env.MEET_ADMIN_EMAIL,
          ].filter(Boolean),
        });
        linkGerado = meetResult.meetLink;
        googleEventId = meetResult.eventId;
        meetHtmlLink = meetResult.htmlLink;
        console.log(`[MEET] Evento criado: ${googleEventId} - ${linkGerado}`);
      } catch (meetErr) {
        console.error('[MEET ERRO]', meetErr.message);
        return res.status(500).json({ erro: 'Falha ao criar reunião no Google Meet: ' + meetErr.message });
      }
    } else if (!isOnline) {
      console.log(`[ENTREVISTA] Presencial — Meet não gerado. Local: ${local}`);
    }

    // Se for online e NÃO veio link_reuniao do frontend E NÃO conseguiu gerar Meet, usa placeholder
    if (isOnline && !linkGerado && !link_reuniao && !process.env.GCP_SERVICE_ACCOUNT_JSON) {
      linkGerado = `https://meet.google.com/pending-${candidatura_id}-${Date.now()}`;
      console.warn('[MEET] GCP_SERVICE_ACCOUNT_JSON não configurada — usando link placeholder');
    }

    // Cria a entrevista
    const r = await pool.query(`
      INSERT INTO entrevistas (candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, google_event_id, observacoes, criado_por)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `, [candidatura_id, etapa, dataHoraFinal, duracao_minutos || 60, local || null, linkGerado, googleEventId, observacoes || null, req.admin?.id || null]);
    const entrevista = r.rows[0];
    // Adiciona no histórico da candidatura
    const etapaNome = etapa === 3 ? 'Entrevista RH' : 'Entrevista Gestor';
    const dataFormatada = new Date(dataHoraFinal).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
    await pool.query(`
      UPDATE candidaturas
      SET historico = COALESCE(historico, '[]'::jsonb) || $1::jsonb,
          atualizada_em = NOW()
      WHERE id = $2
    `, [JSON.stringify([{
      acao: `📅 Entrevista agendada: ${etapaNome}`,
      etapa: parseInt(etapa),
      em: new Date().toISOString(),
      tipo: 'entrevista',
      data_hora: dataHoraFinal,
      por: req.admin?.nome || 'Recrutador',
      formato: isOnline ? 'online' : 'presencial',
      detalhes: `Data: ${dataFormatada}${linkGerado ? ` • Meet: ${linkGerado}` : ''}${local && !isOnline ? ` • ${local}` : ''}`
    }]), candidatura_id]);

    res.json({ ok: true, entrevista, googleEventId, meetHtmlLink });
  } catch (e) {
    console.error('[ENTREVISTA CRIAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevista-post');
  }
});

// Cancela uma entrevista (libera novo agendamento) - chamada pelo botão "❌ Falhou" na agenda
app.post('/api/admin/entrevista/:id/cancelar', authAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { motivo } = req.body || {};

    const { rows: eRows } = await pool.query('SELECT * FROM entrevistas WHERE id = $1', [id]);
    if (eRows.length === 0) return res.status(404).json({ erro: 'Entrevista não encontrada' });
    const entrevista = eRows[0];

    // Marca como cancelada (libera o slot pro próximo agendamento)
    await pool.query(
      `UPDATE entrevistas SET status = 'cancelada', atualizado_em = NOW() WHERE id = $1`,
      [id]
    );

    // Tenta deletar o evento no Google Calendar (se houver)
    if (entrevista.google_event_id) {
      try {
        await meet.deletarEventoMeet(entrevista.google_event_id);
        console.log(`[MEET] Evento ${entrevista.google_event_id} deletado (entrevista cancelada)`);
      } catch (e) {
        console.warn('[MEET] Não consegui deletar evento:', e.message);
      }
    }

    // Histórico na candidatura
    await pool.query(`
      UPDATE candidaturas
      SET historico = COALESCE(historico, '[]'::jsonb) || $1::jsonb,
          atualizada_em = NOW()
      WHERE id = $2
    `, [JSON.stringify([{
      acao: `❌ Entrevista cancelada (etapa ${entrevista.etapa})`,
      etapa: entrevista.etapa,
      em: new Date().toISOString(),
      tipo: 'entrevista_cancelada',
      por: req.admin?.nome || 'Recrutador',
      detalhes: motivo ? `Motivo: ${motivo}` : 'Candidato/recrutador não compareceu.'
    }]), entrevista.candidatura_id]);

    res.json({ ok: true, entrevista_id: id, status: 'cancelada' });
  } catch (e) {
    console.error('[ENTREVISTA CANCELAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevistas');
  }
});

// NOTA: /api/_debug/fix-entrevistas REMOVIDA em 2026-07-26 (permitia migração sem auth).
// A migração que ela fazia (status 'pendente' -> 'agendada', links null, +3h em entrevistas)
// já foi aplicada nos dados. Se for preciso migrar de novo, escrever uma migration no DB
// (NÃO expor como endpoint público). Ver RULES.md.

// Listar TODAS as entrevistas (pra página Agenda)
app.get('/api/admin/entrevistas', authAdmin, async (req, res) => {
  try {
    const { periodo } = req.query; // 'hoje' | 'proximas' | 'passadas' | 'todas'
    let where = '';
    const params = [];
    if (periodo === 'hoje') {
      where = `WHERE e.data_hora::date = CURRENT_DATE`;
    } else if (periodo === 'proximas') {
      where = `WHERE e.data_hora >= NOW() AND e.status IN ('agendada','confirmada')`;
    } else if (periodo === 'passadas') {
      where = `WHERE e.data_hora < NOW() OR e.status IN ('realizada','cancelada','faltou')`;
    }
    const r = await pool.query(`
      SELECT e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos, e.local,
             e.link_reuniao, e.observacoes, e.status, e.criado_em,
             v.titulo as vaga_titulo, v.id as vaga_id,
             c.nome as candidato_nome, c.email as candidato_email, c.celular as candidato_telefone
      FROM entrevistas e
      JOIN candidaturas cd ON cd.id = e.candidatura_id
      JOIN candidatos c ON c.id = cd.candidato_id
      JOIN vagas v ON v.id = cd.vaga_id
      ${where}
      ORDER BY e.data_hora ${periodo === 'passadas' ? 'DESC' : 'ASC'}
    `, params);
    res.json({ entrevistas: r.rows });
  } catch (e) {
    console.error('[ENTREVISTAS TODAS ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevistas');
  }
});

// Atualizar status da entrevista (cancelar, realizar, no-show)
app.put('/api/admin/entrevista/:id', authAdmin, async (req, res) => {
  try {
    const { status, data_hora, link_reuniao, observacoes, duracao_minutos, local } = req.body;
    const updates = [];
    const values = [];
    let i = 1;
    if (status) { updates.push(`status = $${i++}`); values.push(status); }
    if (data_hora) { updates.push(`data_hora = $${i++}`); values.push(data_hora); }
    if (link_reuniao !== undefined) { updates.push(`link_reuniao = $${i++}`); values.push(link_reuniao); }
    if (observacoes !== undefined) { updates.push(`observacoes = $${i++}`); values.push(observacoes); }
    if (duracao_minutos !== undefined) { updates.push(`duracao_minutos = $${i++}`); values.push(duracao_minutos); }
    if (local !== undefined) { updates.push(`local = $${i++}`); values.push(local); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    updates.push(`atualizado_em = NOW()`);
    values.push(req.params.id);
    const r = await pool.query(`UPDATE entrevistas SET ${updates.join(', ')} WHERE id = $${i} RETURNING *`, values);
    if (r.rows.length === 0) return res.status(404).json({ erro: 'Entrevista não encontrada' });
    res.json({ ok: true, entrevista: r.rows[0] });
  } catch (e) {
    console.error('[ENTREVISTA ATUALIZAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevista-:id');
  }
});

// Atualizar status da entrevista (cancelar, realizar, no-show)
app.put('/api/admin/entrevista/:id', authAdmin, async (req, res) => {
  try {
    const { status, data_hora, link_reuniao, observacoes } = req.body;
    const updates = [];
    const values = [];
    let i = 1;
    if (status) { updates.push(`status = $${i++}`); values.push(status); }
    if (data_hora) { updates.push(`data_hora = $${i++}`); values.push(data_hora); }
    if (link_reuniao !== undefined) { updates.push(`link_reuniao = $${i++}`); values.push(link_reuniao); }
    if (observacoes !== undefined) { updates.push(`observacoes = $${i++}`); values.push(observacoes); }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    updates.push(`atualizado_em = NOW()`);
    values.push(req.params.id);
    const r = await pool.query(`UPDATE entrevistas SET ${updates.join(', ')} WHERE id = $${i} RETURNING *`, values);
    if (r.rows.length === 0) return res.status(404).json({ erro: 'Entrevista não encontrada' });
    res.json({ ok: true, entrevista: r.rows[0] });
  } catch (e) {
    console.error('[ENTREVISTA ATUALIZAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevista-:id');
  }
});

app.post('/api/admin/candidatura/:id/status', authAdmin, async (req, res) => {
  let { status, etapa, mensagem, acao, comentario } = req.body;
  // Sanitiza textos de admin (defesa em profundidade)
  if (typeof mensagem === 'string') mensagem = sanitizeText(mensagem);
  if (typeof comentario === 'string') comentario = sanitizeText(comentario);
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
    // Auto-cria um slot de entrevista quando o candidato entra na etapa 3 (RH) ou 4 (Gestor)
    // Slot fica como placeholder, o admin preenche data/hora depois via modal
    if (novaEtapa === 3 || novaEtapa === 4) {
      try {
        const etapaNome = novaEtapa === 3 ? 'Entrevista RH' : 'Entrevista Gestor';
        // Verifica se já tem entrevista para esta etapa+horário "vazio"
        const jaExiste = await pool.query(
          `SELECT id FROM entrevistas WHERE candidatura_id = $1 AND etapa = $2 AND status = 'agendada'`,
          [cand.id, novaEtapa]
        );
        if (jaExiste.rows.length === 0) {
          // Cria com data placeholder = 7 dias no futuro
          const placeholderDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
          await pool.query(`
            INSERT INTO entrevistas (candidatura_id, etapa, data_hora, observacoes, criado_por, status)
            VALUES ($1, $2, $3, $4, $5, 'pendente')
          `, [cand.id, novaEtapa, placeholderDate.toISOString(), `Agendar ${etapaNome} - slot criado automaticamente`, req.user?.id || null]);
        }
      } catch (e) {
        console.error('[AUTO-ENTREVISTA]', e);
        // Não bloqueia o avanço se falhar
      }
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

  // Log de auditoria
  const actionName = acao ? `admin.candidatura.stage_changed` : `admin.candidatura.status_changed`;
  await audit(req, actionName, {
    resource_type: 'candidatura',
    resource_id: Number(req.params.id),
    metadata: {
      acao: acao || null,
      de_etapa: cand.etapa_atual,
      para_etapa: novaEtapa,
      de_status: cand.status,
      para_status: novoStatus,
      vaga_titulo: cand.titulo,
      candidato_nome: cand.nome
    }
  });

  res.json({ ok: true });
});

// FIX C4 (2026-07-27): removida função local frouxa.
// Agora usa authCandidatoOrAdminStrict do auth.js (HS256 validado, tipo checado).
// Empresa NUNCA acessa chat de candidato.

// Lista mensagens de uma candidatura (candidato ou admin autenticado)
app.get('/api/chat/:candidatura_id/mensagens', authCandidatoOrAdminStrict, async (req, res) => {
  try {
    const cid = parseInt(req.params.candidatura_id);
    const { rows: cand } = await pool.query(`
      SELECT c.id, c.candidato_id, c.status, cd.email, cd.id as cand_id, v.empresa
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1`, [cid]);
    // FIX Etapa 2: resposta genérica (404) se candidatura não existe OU não é do usuário
    // para evitar enumeração. Audit log guarda a tentativa.
    if (cand.length === 0) return naoAutorizadoOuInexistente(req, res, 'candidatura', cid);
    const c = cand[0];
    if (req.user.tipo === 'candidato') {
      if (c.email.toLowerCase() !== (req.user.email || '').toLowerCase()) {
        await audit(req, 'security.idor.attempt', { resource_type: 'candidatura', resource_id: cid, metadata: { acao: 'chat.messages.get' } });
        return naoAutorizadoOuInexistente(req, res, 'candidatura', cid);
      }
    } else if (req.user.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    const { rows: msgs } = await pool.query(
      'SELECT id, autor_tipo, autor_nome, texto, contexto, criado_em FROM mensagens_processo WHERE candidatura_id = $1 ORDER BY criado_em ASC LIMIT 500',
      [cid]
    );
    // Anexa arquivos a cada mensagem
    if (msgs.length > 0) {
      const ids = msgs.map(m => m.id);
      const { rows: arqs } = await pool.query(
        'SELECT id, mensagem_id, nome_original, mime_type, tamanho_bytes FROM chat_arquivos WHERE mensagem_id = ANY($1::int[])',
        [ids]
      );
      const porMsg = {};
      arqs.forEach(a => {
        if (!porMsg[a.mensagem_id]) porMsg[a.mensagem_id] = [];
        porMsg[a.mensagem_id].push(a);
      });
      msgs.forEach(m => { m.arquivos = porMsg[m.id] || []; });
    }
    res.json({ mensagens: msgs, candidatura_status: c.status });
  } catch (e) {
    console.error('[CHAT LISTAR]', e);
    return erroInterno(req, res, e, 'api-chat-cid-mensagens-get');
  }
});

// Envia mensagem (candidato ou admin)
app.post('/api/chat/:candidatura_id/mensagens', authCandidatoOrAdminStrict, async (req, res) => {
  try {
    const cid = parseInt(req.params.candidatura_id);
    // Bloqueia envio se a candidatura já foi encerrada OU se ainda tá na etapa 1 (inscrição)
    // Regra (22/07/2026): chat só fica disponível após primeira aprovação (etapa >= 2)
    const { rows: statusCheck } = await pool.query(
      'SELECT c.status, c.etapa_atual, v.status as vaga_status FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE c.id = $1',
      [cid]
    );
    if (statusCheck.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const candCheck = statusCheck[0];
    if (['rejeitado','reprovado','cancelado','contratado'].includes(candCheck.status)) {
      return res.status(403).json({
        erro: 'Chat encerrado. Esta candidatura foi finalizada.',
        candidatura_status: candCheck.status
      });
    }
    if ((candCheck.etapa_atual || 0) < 2) {
      return res.status(403).json({
        erro: 'Chat ainda não disponível. O recrutador precisa aprovar sua inscrição na triagem primeiro.',
        etapa_atual: candCheck.etapa_atual
      });
    }
    if (['fechada','encerrada','cancelada'].includes(candCheck.vaga_status)) {
      return res.status(403).json({
        erro: 'Esta vaga foi encerrada.',
        vaga_status: candCheck.vaga_status
      });
    }
    const { texto } = req.body;
    if (!texto || !texto.trim()) return res.status(400).json({ erro: 'Mensagem vazia' });
    if (texto.length > 2000) return res.status(400).json({ erro: 'Mensagem muito longa (máx 2000 caracteres)' });
    // Sanitização XSS (defesa em profundidade — front também escapa)
    const textoLimpo = sanitizeText(texto.trim());

    const { rows: cand } = await pool.query(`
      SELECT c.id, c.candidato_id, cd.email, cd.nome as cand_nome, v.titulo, v.empresa
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1`, [cid]);
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const c = cand[0];
    if (req.user.tipo === 'candidato') {
      if (c.email.toLowerCase() !== (req.user.email || '').toLowerCase()) {
        return res.status(403).json({ erro: 'Sem permissão' });
      }
    } else if (req.user.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    const autorTipo = req.user.tipo === 'admin' ? 'admin' : 'candidato';
    const autorNome = req.user.tipo === 'admin' ? (req.user.nome || 'Recrutador') : c.cand_nome;

    const { rows: msg } = await pool.query(
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [cid, autorTipo, autorNome, textoLimpo, 'chat']
    );

    // Notifica o outro lado por e-mail (em background)
    setImmediate(() => {
      try {
        const safe = texto.replace(/</g,'&lt;').replace(/>/g,'&gt;');
        if (autorTipo === 'candidato') {
          enviarEmailBg(enviarEmail, ADMIN_NOTIF_EMAIL,
            `💬 Nova mensagem de ${autorNome}`,
            `<p><b>${autorNome}</b> enviou uma mensagem sobre a vaga <b>${c.titulo}</b>:</p>
             <blockquote style="border-left:3px solid #d4a017;padding:8px 12px;background:#f8f8f8;">${safe}</blockquote>
             <p><a href="https://vagasio.com.br/admin/analisar.html?id=${cid}">Responder no painel →</a></p>`
          );
        } else {
          enviarEmailBg(enviarEmail, c.email,
            `💬 Nova mensagem sobre sua candidatura - ${c.titulo}`,
            `<p>Olá <b>${c.cand_nome}</b>,</p>
             <p><b>${autorNome}</b> enviou uma mensagem sobre sua candidatura na vaga <b>${c.titulo}</b>:</p>
             <blockquote style="border-left:3px solid #d4a017;padding:8px 12px;background:#f8f8f8;">${safe}</blockquote>
             <p><a href="https://vagasio.com.br/candidato/entrevistas.html">Responder no portal →</a></p>`
          );
        }
      } catch (e) { console.error('[CHAT EMAIL]', e.message); }
    });

    res.json({ ok: true, mensagem: msg[0] });
  } catch (e) {
    console.error('[CHAT ENVIAR]', e);
    return erroInterno(req, res, e, 'api-chat-cid-upload');
  }
});

// Upload de arquivo pra chat (POST /api/chat/:cid/upload)
// Body JSON: { texto?: string, arquivo: { nome, mime, base64 } }
app.post('/api/chat/:candidatura_id/upload', authCandidatoOrAdminStrict, rateLimitByIp('upload'), async (req, res) => {
  try {
    const cid = parseInt(req.params.candidatura_id);
    const { texto, arquivo } = req.body;
    if (!arquivo || !arquivo.nome || !arquivo.mime || !arquivo.base64) {
      return res.status(400).json({ erro: 'Arquivo inválido' });
    }
    // Valida tamanho (base64 fica ~33% maior; 8MB base64 = ~6MB real)
    if (arquivo.base64.length > 8 * 1024 * 1024) {
      return res.status(413).json({ erro: 'Arquivo muito grande. Limite: 6MB' });
    }
    // Valida tipo (whitelist básico)
    const mimePermitidos = [
      'image/jpeg','image/jpg','image/png','image/gif','image/webp',
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/plain','text/csv'
    ];
    if (!mimePermitidos.includes(arquivo.mime)) {
      return res.status(400).json({ erro: 'Tipo de arquivo não permitido' });
    }
    // Calcula tamanho real (base64 -> bytes)
    const tamanhoBytes = Math.floor(arquivo.base64.length * 3 / 4);
    if (tamanhoBytes > 6 * 1024 * 1024) {
      return res.status(413).json({ erro: 'Arquivo muito grande. Limite: 6MB' });
    }
    // Verifica permissão (igual endpoint de mensagens)
    const { rows: cand } = await pool.query(`
      SELECT c.id, c.candidato_id, cd.email, cd.nome as cand_nome, v.titulo
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1`, [cid]);
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    const c = cand[0];
    if (req.user.tipo === 'candidato') {
      if (c.email.toLowerCase() !== (req.user.email || '').toLowerCase()) {
        return res.status(403).json({ erro: 'Sem permissão' });
      }
    } else if (req.user.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    const autorTipo = req.user.tipo === 'admin' ? 'admin' : 'candidato';
    const autorNome = req.user.tipo === 'admin' ? (req.user.nome || 'Recrutador') : c.cand_nome;
    // Sanitiza nome do arquivo (impede injection no log + no texto)
    const arquivoNomeSanitizado = sanitizeFilename(arquivo.nome || 'arquivo');
    // Texto da mensagem (se vazio, usa padrão)
    const textoFinal = sanitizeText((texto && texto.trim()) || `📎 ${arquivoNomeSanitizado}`);
    // 1) Insere a mensagem
    const { rows: msgRows } = await pool.query(
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [cid, autorTipo, autorNome, textoFinal, 'chat']
    );
    const msg = msgRows[0];
    // 2) Insere o arquivo vinculado
    const { rows: arqRows } = await pool.query(
      'INSERT INTO chat_arquivos (mensagem_id, candidatura_id, nome_original, mime_type, tamanho_bytes, base64_data) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, nome_original, mime_type, tamanho_bytes',
      [msg.id, cid, arquivoNomeSanitizado, arquivo.mime, tamanhoBytes, arquivo.base64]
    );
    res.json({ ok: true, mensagem: msg, arquivo: arqRows[0] });
  } catch (e) {
    console.error('[CHAT UPLOAD]', e);
    return erroInterno(req, res, e, 'api-chat-arquivo-id');
  }
});

// Download de arquivo do chat
app.get('/api/chat/arquivo/:id', authCandidatoOrAdminStrict, rateLimitByIp('chat-download'), async (req, res) => {
  // FIX Etapa 2 (2026-07-27): whitelist + verificação de tamanho ANTES de carregar base64.
  // Atacante podia tentar baixar arquivo de outro candidato via ID guessing.
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ erro: 'ID inválido' });
    // Whitelist: nunca trazer base64_data no SELECT inicial (seria lido só se autorizado)
    const { rows } = await pool.query(
      `SELECT ca.id, ca.mensagem_id, ca.candidatura_id, ca.nome_original, ca.mime_type,
              ca.tamanho_bytes, ca.criado_em, c.candidato_id, cd.email
       FROM chat_arquivos ca
       JOIN candidaturas c ON c.id = ca.candidatura_id
       JOIN candidatos cd ON cd.id = c.candidato_id
       WHERE ca.id = $1`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    const arq = rows[0];
    // Verifica permissão ANTES de gastar memória com o base64
    if (req.user.tipo === 'candidato') {
      if ((arq.email || '').toLowerCase() !== (req.user.email || '').toLowerCase()) {
        await audit(req, 'security.idor.attempt', { resource_type: 'chat_arquivo', resource_id: id, metadata: { blocked: true } });
        return res.status(403).json({ erro: 'Sem permissão' });
      }
    } else if (req.user.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    // Bloqueia arquivos muito grandes (>10MB) - mitigação de DoS via download
    if (arq.tamanho_bytes > 10 * 1024 * 1024) {
      return res.status(413).json({ erro: 'Arquivo excede o limite de 10MB para download via chat' });
    }
    // Agora sim, segunda query buscando base64 (só passou nos gates)
    const { rows: dataRows } = await pool.query(
      'SELECT base64_data FROM chat_arquivos WHERE id = $1',
      [id]
    );
    if (dataRows.length === 0) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    const buffer = Buffer.from(dataRows[0].base64_data, 'base64');
    res.setHeader('Content-Type', arq.mime_type);
    const nomeSeguro = escapeContentDispositionFilename(arq.nome_original || 'arquivo');
    res.setHeader('Content-Disposition', `inline; filename="${nomeSeguro}"`);
    res.setHeader('Content-Length', arq.tamanho_bytes);
    res.send(buffer);
  } catch (e) {
    console.error('[CHAT ARQUIVO]', e);
    res.status(500).json({ erro: 'Erro ao buscar arquivo' });
  }
});

// Lista arquivos de uma mensagem
app.get('/api/chat/mensagem/:id/arquivos', authCandidatoOrAdminStrict, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { rows } = await pool.query(
      'SELECT id, nome_original, mime_type, tamanho_bytes FROM chat_arquivos WHERE mensagem_id = $1',
      [id]
    );
    res.json({ arquivos: rows });
  } catch (e) {
    return erroInterno(req, res, e, 'api-chat-mensagem-:id-arquivos');
  }
});

// Lista TODAS as conversas (admin) agrupadas por candidatura
// Regra (22/07/2026): chat só aparece se candidato passou da INSCRIÇÃO (etapa_atual >= 2)
// e se a vaga não foi fechada/encerrada
app.get('/api/admin/conversas', authAdmin, async (req, res) => {
  try {
    // Filtro opcional: ?candidatura_id=X → só 1 conversa
    // Sem filtro: lista conversas ATIVAS (candidatura não encerrada E etapa >= 2 E vaga ativa)
    const cid = parseInt(req.query.candidatura_id);
    let where, params = [];
    if (cid) {
      // Quando filtra por id específico, ignora o status (pra admin ver histórico ao reprovar)
      where = 'WHERE c.id = $1';
      params = [cid];
    } else {
      // Lista geral: só candidaturas ativas e pós-inscrição, com vaga ativa
      where = `WHERE EXISTS (SELECT 1 FROM mensagens_processo WHERE candidatura_id = c.id)
                AND c.etapa_atual >= 2
                AND c.status NOT IN ('rejeitado','reprovado','cancelado','contratado')
                AND COALESCE(v.status, 'publicada') NOT IN ('fechada','encerrada','cancelada')`;
    }
    const { rows } = await pool.query(`
      SELECT c.id as candidatura_id, v.titulo as vaga_titulo, cd.nome as candidato_nome,
             cd.email as candidato_email, c.etapa_atual, c.status,
             (SELECT COUNT(*) FROM mensagens_processo WHERE candidatura_id = c.id AND autor_tipo = 'candidato' AND criado_em > COALESCE((SELECT MAX(criado_em) FROM mensagens_processo WHERE candidatura_id = c.id AND autor_tipo = 'admin'), '1970-01-01')) as nao_lidas_admin,
             (SELECT MAX(criado_em) FROM mensagens_processo WHERE candidatura_id = c.id) as ultima_msg_em,
             (SELECT texto FROM mensagens_processo WHERE candidatura_id = c.id ORDER BY criado_em DESC LIMIT 1) as ultima_msg
      FROM candidaturas c
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      ${where}
      ORDER BY ultima_msg_em DESC
    `, params);
    res.json({ conversas: rows });
  } catch (e) {
    console.error('[CONVERSAS LISTAR]', e);
    return erroInterno(req, res, e, 'api-admin-candidatura-id-enviar-proposta');
  }
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
      return erroInterno(req, res, e, 'upload-pdf-proposta');
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
  await audit(req, 'candidatura.proposta.aceitar', { resource_type: 'candidatura', resource_id: req.params.candidaturaId });
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
// Candidato desiste da vaga a qualquer momento
app.post('/api/candidatura/:id/desistir', authCandidato, async (req, res) => {
  await audit(req, 'candidatura.desistir', { resource_type: 'candidatura', resource_id: req.params.id });
  const { motivo } = req.body;
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, cd.email as cand_email, cd.nome_completo as cand_nome
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];

  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });
  if (['cancelado','rejeitado','contratado'].includes(cand.status)) {
    return res.status(400).json({ erro: `Não é possível desistir: candidatura já está como '${cand.status}'` });
  }

  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: cand.etapa_atual || 0,
    status: 'cancelado',
    acao: 'desistir',
    mensagem: 'Candidato desistiu da vaga' + (motivo ? `: ${motivo}` : ''),
    data: new Date().toISOString(),
    por: cand.cand_email
  });

  await pool.query(
    `UPDATE candidaturas
     SET status = 'cancelado',
         historico = $1
     WHERE id = $2`,
    [JSON.stringify(historico), req.params.id]
  );

  res.json({ ok: true, mensagem: 'Você desistiu da vaga com sucesso.' });
});

app.post('/api/candidato/recusar-proposta/:candidaturaId', authCandidato, async (req, res) => {
  await audit(req, 'candidatura.proposta.recusar', { resource_type: 'candidatura', resource_id: req.params.candidaturaId });
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
    await audit(req, 'admin.recrutador.created', { resource_type: 'recrutador', resource_id: rows[0].id, metadata: { email: email.toLowerCase() } });
    res.json({ ok: true, recrutador: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'E-mail já cadastrado' });
    res.status(500).json({ erro: 'Erro ao criar recrutador' });
  }
});

app.get('/api/admin/recrutadores', authAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, nome, email, ativo, role, primeiro_acesso, criado_em FROM recrutadores ORDER BY criado_em DESC');
  res.json({ recrutadores: rows });
});

// Atualizar recrutador (ativar/desativar, resetar senha)
app.put('/api/admin/recrutadores/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  const { nome, ativo, senha } = req.body;
  try {
    let query = 'UPDATE recrutadores SET ';
    const sets = [];
    const params = [];
    let i = 1;
    if (nome !== undefined) { sets.push(`nome = $${i++}`); params.push(nome); }
    if (ativo !== undefined) { sets.push(`ativo = $${i++}`); params.push(ativo); }
    if (senha) {
      const hash = await bcrypt.hash(senha, 10);
      sets.push(`senha_hash = $${i++}`); params.push(hash);
      sets.push(`primeiro_acesso = true`);
    }
    if (sets.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    query += sets.join(', ') + ` WHERE id = $${i} RETURNING id, nome, email, ativo, role`;
    params.push(id);
    const { rows } = await pool.query(query, params);
    if (rows.length === 0) return res.status(404).json({ erro: 'Recrutador não encontrado' });
    res.json({ ok: true, recrutador: rows[0] });
  } catch (e) {
    console.error('[atualizar recrutador]', e);
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});

app.delete('/api/admin/recrutadores/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('DELETE FROM recrutadores WHERE id = $1 RETURNING id', [id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Recrutador não encontrado' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao deletar' });
  }
});

// ========== LOGIN RECRUTADOR ==========
app.post('/api/auth/login-recrutador', rateLimitLogin, async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });
  try {
    // 🔍 Debug: loga a query exata pra investigar erro 500
    console.log('[login-recrutador] tentando:', email);
    const result = await pool.query(
      'SELECT id, nome, email, senha_hash, ativo, role, primeiro_acesso FROM recrutadores WHERE email = $1',
      [email.toLowerCase()]
    ).catch((err) => {
      console.error('[login-recrutador] ERRO na query:', err.message, err.code, err.detail);
      throw err;
    });
    const rows = result.rows;
    console.log('[login-recrutador] rows:', rows.length);
    if (rows.length === 0) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'recrutador', metadata: { email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
    }
    const r = rows[0];
    if (!r.ativo) {
      await audit(req, 'login.failure', { resource_type: 'recrutador', metadata: { email: email.toLowerCase(), motivo: 'conta_desativada' } });
      return res.status(403).json({ erro: 'Conta desativada. Fale com o admin.' });
    }
    const ok = await bcrypt.compare(senha, r.senha_hash);
    if (!ok) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'recrutador', metadata: { email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
    }
    rateLimitClear(req);
    // FIX Etapa 2: access (30m) + refresh (7d, hash no DB)
    const accessToken = criarAccessToken({
      id: r.id, email: r.email, nome: r.nome, tipo: 'recrutador', role: r.role
    });
    const refresh = criarRefreshToken();
    await persistirRefresh('recrutador', r.id, r.email, refresh, req, { user_role: r.role || 'recrutador' });
    await audit(req, 'login.success', { resource_type: 'recrutador', resource_id: r.id, user_email: r.email });
    res.json({
      ok: true,
      token: accessToken,
      refreshToken: refresh,
      usuario: { id: r.id, nome: r.nome, email: r.email, tipo: 'recrutador', role: r.role, primeiro_acesso: r.primeiro_acesso }
    });
  } catch (e) {
    console.error('[login recrutador]', e);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// Trocar própria senha (recrutador)
app.post('/api/auth/trocar-senha-recrutador', authAdmin, async (req, res) => {
  const { senha_atual, senha_nova } = req.body;
  if (!senha_atual || !senha_nova) return res.status(400).json({ erro: 'Informe senha atual e nova' });
  try {
    const { rows } = await pool.query('SELECT senha_hash FROM recrutadores WHERE id = $1', [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado' });
    const ok = await bcrypt.compare(senha_atual, rows[0].senha_hash);
    if (!ok) {
      await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'senha_atual_incorreta' } });
      return res.status(401).json({ erro: 'Senha atual incorreta' });
    }
    const hash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE recrutadores SET senha_hash = $1, primeiro_acesso = false WHERE id = $2', [hash, req.user.id]);
    await audit(req, 'password.changed', { result: 'success', resource_type: 'recrutador', resource_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao trocar senha' });
  }
});

// ========== EMPRESAS (clientes) ==========

// Listar recrutadores + empresas em um único endpoint (pra página /admin/equipe)
app.get('/api/admin/equipe', authAdmin, async (req, res) => {
  try {
    const recrutadores = await pool.query(`
      SELECT id, nome, email, ativo, criado_em
      FROM recrutadores
      ORDER BY criado_em DESC
    `);
    const empresas = await pool.query(`
      SELECT e.id, e.nome, e.email_principal as email, e.cnpj, e.ativo, e.criado_em,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE empresa_id = e.id) as qtd_vagas,
        (SELECT COUNT(*) FROM empresa_usuarios WHERE empresa_id = e.id) as qtd_usuarios
      FROM empresas e
      ORDER BY e.criado_em DESC
    `);
    const usuarios = await pool.query(`
      SELECT id, empresa_id, nome, email, cargo, ativo, primeiro_acesso, criado_em
      FROM empresa_usuarios
      ORDER BY criado_em DESC
    `);
    res.json({
      recrutadores: recrutadores.rows,
      empresas: empresas.rows,
      empresaUsuarios: usuarios.rows
    });
  } catch (err) {
    console.error('[/api/admin/equipe]', err);
    res.status(500).json({ erro: 'Erro ao carregar equipe' });
  }
});

// Listar empresas + quais vagas cada uma tem acesso
app.get('/api/admin/empresas', authAdmin, async (req, res) => {
  try {
    const empresas = await pool.query(`
      SELECT e.id, e.nome, e.cnpj, e.email_principal, e.telefone, e.ativo, e.criado_em,
        (SELECT COUNT(*) FROM empresa_usuarios WHERE empresa_id = e.id) as qtd_usuarios,
        (SELECT COUNT(*) FROM empresa_vaga_acesso WHERE empresa_id = e.id) as qtd_vagas
      FROM empresas e
      ORDER BY e.criado_em DESC
    `);
    const usuarios = await pool.query(`
      SELECT id, empresa_id, nome, email, cargo, ativo, primeiro_acesso, criado_em
      FROM empresa_usuarios ORDER BY criado_em DESC
    `);
    res.json({ empresas: empresas.rows, usuarios: usuarios.rows });
  } catch (e) {
    console.error('[listar empresas]', e);
    res.status(500).json({ erro: 'Erro ao listar empresas' });
  }
});

// Criar empresa
app.post('/api/admin/empresas', authAdminOnly, async (req, res) => {
  const { nome, cnpj, email_principal, telefone, usuario } = req.body;
  if (!nome) return res.status(400).json({ erro: 'Nome obrigatório' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO empresas (nome, cnpj, email_principal, telefone, criado_por)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nome, cnpj, email_principal, telefone, req.user.id]
    );
    const empresa = rows[0];
    let usuarioCriado = null;
    // Se veio bloco 'usuario' (opcional), cria o usuário principal da empresa
    if (usuario && usuario.nome && usuario.email && usuario.senha) {
      try {
        const hash = await bcrypt.hash(usuario.senha, 10);
        const ur = await pool.query(
          `INSERT INTO empresa_usuarios (empresa_id, nome, email, senha_hash, cargo, criado_por, role)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, nome, email, cargo, role, ativo`,
          [empresa.id, usuario.nome, usuario.email.toLowerCase(), hash, usuario.cargo || 'Recrutador', req.user.id, usuario.role || 'recrutador']
        );
        usuarioCriado = ur.rows[0];
      } catch (e) {
        if (e.code === '23505') return res.status(400).json({ erro: 'E-mail do usuário já cadastrado' });
        throw e;
      }
    }
    res.json({ ok: true, empresa, usuario: usuarioCriado });
    await audit(req, 'admin.empresa.created', { resource_type: 'empresa', resource_id: empresa.id, metadata: { nome: empresa.nome, cnpj: cnpj || null, usuario_criado: !!usuarioCriado } });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'E-mail já cadastrado' });
    console.error('[criar empresa]', e);
    res.status(500).json({ erro: 'Erro ao criar empresa' });
  }
});

// Atualizar empresa
app.put('/api/admin/empresas/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  const { nome, cnpj, email_principal, telefone, ativo } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE empresas SET
        nome = COALESCE($1, nome),
        cnpj = COALESCE($2, cnpj),
        email_principal = COALESCE($3, email_principal),
        telefone = COALESCE($4, telefone),
        ativo = COALESCE($5, ativo)
       WHERE id = $6 RETURNING *`,
      [nome, cnpj, email_principal, telefone, ativo, id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
    res.json({ ok: true, empresa: rows[0] });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});

// Excluir empresa (e seus vínculos)
app.delete('/api/admin/empresas/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM empresa_vaga_acesso WHERE empresa_id = $1', [id]);
    await pool.query('DELETE FROM empresa_usuarios WHERE empresa_id = $1', [id]);
    const { rows } = await pool.query('DELETE FROM empresas WHERE id = $1 RETURNING id', [id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
    res.json({ ok: true });
  } catch (e) {
    console.error('[excluir empresa]', e);
    res.status(500).json({ erro: 'Erro ao excluir' });
  }
});

// ========== USUÁRIOS DA EMPRESA ==========
app.post('/api/admin/empresas/:id/usuarios', authAdminOnly, async (req, res) => {
  const { id: empresa_id } = req.params;
  const { nome, email, senha, cargo } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Nome, e-mail e senha obrigatórios' });
  try {
    // Verifica se a empresa existe
    const emp = await pool.query('SELECT id FROM empresas WHERE id = $1', [empresa_id]);
    if (emp.rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
    const hash = await bcrypt.hash(senha, 10);
    const { rows } = await pool.query(
      `INSERT INTO empresa_usuarios (empresa_id, nome, email, senha_hash, cargo, criado_por)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, nome, email, cargo, ativo`,
      [empresa_id, nome, email.toLowerCase(), hash, cargo, req.user.id]
    );
    res.json({ ok: true, usuario: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ erro: 'E-mail já cadastrado' });
    console.error('[criar usuario empresa]', e);
    res.status(500).json({ erro: 'Erro ao criar usuário' });
  }
});

app.put('/api/admin/empresa-usuarios/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  const { nome, cargo, ativo, senha } = req.body;
  try {
    let q = 'UPDATE empresa_usuarios SET ';
    const sets = [], params = [];
    let i = 1;
    if (nome !== undefined) { sets.push(`nome = $${i++}`); params.push(nome); }
    if (cargo !== undefined) { sets.push(`cargo = $${i++}`); params.push(cargo); }
    if (ativo !== undefined) { sets.push(`ativo = $${i++}`); params.push(ativo); }
    if (senha) {
      const hash = await bcrypt.hash(senha, 10);
      sets.push(`senha_hash = $${i++}`); params.push(hash);
      sets.push(`primeiro_acesso = true`);
    }
    if (sets.length === 0) return res.status(400).json({ erro: 'Nada para atualizar' });
    q += sets.join(', ') + ` WHERE id = $${i} RETURNING id, nome, email, cargo, ativo`;
    params.push(id);
    const { rows } = await pool.query(q, params);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado' });
    res.json({ ok: true, usuario: rows[0] });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});

app.delete('/api/admin/empresa-usuarios/:id', authAdminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query('DELETE FROM empresa_usuarios WHERE id = $1 RETURNING id', [id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao deletar' });
  }
});

// ========== LIBERAR VAGAS PARA EMPRESA ==========
app.post('/api/admin/empresa-vaga', authAdminOnly, async (req, res) => {
  const { empresa_id, vaga_id } = req.body;
  if (!empresa_id || !vaga_id) return res.status(400).json({ erro: 'empresa_id e vaga_id obrigatórios' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO empresa_vaga_acesso (empresa_id, vaga_id, concedido_por, tipo)
       VALUES ($1,$2,$3,'propria')
       ON CONFLICT (empresa_id, vaga_id) DO NOTHING
       RETURNING *`,
      [empresa_id, vaga_id, req.user.id]
    );
    res.json({ ok: true, acesso: rows[0] || 'já existia' });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao liberar vaga' });
  }
});

app.delete('/api/admin/empresa-vaga', authAdminOnly, async (req, res) => {
  const { empresa_id, vaga_id } = req.body;
  if (!empresa_id || !vaga_id) return res.status(400).json({ erro: 'empresa_id e vaga_id obrigatórios' });
  try {
    await pool.query('DELETE FROM empresa_vaga_acesso WHERE empresa_id = $1 AND vaga_id = $2', [empresa_id, vaga_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao remover acesso' });
  }
});

app.get('/api/admin/empresa-vaga/:empresa_id', authAdmin, async (req, res) => {
  const { empresa_id } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.status, eva.concedido_em
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      WHERE eva.empresa_id = $1
      ORDER BY v.titulo
    `, [empresa_id]);
    res.json({ vagas: rows });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao listar vagas da empresa' });
  }
});

// ========== CADASTRO DE EMPRESA (Caminho A — free beta) ==========
// ETAPA 3 (2026-07-27): signup B2B.
// Recebe dados da empresa + admin master, cria as duas entidades em transação,
// e já autentica (access + refresh) pra redirecionar direto pro painel.
//
// Validações:
// - Empresa: nome (obrigatório), cnpj (opcional mas validado se preenchido)
// - Admin master: nome, email (único), senha (≥8 chars)
// - Slug da empresa: gerado a partir do nome (lowercase, sem acentos)
//   pra futura URL amigável (empresa.vagasio.com.br/<slug>).
//
// NOTA: não usa transação explícita pq o pg.Pool faz auto-commit por statement.
// Se empresa_insert falhar, empresa_usuario_insert NÃO roda (erro retorna antes).
app.post('/api/empresa/cadastro', rateLimitByIp('cadastro-empresa'), async (req, res) => {
  const {
    empresa_nome,
    cnpj,
    telefone,
    email_principal,
    plano,                  // 'essencial' | 'profissional' | 'enterprise' (cosmético nesta fase)
    admin_nome,
    admin_email,
    admin_senha,
    admin_cargo
  } = req.body || {};

  // Validação básica
  if (!empresa_nome || empresa_nome.trim().length < 2) {
    return res.status(400).json({ erro: 'Nome da empresa é obrigatório (mínimo 2 caracteres)' });
  }
  if (!admin_nome || !admin_email || !admin_senha) {
    return res.status(400).json({ erro: 'Nome, e-mail e senha do administrador são obrigatórios' });
  }
  if (admin_senha.length < 8) {
    return res.status(400).json({ erro: 'A senha deve ter no mínimo 8 caracteres' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(admin_email)) {
    return res.status(400).json({ erro: 'E-mail do administrador inválido' });
  }
  // CNPJ: se preenchido, valida formato básico (14 dígitos)
  if (cnpj && cnpj.replace(/\D/g, '').length !== 14) {
    return res.status(400).json({ erro: 'CNPJ deve ter 14 dígitos (com ou sem pontuação)' });
  }

  const emailLower = admin_email.toLowerCase().trim();
  const cnpjClean = cnpj ? cnpj.replace(/\D/g, '') : null;

  // Gera slug a partir do nome (lowercase, sem acentos, sem caracteres especiais).
  // Se já existir, anexa sufixo numérico.
  function slugify(txt) {
    return txt
      .toString().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').substring(0, 60) || 'empresa';
  }
  let slugBase = slugify(empresa_nome);
  let slugFinal = slugBase;
  let slugSufixo = 1;
  while (true) {
    const dup = await pool.query('SELECT id FROM empresas WHERE slug = $1', [slugFinal]);
    if (dup.rowCount === 0) break;
    slugSufixo++;
    slugFinal = `${slugBase}-${slugSufixo}`;
    if (slugSufixo > 99) { slugFinal = `${slugBase}-${Date.now()}`; break; }
  }

  try {
    // 1. Verifica se já existe usuário com esse email
    const existe = await pool.query('SELECT id FROM empresa_usuarios WHERE email = $1', [emailLower]);
    if (existe.rowCount > 0) {
      return res.status(409).json({ erro: 'Já existe uma conta com esse e-mail. Faça login.' });
    }

    // 2. Verifica se já existe empresa com mesmo CNPJ (se informado)
    if (cnpjClean) {
      const existeCnpj = await pool.query('SELECT id FROM empresas WHERE cnpj = $1', [cnpjClean]);
      if (existeCnpj.rowCount > 0) {
        return res.status(409).json({ erro: 'Já existe uma empresa cadastrada com esse CNPJ' });
      }
    }

    // 3. Cria a empresa
    const empRes = await pool.query(`
      INSERT INTO empresas (nome, cnpj, email_principal, telefone, ativo, plano, slug)
      VALUES ($1, $2, $3, $4, true, $5, $6)
      RETURNING id, nome, cnpj, email_principal, plano, slug, criado_em
    `, [empresa_nome.trim(), cnpjClean, email_principal?.toLowerCase() || null, telefone || null, plano || 'essencial', slugFinal]);
    const empresa = empRes.rows[0];

    // 4. Cria o admin master (empresa_usuarios) — primeiro usuário = admin_empresa
    const senhaHash = await bcrypt.hash(admin_senha, 10);
    const userRes = await pool.query(`
      INSERT INTO empresa_usuarios (empresa_id, nome, email, senha_hash, cargo, ativo, primeiro_acesso, role)
      VALUES ($1, $2, $3, $4, $5, true, false, 'admin_empresa')
      RETURNING id, nome, email, cargo, role, empresa_id
    `, [empresa.id, admin_nome.trim(), emailLower, senhaHash, admin_cargo || 'Administrador']);
    const adminUser = userRes.rows[0];

    // 5. Gera tokens (já loga o admin master)
    const accessToken = criarAccessToken({
      id: adminUser.id, email: adminUser.email, nome: adminUser.nome, tipo: 'empresa',
      empresa_id: empresa.id, empresa_nome: empresa.nome, role: adminUser.role
    });
    const refresh = criarRefreshToken();
    await persistirRefresh('empresa', adminUser.id, adminUser.email, refresh, req, {
      user_role: adminUser.role, // 'admin_empresa' — RBAC canônico
      user_empresa_id: empresa.id
    });

    // 6. Audit log
    await audit(req, 'empresa.created', {
      resource_type: 'empresa',
      resource_id: empresa.id,
      user_email: adminUser.email,
      metadata: { plano: empresa.plano, cnpj: cnpjClean, admin_user_id: adminUser.id }
    });

    res.status(201).json({
      ok: true,
      msg: 'Empresa cadastrada com sucesso! Você já está logado.',
      token: accessToken,
      refreshToken: refresh,
      usuario: {
        id: adminUser.id,
        nome: adminUser.nome,
        email: adminUser.email,
        tipo: 'empresa',
        cargo: adminUser.cargo,
        empresa_id: empresa.id,
        empresa_nome: empresa.nome,
        primeiro_acesso: false
      },
      empresa: {
        id: empresa.id,
        nome: empresa.nome,
        cnpj: empresa.cnpj,
        email_principal: empresa.email_principal,
        plano: empresa.plano,
        slug: empresa.slug,
        criado_em: empresa.criado_em
      }
    });
  } catch (e) {
    return erroInterno(req, res, e, 'api-empresa-cadastro');
  }
});

// ========== LOGIN EMPRESA ==========
app.post('/api/auth/login-empresa', rateLimitLogin, async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });
  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.nome, u.email, u.senha_hash, u.ativo, u.primeiro_acesso, u.cargo, u.role,
        u.empresa_id, e.nome as empresa_nome, e.ativo as empresa_ativa
      FROM empresa_usuarios u
      JOIN empresas e ON e.id = u.empresa_id
      WHERE u.email = $1
    `, [email.toLowerCase()]);
    if (rows.length === 0) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'empresa', metadata: { email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
    }
    const u = rows[0];
    if (!u.ativo || !u.empresa_ativa) {
      await audit(req, 'login.failure', { resource_type: 'empresa', metadata: { email: email.toLowerCase(), motivo: 'conta_desativada' } });
      return res.status(403).json({ erro: 'Conta ou empresa desativada' });
    }
    const ok = await bcrypt.compare(senha, u.senha_hash);
    if (!ok) {
      rateLimitRegisterFail(req);
      await audit(req, 'login.failure', { resource_type: 'empresa', metadata: { email: email.toLowerCase() } });
      return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
    }
    rateLimitClear(req);
    // FIX Etapa 2: access (30m) + refresh (7d, hash no DB)
    const accessToken = criarAccessToken({
      id: u.id, email: u.email, nome: u.nome, tipo: 'empresa',
      role: u.role || 'recrutador',
      empresa_id: u.empresa_id, empresa_nome: u.empresa_nome
    });
    const refresh = criarRefreshToken();
    await persistirRefresh('empresa', u.id, u.email, refresh, req, {
      user_role: u.role || 'recrutador',
      user_empresa_id: u.empresa_id
    });
    await audit(req, 'login.success', { resource_type: 'empresa', resource_id: u.id, user_email: u.email, metadata: { empresa_id: u.empresa_id } });
    res.json({
      ok: true,
      token: accessToken,
      refreshToken: refresh,
      usuario: {
        id: u.id, nome: u.nome, email: u.email, tipo: 'empresa',
        cargo: u.cargo, empresa_id: u.empresa_id, empresa_nome: u.empresa_nome,
        primeiro_acesso: u.primeiro_acesso
      }
    });
  } catch (e) {
    console.error('[login empresa]', e);
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// Trocar própria senha (empresa)
app.post('/api/auth/trocar-senha-empresa', requireEmpresaViewer, async (req, res) => {
  const { senha_atual, senha_nova } = req.body;
  if (!senha_atual || !senha_nova) return res.status(400).json({ erro: 'Informe senha atual e nova' });
  try {
    const { rows } = await pool.query('SELECT senha_hash FROM empresa_usuarios WHERE id = $1', [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado' });
    const ok = await bcrypt.compare(senha_atual, rows[0].senha_hash);
    if (!ok) {
      await audit(req, 'password.changed', { result: 'failure', metadata: { motivo: 'senha_atual_incorreta' } });
      return res.status(401).json({ erro: 'Senha atual incorreta' });
    }
    const hash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE empresa_usuarios SET senha_hash = $1, primeiro_acesso = false WHERE id = $2', [hash, req.user.id]);
    await audit(req, 'password.changed', { result: 'success', resource_type: 'empresa', resource_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao trocar senha' });
  }
});

// ========== ROTAS DA EMPRESA (acesso às vagas liberadas) ==========

// ========== EMPRESA CRIAR VAGA (Etapa 3 — SaaS B2B) ==========
// 2026-07-27: Empresas agora podem criar suas próprias vagas.
// Fluxo: cria a vaga + vincula automaticamente no empresa_vaga_acesso.
// A vaga começa com status='rascunho' e a empresa precisa publicar depois
// (futuro: publicar imediato pra planos pagos; moderação pra free beta).
app.post('/api/empresa/vagas', requireRecrutadorOuAdmin, async (req, res) => {
  try {
    const v = req.body || {};
    if (!v.titulo || String(v.titulo).trim().length < 2) {
      return res.status(400).json({ erro: 'Título é obrigatório (mínimo 2 caracteres)' });
    }
    const { empresa_id, empresa_nome } = req.user;

    // Etapas padrão (mesmas do admin). Empresa pode customizar enviando array.
    const etapas = (Array.isArray(v.etapas) && v.etapas.length > 0)
      ? v.etapas
      : [
          { nome: 'Inscrição' },
          { nome: 'Triagem curricular' },
          { nome: 'Entrevista RH' },
          { nome: 'Entrevista gestor' },
          { nome: 'Proposta' },
          { nome: 'Coleta de documentos' },
          { nome: 'Contratação' }
        ];

    // INSERT vaga (empresa = nome da empresa do usuário logado; empresa_id vem do JWT)
    const { rows: vagaRows } = await pool.query(
      `INSERT INTO vagas (
        titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area,
        salario_min, salario_max, descricao, requisitos, beneficios,
        etapas, status, criada_por
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      RETURNING *`,
      [
        v.titulo,
        empresa_nome,         // TEXT legado
        empresa_id,           // FK → empresas (Fase 5: portal público usa este FK)
        v.cidade || null,
        v.estado || null,
        v.tipo_contrato || null,
        v.nivel || null,
        v.area || null,
        v.salario_min || null,
        v.salario_max || null,
        v.descricao || null,
        v.requisitos || null,
        v.beneficios || null,
        JSON.stringify(etapas),
        'rascunho',           // empresa cria em rascunho; admin pode aprovar depois
        null                  // criada_por FK → admins(id). NULL pq é empresa (não admin).
      ]
    );
    const vaga = vagaRows[0];

    // Vincula automaticamente a vaga à empresa (pra ela ver no dashboard)
    // NOTA: concedido_por é FK pra admins(id). Como o usuário é empresa_usuarios (não admin),
    // passamos NULL pra evitar violação de FK. Auto-criação é da própria empresa.
    await pool.query(
      `INSERT INTO empresa_vaga_acesso (empresa_id, vaga_id, concedido_por, tipo)
       VALUES ($1, $2, NULL, 'propria')
       ON CONFLICT (empresa_id, vaga_id) DO NOTHING`,
      [empresa_id, vaga.id]
    );

    await audit(req, 'empresa.vaga.created', {
      resource_type: 'vaga',
      resource_id: vaga.id,
      metadata: { titulo: v.titulo, empresa_id }
    });

    res.status(201).json({ ok: true, vaga });
  } catch (e) {
    console.error('[EMPRESA CRIAR VAGA ERRO]', e.message, e.stack);
    res.status(500).json({ erro: 'Erro ao criar vaga: ' + e.message });
  }
});

// ========== EMPRESA LISTAR/EDITAR/PUBLICAR VAGA ==========

// Lista vagas da empresa (criadas por ela + liberadas pelo admin)
app.get('/api/empresa/vagas', requireEmpresaViewer, async (req, res) => {
  try {
    const { empresa_id } = req.user;
    const { rows } = await pool.query(`
      SELECT
        v.*,
        eva.concedido_em AS vinculado_em,
        CASE
          WHEN v.criada_por = $1 THEN 'criada'
          ELSE 'compartilhada'
        END AS origem
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      WHERE eva.empresa_id = $2
      ORDER BY eva.concedido_em DESC
    `, [req.user.id, empresa_id]);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[EMPRESA LISTAR VAGAS ERRO]', e.message);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

// Atualizar vaga (empresa só pode editar vagas criadas por ela)
app.put('/api/empresa/vagas/:id', requireRecrutadorOuAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { empresa_id } = req.user;
    // Garante que a vaga pertence à empresa (via empresa_vaga_acesso)
    const check = await pool.query(
      `SELECT 1 FROM empresa_vaga_acesso WHERE vaga_id = $1 AND empresa_id = $2`,
      [id, empresa_id]
    );
    if (check.rows.length === 0) {
      return res.status(403).json({ erro: 'Vaga não pertence à sua empresa' });
    }

    const v = req.body || {};
    const updates = [];
    const values = [];
    const push = (col, val) => { values.push(val); updates.push(`${col} = $${values.length}`); };
    if (v.titulo !== undefined) push('titulo', v.titulo);
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
    if (v.etapas !== undefined && Array.isArray(v.etapas)) push('etapas', JSON.stringify(v.etapas));
    if (updates.length === 0) return res.status(400).json({ erro: 'Nenhum campo para atualizar' });
    values.push(id);
    const { rows } = await pool.query(
      `UPDATE vagas SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values
    );
    await audit(req, 'empresa.vaga.updated', { resource_type: 'vaga', resource_id: id, metadata: { campos: Object.keys(v) } });
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[EMPRESA EDITAR VAGA ERRO]', e.message);
    res.status(500).json({ erro: 'Erro ao atualizar vaga' });
  }
});

// Publicar/despublicar vaga (empresa)
app.patch('/api/empresa/vagas/:id/status', requireRecrutadorOuAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!['publicada', 'pausada', 'rascunho', 'encerrada'].includes(status)) {
      return res.status(400).json({ erro: 'Status inválido. Use: publicada, pausada, rascunho ou encerrada' });
    }
    const check = await pool.query(`SELECT 1 FROM empresa_vaga_acesso WHERE vaga_id = $1 AND empresa_id = $2`, [id, req.user.empresa_id]);
    if (check.rows.length === 0) {
      return res.status(403).json({ erro: 'Vaga não pertence à sua empresa' });
    }
    const { rows } = await pool.query(
      `UPDATE vagas SET status = $1 WHERE id = $2 RETURNING *`,
      [status, id]
    );
    await audit(req, 'empresa.vaga.status_changed', { resource_type: 'vaga', resource_id: id, metadata: { status } });
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[EMPRESA STATUS VAGA ERRO]', e.message);
    res.status(500).json({ erro: 'Erro ao alterar status' });
  }
});

// Dashboard da empresa
app.get('/api/empresa/dashboard', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  try {
    const now = new Date();
    const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const fourteenDaysAgo = new Date(now - 14 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
    const sixtyDaysAgo = new Date(now - 60 * 24 * 60 * 60 * 1000);

    // TODAS as queries abaixo usam JOIN com empresa_vaga_acesso(eva.empresa_id = $1)
    // garantem que dados sejam SEMPRE filtrados pela empresa autenticada.

    // 1. Vagas liberadas para essa empresa
    const vagas = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id) as total_candidatos,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'em_andamento') as em_andamento,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'contratado') as contratados
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      WHERE eva.empresa_id = $1
      ORDER BY v.criada_em DESC
    `, [empresa_id]);

    // 2. KPIs principais (espelho do admin)
    const kpis = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
         WHERE eva.empresa_id = $1 AND v.status = 'publicada')::int as vagas_ativas,
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
         WHERE eva.empresa_id = $1 AND v.status = 'publicada' AND v.criada_em > $2)::int as vagas_ativas_novas_7d,
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
         WHERE eva.empresa_id = $1 AND v.status = 'publicada' AND v.criada_em > $3)::int as vagas_ativas_novas_14d,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1)::int as total_candidatos,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.criada_em > $2)::int as candidatos_novos_7d,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.criada_em > $3)::int as candidatos_novos_14d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.status NOT IN ('reprovado','contratado','rejeitado'))::int as processos_ativos,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.criada_em > $2)::int as processos_novos_7d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.criada_em > $3)::int as processos_novos_14d,
        (SELECT COUNT(*) FROM entrevistas e
         JOIN candidaturas cand ON cand.id = e.candidatura_id
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = cand.vaga_id
         WHERE eva.empresa_id = $1 AND e.data_hora >= NOW() AND e.status = 'agendada')::int as entrevistas_agendadas,
        (SELECT COUNT(*) FROM entrevistas e
         JOIN candidaturas cand ON cand.id = e.candidatura_id
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = cand.vaga_id
         WHERE eva.empresa_id = $1 AND e.data_hora >= NOW() AND e.data_hora < NOW() + INTERVAL '7 days' AND e.status = 'agendada')::int as entrevistas_proximos_7d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.status IN ('contratado') AND c.atualizada_em > $4)::int as contratacoes_30d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
         WHERE eva.empresa_id = $1 AND c.status IN ('contratado') AND c.atualizada_em > $5 AND c.atualizada_em <= $4)::int as contratacoes_30d_anterior
    `, [empresa_id, sevenDaysAgo, fourteenDaysAgo, thirtyDaysAgo, sixtyDaysAgo]);
    const k = kpis.rows[0];

    // 3. Candidatos por etapa (1..7) — espelho do admin
    const etapasQ = await pool.query(`
      SELECT c.etapa_atual, COUNT(*)::int as total
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE eva.empresa_id = $1 AND c.status NOT IN ('reprovado','rejeitado')
      GROUP BY c.etapa_atual
      ORDER BY c.etapa_atual
    `, [empresa_id]);
    const etapasMap = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0 };
    etapasQ.rows.forEach(r => { etapasMap[r.etapa_atual] = r.total; });

    // 4. Indicadores secundários (espelho do admin)
    // tempo_medio_contratacao: média de dias entre criada_em e atualizada_em nas contratadas da empresa
    const tempoMedioQ = await pool.query(`
      SELECT COALESCE(AVG(EXTRACT(DAY FROM (c.atualizada_em - c.criada_em))), 0)::int as dias
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE eva.empresa_id = $1 AND c.status IN ('contratado') AND c.atualizada_em IS NOT NULL
    `, [empresa_id]);
    const tempoMedio = tempoMedioQ.rows[0]?.dias || 0;

    // taxa_aprovacao_30d: % de vagas fechadas nos últimos 30d que geraram contratação
    // (vagas usa criada_em; atualizada_em não existe)
    const taxa30Q = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE c.status IN ('contratado'))::int as com_contratacao,
        COUNT(*)::int as total_fechadas
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
      LEFT JOIN candidaturas c ON c.vaga_id = v.id AND c.status IN ('contratado','rejeitado','reprovado')
      WHERE eva.empresa_id = $1 AND v.status = 'fechada' AND v.criada_em > $2
    `, [empresa_id, thirtyDaysAgo]);
    const total_fechadas_30d = taxa30Q.rows[0]?.total_fechadas || 0;
    const com_contratacao_30d = taxa30Q.rows[0]?.com_contratacao || 0;
    const taxa_fechadas_30d = total_fechadas_30d > 0
      ? Math.round((com_contratacao_30d / total_fechadas_30d) * 100)
      : 0;

    // vagas_encerradas (totais) — total no período
    const encerradasQ = await pool.query(`
      SELECT COUNT(*)::int as total
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
      WHERE eva.empresa_id = $1 AND v.status = 'fechada'
    `, [empresa_id]);
    const vagas_encerradas = encerradasQ.rows[0]?.total || 0;

    // taxa_desistencia: candidatos reprovados / total de candidaturas ativas
    const desistenciaQ = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE c.status IN ('reprovado','rejeitado'))::int as reprovados,
        COUNT(*)::int as total
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE eva.empresa_id = $1
    `, [empresa_id]);
    const reprovados = desistenciaQ.rows[0]?.reprovados || 0;
    const totalCand = desistenciaQ.rows[0]?.total || 0;
    const taxaDesistencia = totalCand > 0 ? Math.round((reprovados / totalCand) * 100) : 0;

    // 5. Próximas entrevistas
    const proximas = await pool.query(`
      SELECT e.id, e.candidatura_id, e.data_hora, e.etapa, e.local,
        cd.nome as candidato_nome, cd.email as candidato_email,
        v.titulo as vaga_titulo
      FROM entrevistas e
      JOIN candidaturas c ON c.id = e.candidatura_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE eva.empresa_id = $1 AND e.data_hora >= NOW() AND e.status = 'agendada'
      ORDER BY e.data_hora ASC
      LIMIT 10
    `, [empresa_id]);

    // 6. Atividades recentes (histórico das candidaturas da empresa)
    let atividadesRecentes = [];
    try {
      const hist = await pool.query(`
        SELECT c.id as candidatura_id, c.atualizada_em as quando,
          c.historico, v.titulo as vaga, v.id as vaga_id, cd.nome as candidato
        FROM candidaturas c
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE eva.empresa_id = $1
        ORDER BY c.atualizada_em DESC NULLS LAST
        LIMIT 8
      `, [empresa_id]);
      hist.rows.forEach(r => {
        if (Array.isArray(r.historico) && r.historico.length > 0) {
          const ultimo = r.historico[r.historico.length - 1];
          let texto = 'Atualização';
          if (ultimo.tipo === 'avancar') texto = 'Avançou de etapa';
          else if (ultimo.tipo === 'reprovar') texto = 'Reprovado';
          else if (ultimo.tipo === 'comentario') texto = 'Parecer adicionado';
          else if (ultimo.tipo === 'inscricao') texto = 'Inscrição realizada';
          atividadesRecentes.push({
            texto, candidato: r.candidato, vaga: r.vaga,
            vaga_id: r.vaga_id, candidatura_id: r.candidatura_id,
            quando: r.quando, por: ultimo.por || ''
          });
        }
      });
    } catch (_) {}

    // 7. Vagas mais procuradas (ranking por total de candidatos)
    const vagasMaisCandidatos = await pool.query(`
      SELECT v.id, v.titulo, COUNT(c.id)::int as total_candidatos
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE eva.empresa_id = $1
      GROUP BY v.id, v.titulo
      ORDER BY total_candidatos DESC
      LIMIT 5
    `, [empresa_id]);

    res.json({
      kpis: {
        // bloco "principal" (compatível com frontend atual)
        vagas_liberadas: vagas.rows.length,
        vagas_ativas: k.vagas_ativas,
        total_candidatos: k.total_candidatos,
        contratacoes: k.contratacoes_30d,
        em_etapa_gestor: etapasMap[4] || 0,
        entrevistas_agendadas: k.entrevistas_agendadas,
        // deltas (para o frontend espelhar setas do admin)
        processos_ativos: k.processos_ativos,
        entrevistas_proximos_7d: k.entrevistas_proximos_7d
      },
      kpis_deltas: {
        vagas_ativas: { atual: k.vagas_ativas, novos_7d: k.vagas_ativas_novas_7d, novos_14d: k.vagas_ativas_novas_14d },
        total_candidatos: { atual: k.total_candidatos, novos_7d: k.candidatos_novos_7d, novos_14d: k.candidatos_novos_14d },
        processos_ativos: { atual: k.processos_ativos, novos_7d: k.processos_novos_7d, novos_14d: k.processos_novos_14d },
        contratacoes: { atual_30d: k.contratacoes_30d, anterior_30d: k.contratacoes_30d_anterior }
      },
      kpis_secundarios: {
        tempo_medio_contratacao: tempoMedio,
        taxa_aprovacao_30d: taxa_fechadas_30d,
        taxa_aprovacao_30d_qtd: com_contratacao_30d,
        taxa_aprovacao_30d_total: total_fechadas_30d,
        taxa_desistencia: taxaDesistencia,
        vagas_encerradas: vagas_encerradas
      },
      etapas: etapasMap,
      etapas_labels: ['Inscrição', 'Triagem', 'RH', 'Gestor', 'Proposta', 'Coleta Docs', 'Contratação'],
      proximas: proximas.rows,
      atividades: atividadesRecentes,
      vagas_mais_candidatos: vagasMaisCandidatos.rows,
      vagas: vagas.rows,
      empresa: { id: empresa_id, nome: req.user?.nome || req.user?.email || 'Empresa' }
    });
  } catch (e) {
    console.error('[empresa dashboard]', e);
    res.status(500).json({ erro: 'Erro ao carregar dashboard' });
  }
});


// Detalhes de uma vaga liberada (info completa, não só KPIs)
app.get('/api/empresa/vagas/:vaga_id', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const { vaga_id } = req.params;
  try {
    const acesso = await pool.query(
      'SELECT 1 FROM empresa_vaga_acesso WHERE empresa_id = $1 AND vaga_id = $2',
      [empresa_id, vaga_id]
    );
    if (acesso.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });
    const { rows } = await pool.query(
      'SELECT id, titulo, empresa, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_em FROM vagas WHERE id = $1',
      [vaga_id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
    res.json({ vaga: rows[0] });
  } catch (e) {
    console.error('[empresa vaga detail]', e);
    res.status(500).json({ erro: 'Erro ao buscar vaga' });
  }
});

// Lista candidatos de UMA vaga liberada
app.get('/api/empresa/vagas/:vaga_id/candidatos', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const { vaga_id } = req.params;
  try {
    // Verifica se a empresa tem acesso a essa vaga
    const acesso = await pool.query(
      'SELECT 1 FROM empresa_vaga_acesso WHERE empresa_id = $1 AND vaga_id = $2',
      [empresa_id, vaga_id]
    );
    if (acesso.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });

    const { rows } = await pool.query(`
      SELECT c.id, c.status, c.etapa_atual, c.atualizada_em, c.criada_em,
        cd.id as candidato_id, cd.nome, cd.email, cd.celular, cd.foto_url,
        v.titulo as vaga_titulo, v.etapas
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.vaga_id = $1
      ORDER BY c.atualizada_em DESC
    `, [vaga_id]);
    res.json({ candidatos: rows });
  } catch (e) {
    console.error('[empresa listar candidatos]', e);
    res.status(500).json({ erro: 'Erro ao listar candidatos' });
  }
});

// Vagas com candidatos (espelho de /api/admin/vagas-com-candidaturas, filtrado por empresa)
// Lista TODAS as vagas liberadas da empresa (independente de ter candidato)
app.get('/api/empresa/vagas-todas', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
        COALESCE(c_agg.total, 0) as total_geral,
        COALESCE(c_agg.em_andamento, 0) as em_andamento,
        COALESCE(c_agg.contratados, 0) as contratados
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      LEFT JOIN (
        SELECT vaga_id,
          COUNT(*) as total,
          COUNT(*) FILTER (WHERE status = 'em_andamento') as em_andamento,
          COUNT(*) FILTER (WHERE status = 'contratado') as contratados
        FROM candidaturas GROUP BY vaga_id
      ) c_agg ON c_agg.vaga_id = v.id
      WHERE eva.empresa_id = $1
      ORDER BY v.criada_em DESC
    `, [empresa_id]);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[empresa vagas-todas]', e);
    res.status(500).json({ erro: 'Erro ao listar vagas' });
  }
});

app.get('/api/empresa/vagas-com-candidaturas', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  try {
    const { rows } = await pool.query(`
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
        COUNT(c.id) as total_geral,
        COUNT(c.id) FILTER (WHERE c.status = 'em_analise') as em_analise,
        COUNT(c.id) FILTER (WHERE c.status = 'em_andamento') as em_andamento,
        COUNT(c.id) FILTER (WHERE c.status = 'contratado') as contratados,
        COUNT(c.id) FILTER (WHERE c.status = 'rejeitado') as reprovados,
        COUNT(c.id) FILTER (WHERE c.status IN ('em_analise','em_andamento')) as total_ativas
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE eva.empresa_id = $1
      GROUP BY v.id
      HAVING COUNT(c.id) > 0
      ORDER BY v.criada_em DESC
    `, [empresa_id]);
    res.json({ vagas: rows });
  } catch (e) {
    console.error('[empresa vagas-com-candidatos]', e);
    res.status(500).json({ erro: 'Erro ao listar vagas com candidatos' });
  }
});

// Agenda da empresa (entrevistas marcadas nas vagas liberadas)
app.get('/api/empresa/agenda', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const { periodo } = req.query; // 'hoje' | 'proximos' | 'passados' | 'todos' | 'semana' | '7dias' | '30dias' | 'atrasadas' | 'realizadas' | 'canceladas'
  try {
    let whereExtra = `AND e.etapa = 4`; // Empresa só vê Entrevista com Gestor (etapa 4)
    const params = [empresa_id];
    const now = new Date();
    if (periodo === 'hoje') {
      const inicio = new Date(now); inicio.setHours(0,0,0,0);
      const fim = new Date(now); fim.setHours(23,59,59,999);
      whereExtra = `AND e.etapa = 4 AND e.data_hora BETWEEN $2 AND $3`;
      params.push(inicio.toISOString(), fim.toISOString());
    } else if (periodo === 'proximos') {
      whereExtra = `AND e.etapa = 4 AND e.data_hora >= NOW()`;
    } else if (periodo === 'passados') {
      whereExtra = `AND e.etapa = 4 AND e.data_hora < NOW() AND e.status NOT IN ('cancelada', 'realizada')`;
    } else if (periodo === 'semana') {
      const inicio = new Date(now); inicio.setHours(0,0,0,0);
      const fim = new Date(now); fim.setDate(fim.getDate() + 7);
      whereExtra = `AND e.etapa = 4 AND e.data_hora BETWEEN $2 AND $3`;
      params.push(inicio.toISOString(), fim.toISOString());
    } else if (periodo === '7dias') {
      const fim = new Date(now); fim.setDate(fim.getDate() + 7);
      whereExtra = `AND e.etapa = 4 AND e.data_hora BETWEEN NOW() AND $2`;
      params.push(fim.toISOString());
    } else if (periodo === '30dias') {
      const fim = new Date(now); fim.setDate(fim.getDate() + 30);
      whereExtra = `AND e.etapa = 4 AND e.data_hora BETWEEN NOW() AND $2`;
      params.push(fim.toISOString());
    } else if (periodo === 'atrasadas') {
      whereExtra = `AND e.etapa = 4 AND e.data_hora < NOW() AND e.status = 'agendada'`;
    } else if (periodo === 'realizadas') {
      whereExtra = `AND e.etapa = 4 AND e.status = 'realizada'`;
    } else if (periodo === 'canceladas') {
      whereExtra = `AND e.etapa = 4 AND e.status = 'cancelada'`;
    }
    const { rows } = await pool.query(`
      SELECT e.id, e.etapa, e.data_hora, e.duracao_minutos, e.local, e.link_reuniao, e.observacoes, e.status,
        c.id as candidatura_id, c.etapa_atual, c.status as cand_status,
        cd.id as candidato_id, cd.nome as candidato_nome, cd.email as candidato_email, cd.foto_url,
        v.id as vaga_id, v.titulo as vaga_titulo, v.empresa as vaga_empresa, v.etapas as vaga_etapas
      FROM entrevistas e
      JOIN candidaturas c ON c.id = e.candidatura_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.empresa_id = $1
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE eva.empresa_id = $1 ${whereExtra}
      ORDER BY e.data_hora ASC
    `, params);
    res.json({ entrevistas: rows });
  } catch (e) {
    console.error('[empresa agenda]', e);
    res.status(500).json({ erro: 'Erro ao carregar agenda' });
  }
});

// Chat Empresa ↔ RH (mensagens trocadas entre empresa e admin/recrutador)
app.get('/api/empresa/candidatura/:id/chat', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const { id } = req.params;
  try {
    // Verifica acesso
    const acc = await pool.query(`
      SELECT c.id FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE c.id = $1 AND eva.empresa_id = $2
    `, [id, empresa_id]);
    if (acc.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });

    // Chat EXCLUSIVO Empresa ↔ RH/Admin. Nunca trazer mensagens do candidato.
    const { rows } = await pool.query(`
      SELECT id, candidatura_id, remetente_tipo, remetente_nome, mensagem, criado_em
      FROM empresa_chat
      WHERE candidatura_id = $1
        AND remetente_tipo IN ('empresa', 'rh')
      ORDER BY criado_em ASC
    `, [id]);
    res.json({ mensagens: rows });
  } catch (e) {
    console.error('[empresa chat listar]', e);
    res.status(500).json({ erro: 'Erro ao carregar chat' });
  }
});

app.post('/api/empresa/candidatura/:id/chat', requireRecrutadorOuAdmin, async (req, res) => {
  const { empresa_id, nome: empresa_nome } = req.user;
  const { id } = req.params;
  let { mensagem } = req.body;
  if (!mensagem || !mensagem.trim()) return res.status(400).json({ erro: 'Mensagem vazia' });
  // Sanitiza XSS (defesa em profundidade)
  mensagem = sanitizeText(mensagem.trim());
  if (mensagem.length > 2000) return res.status(400).json({ erro: 'Mensagem muito longa (máx 2000 caracteres)' });
  try {
    // Verifica acesso
    const acc = await pool.query(`
      SELECT c.id FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE c.id = $1 AND eva.empresa_id = $2
    `, [id, empresa_id]);
    if (acc.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });

    const { rows } = await pool.query(`
      INSERT INTO empresa_chat (candidatura_id, remetente_tipo, remetente_id, remetente_nome, mensagem)
      VALUES ($1, 'empresa', $2, $3, $4)
      RETURNING id, candidatura_id, remetente_tipo, remetente_nome, mensagem, criado_em
    `, [id, empresa_id, empresa_nome, mensagem.trim()]);
    res.json({ ok: true, mensagem: rows[0] });
  } catch (e) {
    console.error('[empresa chat enviar]', e);
    res.status(500).json({ erro: 'Erro ao enviar mensagem' });
  }
});

// Detalhe do candidato (com verificação de acesso)
app.get('/api/empresa/candidatura/:id', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT c.*, cd.id as candidato_id_full, cd.nome, cd.email, cd.celular, cd.cpf, cd.data_nascimento,
             cd.acessibilidade, cd.cep, cd.estado, cd.cidade, cd.bairro,
             cd.logradouro, cd.numero, cd.complemento,
             cd.formacao, cd.instituicao, cd.curso, cd.situacao, cd.data_conclusao,
             cd.primeiro_emprego, cd.sobre_voce, cd.experiencia, cd.foto_url,
             cd.areas_interesse, cd.banco_talentos,
             v.titulo as vaga_titulo, v.etapas, v.empresa as vaga_empresa, v.cidade as v_cidade, v.estado as v_estado,
        (SELECT 1 FROM empresa_vaga_acesso WHERE empresa_id = $1 AND vaga_id = c.vaga_id) as tem_acesso
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $2
    `, [empresa_id, id]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    if (!rows[0].tem_acesso) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
    const candidatura = rows[0];

    await audit(req, 'empresa.candidatura.viewed', { resource_type: 'candidatura', resource_id: Number(id), metadata: { vaga_titulo: candidatura.vaga_titulo } });

    // Buscar experiencias do candidato (mesma tabela usada pelo admin)
    const { rows: exps } = await pool.query(
      'SELECT * FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC',
      [candidatura.candidato_id]
    );
    candidatura.experiencias = exps;

    res.json(candidatura);
  } catch (e) {
    console.error('[empresa detalhe candidatura]', e);
    res.status(500).json({ erro: 'Erro ao carregar' });
  }
});

// Empresa visualiza documentos de uma candidatura das suas vagas (READ-ONLY)
app.get('/api/empresa/candidatura/:id/documentos', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  const candidaturaId = Number(req.params.id);
  if (!Number.isInteger(candidaturaId) || candidaturaId <= 0) {
    return res.status(400).json({ erro: 'ID de candidatura inválido' });
  }
  try {
    // OWNERSHIP: empresa só vê docs de candidaturas de vagas vinculadas à empresa
    const { rows: cand } = await pool.query(
      `SELECT c.id, c.vaga_id,
              (SELECT 1 FROM empresa_vaga_acesso WHERE empresa_id = $1 AND vaga_id = c.vaga_id) as tem_acesso
       FROM candidaturas c WHERE c.id = $2`,
      [empresa_id, candidaturaId]
    );
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    if (!cand[0].tem_acesso) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });

    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_nome, arquivo_tipo,
              arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows, obrigatorios: DOCUMENTOS_OBRIGATORIOS });
    await audit(req, 'empresa.documento.viewed', { resource_type: 'candidatura', resource_id: candidaturaId, metadata: { qtd_documentos: rows.length } });
  } catch (e) {
    console.error('[empresa docs]', e);
    res.status(500).json({ erro: 'Erro ao carregar documentos' });
  }
});

// Ação da empresa (aprovar, reprovar, avançar) — só etapa 4+
app.post('/api/empresa/candidatura/:id/acao', requireRecrutadorOuAdmin, async (req, res) => {
  const { empresa_id, nome: empresa_nome } = req.user;
  const { id } = req.params;
  const { acao, motivo, comentario } = req.body; // acao: 'avancar' | 'reprovar' | 'comentar'
    // 'comentario' tem prioridade sobre 'motivo' (frontend manda ambos pra garantir)
    const parecer = (comentario || motivo || '').trim();
  if (!['avancar', 'reprovar', 'comentar'].includes(acao)) {
    return res.status(400).json({ erro: 'Ação inválida' });
  }
  try {
    // Verifica acesso + traz etapas[] da vaga
    const acc = await pool.query(`
      SELECT c.id, c.etapa_atual, c.status, c.historico, c.vaga_id, v.etapas
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1 AND eva.empresa_id = $2
    `, [id, empresa_id]);
    if (acc.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
    const cand = acc.rows[0];

    // REGRA: a empresa só pode comentar/avançar/reprovar quando a etapa ATUAL da vaga
    // tiver nome contendo "gestor" ou "empresa" (case-insensitive).
    // etapa_atual é 0-indexed e aponta a etapa em que o candidato está.
    // Ex: etapa_atual=3 → etapas[3] = "Entrevista Gestor" → empresa PODE agir.
    let etapasArr = cand.etapas;
    if (typeof etapasArr === 'string') { try { etapasArr = JSON.parse(etapasArr); } catch (_) { etapasArr = []; } }
    const etapaIdx = cand.etapa_atual;
    const etapaObj = Array.isArray(etapasArr) ? etapasArr[etapaIdx] : null;
    const etapaNomeAtual = etapaObj == null
      ? ''
      : (typeof etapaObj === 'string' ? etapaObj : (etapaObj.nome || etapaObj.titulo || ''));
    const ehEtapaEmpresa = /gestor|empresa/i.test(etapaNomeAtual || '');

    if (['avancar', 'reprovar', 'comentar'].includes(acao) && !ehEtapaEmpresa) {
      return res.status(403).json({
        erro: `A empresa só pode agir na etapa de entrevista com a empresa/gestor (etapa atual: "${etapaNomeAtual || '—'}").`
      });
    }

    // Adiciona entrada no histórico
    const hist = cand.historico || [];
    let novoStatus = cand.status;
    let novaEtapa = cand.etapa_atual;
    const agora = new Date().toISOString();

    if (acao === 'avancar') {
      novaEtapa = cand.etapa_atual + 1;
      // Não passa do total de etapas (deixar pro admin finalizar contratação)
      hist.push({ tipo: 'avancar', por: `empresa:${empresa_nome}`, quando: agora, etapa_de: cand.etapa_atual, etapa_para: novaEtapa, motivo: parecer || '' });
    } else if (acao === 'reprovar') {
      novoStatus = 'rejeitado';
      hist.push({ tipo: 'reprovar', por: `empresa:${empresa_nome}`, quando: agora, motivo: parecer || '' });
    } else if (acao === 'comentar') {
      hist.push({ tipo: 'comentario', por: `empresa:${empresa_nome}`, quando: agora, texto: parecer });
    }

    await pool.query(
      `UPDATE candidaturas SET historico = $1::jsonb, status = $2, etapa_atual = $3, atualizada_em = NOW() WHERE id = $4`,
      [JSON.stringify(hist), novoStatus, novaEtapa, id]
    );

    // Loga notificação (pra histórico, e-mail pode ser enviado depois)
    try {
      await pool.query(
        `INSERT INTO empresa_notificacoes (empresa_id, candidatura_id, tipo, assunto, corpo)
         VALUES ($1, $2, $3, $4, $5)`,
        [empresa_id, id, acao, `Empresa ${acao} em candidatura #${id}`, `Empresa ${empresa_nome} executou ${acao} na etapa ${cand.etapa_atual}`]
      );
    } catch (_) { /* não bloquear se log falhar */ }

    // Log de auditoria da ação da empresa
    await audit(req, 'empresa.candidatura.action', { resource_type: 'candidatura', resource_id: Number(id), metadata: { acao, empresa_nome, de_etapa: cand.etapa_atual, para_etapa: novaEtapa, parecer: parecer || null } });

    res.json({ ok: true, etapa_atual: novaEtapa, status: novoStatus });
  } catch (e) {
    console.error('[empresa acao]', e);
    res.status(500).json({ erro: 'Erro ao processar ação' });
  }
});

// FASE 4 — PATCH etapa/status da candidatura pela empresa (qualquer etapa, sem trava de "entrevista gestor")
app.patch('/api/empresa/candidaturas/:id/etapa', requireRecrutadorOuAdmin, async (req, res) => {
  const { empresa_id, nome: empresa_nome } = req.user;
  const { id } = req.params;
  const { etapa_atual, status, motivo } = req.body || {};
  const parecer = (motivo || '').trim();
  try {
    // Carrega candidatura + etapas[] validando tenant via empresa_vaga_acesso
    const acc = await pool.query(`
      SELECT c.id, c.etapa_atual, c.status, c.historico, c.vaga_id, v.etapas
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1 AND eva.empresa_id = $2
    `, [id, empresa_id]);
    if (acc.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
    const cand = acc.rows[0];

    // Bloqueia candidatura fechada
    if (cand.status === 'contratado' || cand.status === 'rejeitado') {
      return res.status(409).json({ erro: `Candidatura já está "${cand.status}" e não pode ser alterada.` });
    }

    let etapasArr = cand.etapas;
    if (typeof etapasArr === 'string') { try { etapasArr = JSON.parse(etapasArr); } catch (_) { etapasArr = []; } }
    const totalEtapas = Array.isArray(etapasArr) ? etapasArr.length : 0;

    // Validar etapa
    let novaEtapa = cand.etapa_atual;
    if (etapa_atual !== undefined && etapa_atual !== null) {
      const n = Number(etapa_atual);
      if (!Number.isInteger(n) || n < 0 || (totalEtapas > 0 && n >= totalEtapas)) {
        return res.status(400).json({ erro: `Etapa inválida. Deve ser entre 0 e ${totalEtapas - 1}.` });
      }
      novaEtapa = n;
    }

    // Validar status
    let novoStatus = cand.status;
    if (status !== undefined && status !== null) {
      if (!['em_analise', 'em_andamento', 'rejeitado', 'contratado'].includes(status)) {
        return res.status(400).json({ erro: 'Status inválido. Use: em_analise, em_andamento, rejeitado ou contratado.' });
      }
      novoStatus = status;
    }

    // FASE 6 — Verifica se há mudança REAL. Não cria histórico desnecessário.
    const etapaMudou = novaEtapa !== cand.etapa_atual;
    const statusMudou = novoStatus !== cand.status;
    const temMotivo = !!parecer;

    if (!etapaMudou && !statusMudou && !temMotivo) {
      // Nada de fato alterou — sem escrita
      return res.json({ ok: true, etapa_atual: novaEtapa, status: novoStatus, historico_registrado: false });
    }

    // Adiciona entrada no histórico legado (JSONB) — manter compatibilidade
    const hist = Array.isArray(cand.historico) ? cand.historico : [];
    hist.push({
      tipo: 'mudar_etapa',
      por: `empresa:${empresa_nome}`,
      quando: new Date().toISOString(),
      etapa_de: cand.etapa_atual,
      etapa_para: novaEtapa,
      status_de: cand.status,
      status_para: novoStatus,
      motivo: parecer || ''
    });

    // FASE 6 — Grava também na tabela append-only `candidatura_historico`
    // (transação atômica: histórico + update)
    await pool.query('BEGIN');
    try {
      if (etapaMudou || statusMudou) {
        await pool.query(
          `INSERT INTO candidatura_historico
             (candidatura_id, vaga_id, empresa_id,
              etapa_anterior, etapa_nova,
              status_anterior, status_novo,
              alterado_por_tipo, alterado_por_id, alterado_por_nome, alterado_por_role,
              motivo, metadata, criado_em)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, NOW())`,
          [
            Number(id),
            cand.vaga_id,
            empresa_id,
            etapaMudou ? cand.etapa_atual : null,
            etapaMudou ? novaEtapa : null,
            statusMudou ? cand.status : null,
            statusMudou ? novoStatus : null,
            'empresa',
            req.user.id || null,
            empresa_nome || null,
            req.user.role || null,
            parecer || null,
            JSON.stringify({
              origem: 'patch_etapa',
              de_etapa: cand.etapa_atual,
              para_etapa: novaEtapa,
              de_status: cand.status,
              para_status: novoStatus,
              empresa_id
            })
          ]
        );
      }

      await pool.query(
        `UPDATE candidaturas SET historico = $1::jsonb, etapa_atual = $2, status = $3, atualizada_em = NOW() WHERE id = $4`,
        [JSON.stringify(hist), novaEtapa, novoStatus, id]
      );

      await pool.query('COMMIT');
    } catch (e) {
      await pool.query('ROLLBACK');
      throw e;
    }

    await audit(req, 'empresa.candidatura.etapa', {
      resource_type: 'candidatura', resource_id: Number(id),
      metadata: { empresa_nome, de_etapa: cand.etapa_atual, para_etapa: novaEtapa, de_status: cand.status, para_status: novoStatus, motivo: parecer || null, historico_registrado: etapaMudou || statusMudou }
    });

    res.json({ ok: true, etapa_atual: novaEtapa, status: novoStatus, historico_registrado: etapaMudou || statusMudou });
  } catch (e) {
    console.error('[empresa etapa patch]', e);
    res.status(500).json({ erro: 'Erro ao atualizar etapa da candidatura' });
  }
});

// FASE 6 — Histórico da candidatura (visão da EMPRESA)
// Tenant isolation via empresa_vaga_acesso. RBAC: viewer+ pode ler.
// NÃO confia em empresa_id do body/query — usa req.user.empresa_id.
app.get('/api/empresa/candidaturas/:id/historico', requireEmpresaViewer, async (req, res) => {
  try {
    const { id } = req.params;
    const { empresa_id, role } = req.user;
    if (!/^\d+$/.test(String(id))) return res.status(404).json({ erro: 'Candidatura não encontrada' });

    // Valida tenant: candidatura → vaga → empresa_vaga_acesso (empresa_id do JWT)
    const acc = await pool.query(
      `SELECT c.id, c.vaga_id, c.etapa_atual, c.status, v.etapas
       FROM candidaturas c
       JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
       JOIN vagas v ON v.id = c.vaga_id
       WHERE c.id = $1 AND eva.empresa_id = $2`,
      [id, empresa_id]
    );
    if (acc.rows.length === 0) {
      // 404 genérico — não revela se existe em outra empresa (anti-IDOR)
      return res.status(404).json({ erro: 'Candidatura não encontrada' });
    }

    const etapasArr = Array.isArray(acc.rows[0].etapas)
      ? acc.rows[0].etapas
      : (typeof acc.rows[0].etapas === 'string' ? (() => { try { return JSON.parse(acc.rows[0].etapas); } catch (_) { return []; } })() : []);

    const { rows } = await pool.query(
      `SELECT
        h.id, h.candidatura_id,
        h.etapa_anterior, h.etapa_nova,
        h.status_anterior, h.status_novo,
        h.alterado_por_tipo, h.alterado_por_id, h.alterado_por_nome, h.alterado_por_role,
        h.motivo, h.metadata, h.criado_em
       FROM candidatura_historico h
       WHERE h.candidatura_id = $1
       ORDER BY h.criado_em ASC`,
      [id]
    );

    const eventos = rows.map((h) => {
      const etapaAntObj = Number.isInteger(h.etapa_anterior) && etapasArr[h.etapa_anterior]
        ? etapasArr[h.etapa_anterior]
        : null;
      const etapaNovaObj = etapasArr[h.etapa_nova];
      const etapaAntNome = etapaAntObj
        ? (typeof etapaAntObj === 'string' ? etapaAntObj : etapaAntObj.nome)
        : null;
      const etapaNovaNome = etapaNovaObj
        ? (typeof etapaNovaObj === 'string' ? etapaNovaObj : etapaNovaObj.nome)
        : (Number.isInteger(h.etapa_nova) ? `Etapa ${h.etapa_nova + 1}` : null);
      return {
        id: h.id,
        de_etapa: etapaAntNome,
        de_etapa_indice: h.etapa_anterior,
        para_etapa: etapaNovaNome,
        para_etapa_indice: h.etapa_nova,
        de_status: h.status_anterior,
        para_status: h.status_novo,
        autor_tipo: h.alterado_por_tipo,
        autor_id: h.alterado_por_id,
        autor_nome: h.alterado_por_nome,
        autor_role: h.alterado_por_role,
        mensagem: h.motivo,
        metadata: h.metadata,
        data: h.criado_em
      };
    });

    res.json({ ok: true, eventos, viewer_role: role });
  } catch (e) {
    console.error('[empresa/candidaturas/:id/historico]', e);
    res.status(500).json({ erro: 'Erro ao buscar histórico' });
  }
});

// ============= CHAT RH <-> EMPRESA (visão do Admin) =============
app.get('/api/admin/candidatura/:id/chat-empresa', authAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`
      SELECT id, candidatura_id, remetente_tipo, remetente_nome, mensagem, criado_em, lida_em
      FROM empresa_chat
      WHERE candidatura_id = $1
      ORDER BY criado_em ASC
    `, [id]);
    // Marca mensagens da empresa como lidas
    await pool.query(
      `UPDATE empresa_chat SET lida_em = NOW() WHERE candidatura_id = $1 AND remetente_tipo = 'empresa' AND lida_em IS NULL`,
      [id]
    );
    res.json({ mensagens: rows });
  } catch (e) {
    console.error('[admin chat empresa listar]', e);
    res.status(500).json({ erro: 'Erro ao carregar chat' });
  }
});

app.post('/api/admin/candidatura/:id/chat-empresa', authAdmin, async (req, res) => {
  const { id } = req.params;
  let { mensagem } = req.body;
  const { id: admin_id, nome: admin_nome } = req.user;
  if (!mensagem || !mensagem.trim()) return res.status(400).json({ erro: 'Mensagem vazia' });
  mensagem = sanitizeText(mensagem.trim());
  try {
    const { rows } = await pool.query(`
      INSERT INTO empresa_chat (candidatura_id, remetente_tipo, remetente_id, remetente_nome, mensagem)
      VALUES ($1, 'rh', $2, $3, $4)
      RETURNING id, candidatura_id, remetente_tipo, remetente_nome, mensagem, criado_em
    `, [id, admin_id, admin_nome || 'RH', mensagem.trim()]);
    res.json({ ok: true, mensagem: rows[0] });
  } catch (e) {
    console.error('[admin chat empresa enviar]', e);
    res.status(500).json({ erro: 'Erro ao enviar mensagem' });
  }
});

// ============= LISTA DE CONVERSAS CHAT EMPRESA (para bolinha flutuante) =============
// Lista TODAS as candidaturas com mensagens trocadas com empresas (para o admin)
app.get('/api/admin/chat-empresa-lista', authAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id AS candidatura_id,
        cand.nome AS candidato_nome,
        v.titulo AS vaga_titulo,
        (SELECT e.nome FROM empresa_vaga_acesso eva
         JOIN empresas e ON e.id = eva.empresa_id
         WHERE eva.vaga_id = v.id ORDER BY eva.concedido_em DESC LIMIT 1) AS empresa_nome,
        (SELECT COUNT(*) FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id AND ec.remetente_tipo = 'empresa' AND ec.lida_em IS NULL) AS nao_lidas,
        (SELECT ec.mensagem FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultima_mensagem,
        (SELECT ec.criado_em FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultima_data,
        (SELECT ec.remetente_tipo FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultimo_remetente_tipo
      FROM candidaturas c
      JOIN candidatos cand ON cand.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.status NOT IN ('rejeitado', 'contratado', 'reprovado')
      ORDER BY ultima_data DESC NULLS LAST
    `);
    res.json({ conversas: rows });
  } catch (e) {
    console.error('[admin chat empresa lista]', e);
    res.status(500).json({ erro: 'Erro ao listar conversas' });
  }
});

// Lista conversas chat RH para a empresa logada (para a bolinha flutuante da empresa)
app.get('/api/empresa/chat-rh-lista', requireEmpresaViewer, async (req, res) => {
  const { empresa_id } = req.user;
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id AS candidatura_id,
        cand.nome AS candidato_nome,
        v.titulo AS vaga_titulo,
        (SELECT COUNT(*) FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id AND ec.remetente_tipo = 'rh' AND ec.lida_em IS NULL) AS nao_lidas,
        (SELECT ec.mensagem FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultima_mensagem,
        (SELECT ec.criado_em FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultima_data,
        (SELECT ec.remetente_tipo FROM empresa_chat ec
         WHERE ec.candidatura_id = c.id ORDER BY ec.criado_em DESC LIMIT 1) AS ultimo_remetente_tipo
      FROM candidaturas c
      JOIN candidatos cand ON cand.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
      WHERE eva.empresa_id = $1
        AND c.status NOT IN ('rejeitado', 'contratado', 'reprovado')
      ORDER BY ultima_data DESC NULLS LAST
    `, [empresa_id]);
    res.json({ conversas: rows });
  } catch (e) {
    console.error('[empresa chat rh lista]', e);
    res.status(500).json({ erro: 'Erro ao listar conversas' });
  }
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

    // ============= DEBUG FASE 6 — checa estrutura tabela
    app.get('/api/_debug/fase6-tabela', async (req, res) => {
      try {
        const cols = await pool.query(
          `SELECT column_name, data_type FROM information_schema.columns
           WHERE table_schema='public' AND table_name='candidatura_historico'
           ORDER BY ordinal_position`
        );
        res.json({ ok: true, colunas: cols.rows });
      } catch (e) {
        res.status(500).json({ erro: e.message });
      }
    });

    // ping test: 1785206962.7014055
    // FIX C3 (2026-07-27): rota /api/_teste/email REMOVIDA.
    // Era pública sem auth — atacante podia mandar e-mail arbitrário pelo nosso domínio.
    // Pra testar envio de e-mail em prod, use uma rota admin com auth + restrição por domínio.

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
      return erroInterno(req, res, e, 'api-admin-audit-logs');
    }
  });

  // ============= AUDIT LOGS (admin) =============
  app.get('/api/admin/audit-logs', authAdmin, async (req, res) => {
    try {
      const { user_id, action, resource_id, limit, offset, since } = req.query;
      const queryLimit = Math.min(500, Math.max(1, parseInt(limit, 10) || 100));
      const queryOffset = Math.max(0, parseInt(offset, 10) || 0);
      const wheres = [];
      const values = [];
      const add = (sql, val) => { values.push(val); wheres.push(sql.replace('?', `$${values.length}`)); };
      if (user_id) add('user_id = ?', parseInt(user_id, 10));
      if (action) add('action = ?', action);
      if (resource_id) add('resource_id = ?', parseInt(resource_id, 10));
      if (since) add('created_at >= ?', since);
      const whereClause = wheres.length > 0 ? 'WHERE ' + wheres.join(' AND ') : '';
      const count = await pool.query(`SELECT COUNT(*) FROM audit_logs ${whereClause}`, values);
      const { rows } = await pool.query(
        `SELECT * FROM audit_logs ${whereClause} ORDER BY created_at DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
        [...values, queryLimit, queryOffset]
      );
      res.json({ logs: rows, total: parseInt(count.rows[0].count, 10) });
    } catch (e) {
      console.error('[AUDIT LOGS]', e);
      res.status(500).json({ erro: 'Erro ao consultar logs de auditoria' });
    }
  });

  // =========================================================================
  // METADADOS DE BACKUP (sem restaurar nada — apenas consulta)
  // =========================================================================
  app.post('/api/admin/restore-test', authAdminOnly, async (req, res) => {
    try {
      const meta = await getBackupMetadata();
      if (!meta) {
        return res.json({ ok: true, msg: 'Nenhum backup encontrado no Cloudinary ainda. Use a rota /api/admin/backup para criar o primeiro.' });
      }
      res.json({
        ok: true,
        msg: 'Metadados do último backup (NÃO foi restaurado nada)',
        backup: meta,
        aviso: 'Esta rota NÃO restaura dados. Para restaurar, siga o procedimento em recrutamento-api/_auditoria/restore-teste.md'
      });
    } catch (e) {
      console.error('[BACKUP META]', e);
      res.status(500).json({ erro: 'Erro ao consultar metadados de backup', detalhes: e.message });
    }
  });

  // =========================================================================
  // CRIAR BACKUP MANUAL (admin only — sob demanda)
  // =========================================================================
  app.post('/api/admin/backup', authAdminOnly, async (req, res) => {
    try {
      const { performBackup } = require('./backup');
      const result = await performBackup();
      await audit(req, 'admin.backup.created', { resource_type: 'backup', metadata: { public_id: result.public_id, size: result.size_compressed } });
      res.json({ ok: true, msg: 'Backup criado com sucesso', ...result });
    } catch (e) {
      console.error('[BACKUP CREATE]', e);
      res.status(500).json({ erro: 'Erro ao criar backup', detalhes: e.message });
    }
  });

  // =========================================================================
  // REFRESH TOKEN (Etapa 2, 2026-07-27)
  // =========================================================================
  // Recebe refresh token (opaco, não JWT) → valida no DB → gera novo access + novo refresh.
  // Implementa ROTAÇÃO: cada uso emite novo refresh e revoga o antigo. Reutilização
  // do refresh antigo = comprometido → revoga TODOS os tokens do usuário.
  app.post('/api/auth/refresh', async (req, res) => {
    try {
      const { refreshToken } = req.body || {};
      if (!refreshToken || typeof refreshToken !== 'string' || refreshToken.length < 32) {
        return res.status(400).json({ erro: 'refreshToken inválido' });
      }
      const r = await consumirRefresh(refreshToken);
      if (!r.valido) {
        await audit(req, 'security.refresh_invalid', { metadata: { motivo: r.motivo } });
        return res.status(401).json({ erro: 'Refresh token inválido' });
      }
      const t = r.token;
      // Gera novo access (15m) + novo refresh (7d)
      // Preserva role, empresa_id E empresa_nome do refresh anterior (Fase 1, jul/2026)
      // FIX FASE 3 (28/07/2026): busca empresa_nome do banco pra incluir no novo JWT,
      // senão o middleware /api/empresa/* falha com NOT NULL constraint
      let empresa_nome = null;
      if (t.user_type === 'empresa' && t.user_id) {
        const { rows: empRows } = await pool.query(
          'SELECT e.nome FROM empresa_usuarios u JOIN empresas e ON e.id = u.empresa_id WHERE u.id = $1',
          [t.user_id]
        );
        if (empRows.length) empresa_nome = empRows[0].nome;
      }
      const novoAccess = criarAccessToken({
        id: t.user_id || undefined,
        email: t.user_email,
        tipo: t.user_type,
        role: t.user_role || undefined,
        empresa_id: t.user_empresa_id || undefined,
        empresa_nome
      });
      const novoRefresh = criarRefreshToken();
      // Revoga o refresh usado e persiste o novo (ROTAÇÃO)
      await revogarRefresh(refreshToken, 'rotacionado');
      await persistirRefresh(
        t.user_type,
        t.user_id,
        t.user_email,
        novoRefresh,
        req,
        { user_role: t.user_role, user_empresa_id: t.user_empresa_id }
      );
      await audit(req, 'security.refresh_rotated', { resource_type: t.user_type, user_email: t.user_email });
      res.json({ ok: true, token: novoAccess, refreshToken: novoRefresh });
    } catch (e) {
      console.error('[AUTH REFRESH]', e);
      res.status(500).json({ erro: 'Erro ao renovar sessão' });
    }
  });

  // =========================================================================
  // LOGOUT (revoga o refresh token)
  // =========================================================================
  app.post('/api/auth/logout', async (req, res) => {
    try {
      const { refreshToken } = req.body || {};
      if (refreshToken && typeof refreshToken === 'string') {
        await revogarRefresh(refreshToken, 'logout');
      }
      // access token é descartado pelo cliente — não tem como "revogar" JWT
      // sem manter blacklist. Refresh revogado é suficiente pra impedir novo access.
      res.json({ ok: true, message: 'Sessão encerrada' });
    } catch (e) {
      console.error('[AUTH LOGOUT]', e);
      res.status(500).json({ erro: 'Erro ao encerrar sessão' });
    }
  });

  // =========================================================================
  // FASE 2 — ROTAS RBAC DE ADMIN_EMPRESA (28/07/2026)
  // admin_empresa gerencia apenas usuarios da PROPRIA empresa (req.user.empresa_id).
  // Bloqueios:
  //   - tentativa de acessar outra empresa -> 403
  //   - self-downgrade (alterar o proprio role) -> 403
  //   - bloquear duplo admin_empresa na mesma empresa
  // =========================================================================

  // Lista usuarios da empresa logada (read-only, qualquer role)
  app.get('/api/empresa/usuarios', requireEmpresaViewer, async (req, res) => {
    const { empresa_id } = req.user;
    try {
      const { rows } = await pool.query(`
        SELECT id, nome, email, cargo, role, ativo, primeiro_acesso, criado_em
        FROM empresa_usuarios
        WHERE empresa_id = $1
        ORDER BY nome
      `, [empresa_id]);
      res.json({ usuarios: rows });
    } catch (e) {
      return erroInterno(req, res, e, 'empresa.usuarios.list');
    }
  });

  // Cria usuario (apenas admin_empresa)
  app.post('/api/empresa/usuarios', requireAdminEmpresa, async (req, res) => {
    const { empresa_id } = req.user;
    const { nome, email, senha, cargo, role } = req.body;
    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'nome, email, senha obrigatorios' });
    }
    let roleFinal = role;
    if (roleFinal && !['admin_empresa', 'recrutador', 'viewer'].includes(roleFinal)) {
      return res.status(400).json({ erro: 'role invalido' });
    }
    if (!roleFinal) roleFinal = 'recrutador';
    try {
      const hash = await bcrypt.hash(senha, 10);
      const { rows } = await pool.query(`
        INSERT INTO empresa_usuarios (empresa_id, nome, email, senha_hash, cargo, criado_por, role, ativo)
        VALUES ($1, $2, $3, $4, $5, NULL, $6, true)
        RETURNING id, nome, email, cargo, role, ativo
      `, [empresa_id, nome, email.toLowerCase(), hash, cargo || 'Recrutador', roleFinal]);
      await audit(req, 'empresa.usuario.created', {
        resource_type: 'empresa_usuario',
        resource_id: rows[0].id,
        user_email: rows[0].email,
        metadata: { empresa_id, role: roleFinal }
      });
      res.json({ ok: true, usuario: rows[0] });
    } catch (e) {
      if (e.code === '23505') return res.status(400).json({ erro: 'Email ja cadastrado' });
      return erroInterno(req, res, e, 'empresa.usuarios.create');
    }
  });

  // Edita role/cargo/ativo (admin_empresa)
  app.put('/api/empresa/usuarios/:id', requireAdminEmpresa, async (req, res) => {
    const { empresa_id } = req.user;
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ erro: 'id invalido' });
    const { cargo, role, ativo } = req.body;
    try {
      const own = await pool.query(
        'SELECT id, role FROM empresa_usuarios WHERE id=$1 AND empresa_id=$2',
        [id, empresa_id]
      );
      if (own.rowCount === 0) return res.status(403).json({ erro: 'Usuario nao pertence a esta empresa' });

      // Self-downgrade: bloquear
      if (id === req.user.id && role !== undefined && role !== 'admin_empresa') {
        return res.status(403).json({ erro: 'admin_empresa nao pode rebaixar a si mesmo' });
      }

      // Promocao a admin_empresa por outra pessoa so se ainda nao existir
      if (id !== req.user.id && role === 'admin_empresa') {
        const admins = await pool.query(
          "SELECT COUNT(*)::int AS qtd FROM empresa_usuarios WHERE empresa_id=$1 AND role='admin_empresa'",
          [empresa_id]
        );
        if (admins.rows[0].qtd >= 1) {
          return res.status(403).json({ erro: 'Ja existe admin_empresa para esta empresa' });
        }
      }

      if (role !== undefined && !['admin_empresa', 'recrutador', 'viewer'].includes(role)) {
        return res.status(400).json({ erro: 'role invalido' });
      }

      const upd = [];
      const vals = [];
      if (cargo !== undefined) { vals.push(cargo); upd.push(`cargo=$${vals.length}`); }
      if (role !== undefined)  { vals.push(role);  upd.push(`role=$${vals.length}`); }
      if (ativo !== undefined) { vals.push(!!ativo); upd.push(`ativo=$${vals.length}`); }
      if (upd.length === 0) return res.status(400).json({ erro: 'nada para atualizar' });
      vals.push(id);
      const { rows } = await pool.query(
        `UPDATE empresa_usuarios SET ${upd.join(', ')} WHERE id=$${vals.length} RETURNING id, nome, email, cargo, role, ativo`,
        vals
      );
      await audit(req, 'empresa.usuario.updated', {
        resource_type: 'empresa_usuario',
        resource_id: id,
        metadata: { fields: Object.keys(req.body) }
      });
      res.json({ ok: true, usuario: rows[0] });
    } catch (e) {
      return erroInterno(req, res, e, 'empresa.usuarios.update');
    }
  });

  // Reset de senha (admin_empresa) para usuarios da empresa
  app.post('/api/empresa/usuarios/:id/reset-senha', requireAdminEmpresa, async (req, res) => {
    const { empresa_id } = req.user;
    const id = parseInt(req.params.id, 10);
    const { nova_senha } = req.body || {};
    if (!Number.isFinite(id) || !nova_senha || nova_senha.length < 6) {
      return res.status(400).json({ erro: 'nova_senha>=6 obrigatoria' });
    }
    try {
      const own = await pool.query('SELECT id FROM empresa_usuarios WHERE id=$1 AND empresa_id=$2', [id, empresa_id]);
      if (own.rowCount === 0) return res.status(403).json({ erro: 'Usuario nao pertence a esta empresa' });
      const hash = await bcrypt.hash(nova_senha, 10);
      await pool.query('UPDATE empresa_usuarios SET senha_hash=$1, primeiro_acesso=true WHERE id=$2', [hash, id]);
      await audit(req, 'empresa.usuario.password_reset', {
        resource_type: 'empresa_usuario',
        resource_id: id
      });
      res.json({ ok: true });
    } catch (e) {
      return erroInterno(req, res, e, 'empresa.usuarios.reset');
    }
  });

  // Desativa usuario (admin_empresa) — soft delete via ativo=false
  app.delete('/api/empresa/usuarios/:id', requireAdminEmpresa, async (req, res) => {
    const { empresa_id } = req.user;
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ erro: 'id invalido' });
    if (id === req.user.id) return res.status(403).json({ erro: 'admin_empresa nao pode desativar a si mesmo' });
    try {
      const own = await pool.query('SELECT id FROM empresa_usuarios WHERE id=$1 AND empresa_id=$2', [id, empresa_id]);
      if (own.rowCount === 0) return res.status(403).json({ erro: 'Usuario nao pertence a esta empresa' });
      await pool.query('UPDATE empresa_usuarios SET ativo=false WHERE id=$1', [id]);
      await audit(req, 'empresa.usuario.deactivated', {
        resource_type: 'empresa_usuario',
        resource_id: id
      });
      res.json({ ok: true });
    } catch (e) {
      return erroInterno(req, res, e, 'empresa.usuarios.delete');
    }
  });



  const port = process.env.PORT || 10000;

  // =========================================================================
  // FIX Etapa 2 (2026-07-27): HANDLER GLOBAL 404 — JSON seguro, sem stack.
  // =========================================================================
  // Impede que Express retorne HTML "<pre>Cannot GET ...</pre>" em rotas inexistentes.
  // Aplica para qualquer método (GET/POST/PUT/DELETE/OPTIONS) em qualquer rota não casada.
  app.use((req, res, next) => {
    res.status(404).json({
      ok: false,
      error: 'NOT_FOUND',
      message: 'Rota não encontrada'
    });
  });

  // =========================================================================
  // FIX Etapa 2 (2026-07-27): HANDLER GLOBAL DE ERRO — sem vazar stack/Express/SQL.
  // =========================================================================
  // 4 args = Express reconhece como error handler. SEMPRE no final.
  app.use((err, req, res, next) => {
    // Log interno com detalhes
    console.error('[UNHANDLED]', err && (err.stack || err.message || err));
    // Resposta genérica pro cliente (sem detalhes de implementação)
    res.status(err.status || 500).json({
      ok: false,
      error: 'INTERNAL_ERROR',
      message: 'Ocorreu um erro interno. Tente novamente em instantes.'
    });
  });

  // Helper: respostas 500 seguras (log interno + mensagem genérica pro cliente).
  // Substitui o padrão `res.status(500).json({ erro: e.message })` que vaza SQL/Express/etc.
  // NÃO usar em rotas /_debug/* (precisam do erro real pro Fabio).
  function erroInterno(req, res, e, contexto) {
    console.error(`[ERRO ${contexto}]`, e && (e.stack || e.message || e));
    return res.status(500).json({ erro: 'Erro interno do servidor' });
  }

  app.listen(port, () => console.log('API rodando na porta ' + port));
  } catch (e) {
    console.error('Erro ao iniciar:', e);
    process.exit(1);
  }
})();
// Tue Jul 28 02:43:09 UTC 2026
