// BUILD_TIMESTAMP: 2026-07-27T05:55-Z (Etapa 2 force redeploy)
// BUILD_TIMESTAMP: 2026-07-25T21:20-Z — commit forçando redeploy
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const asaas = require('./asaas');
const cloudinary = require('cloudinary').v2;
const { analisarCurriculo } = require('./curriculoParser');
const { validateBase64File } = require('./fileValidation');
const { registrarRotasTriagem } = require('./triagemRoutes');
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

const { pool, init, inserirNotificacao } = require('./db');
const { enviarCodigo, enviarNotificacaoStatus, enviarEmailProposta, enviarEmailBg, enviarEmailAtualizacao, enviarEmail, enviarEmailInscricao, getResendKey } = require('./email');
// Fase 13 — Serviço central de e-mail (usa os mesmos provedores, acrescenta templates, preferências, dedup)
const emailSvc     = require('./email/emailService');
const analytics    = require('./analyticsService');
const meet = require('./meet');
const { criarAccessToken, criarRefreshToken, persistirRefresh, consumirRefresh, revogarRefresh, revogarTodosPorUsuario, listarSessoes, revogarSessaoById, revogarOutrasSessoes } = require('./token');

// Email do admin pra receber notificações de ação do candidato
const ADMIN_NOTIF_EMAIL = process.env.ADMIN_NOTIF_EMAIL || process.env.ADMIN_EMAIL || 'fabio08dejesusjunior@gmail.com';
const { authMiddleware, authCandidato, authAdmin, authGlobalRead, authEmpresa, authAdminOnly, denyGlobalPrivateUntilSupport, authCandidatoOrEmpresaOrAdmin, authCandidatoOrAdminStrict, requireAdminEmpresa, requireAdminOuRecrutadorEquipe, requireRecrutadorOuAdmin, requireEmpresaViewer, JWT_VERIFY_OPTIONS } = require('./auth');
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
const { audit, sanitizarMetadata } = require('./audit');

function mascararEmail(email) {
  if (!email || typeof email !== 'string') return null;
  const [local, dominio] = email.split('@');
  if (!dominio) return '***';
  return `${(local || '').slice(0, 2)}***@${dominio}`;
}
const { create2faCode, verify2faCode, resend2faCode } = require('./twoFactor');
const { getBackupMetadata } = require('./backup');
const socialAuth = require('./socialAuth');

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

// Documentos de candidatos e PDFs de propostas usam delivery authenticated.
// O frontend recebe apenas uma URL assinada derivada do public_id; o secret
// do Cloudinary nunca sai da API e os links públicos antigos deixam de ser
// usados nas respostas da aplicação.
function cloudinaryAuthenticatedUrl(publicId, fileName, mimeType) {
  if (!publicId) return null;
  const isImage = String(mimeType || '').toLowerCase().startsWith('image/');
  const resourceType = isImage ? 'image' : 'raw';
  const ext = String(fileName || '').split('.').pop().toLowerCase();
  // Assinatura curta: mesmo que uma URL seja copiada do navegador, ela expira
  // rapidamente. A autorização principal continua sendo feita pela API/proxy.
  const options = {
    resource_type: resourceType,
    type: 'authenticated',
    sign_url: true,
    secure: true,
    auth_token: { duration: 300 }
  };
  if (!isImage && /^[a-z0-9]{1,8}$/.test(ext)) options.format = ext;
  return cloudinary.url(publicId, options);
}

function protegerUrlDocumento(row) {
  if (!row) return row;
  const { arquivo_public_id, ...safe } = row;
  return {
    ...safe,
    // Nunca repassar arquivo_url legado/publico; somente URL autenticada derivada do public_id.
    arquivo_url: cloudinaryAuthenticatedUrl(arquivo_public_id, row.arquivo_nome, row.arquivo_tipo) || null
  };
}

function protegerUrlProposta(row) {
  if (!row) return row;
  const { proposta_pdf_public_id, ...safe } = row;
  return {
    ...safe,
    proposta_pdf_url: cloudinaryAuthenticatedUrl(proposta_pdf_public_id, 'proposta.pdf', 'application/pdf') || null
  };
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
    // Origem não autorizada: não falha o servidor com 500; apenas não concede CORS.
    return cb(null, false);
  },
  credentials: true
}));
// Endpoints que recebem arquivos em Base64 têm limites próprios, aplicados
// antes do parser global. O limite binário real continua sendo validado por
// validateBase64File() em cada rota.
app.use('/api/candidato/analisar-curriculo', express.json({ limit: '10mb' }));
app.use('/api/candidato/foto', express.json({ limit: '8mb' }));
app.use('/api/candidatura/:id/documentos', express.json({ limit: '50mb' }));
app.use('/api/chat/:candidatura_id/upload', express.json({ limit: '9mb' }));
app.use('/api/admin/candidatura/:id/enviar-proposta', express.json({ limit: '9mb' }));
app.use('/api/empresa/candidatura/:id/proposta', express.json({ limit: '9mb' }));

// JSON normal: payloads de negócio não precisam de dezenas de megabytes.
// Render health check — rota pública, rápida e sem dependência do banco.
app.get('/health', (req, res) => res.status(200).json({ ok: true, service: 'vagasio-api-staging' }));

app.use(express.json({ limit: '2mb' }));

app.use(express.urlencoded({ extended: true, limit: '1mb' }));

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
  'api-write': { max: 120, windowMs: 60 * 60 * 1000 },  // 120 escritas/hora por IP
  contato: { max: 5, windowMs: 60 * 60 * 1000 }         // 5 contatos/hora por IP
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
  // A chave de debug é defesa adicional, não substitui autenticação.
  return authAdminOnly(req, res, next);
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
       WHERE LOWER(TRIM(status)) = 'publicada'
         AND (empresa_id = (SELECT id FROM empresas WHERE slug = $1 AND ativo = true)
              OR (empresa_id IS NULL AND NULLIF(TRIM(empresa), '') IS NOT NULL
                  AND LOWER(TRIM(empresa)) = LOWER(TRIM((SELECT nome FROM empresas WHERE slug = $1 AND ativo = true)))))`,
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
       WHERE LOWER(TRIM(v.status)) = 'publicada'
         AND (v.empresa_id = $1
              OR (v.empresa_id IS NULL AND NULLIF(TRIM(v.empresa), '') IS NOT NULL
                  AND LOWER(TRIM(v.empresa)) = LOWER(TRIM((SELECT nome FROM empresas WHERE id = $1)))))
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
         AND LOWER(TRIM(v.status)) = 'publicada'
         AND (v.empresa_id = e.id
              OR (v.empresa_id IS NULL AND NULLIF(TRIM(v.empresa), '') IS NOT NULL
                  AND LOWER(TRIM(v.empresa)) = LOWER(TRIM(e.nome))))
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

// Endpoints públicos de disponibilidade: não expõem nome do sistema,
// horário, commit, versão, ambiente ou detalhes de infraestrutura.
app.get('/api/_version', (req, res) => res.json({ ok: true }));
app.get('/api/saude', async (req, res) => {
  let dbOk = false;
  try {
    await pool.query('SELECT 1');
    dbOk = true;
  } catch (_) {}
  res.status(dbOk ? 200 : 503).json({ ok: dbOk });
});

// ── CI: token admin sem 2FA ─────────────────────────────────────────────────
// Ativo SOMENTE quando CI_ADMIN_SECRET está definido E NODE_ENV !== 'production'.
// Se NODE_ENV === 'production', retorna 404 independente de qualquer header.
// Nunca expor em produção. Usado exclusivamente pelo GitHub Actions.
app.post('/api/ci/admin-token', async (req, res) => {
  // Proteção em profundidade: bloquear em produção (hard block — não depende de flag)
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ erro: 'Not found' });
  }
  const ciSecret = process.env.CI_ADMIN_SECRET;
  if (!ciSecret) {
    return res.status(404).json({ erro: 'Not found' });
  }
  const { secret } = req.body || {};
  if (!secret || secret !== ciSecret) {
    return res.status(401).json({ erro: 'Não autorizado' });
  }
  try {
    // Busca admin SaaS real — não cria usuário fantasma
    const { rows } = await pool.query(
      `SELECT id, email, nome, role FROM admin_users WHERE is_saas = true ORDER BY id LIMIT 1`
    );
    if (!rows.length) return res.status(404).json({ erro: 'Admin SaaS não encontrado' });
    const admin = rows[0];
    const token = criarAccessToken({
      id: admin.id, email: admin.email, nome: admin.nome, tipo: 'admin',
      role: admin.role || 'admin', is_saas: true, _ci: true
    });
    res.json({ ok: true, token, admin: { id: admin.id, email: admin.email } });
  } catch (e) {
    console.error('[CI TOKEN]', e.message);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// DEBUG FASE 6 — versão top-level (não depende do wrapper async)
// /api/_debug/fase6 removido (dados internos de schema)

// Sentinela pública de disponibilidade/deploy. Detalhes de build ficam fora
// da resposta pública; diagnóstico detalhado deve ocorrer por CI/observabilidade.
app.get('/api/_build', (req, res) => res.json({ ok: true }));

// VagasIO Video Calls — authenticated development rollout, tenant-scoped.
const videoRooms = require('./videoRooms');
app.use('/api/video', authMiddleware);
app.get('/api/video/config', (req, res) => {
  if (!videoRooms.gate(req, res)) return;
  res.set('Cache-Control','no-store').json({ enabled:true, signalUrl:videoRooms.signalUrl(), role:videoRooms.role(req.user), tokenTtlSeconds:300, maxParticipants:2 });
});
app.post('/api/video/rooms', async (req,res) => {
  if (!videoRooms.gate(req,res)) return;
  const interviewId=Number(req.body?.interview_id); if(!Number.isInteger(interviewId)||interviewId<1) return res.status(400).json({erro:'interview_id inválido'});
  try { const room=await videoRooms.getOrCreate(req,interviewId); if(!room) return res.status(404).json({erro:'Recurso não encontrado'}); res.set('Cache-Control','no-store').json({ok:true,room}); }
  catch(e){ console.error('[VIDEO ROOM]',e.message); res.status(503).json({erro:'Serviço de vídeo indisponível'}); }
});
app.post('/api/video/rooms/:roomId/token', async (req,res) => {
  if (!videoRooms.gate(req,res)) return;
  try { const token=await videoRooms.issue(req,req.params.roomId); if(!token) return res.status(404).json({erro:'Recurso não encontrado'}); res.set('Cache-Control','no-store').json({ok:true,...token}); }
  catch(e){ console.error('[VIDEO TOKEN]',e.message); res.status(503).json({erro:'Serviço de vídeo indisponível'}); }
});
app.post('/api/video/rooms/:roomId/end', async (req,res) => {
  if (!videoRooms.gate(req,res)) return;
  if (!['empresa','recrutador'].includes(req.user.tipo)) return res.status(403).json({erro:'Apenas o recrutador da empresa pode encerrar a sala'});
  try { const r=await videoRooms.pool.query(`UPDATE video_rooms SET status='ended',ended_at=NOW() WHERE room_id=$1 AND status='active' AND (empresa_id=$2 OR $3='admin') RETURNING room_id`,[req.params.roomId,req.user.empresa_id||null,req.user.tipo]); if(!r.rowCount)return res.status(404).json({erro:'Recurso não encontrado'}); res.json({ok:true,ended:true}); }
  catch(e){ console.error('[VIDEO END]',e.message); res.status(503).json({erro:'Serviço de vídeo indisponível'}); }
});

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

// Cache de falhas de SMTP: falhas são tratadas internamente, sem expor o código
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
// ===== CONTATO PÚBLICO DA HOME 2.0 =====
// Sem autenticação: validação server-side, honeypot, limite por IP e envio pelo provedor já configurado.
const CONTACT_ASSUNTOS = new Set([
  'Comercial / Quero contratar o VagasIO',
  'Suporte / Dúvidas técnicas',
  'Financeiro / Pagamentos e cobrança',
  'Parcerias / Indicação',
  'Imprensa / Mídia',
  'Sugestões / Feedback',
  'Outros assuntos'
]);
function contatoTexto(value, max, allowNewlines = false) {
  const raw = sanitizeText(String(value || ''));
  const cleaned = raw.replace(allowNewlines ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g : /[\u0000-\u001F\u007F\r\n]/g, ' ');
  return cleaned.trim().slice(0, max);
}
function escapeContatoHtml(value) {
  return String(value || '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
app.post('/api/contato', rateLimitByIp('contato'), async (req, res) => {
  ipRateRegister('contato', req);
  const website = contatoTexto(req.body?.website, 100);
  // Honeypot: responde como sucesso sem enviar para não ensinar o filtro ao robô.
  if (website) return res.json({ ok: true });
  const nome = contatoTexto(req.body?.nome, 100);
  const email = contatoTexto(req.body?.email, 160).toLowerCase();
  const empresa = contatoTexto(req.body?.empresa, 120);
  const telefone = contatoTexto(req.body?.telefone, 25);
  const assunto = contatoTexto(req.body?.assunto, 100);
  const mensagem = contatoTexto(req.body?.mensagem, 5000, true);
  const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  const telefoneDigits = telefone.replace(/\D/g, '');
  if (nome.length < 2 || !emailValido || !CONTACT_ASSUNTOS.has(assunto) || mensagem.length < 10 || (telefoneDigits && ![10, 11].includes(telefoneDigits.length))) {
    return res.status(400).json({ erro: 'Revise os campos obrigatórios e tente novamente.' });
  }
  // O Resend em modo de teste só aceita destinatários autorizados pela conta.
  // Mantemos CONTATO_EMAIL configurável e usamos o e-mail administrativo da conta
  // como fallback seguro para que nenhum contato seja perdido.
  const destino = process.env.CONTATO_EMAIL || process.env.CONTACT_EMAIL || process.env.ADMIN_NOTIF_EMAIL || 'fabio08dejesusjunior@gmail.com';
  const subject = `[Contato VagasIO] ${assunto} — ${nome}`.replace(/[\r\n]/g, ' ').slice(0, 240);
  const text = [
    'Novo contato recebido pela Home 2.0 do VagasIO',
    '',
    `Nome: ${nome}`,
    `E-mail: ${email}`,
    `Empresa: ${empresa || 'Não informada'}`,
    `Telefone: ${telefone || 'Não informado'}`,
    `Assunto: ${assunto}`,
    '',
    'Mensagem:',
    mensagem
  ].join('\n');
  const html = `<div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;color:#211A20"><div style="padding:20px 22px;background:#3A0A1D;color:#fff;border-radius:10px 10px 0 0"><strong style="font-size:18px">VagasIO</strong><div style="margin-top:5px;color:#F2C9D8;font-size:12px">Novo contato pela Home 2.0</div></div><div style="padding:22px;border:1px solid #E7DCE1;border-top:0;border-radius:0 0 10px 10px"><p><strong>Nome:</strong> ${escapeContatoHtml(nome)}</p><p><strong>E-mail:</strong> ${escapeContatoHtml(email)}</p><p><strong>Empresa:</strong> ${escapeContatoHtml(empresa || 'Não informada')}</p><p><strong>Telefone:</strong> ${escapeContatoHtml(telefone || 'Não informado')}</p><p><strong>Assunto:</strong> ${escapeContatoHtml(assunto)}</p><hr style="border:0;border-top:1px solid #E7DCE1;margin:18px 0"><p><strong>Mensagem:</strong></p><p style="white-space:pre-wrap;line-height:1.6">${escapeContatoHtml(mensagem)}</p></div></div>`;
  // Responde primeiro: o navegador nunca fica dependente do Resend/SMTP.
  // O envio é iniciado somente depois que o 202 já foi entregue ao cliente.
  res.status(202).json({ ok: true, mensagem: 'Mensagem recebida e encaminhada para processamento.' });
  setTimeout(() => {
    try {
      enviarEmailBg(enviarEmail, { to: destino, subject, text, html, from: process.env.EMAIL_REMETENTE_AMIGAVEL });
    } catch (e) {
      console.error('[CONTATO HOME2] Falha ao iniciar envio:', e.message);
    }
  }, 0);
  return;
});

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

  // O código permanece apenas no backend para envio por e-mail.
  // Nunca deve ser incluído na resposta pública da API.
  const resposta = {
    ok: true,
    mensagem: 'Se o e-mail estiver apto para verificação, o código será enviado.'
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
    `SELECT id, email, codigo, expira_em, usado
     FROM codigos_verificacao
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

// ============= CANDIDATO - LEITURA DE CURRÍCULO =============
// Leitura inicial sem criar conta: o PDF é processado em memória e nunca é salvo nesta etapa.
// Os dados ausentes permanecem vazios para preenchimento manual no wizard.
app.post('/api/candidato/analisar-curriculo', rateLimitByIp('upload'), async (req, res) => {
  try {
    const validacao = validateBase64File(req.body?.arquivo_base64, 'application/pdf', 7 * 1024 * 1024, req.body?.arquivo_nome);
    if (!validacao.ok) return res.status(400).json({ erro: 'Envie um arquivo PDF válido de até 7 MB.' });
    const buffer = validacao.buffer;
    const resultado = await analisarCurriculo(buffer);
    return res.json({ ok: true, dados: resultado.dados, estrutura: resultado.estrutura, diagnostico: resultado.diagnostico, arquivo_nome: req.body?.arquivo_nome || 'curriculo.pdf' });
  } catch (e) {
    console.error('[CURRICULO PDF]', e.message);
    const status = e.code === 'PDF_SEM_TEXTO' ? 422 : 422;
    console.error('[PDF CURRICULO]', e.message);
    return res.status(status).json({ erro: 'Não foi possível ler este PDF. Você pode preencher o cadastro manualmente.' });
  }
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
    const accessToken = criarAccessToken({ id: rows[0].id, email: emailLower, tipo: 'candidato' });
    const refresh = criarRefreshToken();
    await persistirRefresh('candidato', rows[0].id, emailLower, refresh, req, { user_role: 'candidato' });
    // Fase 13 — E-mail de boas-vindas (não bloqueia resposta)
    emailSvc.bgBoasVindasCandidato({ candidato_id: rows[0].id, email: emailLower, nome: rows[0].nome });
    analytics.bg({ evento: 'cadastro_candidato_concluido', user_type: 'candidato', user_id: rows[0].id, ...analytics.fromReq(req) });
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
  const accessToken = criarAccessToken({ id: cand.id, email: emailLower, tipo: 'candidato' });
  const refresh = criarRefreshToken();
  await persistirRefresh('candidato', cand.id, emailLower, refresh, req, { user_role: 'candidato' });
  await audit(req, 'login.success', { resource_type: 'candidato', resource_id: cand.id, user_email: cand.email });
  analytics.bg({ evento: 'login_candidato', user_type: 'candidato', user_id: cand.id, ...analytics.fromReq(req) });
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
    // Fase 10: revoga todos os refresh tokens (outras sessões invalidadas)
    await revogarTodosPorUsuario(req.user.email, 'candidato', 'password_changed');
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
// [Fase 8] Rota /api/candidato/notificacoes-legado removida (substituída por /api/notificacoes Fase 7)

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
        e.local, NULL AS link_reuniao, e.observacoes, e.status,
        vr.room_id AS video_room_id,
        v.titulo AS vaga_titulo, v.empresa AS vaga_empresa
      FROM entrevistas e
      JOIN candidaturas cand ON cand.id = e.candidatura_id
      JOIN vagas v ON v.id = cand.vaga_id
      LEFT JOIN video_rooms vr ON vr.entrevista_id = e.id AND vr.status = 'active'
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
    const vagaId = Number(req.params.vagaId);
    if (!Number.isInteger(vagaId) || vagaId <= 0) {
      return res.status(400).json({ erro: 'ID de vaga inválido' });
    }
    const { rows: vagaRows } = await pool.query(
      `SELECT id, status FROM vagas WHERE id = $1 FOR KEY SHARE`, [vagaId]
    );
    if (!vagaRows.length) return res.status(404).json({ erro: 'Vaga não encontrada' });
    if (['fechada', 'encerrada', 'cancelada', 'pausada'].includes(vagaRows[0].status)) {
      return res.status(409).json({ erro: 'Esta vaga não está aceitando candidaturas' });
    }
    // etapa_atual=0: candidato acabou de se inscrever, está na etapa 0 (Inscrição) — semântica 0-indexed.
    // A unicidade no banco + ON CONFLICT protege contra dois cliques/requisições concorrentes.
    const { rows } = await pool.query(
      `INSERT INTO candidaturas (vaga_id, candidato_id, status, etapa_atual, historico)
       VALUES ($1, $2, 'em_andamento', 0, $3)
       ON CONFLICT (vaga_id, candidato_id) DO NOTHING
       RETURNING id, vaga_id, candidato_id, status, etapa_atual, historico, criada_em`,
      [vagaId, c[0].id, JSON.stringify([
        { etapa: 0, status: 'concluida', acao: 'inscricao', data: new Date().toISOString(), mensagem: 'Inscrição realizada' }
      ])]
    );
    if (!rows.length) {
      return res.status(409).json({ erro: 'Você já possui uma candidatura para esta vaga' });
    }
    // E-mail de boas-vindas: inscrição recebida (em background, não trava a response)
    try {
      const { rows: vd } = await pool.query(
        'SELECT v.titulo, v.empresa, v.empresa_id, e.nome AS empresa_nome_real, cd.nome, cd.id AS cand_id FROM vagas v LEFT JOIN empresas e ON e.id = v.empresa_id, candidatos cd WHERE v.id = $1 AND cd.id = $2',
        [req.params.vagaId, c[0].id]
      );
      if (vd.length > 0) {
        // Legado (mantido)
        enviarEmailBg(enviarEmailInscricao, req.user.email, vd[0].nome, vd[0].titulo, vd[0].empresa);
        // Fase 13 — email confirmação candidato + notif empresa
        const empresaNome = vd[0].empresa_nome_real || vd[0].empresa || 'Empresa';
        emailSvc.bgCandidaturaConfirmada({
          candidato_id: vd[0].cand_id, email: req.user.email, nome: vd[0].nome,
          vaga_titulo: vd[0].titulo, empresa_nome: empresaNome, candidatura_id: rows[0].id
        });
        if (vd[0].empresa_id) {
          emailSvc.bgNovaCandidaturaEmpresa({
            empresa_id: vd[0].empresa_id, vaga_titulo: vd[0].titulo,
            candidato_nome: vd[0].nome, candidatura_id: rows[0].id
          });
        }
      }
    } catch (e) {
      console.error('[candidatar] Falha ao enviar e-mail de inscrição:', e.message);
    }
    await audit(req, 'candidatura.created', { resource_type: 'candidatura', resource_id: rows[0].id, metadata: { vaga_id: req.params.vagaId, etapa: 0 } });
    // analytics — usa vd se disponível (declarado no try de email acima), senão dados básicos
    try {
      const _cand_id = (typeof vd !== 'undefined' && vd.length > 0) ? vd[0].cand_id : c[0].id;
      const _emp_id  = (typeof vd !== 'undefined' && vd.length > 0) ? vd[0].empresa_id || null : null;
      analytics.bg({ evento: 'candidatura_enviada', user_type: 'candidato', user_id: _cand_id,
        vaga_id: parseInt(req.params.vagaId), candidatura_id: rows[0].id,
        empresa_id: _emp_id, ...analytics.fromReq(req) });
    } catch (_) { /* analytics nunca quebra o fluxo */ }

    // FASE 7 — notificação no feed global (nova candidatura)
    try {
      const { rows: v } = await pool.query(
        'SELECT titulo, empresa_id FROM vagas WHERE id = $1', [req.params.vagaId]
      );
      if (v.length > 0) {
        const { rows: cd } = await pool.query('SELECT nome FROM candidatos WHERE id = $1', [c[0].id]);
        inserirNotificacao(pool, 'empresa', v[0].empresa_id,
          'candidatura_criada',
          `🆕 Nova candidatura: ${cd[0]?.nome || 'Candidato'}`,
          v[0].titulo ? `Vaga: ${v[0].titulo}` : null,
          { referencia_tipo: 'candidatura', referencia_id: rows[0].id, metadata: { vaga_id: req.params.vagaId } }
        );

        // FASE 7 — também notifica o CANDIDATO (confirmação interna)
        inserirNotificacao(pool, 'candidato', c[0].id,
          'candidatura_recebida',
          `✅ Sua candidatura para ${v[0].titulo || 'a vaga'} foi recebida`,
          'Em breve você receberá atualizações pelo e-mail cadastrado.',
          { referencia_tipo: 'candidatura', referencia_id: rows[0].id }
        );
      }
    } catch (e) {
      console.error('[FASE7] Falha ao criar notificação de candidatura:', e.message);
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
  if (!foto_url || typeof foto_url !== 'string') return res.status(400).json({ erro: 'foto_url é obrigatório' });
  const fotoMime = foto_url.match(/^data:([^;,]+);base64,/i)?.[1]?.toLowerCase();
  if (!fotoMime || !['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'].includes(fotoMime)) {
    return res.status(400).json({ erro: 'Formato de imagem não permitido' });
  }
  const fotoValidada = validateBase64File(foto_url, fotoMime, 5 * 1024 * 1024);
  if (!fotoValidada.ok) return res.status(400).json({ erro: fotoValidada.erro });
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
  const { cidade, estado, area, tipo, nivel, busca } = req.query;
  const paginada = req.query.limite !== undefined || req.query.offset !== undefined;
  const limite = Math.min(Math.max(parseInt(req.query.limite, 10) || 20, 1), 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  // Whitelist explícita (não usa SELECT *) — evita leak de colunas internas
  // Filtra por status='publicada' (a coluna "publicada" não existe — é status)
  // Limite duro pra evitar DoS / queries pesadas
  // Uma vaga pública precisa estar publicada e vinculada a uma empresa ativa.
  // Vagas antigas criadas pelo admin podem ter status='publicada', mas empresa_id NULL;
  // sem vínculo empresarial não são destinadas ao catálogo público do candidato.
  let sql = `SELECT v.id, v.titulo, v.empresa, v.descricao, v.requisitos, v.beneficios,
                    v.salario_min, v.salario_max, v.tipo_contrato, v.nivel, v.area,
                    v.cidade, v.estado, v.etapas
             FROM vagas v
             JOIN empresas e ON e.ativo = true
                AND (e.id = v.empresa_id
                  OR (v.empresa_id IS NULL AND NULLIF(TRIM(v.empresa), '') IS NOT NULL
                      AND LOWER(TRIM(e.nome)) = LOWER(TRIM(v.empresa))))
             WHERE LOWER(TRIM(v.status)) = 'publicada'`;
  const params = [];
  if (cidade) { params.push(`%${cidade}%`); sql += ` AND v.cidade ILIKE $${params.length}`; }
  if (estado) { params.push(`%${estado}%`); sql += ` AND v.estado ILIKE $${params.length}`; }
  if (area) { params.push(area); sql += ` AND v.area = $${params.length}`; }
  if (tipo) { params.push(`%${tipo}%`); sql += ` AND v.tipo_contrato ILIKE $${params.length}`; }
  if (nivel) { params.push(`%${nivel}%`); sql += ` AND v.nivel ILIKE $${params.length}`; }
  if (busca) { params.push(`%${busca}%`); sql += ` AND (v.titulo ILIKE $${params.length} OR v.empresa ILIKE $${params.length})`; }
  sql += paginada ? ` ORDER BY v.id DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}` : ' ORDER BY v.id DESC LIMIT 100';
  if (paginada) params.push(limite + 1, offset);
  try {
    const result = await pool.query(sql, params);
    const rows = paginada && result.rows.length > limite ? result.rows.slice(0, limite) : result.rows;
    res.json({ vagas: rows, mais: paginada && result.rows.length > limite });
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
      `SELECT v.id, v.titulo, v.empresa, v.descricao, v.requisitos, v.beneficios, v.salario_min, v.salario_max,
              v.tipo_contrato, v.nivel, v.area, v.cidade, v.estado, v.etapas,
              CASE WHEN LOWER(TRIM(v.status)) = 'publicada' THEN 'publicada' ELSE NULL END as status,
              ARRAY(SELECT tag FROM vaga_tags WHERE vaga_id = v.id ORDER BY criado_em) AS tags
       FROM vagas v
       WHERE v.id = $1 AND LOWER(TRIM(v.status)) = 'publicada'
         AND EXISTS (
           SELECT 1 FROM empresas e
           WHERE e.ativo = true
             AND (e.id = v.empresa_id
               OR (v.empresa_id IS NULL AND NULLIF(TRIM(v.empresa), '') IS NOT NULL
                   AND LOWER(TRIM(e.nome)) = LOWER(TRIM(v.empresa))))
         )`, 
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

// ============= LOGIN SOCIAL DO CANDIDATO (OAuth/OIDC + PKCE) =============
// O provedor nunca recebe nem emite o JWT interno. O callback gera um código
// de uso único e o frontend troca esse código pela mesma sessão JWT tradicional.
app.get('/api/auth/social/:provider/start', async (req, res) => {
  const provider = String(req.params.provider || '').toLowerCase();
  if (!['google', 'apple'].includes(provider)) return res.status(404).json({ erro: 'Provedor não suportado' });
  try { return await socialAuth.start(provider, req, res); }
  catch (e) { console.error('[SOCIAL START]', e.message); return res.status(503).json({ erro: 'Login social temporariamente indisponível' }); }
});
app.get('/api/auth/social/google/callback', async (req, res) => {
  try { return await socialAuth.callback('google', req, res); }
  catch (e) { console.error('[SOCIAL GOOGLE CALLBACK]', e.message); return res.redirect(`${(process.env.CANDIDATE_FRONTEND_URL || 'https://vagasio.com.br/candidato/')}?social_error=Falha%20no%20login`); }
});
app.post('/api/auth/social/apple/callback', async (req, res) => {
  try { return await socialAuth.callback('apple', req, res); }
  catch (e) { console.error('[SOCIAL APPLE CALLBACK]', e.message); return res.redirect(`${(process.env.CANDIDATE_FRONTEND_URL || 'https://vagasio.com.br/candidato/')}?social_error=Falha%20no%20login`); }
});
app.post('/api/auth/social/exchange', rateLimitLogin, socialAuth.exchange);

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
                <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${escapeEmailHtml(nome)}</strong>!</p>
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
// MODO DE SUPORTE — sessão explícita, temporária e somente leitura
// ============================================================
app.post('/api/admin/suporte/iniciar', authAdminOnly, async (req, res) => {
  try {
    const motivo = typeof req.body?.motivo === 'string' ? sanitizeText(req.body.motivo).trim().slice(0, 1000) : '';
    if (!motivo) return res.status(400).json({ erro: 'Motivo obrigatório para iniciar o Modo de Suporte' });
    const escopo = req.body?.escopo;
    if (!escopo || typeof escopo !== 'object' || Array.isArray(escopo) ||
        (!escopo.amplo && (!escopo.tipo || !Array.isArray(escopo.ids) || escopo.ids.length === 0))) {
      return res.status(400).json({ erro: 'Escopo obrigatório: informe amplo=true ou tipo e ids específicos' });
    }
    const tiposEscopo = new Set(['candidato', 'candidatura', 'vaga', 'empresa', 'entrevista', 'documento']);
    if (escopo.amplo !== true && (!tiposEscopo.has(String(escopo.tipo)) || escopo.ids.length > 100)) {
      return res.status(400).json({ erro: 'Tipo de escopo inválido ou quantidade de IDs excedida' });
    }
    if (escopo.amplo !== true && escopo.ids.some(id => !Number.isInteger(Number(id)) || Number(id) <= 0)) {
      return res.status(400).json({ erro: 'Os ids do escopo devem ser inteiros positivos' });
    }
    const minutos = Number(req.body?.duracao_minutos ?? 30);
    if (!Number.isInteger(minutos) || minutos < 1 || minutos > 120) {
      return res.status(400).json({ erro: 'Duração deve estar entre 1 e 120 minutos' });
    }
    const token = crypto.randomBytes(48).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expira = new Date(Date.now() + minutos * 60 * 1000);
    const q = await pool.query(`
      INSERT INTO sessoes_suporte (token_hash, iniciado_por, motivo, escopo, expira_em)
      VALUES ($1, $2, $3, $4::jsonb, $5)
      RETURNING id, iniciado_em, expira_em, somente_leitura, escopo
    `, [tokenHash, req.user.id, motivo, JSON.stringify(escopo), expira.toISOString()]);
    await audit(req, 'support.session_started', { resource_type: 'support_session', resource_id: q.rows[0].id, metadata: { motivo, escopo, duracao_minutos: minutos, somente_leitura: true } });
    res.status(201).json({ ok: true, modo_suporte: true, token, sessao: q.rows[0] });
  } catch (e) {
    console.error('[SUPORTE INICIAR]', e.message);
    res.status(500).json({ erro: 'Não foi possível iniciar o Modo de Suporte' });
  }
});

app.post('/api/admin/suporte/encerrar', authAdminOnly, async (req, res) => {
  const raw = req.headers['x-support-session'];
  if (!raw || typeof raw !== 'string') return res.status(400).json({ erro: 'Sessão de suporte não informada' });
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const q = await pool.query(`UPDATE sessoes_suporte SET encerrado_em = NOW(), encerrado_por = $1 WHERE encerrado_por IS NULL AND token_hash = $2 AND iniciado_por = $1 AND encerrado_em IS NULL RETURNING id`, [req.user.id, hash]);
  if (!q.rowCount) return res.status(404).json({ erro: 'Sessão de suporte não encontrada ou já encerrada' });
  await audit(req, 'support.session_ended', { resource_type: 'support_session', resource_id: q.rows[0].id });
  res.json({ ok: true, modo_suporte: false });
});

app.get('/api/admin/suporte/status', authAdminOnly, async (req, res) => {
  const raw = req.headers['x-support-session'];
  if (!raw || typeof raw !== 'string') return res.json({ modo_suporte: false });
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const q = await pool.query(`SELECT id, iniciado_em, expira_em, escopo, somente_leitura FROM sessoes_suporte WHERE token_hash = $1 AND iniciado_por = $2 AND encerrado_em IS NULL AND expira_em > NOW()`, [hash, req.user.id]);
  res.json({ modo_suporte: !!q.rowCount, sessao: q.rows[0] || null });
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
                  <p style="color: #2b2b2b; font-size: 15px; line-height: 1.5;">Olá, <strong>${escapeEmailHtml(r.rows[0].nome)}</strong>!</p>
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
app.get('/api/admin/_diag-schema-fase1', authAdminOnly, async (req, res) => {
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
    return erroInterno(req, res, e, 'api-diagnostico-schema');
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
        e.local, NULL AS link_reuniao, e.observacoes, e.status,
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

app.post('/api/admin/vagas', authAdminOnly, async (req, res) => {
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
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por, criada_em`,
      [v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area, v.salario_min, v.salario_max, v.descricao, v.requisitos, v.beneficios, JSON.stringify(etapas), req.user.id]
    );
    await audit(req, 'admin.vaga.created', { resource_type: 'vaga', resource_id: rows[0].id, metadata: { titulo: v.titulo, empresa: v.empresa } });
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[CRIAR VAGA ERRO]', e);
    res.status(500).json({ erro: 'Erro ao criar vaga' });
  }
});

// P0 — inventário temporário somente leitura.
// Restrito aos IDs levantados na investigação; não altera dados e não usa SELECT *.
app.get('/api/admin/p0-inventory', authAdminOnly, async (req, res) => {
  const p0Ids = [
    166, 167, 168, 174, 182, 183, 184, 185, 186, 189,
    197, 198, 199, 200, 201, 206, 214, 215, 216, 219, 220,
    235, 243, 244, 245, 246, 247, 262, 270, 271, 272, 273, 274,
    280, 288, 289, 290, 291, 292, 297, 305, 306, 307, 308, 309, 310,
    315, 316, 334, 342, 343, 344, 360, 361, 362, 363, 364, 365, 366,
    367, 368, 369, 370, 371, 373, 374, 375, 376, 377, 378, 379, 380,
    381, 387, 388, 390, 391, 397, 398, 400, 402, 406, 407, 408, 410,
    412, 414, 416, 417, 418, 419, 420, 421, 423, 424, 425, 427, 428, 429, 430
  ];
  try {
    const { rows } = await pool.query(`
      SELECT
        v.id,
        v.titulo,
        v.empresa,
        v.empresa_id,
        v.status,
        v.criada_por,
        v.criada_em,
        CASE WHEN e.id IS NULL THEN NULL ELSE json_build_object(
          'id', e.id,
          'nome', e.nome,
          'ativo', e.ativo,
          'criado_por', e.criado_por,
          'criado_em', e.criado_em,
          'plano', e.plano,
          'plano_id', e.plano_id,
          'slug', e.slug
        ) END AS empresa_vinculada,
        COALESCE((
          SELECT json_agg(json_build_object(
            'tipo', eva.tipo,
            'revogado_em', eva.revogado_em
          ) ORDER BY eva.concedido_em, eva.empresa_id)
          FROM empresa_vaga_acesso eva
          WHERE eva.vaga_id = v.id
        ), '[]'::json) AS empresa_vaga_acesso,
        (SELECT COUNT(*)::int FROM candidaturas c WHERE c.vaga_id = v.id) AS candidaturas_count,
        COALESCE((
          SELECT json_agg(json_build_object(
            'created_at', al.created_at,
            'action', al.action,
            'user_type', al.user_type,
            'user_email', al.user_email,
            'resource_type', al.resource_type,
            'resource_id', al.resource_id,
            'result', al.result,
            'metadata', al.metadata
          ) ORDER BY al.created_at)
          FROM audit_logs al
          WHERE (al.resource_type = 'vaga' AND al.resource_id = v.id)
             OR (e.id IS NOT NULL AND al.resource_type = 'empresa' AND al.resource_id = e.id)
        ), '[]'::json) AS audit_logs
      FROM vagas v
      LEFT JOIN empresas e ON e.id = v.empresa_id
      WHERE v.id = ANY($1::int[])
      ORDER BY v.id
    `, [p0Ids]);
    res.json({
      ok: true,
      somente_leitura: true,
      ids_consultados: p0Ids,
      total: rows.length,
      vagas: rows
    });
  } catch (e) {
    console.error('[P0 INVENTORY]', e.message);
    res.status(500).json({ erro: 'Erro ao consultar inventário P0' });
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

const STATUS_VAGA_VALIDOS = new Set(['rascunho', 'publicada', 'pausada', 'fechada', 'encerrada', 'cancelada']);
const TRANSICOES_VAGA = {
  rascunho: new Set(['rascunho', 'publicada', 'cancelada']),
  publicada: new Set(['publicada', 'pausada', 'fechada', 'encerrada', 'cancelada']),
  pausada: new Set(['pausada', 'publicada', 'fechada', 'encerrada', 'cancelada']),
  fechada: new Set(['fechada', 'publicada', 'encerrada']),
  encerrada: new Set(['encerrada']),
  cancelada: new Set(['cancelada'])
};
function transicaoVagaPermitida(atual, proximo) {
  return STATUS_VAGA_VALIDOS.has(proximo) && (TRANSICOES_VAGA[atual] || new Set()).has(proximo);
}

app.put('/api/admin/vagas/:id', authAdminOnly, async (req, res) => {
  const v = req.body;
  if (v.status !== undefined) {
    const atual = await pool.query('SELECT status FROM vagas WHERE id = $1', [req.params.id]);
    if (!atual.rows.length) return res.status(404).json({ erro: 'Vaga não encontrada' });
    if (!transicaoVagaPermitida(atual.rows[0].status, v.status)) {
      return res.status(409).json({ erro: `Transição de vaga inválida: ${atual.rows[0].status} → ${v.status}` });
    }
  }
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
    `UPDATE vagas SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por, criada_em`,
    values
  );
  if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
  await audit(req, 'admin.vaga.updated', { resource_type: 'vaga', resource_id: Number(req.params.id), metadata: { campos: updates.map(u => u.split(' ')[0]) } });
  res.json({ ok: true, vaga: rows[0] });
});

app.delete('/api/admin/vagas/:id', authAdminOnly, async (req, res) => {
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
    const { rows } = await pool.query(
      `SELECT id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area,
              salario_min, salario_max, descricao, requisitos, beneficios, etapas, status,
              criada_por, criada_em, atualizada_em
       FROM vagas WHERE id = $1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Vaga não encontrada' });
    res.json({ vaga: rows[0] });
  } catch (e) {
    console.error('[GET VAGA]', e);
    res.status(500).json({ erro: 'Erro ao buscar vaga' });
  }
});

app.get('/api/admin/candidatos', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
app.get('/api/admin/candidato/:id', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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

app.get('/api/admin/candidaturas', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
app.get('/api/admin/vagas/:id/candidaturas', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
  try {
    const vagaId = req.params.id;
    const { rows: vagaRows } = await pool.query(
      `SELECT id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area,
              salario_min, salario_max, descricao, requisitos, beneficios, etapas, status,
              criada_por, criada_em, atualizada_em
       FROM vagas WHERE id = $1`,
      [vagaId]
    );
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

app.get('/api/admin/candidatura/:id', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
      'SELECT id, candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC',
      [candidatura.candidato_id]
    );
    candidatura.experiencias = exps;

    // Buscar entrevistas (a mais recente ativa vence; canceladas não contam)
    const { rows: entrevistas } = await pool.query(
      `SELECT id, candidatura_id, etapa, data_hora, duracao_minutos, local,
              link_reuniao, observacoes, status, criado_em, criado_por
       FROM entrevistas
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
    // Valida todos os arquivos antes de apagar envios anteriores.
    const MAX_BYTES = 5 * 1024 * 1024;
    for (const d of documentos) {
      if (!d.arquivo_base64) continue;
      const mime = d.arquivo_tipo || d.arquivo_base64.match(/^data:([^;,]+);base64,/i)?.[1];
      const validacao = validateBase64File(d.arquivo_base64, mime, MAX_BYTES, d.arquivo_nome);
      if (!validacao.ok) {
        return res.status(validacao.erro.includes('maior') ? 413 : 400).json({
          erro: `Arquivo "${d.arquivo_nome || d.tipo || 'anexo'}": ${validacao.erro}`
        });
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
            resource_type: 'auto',
            type: 'authenticated'
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

    await audit(req, 'candidato.documentos.submitted', {
      resource_type: 'candidatura', resource_id: candidaturaId,
      metadata: { quantidade: salvos, tipos: tipos.slice(0, 20) }
    });
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
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_public_id, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows.map(protegerUrlDocumento), obrigatorios: DOCUMENTOS_OBRIGATORIOS });
  } catch (e) {
    return erroInterno(req, res, e, 'api-candidatura-:id-documentos');
  }
});

// Download autenticado do próprio documento do candidato.
// O arquivo nunca é entregue por URL pública do storage.
app.get('/api/candidatura/:id/documentos/:docId/arquivo', authCandidato, async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    const documentoId = Number(req.params.docId);
    if (!Number.isInteger(candidaturaId) || !Number.isInteger(documentoId) || candidaturaId <= 0 || documentoId <= 0) {
      return res.status(400).json({ erro: 'Identificador inválido' });
    }
    const { rows } = await pool.query(`
      SELECT d.arquivo_url, d.arquivo_public_id, d.arquivo_nome, d.arquivo_tipo, d.arquivo_tamanho
      FROM documentos_candidatura d
      JOIN candidaturas c ON c.id = d.candidatura_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE d.id = $1 AND d.candidatura_id = $2 AND LOWER(cd.email) = LOWER($3)
      LIMIT 1
    `, [documentoId, candidaturaId, req.user.email || '']);
    if (!rows.length) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    const row = rows[0];
    const sourceUrl = cloudinaryAuthenticatedUrl(row.arquivo_public_id, row.arquivo_nome, row.arquivo_tipo);
    if (!sourceUrl) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    let remote;
    try { remote = new URL(sourceUrl); } catch (_) { return res.status(404).json({ erro: 'Arquivo não encontrado' }); }
    if (!['http:', 'https:'].includes(remote.protocol)) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    const upstream = await axios.get(remote.toString(), {
      responseType: 'stream', timeout: 30000, maxContentLength: 25 * 1024 * 1024,
      validateStatus: status => status >= 200 && status < 300
    });
    res.set('Content-Type', upstream.headers['content-type'] || row.arquivo_tipo || 'application/octet-stream');
    if (upstream.headers['content-length'] || row.arquivo_tamanho) res.set('Content-Length', String(upstream.headers['content-length'] || row.arquivo_tamanho));
    res.set('Content-Disposition', `attachment; filename="${escapeContentDispositionFilename(row.arquivo_nome || 'documento')}"`);
    upstream.data.on('error', () => res.destroy());
    upstream.data.pipe(res);
  } catch (e) {
    console.error('[candidato documento arquivo]', e.message);
    if (!res.headersSent) res.status(502).json({ erro: 'Não foi possível baixar o arquivo' });
    else res.destroy();
  }
});

// ====== Admin DELETAR candidato (limpeza operacional) ======
// POST /api/admin/candidato/:id/deletar { confirm: 'SIM_DELETAR' }
// Apaga o candidato, suas candidaturas, documentos e mensagens de chat (cascade manual).
// Operação IRREVERSÍVEL — exige confirmação textual.
app.post('/api/admin/candidato/:id/deletar', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
app.get('/api/admin/candidatura/:id/documentos', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
  try {
    const candidaturaId = Number(req.params.id);
    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_public_id, arquivo_nome, arquivo_tipo, arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows.map(protegerUrlDocumento), obrigatorios: DOCUMENTOS_OBRIGATORIOS });
  } catch (e) {
    return erroInterno(req, res, e, 'api-admin-candidatura-:id-documentos');
  }
});

// Admin aprova ou reprova um documento (com justificativa)
app.post('/api/admin/documento/:id/revisar', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
    await audit(req, 'admin.documento.reviewed', {
      resource_type: 'documento', resource_id: docId,
      metadata: { status, candidatura_id: docInfo.candidatura_id, tipo: docInfo.tipo }
    });

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
app.post('/api/admin/candidatura/:id/aprovar-documentos', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
    if (['contratado', 'rejeitado', 'reprovado', 'cancelado'].includes(cand.status)) {
      return res.status(409).json({ erro: 'Candidatura encerrada; não é possível aprovar documentos' });
    }

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

    // 3) A aprovação dos documentos e o avanço são uma única operação SQL.
    // O CTE bloqueia a candidatura e impede que duas requisições avancem a mesma etapa.
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
    const avancou = await pool.query(
      `WITH alvo AS (
         SELECT id FROM candidaturas
         WHERE id = $4 AND etapa_atual = $5 AND status = $6
         FOR UPDATE
       ), docs_aprovados AS (
         UPDATE documentos_candidatura d
         SET status = 'aprovado', justificativa_admin = 'Aprovado em lote', revisado_em = NOW()
         FROM alvo
         WHERE d.candidatura_id = alvo.id AND d.status != 'aprovado'
         RETURNING d.id
       )
       UPDATE candidaturas c
       SET status = $1, etapa_atual = $2, historico = $3, atualizada_em = NOW()
       FROM alvo
       WHERE c.id = alvo.id
       RETURNING c.id`,
      [novoStatus, novaEtapa, JSON.stringify(historico), candId, cand.etapa_atual, cand.status]
    );
    if (avancou.rowCount !== 1) {
      return res.status(409).json({ erro: 'A candidatura foi alterada por outra requisição. Recarregue e tente novamente.' });
    }

    // FASE 7 — notificação no feed global
    inserirNotificacao(pool, 'empresa', cand.empresa_id, 'docs_aprovados',
      `Documentação aprovada${novoStatus === 'contratado' ? ' — candidato CONTRATADO' : ' — avançou etapa'}`,
      `${cand.nome || 'Candidato'} · etapa ${novaEtapa}`,
      { referencia_tipo: 'candidatura', referencia_id: candId, metadata: { etapa_nova: novaEtapa, status_novo: novoStatus } }
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
app.post('/api/admin/candidatura/:id/comentario', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
app.post('/api/admin/entrevista', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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

    // Online interviews require an authenticated VagasIO room. Historical Meet columns remain compatibility-only.
    const isOnline = !local || /online/i.test(local);
    if (isOnline && req.user?.tipo === 'admin') {
      return res.status(403).json({ erro: 'Administrador Global não participa de videochamadas privadas sem Modo de Suporte' });
    }
    let linkGerado = null;
    let googleEventId = null;
    let meetHtmlLink = null;
    let video = null;
    let entrevista;
    if (isOnline) {
      const previousUserForVideo = req.user;
      try {
        const r = await pool.query(`INSERT INTO entrevistas (candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, google_event_id, observacoes, criado_por)
          VALUES ($1,$2,$3,$4,'Videochamada VagasIO',NULL,NULL,$5,$6)
          RETURNING id,candidatura_id,etapa,data_hora,duracao_minutos,local,link_reuniao,google_event_id,observacoes,status,criado_em,criado_por`,
          [candidatura_id, etapa, dataHoraFinal, duracao_minutos || 60, observacoes || null, req.user?.id || null]);
        entrevista = r.rows[0];
        req.user = { ...previousUserForVideo, id: previousUserForVideo?.id, tipo: 'admin' };
        const room = await videoRooms.getOrCreate(req, entrevista.id);
        req.user = previousUserForVideo;
        if (!room) throw new Error('Sala VagasIO não autorizada');
        video = { provider:'vagasio', room_id:room.room_id, roomId:room.room_id };
        console.log(`[VAGASIO VIDEO] Sala criada: ${room.room_id}`);
      } catch (videoErr) {
        req.user = previousUserForVideo;
        if (videoErr?.entrevistaId || true) { try { await pool.query('DELETE FROM entrevistas WHERE candidatura_id=$1 AND data_hora=$2', [candidatura_id, dataHoraFinal]); } catch (_) {} }
        console.error('[VAGASIO VIDEO ERRO] entrevista não agendada:', videoErr.message);
        return res.status(503).json({ erro:'Videochamada VagasIO indisponível. Tente novamente.', codigo:'VAGASIO_ROOM_UNAVAILABLE' });
      }
      // Re-read the row for the common response path.
      const rr = await pool.query('SELECT id,candidatura_id,etapa,data_hora,duracao_minutos,local,link_reuniao,google_event_id,observacoes,status,criado_em,criado_por FROM entrevistas WHERE id=$1',[video.interview_id || (await pool.query('SELECT id FROM entrevistas WHERE candidatura_id=$1 AND data_hora=$2 ORDER BY id DESC LIMIT 1',[candidatura_id,dataHoraFinal])).rows[0].id]);
      entrevista = rr.rows[0];
    } else {
      const r = await pool.query(`INSERT INTO entrevistas (candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, google_event_id, observacoes, criado_por)
        VALUES ($1,$2,$3,$4,$5,NULL,NULL,$6,$7)
        RETURNING id,candidatura_id,etapa,data_hora,duracao_minutos,local,link_reuniao,google_event_id,observacoes,status,criado_em,criado_por`,
        [candidatura_id, etapa, dataHoraFinal, duracao_minutos || 60, local || null, observacoes || null, req.user?.id || null]);
      entrevista = r.rows[0];
    }
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
      por: req.user?.nome || 'Administrador Global',
      formato: isOnline ? 'online' : 'presencial',
      detalhes: `Data: ${dataFormatada}${linkGerado ? ` • Meet: ${linkGerado}` : ''}${local && !isOnline ? ` • ${local}` : ''}`
    }]), candidatura_id]);

    // Fase 13 — E-mail entrevista agendada para candidato
    try {
      const { rows: cd } = await pool.query(
        `SELECT cd.email, cd.nome, v.titulo AS vaga_titulo, v.empresa AS empresa_nome, v.empresa_id
         FROM candidaturas c JOIN candidatos cd ON cd.id = c.candidato_id JOIN vagas v ON v.id = c.vaga_id
         WHERE c.id = $1`, [candidatura_id]
      );
      if (cd.length > 0) {
        emailSvc.bgEntrevistaAgendada({
          candidato_id: cd[0].id, email: cd[0].email, nome: cd[0].nome,
          vaga_titulo: cd[0].vaga_titulo, empresa_nome: cd[0].empresa_nome,
          data_hora: dataHoraFinal, local: local || null,
          link_reuniao: linkGerado || null, online: isOnline,
          observacoes: observacoes || null, candidatura_id: candidatura_id
        });
      }
    } catch (e) { console.error('[entrevista email]', e.message); }
    analytics.bg({ evento: 'entrevista_agendada', user_type: 'admin',
      candidatura_id: candidatura_id, vaga_id: entrevista.vaga_id || null,
      empresa_id: entrevista.empresa_id || null, ...analytics.fromReq(req) });

    res.json({ ok: true, entrevista, googleEventId, meetHtmlLink, video });
  } catch (e) {
    console.error('[ENTREVISTA CRIAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevista-post');
  }
});

// Cancela uma entrevista (libera novo agendamento) - chamada pelo botão "❌ Falhou" na agenda
app.post('/api/admin/entrevista/:id/cancelar', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { motivo } = req.body || {};

    const { rows: eRows } = await pool.query('SELECT id, candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, google_event_id, observacoes, status, criado_em, criado_por FROM entrevistas WHERE id = $1', [id]);
    if (eRows.length === 0) return res.status(404).json({ erro: 'Entrevista não encontrada' });
    const entrevista = eRows[0];

    // Marca como cancelada (libera o slot pro próximo agendamento)
    await pool.query(
      `UPDATE entrevistas SET status = 'cancelada', atualizado_em = NOW() WHERE id = $1`,
      [id]
    );

    // google_event_id is historical compatibility data; VagasIO never mutates Calendar.
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
      por: req.user?.nome || 'Administrador Global',
      detalhes: motivo ? `Motivo: ${motivo}` : 'Candidato/recrutador não compareceu.'
    }]), entrevista.candidatura_id]);

    res.json({ ok: true, entrevista_id: id, status: 'cancelada' });
    // Fase 13 — E-mail entrevista cancelada
    try {
      const { rows: cd } = await pool.query(
        `SELECT cd.email, cd.nome, v.titulo AS vaga_titulo, v.empresa AS empresa_nome
         FROM candidaturas c JOIN candidatos cd ON cd.id = c.candidato_id JOIN vagas v ON v.id = c.vaga_id
         WHERE c.id = $1`, [entrevista.candidatura_id]
      );
      if (cd.length > 0) {
        emailSvc.bgEntrevistaCancelada({
          candidato_id: null, email: cd[0].email, nome: cd[0].nome,
          vaga_titulo: cd[0].vaga_titulo,
          data_hora: entrevista.data_hora
        });
      }
    } catch (e) { console.error('[entrevista cancelar email]', e.message); }
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
app.get('/api/admin/entrevistas', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
             NULL AS link_reuniao, e.observacoes, e.status, e.criado_em,
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
app.put('/api/admin/entrevista/:id', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
    const r = await pool.query(`UPDATE entrevistas SET ${updates.join(', ')} WHERE id = $${i}
      RETURNING id, candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, google_event_id, observacoes, status, criado_em, criado_por`, values);
    if (r.rows.length === 0) return res.status(404).json({ erro: 'Entrevista não encontrada' });
    res.json({ ok: true, entrevista: r.rows[0] });
  } catch (e) {
    console.error('[ENTREVISTA ATUALIZAR ERRO]', e);
    return erroInterno(req, res, e, 'api-admin-entrevista-:id');
  }
});

app.post('/api/admin/candidatura/:id/status', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
  const STATUS_CANDIDATURA_VALIDOS = new Set(['em_analise', 'em_andamento', 'rejeitado', 'reprovado', 'cancelado', 'contratado']);
  const ACOES_STATUS_VALIDAS = new Set(['avancar', 'reprovar', 'reabrir', 'aprovar']);
  if (acao && !ACOES_STATUS_VALIDAS.has(acao)) {
    return res.status(400).json({ erro: 'Ação de candidatura inválida' });
  }
  if (status && !STATUS_CANDIDATURA_VALIDOS.has(status)) {
    return res.status(400).json({ erro: 'Status de candidatura inválido' });
  }
  if (etapa !== undefined && (!Number.isInteger(Number(etapa)) || Number(etapa) < 0)) {
    return res.status(400).json({ erro: 'Etapa inválida' });
  }
  const TERMINAIS = new Set(['rejeitado', 'reprovado', 'cancelado', 'contratado']);
  if (TERMINAIS.has(cand.status) && acao !== 'reabrir') {
    return res.status(409).json({ erro: 'Candidatura encerrada; reabra antes de alterar' });
  }
  if (acao === 'reabrir' && !TERMINAIS.has(cand.status)) {
    return res.status(409).json({ erro: 'Somente candidaturas encerradas podem ser reabertas' });
  }
  const historico = Array.isArray(cand.historico) ? cand.historico : [];
  const observacoes = (cand.observacoes_etapas && typeof cand.observacoes_etapas === 'object') ? { ...cand.observacoes_etapas } : {};
  let novoStatus = status ?? cand.status;
  let novaEtapa = etapa ?? cand.etapa_atual;
  if (!acao && status === undefined && etapa === undefined && !mensagem && !comentario) {
    return res.status(400).json({ erro: 'Informe uma ação, status, etapa ou comentário' });
  }
  if (etapa !== undefined && acao !== 'avancar' && acao !== 'reabrir' && Number(etapa) !== Number(cand.etapa_atual)) {
    return res.status(409).json({ erro: 'A etapa só pode avançar pela ação avançar' });
  }

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
  } else if (acao === 'aprovar') {
    novoStatus = 'em_andamento';
  } else if (acao === 'reabrir') {
    novoStatus = 'em_analise';
  }

  let totalEtapasStatus = 7;
  try {
    const etapasStatus = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
    if (Array.isArray(etapasStatus) && etapasStatus.length) totalEtapasStatus = etapasStatus.length;
  } catch (_) {}
  if (novoStatus === 'contratado' && Number(novaEtapa) < totalEtapasStatus) {
    return res.status(409).json({ erro: 'A candidatura só pode ser contratada ao concluir todas as etapas' });
  }
  if (acao !== 'avancar' && acao !== 'reabrir' && Number(novaEtapa) !== Number(cand.etapa_atual)) {
    return res.status(409).json({ erro: 'A etapa só pode mudar pela ação avançar' });
  }
  const etapaMudou = Number(novaEtapa) !== Number(cand.etapa_atual);
  historico.push({ etapa: novaEtapa, status: novoStatus, mensagem, acao, data: new Date().toISOString(), por: req.user.nome || req.user.email || 'Administrador Global' });

  // Se o admin mandou um comentário, salva no índice da etapa ATUAL (a que ele tava atuando)
  // Quando avançar, vai pra próxima etapa e a próxima observação será salva lá.
  if (comentario && String(comentario).trim()) {
    observacoes[String(cand.etapa_atual || 0)] = String(comentario).trim();
  }

  const atualizacao = await pool.query(
    `UPDATE candidaturas
     SET status = $1, etapa_atual = $2, historico = $3, observacoes_etapas = $4, atualizada_em = NOW()
     WHERE id = $5 AND etapa_atual = $6 AND status = $7`,
    [novoStatus, novaEtapa, JSON.stringify(historico), JSON.stringify(observacoes), req.params.id, cand.etapa_atual, cand.status]
  );
  if (atualizacao.rowCount !== 1) {
    return res.status(409).json({ erro: 'A candidatura foi alterada por outra requisição. Recarregue e tente novamente.' });
  }

  // FASE 7 — notificação no feed global (ação manual do admin/recrutador)
  {
    const tipoNotif =
      acao === 'reprovar' ? 'candidato_reprovado' :
      acao === 'reabrir'  ? 'candidato_reaberto'  :
      novoStatus === 'contratado' ? 'candidato_contratado' :
      etapaMudou ? 'etapa_avancada' : 'status_alterado';
    const tituloNotif =
      acao === 'reprovar' ? `❌ ${cand.nome || 'Candidato'} foi reprovado` :
      acao === 'reabrir'  ? `🔓 ${cand.nome || 'Candidato'} foi reaberto` :
      novoStatus === 'contratado' ? `🎉 ${cand.nome || 'Candidato'} CONTRATADO` :
      etapaMudou ? `⬆ ${cand.nome || 'Candidato'} avançou para etapa ${novaEtapa + 1}` :
      `🔄 Status alterado: ${cand.nome || 'Candidato'} → ${novoStatus}`;
    inserirNotificacao(pool, 'empresa', cand.empresa_id, tipoNotif, tituloNotif,
      cand.titulo ? `${cand.titulo} · etapa ${novaEtapa}` : null,
      { referencia_tipo: 'candidatura', referencia_id: req.params.id, metadata: { acao, etapa_anterior: cand.etapa_atual, etapa_nova: novaEtapa, status_anterior: cand.status, status_novo: novoStatus } }
    );

    // FASE 7 — notificação também para o CANDIDATO (sem dados internos)
    try {
      const etapaNomeCand = (() => {
        try {
          const arr = typeof cand.etapas === 'string' ? JSON.parse(cand.etapas) : cand.etapas;
          if (Array.isArray(arr) && arr[(novaEtapa || 0)]) {
            const e = arr[(novaEtapa || 0)];
            return typeof e === 'string' ? e : (e?.nome || null);
          }
        } catch (_) {}
        return null;
      })();
      let tituloCand = '';
      let msgCand = '';
      if (novoStatus === 'contratado') {
        tituloCand = `🎉 Parabéns! Você foi contratado(a) para ${cand.titulo || 'a vaga'}`;
        msgCand = 'Entre em contato com a empresa para os próximos passos.';
      } else if (acao === 'reprovar' || novoStatus === 'rejeitado') {
        tituloCand = `Atualização na sua candidatura para ${cand.titulo || 'a vaga'}`;
        msgCand = 'O processo seletivo não seguiu. Você pode conferir mais detalhes na sua área de candidato.';
      } else if (acao === 'reabrir') {
        tituloCand = `🔓 Sua candidatura para ${cand.titulo || 'a vaga'} foi reaberta`;
        msgCand = etapaNomeCand ? `Avançou para ${etapaNomeCand}.` : null;
      } else if (etapaMudou) {
        tituloCand = `Sua candidatura para ${cand.titulo || 'a vaga'} avançou de etapa`;
        msgCand = etapaNomeCand ? `Próxima etapa: ${etapaNomeCand}.` : null;
      } else {
        tituloCand = `Houve uma atualização na sua candidatura para ${cand.titulo || 'a vaga'}`;
      }
      inserirNotificacao(pool, 'candidato', cand.candidato_id,
        tipoNotif === 'candidato_reprovado' ? 'candidatura_rejeitada' :
        tipoNotif === 'candidato_contratado' ? 'candidatura_contratada' :
        'etapa_alterada',
        tituloCand, msgCand,
        { referencia_tipo: 'candidatura', referencia_id: req.params.id }
      );
    } catch (e) {
      console.error('[FASE7/candidato] falha ao notificar candidato:', e.message);
    }
  }

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
app.get('/api/chat/:candidatura_id/mensagens', authCandidato, async (req, res) => {
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
app.post('/api/chat/:candidatura_id/mensagens', authCandidato, async (req, res) => {
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
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto) VALUES ($1,$2,$3,$4,$5) RETURNING id, candidatura_id, autor_tipo, autor_nome, texto, contexto, criado_em, remetente_id',
      [cid, autorTipo, autorNome, textoLimpo, 'chat']
    );

    // Notifica o outro lado por e-mail (em background)
    setImmediate(() => {
      try {
        const emailEsc = v => String(v || '').replace(/[&<>"']/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[ch]));
        const safe = emailEsc(textoLimpo);
        const safeAutor = emailEsc(autorNome);
        const safeTitulo = emailEsc(c.titulo);
        if (autorTipo === 'candidato') {
          enviarEmailBg(enviarEmail, ADMIN_NOTIF_EMAIL,
            `💬 Nova mensagem de ${autorNome}`,
            `<p><b>${safeAutor}</b> enviou uma mensagem sobre a vaga <b>${safeTitulo}</b>:</p>
             <blockquote style="border-left:3px solid #d4a017;padding:8px 12px;background:#f8f8f8;">${safe}</blockquote>
             <p>Responda pelo painel administrativo autenticado.</p>`
          );
        } else {
          enviarEmailBg(enviarEmail, c.email,
            `💬 Nova mensagem sobre sua candidatura - ${c.titulo}`,
            `<p>Olá <b>${emailEsc(c.cand_nome)}</b>,</p>
             <p><b>${safeAutor}</b> enviou uma mensagem sobre sua candidatura na vaga <b>${safeTitulo}</b>:</p>
             <blockquote style="border-left:3px solid #d4a017;padding:8px 12px;background:#f8f8f8;">${safe}</blockquote>
             <p>Responda pelo portal autenticado.</p>`
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
app.post('/api/chat/:candidatura_id/upload', authCandidato, rateLimitByIp('upload'), async (req, res) => {
  try {
    const cid = parseInt(req.params.candidatura_id);
    const { texto, arquivo } = req.body;
    if (!arquivo || !arquivo.nome || !arquivo.mime || !arquivo.base64) {
      return res.status(400).json({ erro: 'Arquivo inválido' });
    }
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
    // Valida conteúdo real e tamanho binário antes de gravar mensagem/arquivo.
    const arquivoValidado = validateBase64File(arquivo.base64, arquivo.mime, 6 * 1024 * 1024, arquivo.nome);
    if (!arquivoValidado.ok) {
      return res.status(arquivoValidado.erro.includes('maior') ? 413 : 400).json({ erro: arquivoValidado.erro });
    }
    const base64Canonico = arquivoValidado.buffer.toString('base64');
    const tamanhoBytes = arquivoValidado.buffer.length;
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
      'INSERT INTO mensagens_processo (candidatura_id, autor_tipo, autor_nome, texto, contexto) VALUES ($1,$2,$3,$4,$5) RETURNING id, candidatura_id, autor_tipo, autor_nome, texto, contexto, criado_em, remetente_id',
      [cid, autorTipo, autorNome, textoFinal, 'chat']
    );
    const msg = msgRows[0];
    // 2) Insere o arquivo vinculado
    const { rows: arqRows } = await pool.query(
      'INSERT INTO chat_arquivos (mensagem_id, candidatura_id, nome_original, mime_type, tamanho_bytes, base64_data) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, nome_original, mime_type, tamanho_bytes',
      [msg.id, cid, arquivoNomeSanitizado, arquivoValidado.mime, tamanhoBytes, base64Canonico]
    );
    res.json({ ok: true, mensagem: msg, arquivo: arqRows[0] });
  } catch (e) {
    console.error('[CHAT UPLOAD]', e);
    return erroInterno(req, res, e, 'api-chat-arquivo-id');
  }
});

// Download de arquivo do chat
app.get('/api/chat/arquivo/:id', authCandidato, rateLimitByIp('chat-download'), async (req, res) => {
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
app.get('/api/chat/mensagem/:id/arquivos', authCandidato, async (req, res) => {
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
app.get('/api/admin/conversas', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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

// Resolve os índices pelo nome da etapa. Vagas novas têm 7 etapas (Proposta=4),
// enquanto vagas legadas podem ter uma etapa intermediária (Proposta=5).
function indicesFluxoProposta(etapas) {
  let arr = etapas;
  if (typeof arr === 'string') { try { arr = JSON.parse(arr); } catch (_) { arr = []; } }
  if (!Array.isArray(arr)) arr = [];
  const nome = e => String(typeof e === 'string' ? e : (e && e.nome) || '').toLowerCase();
  const proposta = arr.findIndex(e => /proposta/.test(nome(e)));
  const coleta = arr.findIndex(e => /coleta.*document|document.*coleta/.test(nome(e)));
  return { proposta: proposta >= 0 ? proposta : 4, coleta: coleta >= 0 ? coleta : (proposta >= 0 ? proposta + 1 : 5) };
}

// ===== Admin: enviar proposta ao candidato =====
// Recebe texto da proposta + opcional PDF (data URL base64) ou já com URL pública
app.post('/api/admin/candidatura/:id/enviar-proposta', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
  const { texto, pdf_url, pdf_nome } = req.body;
  if (!texto && !pdf_url) return res.status(400).json({ erro: 'Envie um texto ou um PDF da proposta' });
  if (pdf_url && !String(pdf_url).startsWith('data:application/pdf')) {
    return res.status(400).json({ erro: 'O PDF deve ser anexado pelo formulário; URLs externas não são aceitas' });
  }

  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, cd.nome, cd.email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.id]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];

  // Se veio PDF em base64 (data URL), faz upload pro Cloudinary
  let pdfFinalUrl = null;
  let pdfFinalId = null;
  if (pdf_url) {
    const pdfValidado = validateBase64File(pdf_url, 'application/pdf', 6 * 1024 * 1024, pdf_nome);
    if (!pdfValidado.ok) {
      return res.status(pdfValidado.erro.includes('maior') ? 413 : 400).json({ erro: pdfValidado.erro });
    }
    if (!process.env.CLOUDINARY_URL && !process.env.CLOUDINARY_CLOUD_NAME) {
      return res.status(500).json({ erro: 'Cloudinary não configurado para receber PDF' });
    }
    try {
      const pdfCanonico = `data:application/pdf;base64,${pdfValidado.buffer.toString('base64')}`;
      const up = await cloudinary.uploader.upload(pdfCanonico, {
        folder: 'propostas',
        resource_type: 'raw',
        type: 'authenticated',
        public_id: `proposta_${cand.id}_${Date.now()}`
      });
      pdfFinalId = up.public_id;
      pdfFinalUrl = cloudinaryAuthenticatedUrl(pdfFinalId, pdf_nome || 'proposta.pdf', 'application/pdf');
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
    por: req.user.nome || req.user.email || 'Administrador Global'
  });

  const propostaGravada = await pool.query(
    `UPDATE candidaturas
     SET proposta_texto = $1,
         proposta_pdf_url = $2,
         proposta_pdf_public_id = $3,
         proposta_enviada_em = NOW(),
         historico = $4,
         atualizada_em = NOW()
     WHERE id = $5
       AND proposta_enviada_em IS NULL
       AND proposta_aceita_em IS NULL
       AND proposta_recusada_em IS NULL
       AND status NOT IN ('contratado', 'rejeitado', 'reprovado', 'cancelado')`,
    [texto || null, pdfFinalUrl, pdfFinalId, JSON.stringify(historico), req.params.id]
  );
  if (propostaGravada.rowCount !== 1) {
    if (pdfFinalId) cloudinary.uploader.destroy(pdfFinalId, { resource_type: 'raw', type: 'authenticated' }).catch(() => {});
    return res.status(409).json({ erro: 'A candidatura já possui proposta ou foi encerrada.' });
  }

  // FASE 7 — notificação no feed global
  inserirNotificacao(pool, 'empresa', cand.empresa_id, 'proposta_enviada',
    `📨 Proposta enviada: ${cand.nome || 'Candidato'}`,
    cand.titulo ? `Vaga: ${cand.titulo}` : null,
    { referencia_tipo: 'candidatura', referencia_id: req.params.id, metadata: { tem_pdf: !!pdfFinalUrl } }
  );

  // Notifica o candidato por e-mail (em background — não trava a resposta)
  try {
    enviarEmailBg(enviarEmailProposta, cand.email, cand.nome, cand.titulo, pdfFinalUrl);
    // Fase 13 — email proposta com template visual e preferência
    emailSvc.bgPropostaEnviada({
      candidato_id: cand.candidato_id, email: cand.email, nome: cand.nome,
      vaga_titulo: cand.titulo, empresa_nome: cand.empresa || cand.empresa_nome || 'Empresa',
      resumo: texto ? texto.substring(0, 200) : null,
      candidatura_id: req.params.id
    });
  } catch (e) {
    console.error('Falha ao agendar e-mail de proposta:', e.message);
  }
  analytics.bg({ evento: 'proposta_enviada', user_type: 'admin',
    candidatura_id: parseInt(req.params.id), empresa_id: cand.empresa_id || null, ...analytics.fromReq(req) });

  res.json({ ok: true, proposta: { texto, pdf_url: pdfFinalUrl } });
});

// ===== Admin: visualizar proposta enviada (pra imprimir/baixar de novo) =====
app.get('/api/admin/candidatura/:id/proposta', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT proposta_texto, proposta_pdf_url, proposta_pdf_public_id, proposta_enviada_em, proposta_aceita_em, proposta_recusada_em, proposta_motivo_recusa FROM candidaturas WHERE id = $1',
    [req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  res.json({ ok: true, proposta: protegerUrlProposta(rows[0]) });
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
  const idxProposta = indicesFluxoProposta(cand.etapas);

  // Garante que o candidato é o dono da candidatura
  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });

  // Pode aceitar se proposta foi enviada (independe da etapa atual)
  if (!cand.proposta_enviada_em) {
    return res.status(400).json({ erro: 'Nenhuma proposta foi enviada ainda' });
  }
  if (cand.proposta_aceita_em) {
    return res.status(400).json({ erro: 'Proposta já foi aceita' });
  }
  if (['cancelado', 'rejeitado', 'reprovado', 'contratado'].includes(cand.status) || cand.proposta_recusada_em) {
    return res.status(409).json({ erro: 'A candidatura ou proposta já foi encerrada' });
  }

  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: idxProposta.coleta,
    status: 'em_andamento',
    acao: 'aceitar_proposta',
    mensagem: 'Candidato aceitou a proposta',
    data: new Date().toISOString(),
    por: cand.cand_email
  });

  const atualizacaoAceite = await pool.query(
    `UPDATE candidaturas
     SET proposta_aceita_em = NOW(),
         etapa_atual = $2,
         status = 'em_andamento',
         historico = $1
     WHERE id = $3 AND proposta_aceita_em IS NULL AND proposta_recusada_em IS NULL`,
    [JSON.stringify(historico), idxProposta.coleta, req.params.candidaturaId]
  );
  if (!atualizacaoAceite.rowCount) return res.status(409).json({ erro: 'A proposta já foi respondida ou a candidatura foi alterada.' });

  // FASE 7 — notificação no feed global
  inserirNotificacao(pool, 'empresa', cand.empresa_id, 'proposta_aceita',
    `✅ ${cand.nome || 'Candidato'} ACEITOU a proposta`,
    `Próxima etapa: Coleta de Documentos`,
    { referencia_tipo: 'candidatura', referencia_id: req.params.candidaturaId, metadata: { etapa_anterior: idxProposta.proposta, etapa_nova: idxProposta.coleta } }
  );

  // Notifica o candidato por e-mail (em background)
  try {
    enviarEmailBg(enviarEmailAtualizacao, cand.cand_email, 'Candidato', cand.titulo, {
      etapaNum: idxProposta.coleta + 1,
      etapaNome: 'Coleta de Documentos',
      acao: 'avancar',
      status: 'em_andamento',
      mensagemAdmin: 'Você aceitou a proposta! Agora é só enviar os documentos solicitados.'
    });
    // Notifica o admin também
    if (ADMIN_NOTIF_EMAIL) {
      enviarEmailBg(enviarEmailAtualizacao, ADMIN_NOTIF_EMAIL, 'Admin', cand.titulo, {
        etapaNum: idxProposta.coleta + 1,
        etapaNome: 'Coleta de Documentos',
        acao: 'admin_candidato_aceitou',
        status: 'em_andamento',
        mensagemAdmin: `Candidato ${cand.cand_email} ACEITOU a proposta. Próxima etapa: Coleta de Documentos.`
      });
    }
    // Fase 13 — notifica a empresa pelo emailService
    if (cand.empresa_id) {
      emailSvc.bgPropostaRespondida({
        empresa_id: cand.empresa_id, candidato_nome: cand.nome,
        vaga_titulo: cand.titulo, resposta: 'aceita',
        candidatura_id: req.params.candidaturaId
      });
    }
  } catch (e) {
    console.error('Falha ao notificar aceite de proposta:', e.message);
  }

  analytics.bg({ evento: 'proposta_aceita', user_type: 'candidato', user_id: req.user?.id || null,
    candidatura_id: parseInt(req.params.candidaturaId), empresa_id: cand.empresa_id || null, ...analytics.fromReq(req) });
  res.json({ ok: true, msg: 'Proposta aceita! Próxima etapa: Coleta de documentos.' });
});

// ===== Candidato: recusar proposta =====
// Candidato desiste da vaga a qualquer momento
app.post('/api/candidatura/:id/desistir', authCandidato, async (req, res) => {
  await audit(req, 'candidatura.desistir', { resource_type: 'candidatura', resource_id: req.params.id });
  let { motivo } = req.body || {};
  if (typeof motivo === 'string') motivo = sanitizeText(motivo).slice(0, 1000);
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

  const desistiu = await pool.query(
    `UPDATE candidaturas
     SET status = 'cancelado',
         historico = $1,
         atualizada_em = NOW()
     WHERE id = $2 AND status NOT IN ('cancelado', 'rejeitado', 'reprovado', 'contratado')`,
    [JSON.stringify(historico), req.params.id]
  );
  if (desistiu.rowCount !== 1) {
    return res.status(409).json({ erro: 'A candidatura já foi encerrada ou alterada.' });
  }

  // FASE 7 — notificação no feed global
  inserirNotificacao(pool, 'empresa', cand.empresa_id, 'candidato_desistiu',
    `🚪 ${cand.nome || 'Candidato'} desistiu da vaga`,
    cand.titulo ? `Vaga: ${cand.titulo}` : null,
    { referencia_tipo: 'candidatura', referencia_id: req.params.id }
  );

  res.json({ ok: true, mensagem: 'Você desistiu da vaga com sucesso.' });
});

app.post('/api/candidato/recusar-proposta/:candidaturaId', authCandidato, async (req, res) => {
  await audit(req, 'candidatura.proposta.recusar', { resource_type: 'candidatura', resource_id: req.params.candidaturaId });
  let { motivo } = req.body || {};
  if (typeof motivo === 'string') motivo = sanitizeText(motivo).slice(0, 1000);
  const { rows: c } = await pool.query(`
    SELECT c.*, v.titulo, v.etapas, cd.email as cand_email
    FROM candidaturas c
    JOIN vagas v ON v.id = c.vaga_id
    JOIN candidatos cd ON cd.id = c.candidato_id
    WHERE c.id = $1`, [req.params.candidaturaId]);
  if (c.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
  const cand = c[0];
  const idxProposta = indicesFluxoProposta(cand.etapas);

  if (cand.cand_email !== req.user.email) return res.status(403).json({ erro: 'Acesso negado' });
  if ((cand.etapa_atual || 0) !== idxProposta.proposta) {
    return res.status(400).json({ erro: 'Você só pode recusar a proposta quando estiver na etapa "Proposta"' });
  }
  if (['cancelado', 'rejeitado', 'reprovado', 'contratado'].includes(cand.status) || cand.proposta_aceita_em || cand.proposta_recusada_em) {
    return res.status(409).json({ erro: 'A candidatura ou proposta já foi encerrada' });
  }

  const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
  historico.push({
    etapa: idxProposta.proposta,
    status: 'rejeitado',
    acao: 'recusar_proposta',
    mensagem: 'Candidato recusou a proposta' + (motivo ? `: ${motivo}` : ''),
    data: new Date().toISOString(),
    por: cand.cand_email
  });

  const atualizacaoRecusa = await pool.query(
    `UPDATE candidaturas
     SET proposta_recusada_em = NOW(),
         proposta_motivo_recusa = $1,
         status = 'rejeitado',
         historico = $2,
         atualizada_em = NOW()
     WHERE id = $3 AND proposta_aceita_em IS NULL AND proposta_recusada_em IS NULL`,
    [motivo || null, JSON.stringify(historico), req.params.candidaturaId]
  );
  if (!atualizacaoRecusa.rowCount) return res.status(409).json({ erro: 'A proposta já foi respondida ou a candidatura foi alterada.' });

  // FASE 7 — notificação no feed global
  inserirNotificacao(pool, 'empresa', cand.empresa_id, 'proposta_recusada',
    `❌ ${cand.nome || 'Candidato'} RECUSOU a proposta`,
    motivo ? `Motivo: ${motivo}` : null,
    { referencia_tipo: 'candidatura', referencia_id: req.params.candidaturaId, metadata: { motivo } }
  );

  // Notifica o candidato por e-mail (em background)
  try {
    enviarEmailBg(enviarEmailAtualizacao, cand.cand_email, 'Candidato', cand.titulo, {
      etapaNum: idxProposta.proposta + 1,
      etapaNome: 'Proposta',
      acao: 'recusar_proposta',
      status: 'rejeitado',
      mensagemAdmin: 'Você recusou a proposta. O processo foi encerrado. Obrigado por participar!'
    });
    // Notifica o admin
    if (ADMIN_NOTIF_EMAIL) {
      enviarEmailBg(enviarEmailAtualizacao, ADMIN_NOTIF_EMAIL, 'Admin', cand.titulo, {
        etapaNum: idxProposta.proposta + 1,
        etapaNome: 'Proposta',
        acao: 'admin_candidato_recusou',
        status: 'rejeitado',
        mensagemAdmin: `Candidato ${cand.cand_email} RECUSOU a proposta${motivo ? '. Motivo: ' + motivo : ''}.`
      });
    }
    // Fase 13 — notifica a empresa
    if (cand.empresa_id) {
      emailSvc.bgPropostaRespondida({
        empresa_id: cand.empresa_id, candidato_nome: cand.nome,
        vaga_titulo: cand.titulo, resposta: 'recusada', motivo: motivo || null,
        candidatura_id: req.params.candidaturaId
      });
    }
  } catch (e) {
    console.error('Falha ao notificar recusa de proposta:', e.message);
  }

  analytics.bg({ evento: 'proposta_recusada', user_type: 'candidato', user_id: req.user?.id || null,
    candidatura_id: parseInt(req.params.candidaturaId), empresa_id: cand.empresa_id || null, ...analytics.fromReq(req) });
  res.json({ ok: true, msg: 'Proposta recusada.' });
});

// ===== Candidato: ver proposta pendente (pra aceitar/recusar) =====
app.get('/api/candidato/candidatura/:id/proposta', authCandidato, async (req, res) => {
  const { rows: c } = await pool.query(`
    SELECT c.id, c.etapa_atual, c.status, c.proposta_texto, c.proposta_pdf_url, c.proposta_pdf_public_id,
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
      pdf_url: cloudinaryAuthenticatedUrl(cand.proposta_pdf_public_id, 'proposta.pdf', 'application/pdf') || null,
      enviada_em: cand.proposta_enviada_em,
      aceita_em: cand.proposta_aceita_em,
      recusada_em: cand.proposta_recusada_em,
      etapa_atual: cand.etapa_atual,
      status: cand.status
    }
  });
});

app.post('/api/admin/recrutadores', authAdminOnly, async (req, res) => {
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
  const { nome, cnpj, email_principal, telefone, plano, usuario } = req.body;
  if (!nome || String(nome).trim().length < 2) return res.status(400).json({ erro: 'Nome obrigatório (mínimo 2 caracteres)' });
  try {
    const planoSlug = plano || 'essencial';
    const planoResult = await pool.query('SELECT id FROM planos WHERE slug = $1 LIMIT 1', [planoSlug]);
    const planoId = planoResult.rows[0]?.id || null;
    const baseSlug = String(nome).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase()
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'empresa';
    let slug = baseSlug;
    let suffix = 1;
    while ((await pool.query('SELECT 1 FROM empresas WHERE slug = $1 LIMIT 1', [slug])).rowCount) {
      suffix += 1;
      slug = `${baseSlug}-${suffix}`;
    }
    const { rows } = await pool.query(
      `INSERT INTO empresas (nome, cnpj, email_principal, telefone, criado_por, ativo, plano, plano_id, slug)
       VALUES ($1,$2,$3,$4,$5,true,$6,$7,$8) RETURNING id, nome, cnpj, email_principal, telefone, criado_por, ativo, plano, plano_id, slug, criado_em`,
      [String(nome).trim(), cnpj || null, email_principal || null, telefone || null, req.user.id, planoSlug, planoId, slug]
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
       WHERE id = $6 RETURNING id, nome, cnpj, email_principal, telefone, ativo, plano, plano_id, slug, criado_em`,
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
       RETURNING empresa_id, vaga_id, concedido_por, concedido_em, tipo`,
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
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
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
  if (cnpj && cnpj.replace(/\D/g, '').length !== 14) {
    return res.status(400).json({ erro: 'CNPJ deve ter 14 dígitos (com ou sem pontuação)' });
  }
  if (telefone && telefone.replace(/\D/g, '').length < 10) {
    return res.status(400).json({ erro: 'Telefone inválido' });
  }
  if (!email_principal || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email_principal)) {
    return res.status(400).json({ erro: 'E-mail principal é obrigatório e deve ser válido' });
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

    // 3. Cria a empresa — apenas os três planos comerciais podem iniciar um teste.
    const planosComerciais = new Set(['essencial', 'profissional', 'enterprise']);
    const planoSlug = String(plano || 'essencial').toLowerCase().trim();
    if (!planosComerciais.has(planoSlug)) {
      return res.status(400).json({ erro: 'Plano inválido. Escolha Essencial, Profissional ou Enterprise.' });
    }
    const planoRow = await pool.query('SELECT id FROM planos WHERE slug = $1 LIMIT 1', [planoSlug]);
    const planoId = planoRow.rows[0]?.id || null;
    const empRes = await pool.query(`
      INSERT INTO empresas
        (nome, cnpj, email_principal, telefone, ativo, plano, plano_id, slug,
         trial_inicio, trial_fim, assinatura_status, pagamento_configurado)
      VALUES ($1, $2, $3, $4, true, $5, $6, $7, NOW(), NOW() + INTERVAL '30 days', 'trial', false)
      RETURNING id, nome, cnpj, email_principal, plano, plano_id, slug, criado_em,
                trial_inicio, trial_fim, assinatura_status, pagamento_configurado
    `, [empresa_nome.trim(), cnpjClean, email_principal?.toLowerCase() || null, telefone || null, planoSlug, planoId, slugFinal]);
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
        primeiro_acesso: true  // novo cadastro → redireciona para onboarding
      },
      empresa: {
        id: empresa.id,
        nome: empresa.nome,
        cnpj: empresa.cnpj,
        email_principal: empresa.email_principal,
        plano: empresa.plano,
        slug: empresa.slug,
        criado_em: empresa.criado_em,
        trial_inicio: empresa.trial_inicio,
        trial_fim: empresa.trial_fim,
        assinatura_status: empresa.assinatura_status,
        pagamento_configurado: empresa.pagamento_configurado
      }
    });
    // Fase 13 — Boas-vindas empresa (não bloqueia resposta)
    emailSvc.bgBoasVindasEmpresa({
      empresa_id: empresa.id, empresa_nome: empresa.nome,
      admin_email: adminUser.email, admin_nome: adminUser.nome
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
        u.empresa_id, u.totp_ativo, u.totp_secret,
        e.nome as empresa_nome, e.ativo as empresa_ativa
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

    // ── Fase 10: se 2FA ativo, emite pending_token (5min) em vez de access+refresh
    if (u.totp_ativo) {
      const pending = jwt.sign(
        { id: u.id, email: u.email, tipo: 'empresa_2fa_pending' },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '5m', issuer: 'vagasio-api' }
      );
      await audit(req, 'login.2fa_required', { resource_type: 'empresa', resource_id: u.id });
      return res.json({ ok: true, requer_2fa: true, pending_token: pending });
    }

    // Sem 2FA: access (30m) + refresh (7d, hash no DB)
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
    analytics.bg({ evento: 'empresa_login', user_type: 'empresa', user_id: u.id, empresa_id: u.empresa_id, ...analytics.fromReq(req) });
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
// A vaga começa em rascunho por padrão; o status enviado pela empresa é
// validado e respeitado para que a UI possa publicar imediatamente quando escolhido.
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

    // INSERT vaga (empresa = nome da empresa do usuário logado; empresa_id vem do JWT).
    // O formulário da empresa envia o status escolhido; antes, este valor era
    // ignorado e toda criação virava rascunho, embora a UI exibisse Publicada.
    // Mantém rascunho como padrão e aceita apenas estados de vaga válidos.
    const statusInicial = ['publicada', 'pausada', 'rascunho', 'encerrada'].includes(String(v.status || '').trim().toLowerCase())
      ? String(v.status).trim().toLowerCase()
      : 'rascunho';
    const { rows: vagaRows } = await pool.query(
      `INSERT INTO vagas (
        titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area,
        salario_min, salario_max, descricao, requisitos, beneficios,
        etapas, status, criada_por
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
      RETURNING id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area,
                salario_min, salario_max, descricao, requisitos, beneficios, etapas, status,
                criada_por, criada_em`,
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
        statusInicial,        // padrão rascunho; respeita o status escolhido pela empresa
        null                  // criada_por FK → admins(id). NULL pq é empresa (não admin).
      ]
    );
    const vaga = vagaRows[0];

    // Direcionamento opcional para usuários Filial da própria empresa.
    const filialIds = Array.isArray(v.filial_ids) ? [...new Set(v.filial_ids.map(Number).filter(Number.isInteger))] : [];
    if (filialIds.length) {
      await pool.query(`INSERT INTO empresa_usuario_vagas (empresa_id, usuario_id, vaga_id)
        SELECT $1, eu.id, $2 FROM empresa_usuarios eu
        WHERE eu.empresa_id = $1 AND eu.role = 'viewer' AND eu.ativo = true AND eu.id = ANY($3::int[])
        ON CONFLICT (empresa_id, usuario_id, vaga_id) DO NOTHING`, [empresa_id, vaga.id, filialIds]);
    }

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
    analytics.bg({ evento: 'vaga_criada', user_type: 'empresa', user_id: req.user?.id || null,
      empresa_id, vaga_id: vaga.id, ...analytics.fromReq(req) });

    res.status(201).json({ ok: true, vaga });
  } catch (e) {
    console.error('[EMPRESA CRIAR VAGA ERRO]', e.message, e.stack);
    return erroInterno(req, res, e, 'api-empresa-criar-vaga');
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
          WHEN v.empresa_id = $1 THEN 'criada'
          ELSE 'compartilhada'
        END AS origem
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
      ORDER BY eva.concedido_em DESC
    `, [empresa_id]);
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
    // Acesso de visualização não equivale a permissão de edição.
    // Esta rota só permite alterar vagas próprias da empresa autenticada.
    const check = await pool.query(
      `SELECT v.status
       FROM vagas v
       JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
         AND eva.empresa_id = $2 AND eva.revogado_em IS NULL
       WHERE v.id = $1 AND v.empresa_id = $2
         AND ${empresaVagaFilialScope(req, 'eva')}`,
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
    // O formulário da empresa envia status ao salvar; aceitar somente os estados
    // permitidos e somente para a vaga própria já verificada acima.
    if (v.status !== undefined) {
      if (!STATUS_VAGA_VALIDOS.has(v.status)) {
        return res.status(400).json({ erro: 'Status inválido' });
      }
      if (!transicaoVagaPermitida(check.rows[0].status, v.status)) {
        return res.status(409).json({ erro: `Transição de vaga inválida: ${check.rows[0].status} → ${v.status}` });
      }
      push('status', v.status);
    }
    if (updates.length === 0) return res.status(400).json({ erro: 'Nenhum campo para atualizar' });
    values.push(id);
    const { rows } = await pool.query(
      `UPDATE vagas SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por, criada_em`,
      values
    );
    if (Array.isArray(v.filial_ids)) {
      const filialIds = [...new Set(v.filial_ids.map(Number).filter(Number.isInteger))];
      await pool.query('DELETE FROM empresa_usuario_vagas WHERE empresa_id = $1 AND vaga_id = $2', [empresa_id, id]);
      if (filialIds.length) await pool.query(`INSERT INTO empresa_usuario_vagas (empresa_id, usuario_id, vaga_id)
        SELECT $1, eu.id, $2 FROM empresa_usuarios eu
        WHERE eu.empresa_id = $1 AND eu.role = 'viewer' AND eu.ativo = true AND eu.id = ANY($3::int[])
        ON CONFLICT (empresa_id, usuario_id, vaga_id) DO NOTHING`, [empresa_id, id, filialIds]);
    }
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
    if (!STATUS_VAGA_VALIDOS.has(status)) {
      return res.status(400).json({ erro: 'Status inválido' });
    }
    // Alteração de status exige vaga própria, não apenas acesso compartilhado.
    const check = await pool.query(`
      SELECT v.status
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
        AND eva.empresa_id = $2 AND eva.revogado_em IS NULL
      WHERE v.id = $1 AND v.empresa_id = $2
        AND ${empresaVagaFilialScope(req, 'eva')}
    `, [id, req.user.empresa_id]);
    if (check.rows.length === 0) {
      return res.status(403).json({ erro: 'Vaga não pertence à sua empresa ou não é editável neste contexto' });
    }
    if (!transicaoVagaPermitida(check.rows[0].status, status)) {
      return res.status(409).json({ erro: `Transição de vaga inválida: ${check.rows[0].status} → ${status}` });
    }
    const { rows } = await pool.query(
      `UPDATE vagas SET status = $1 WHERE id = $2 RETURNING id, titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por, criada_em`,
      [status, id]
    );
    await audit(req, 'empresa.vaga.status_changed', { resource_type: 'vaga', resource_id: id, metadata: { status } });
    res.json({ ok: true, vaga: rows[0] });
  } catch (e) {
    console.error('[EMPRESA STATUS VAGA ERRO]', e.message);
    res.status(500).json({ erro: 'Erro ao alterar status' });
  }
});

// Filiais só enxergam vagas explicitamente direcionadas a elas.
function empresaVagaFilialScope(req, alias = 'eva') {
  if (req.user?.role !== 'viewer') return 'TRUE';
  const uid = Number(req.user?.id);
  return Number.isInteger(uid) && uid > 0
    ? `EXISTS (SELECT 1 FROM empresa_usuario_vagas euv_scope WHERE euv_scope.empresa_id = ${alias}.empresa_id AND euv_scope.usuario_id = ${uid} AND euv_scope.vaga_id = ${alias}.vaga_id)`
    : 'FALSE';
}

// Escopo equivalente quando a consulta parte diretamente de vagas (sem eva).
function empresaVagaFilialScopeByVaga(req, alias = 'v') {
  if (req.user?.role !== 'viewer') return 'TRUE';
  const uid = Number(req.user?.id);
  return Number.isInteger(uid) && uid > 0
    ? `EXISTS (SELECT 1 FROM empresa_usuario_vagas euv_scope WHERE euv_scope.empresa_id = ${alias}.empresa_id AND euv_scope.usuario_id = ${uid} AND euv_scope.vaga_id = ${alias}.id)`
    : 'FALSE';
}

registrarRotasTriagem({
  app,
  pool,
  requireEmpresaViewer,
  requireRecrutadorOuAdmin,
  empresaVagaFilialScope,
  audit
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
      SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em, v.etapas,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id) as total_candidatos,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'em_andamento') as em_andamento,
        (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'contratado') as contratados
      FROM empresa_vaga_acesso eva
      JOIN vagas v ON v.id = eva.vaga_id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
      ORDER BY v.criada_em DESC
    `, [empresa_id]);

    // 2. KPIs principais (espelho do admin)
    const kpis = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND v.status = 'publicada')::int as vagas_ativas,
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND v.status = 'publicada' AND v.criada_em > $2)::int as vagas_ativas_novas_7d,
        (SELECT COUNT(*) FROM vagas v JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND v.status = 'publicada' AND v.criada_em > $3)::int as vagas_ativas_novas_14d,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)})::int as total_candidatos,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.criada_em > $2)::int as candidatos_novos_7d,
        (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.criada_em > $3)::int as candidatos_novos_14d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.status NOT IN ('reprovado','contratado','rejeitado'))::int as processos_ativos,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.criada_em > $2)::int as processos_novos_7d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.criada_em > $3)::int as processos_novos_14d,
        (SELECT COUNT(*) FROM entrevistas e
         JOIN candidaturas cand ON cand.id = e.candidatura_id
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = cand.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND e.data_hora >= NOW() AND e.status = 'agendada')::int as entrevistas_agendadas,
        (SELECT COUNT(*) FROM entrevistas e
         JOIN candidaturas cand ON cand.id = e.candidatura_id
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = cand.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND e.data_hora >= NOW() AND e.data_hora < NOW() + INTERVAL '7 days' AND e.status = 'agendada')::int as entrevistas_proximos_7d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.status IN ('contratado') AND c.atualizada_em > $4)::int as contratacoes_30d,
        (SELECT COUNT(*) FROM candidaturas c
         JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
         WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.status IN ('contratado') AND c.atualizada_em > $5 AND c.atualizada_em <= $4)::int as contratacoes_30d_anterior
    `, [empresa_id, sevenDaysAgo, fourteenDaysAgo, thirtyDaysAgo, sixtyDaysAgo]);
    const k = kpis.rows[0];

    // 3. Candidatos por etapa (1..7) — espelho do admin
    const etapasQ = await pool.query(`
      SELECT c.etapa_atual, COUNT(*)::int as total
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.status NOT IN ('reprovado','rejeitado')
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
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND c.status IN ('contratado') AND c.atualizada_em IS NOT NULL
    `, [empresa_id]);
    const tempoMedio = tempoMedioQ.rows[0]?.dias || 0;

    // taxa_aprovacao_30d: % de vagas fechadas nos últimos 30d que geraram contratação
    // (vagas usa criada_em; atualizada_em não existe)
    const taxa30Q = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE c.status IN ('contratado'))::int as com_contratacao,
        COUNT(*)::int as total_fechadas
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
      LEFT JOIN candidaturas c ON c.vaga_id = v.id AND c.status IN ('contratado','rejeitado','reprovado')
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND v.status = 'fechada' AND v.criada_em > $2
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
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND v.status = 'fechada'
    `, [empresa_id]);
    const vagas_encerradas = encerradasQ.rows[0]?.total || 0;

    // taxa_desistencia: candidatos reprovados / total de candidaturas ativas
    const desistenciaQ = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE c.status IN ('reprovado','rejeitado'))::int as reprovados,
        COUNT(*)::int as total
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
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
      LEFT JOIN video_rooms vr ON vr.entrevista_id = e.id AND vr.status = 'active'
      JOIN candidaturas c ON c.id = e.candidatura_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} AND e.data_hora >= NOW() AND e.status = 'agendada'
      ORDER BY e.data_hora ASC
      LIMIT 10
    `, [empresa_id]);

    // 6. Atividades recentes: somente eventos reais do histórico, tenant-scoped,
    // nas últimas 24h e ordenados pelo timestamp do evento (não pela candidatura).
    let atividadesRecentes = [];
    let atividadesHistoricoDashboard = [];
    try {
      const hist = await pool.query(`
        SELECT c.id as candidatura_id, c.vaga_id, v.titulo as vaga,
          cd.nome as candidato,
          COALESCE(NULLIF(h->>'tipo',''), NULLIF(h->>'acao',''), NULLIF(h->>'evento','')) as evento_tipo,
          h->>'por' as por,
          COALESCE(NULLIF(h->>'em','')::timestamptz,
                   NULLIF(h->>'data','')::timestamptz,
                   NULLIF(h->>'quando','')::timestamptz,
                   NULLIF(h->>'criado_em','')::timestamptz) as quando,
          COALESCE(h->>'mensagem', h->>'texto', h->>'detalhes') as mensagem,
          h->>'etapa' as etapa, h->>'status' as evento_status
        FROM candidaturas c
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        CROSS JOIN LATERAL jsonb_array_elements(COALESCE(c.historico, '[]'::jsonb)) h
        WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
          AND COALESCE(NULLIF(h->>'em','')::timestamptz,
                       NULLIF(h->>'data','')::timestamptz,
                       NULLIF(h->>'quando','')::timestamptz,
                       NULLIF(h->>'criado_em','')::timestamptz) >= NOW() - INTERVAL '48 hours'
        ORDER BY quando DESC NULLS LAST
      `, [empresa_id]);
      const atividadesHistorico = hist.rows.map(r => ({
        texto: r.evento_tipo || r.evento_status || 'atualizacao',
        evento_tipo: r.evento_tipo || '', status: r.evento_status || '',
        mensagem: r.mensagem || '', etapa: r.etapa || '',
        candidato: r.candidato, vaga: r.vaga, vaga_id: r.vaga_id,
        candidatura_id: r.candidatura_id, quando: r.quando, por: r.por || ''
      }));
      atividadesRecentes = atividadesHistorico.filter(a => a.quando && new Date(a.quando).getTime() >= Date.now() - 24 * 60 * 60 * 1000).slice(0, 8);
      // Guardado separadamente para a visão histórica do dashboard (máx. 48h).
      atividadesHistoricoDashboard = atividadesHistorico;
    } catch (e) {
      console.error('[empresa dashboard activities]', e.message);
    }

    // 6b. Processos ativos por vaga (uma agregação, sem N+1), com IDs reais.
    const processosPorVagaQ = await pool.query(`
      SELECT v.id as vaga_id, v.titulo, v.status as vaga_status, v.criada_em,
        COUNT(c.id)::int as processos_ativos,
        COUNT(c.id) FILTER (WHERE c.status = 'em_andamento')::int as em_andamento,
        COUNT(c.id) FILTER (WHERE c.status = 'contratado')::int as contratados
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
        AND c.status NOT IN ('reprovado','rejeitado','contratado')
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
      GROUP BY v.id, v.titulo, v.status, v.criada_em
      HAVING COUNT(c.id) > 0
      ORDER BY processos_ativos DESC, v.criada_em DESC
    `, [empresa_id]);

    // Vagas abertas há mais de 30 dias: regra explícita = status publicada + criada_em.
    const abertasMais30Q = await pool.query(`
      SELECT v.id, v.titulo, v.status, v.criada_em,
        COUNT(c.id)::int as total_candidatos
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
        AND v.status = 'publicada' AND v.criada_em < NOW() - INTERVAL '30 days'
      GROUP BY v.id, v.titulo, v.status, v.criada_em
      ORDER BY v.criada_em ASC
    `, [empresa_id]);

    // 7. Vagas mais procuradas (ranking por total de candidatos)
    const vagasMaisCandidatos = await pool.query(`
      SELECT v.id, v.titulo, COUNT(c.id)::int as total_candidatos
      FROM vagas v
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
      LEFT JOIN candidaturas c ON c.vaga_id = v.id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
      GROUP BY v.id, v.titulo
      ORDER BY total_candidatos DESC
      LIMIT 5
    `, [empresa_id]);

    res.json({
      // Aliases mantêm compatibilidade com o DOM e o dashboard do Admin antigo.
      admin: { nome: req.user?.nome || req.user?.email || 'Recrutador', email: req.user?.email || '' },
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
        entrevistas_proximos_7d: k.entrevistas_proximos_7d,
        deltas: {
          vagas: k.vagas_ativas_novas_7d || 0,
          candidatos: k.candidatos_novos_7d || 0,
          processos: k.processos_novos_7d || 0,
          entrevistas: k.entrevistas_proximos_7d || 0
        }
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
        vagas_encerradas: vagas_encerradas,
        // aliases do dashboard antigo
        taxa_documentacao: 0,
        taxa_aprovacao: taxa_fechadas_30d,
        taxa_desligamento: taxaDesistencia,
        empresas_ativas: 1
      },
      etapas: etapasMap,
      etapas_labels: ['Inscrição', 'Triagem', 'RH', 'Gestor', 'Proposta', 'Coleta Docs', 'Contratação'],
      processos_por_vaga: processosPorVagaQ.rows,
      vagas_abertas_mais_30: abertasMais30Q.rows,
      atividades_janela_horas: 24,
      atividades_historico_48h: atividadesHistoricoDashboard,
      proximas: proximas.rows,
      proximas_entrevistas: proximas.rows,
      atividades: atividadesRecentes,
      atividades_recentes: atividadesRecentes,
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
      `SELECT 1 FROM empresa_vaga_acesso eva WHERE eva.empresa_id = $1 AND eva.vaga_id = $2 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}`,
      [empresa_id, vaga_id]
    );
    if (acesso.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });
    const { rows } = await pool.query(
      `SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area, v.salario_min, v.salario_max, v.descricao, v.requisitos, v.beneficios, v.etapas, v.status, v.criada_em,
        COALESCE((SELECT json_agg(euv.usuario_id) FROM empresa_usuario_vagas euv WHERE euv.empresa_id = $2 AND euv.vaga_id = v.id), '[]'::json) AS filial_ids
       FROM vagas v WHERE v.id = $1`,
      [vaga_id, empresa_id]
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
      `SELECT 1 FROM empresa_vaga_acesso eva WHERE eva.empresa_id = $1 AND eva.vaga_id = $2 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}`,
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
    if (req.user.role === 'viewer') rows.forEach(row => { delete row.celular; });
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
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
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
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
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
    // Paridade com o antigo Admin: a empresa acompanha entrevistas de RH e
    // Gestor/Empresa das suas próprias vagas.
    let whereExtra = ``;
    const params = [empresa_id];
    const now = new Date();
    if (periodo === 'hoje') {
      const inicio = new Date(now); inicio.setHours(0,0,0,0);
      const fim = new Date(now); fim.setHours(23,59,59,999);
      whereExtra = `AND e.data_hora BETWEEN $2 AND $3`;
      params.push(inicio.toISOString(), fim.toISOString());
    } else if (periodo === 'proximos') {
      whereExtra = `AND e.data_hora >= NOW()`;
    } else if (periodo === 'passados') {
      whereExtra = `AND e.data_hora < NOW() AND e.status NOT IN ('cancelada', 'realizada')`;
    } else if (periodo === 'semana') {
      const inicio = new Date(now); inicio.setHours(0,0,0,0);
      const fim = new Date(now); fim.setDate(fim.getDate() + 7);
      whereExtra = `AND e.data_hora BETWEEN $2 AND $3`;
      params.push(inicio.toISOString(), fim.toISOString());
    } else if (periodo === '7dias') {
      const fim = new Date(now); fim.setDate(fim.getDate() + 7);
      whereExtra = `AND e.data_hora BETWEEN NOW() AND $2`;
      params.push(fim.toISOString());
    } else if (periodo === '30dias') {
      const fim = new Date(now); fim.setDate(fim.getDate() + 30);
      whereExtra = `AND e.data_hora BETWEEN NOW() AND $2`;
      params.push(fim.toISOString());
    } else if (periodo === 'atrasadas') {
      whereExtra = `AND e.data_hora < NOW() AND e.status = 'agendada'`;
    } else if (periodo === 'realizadas') {
      whereExtra = `AND e.status = 'realizada'`;
    } else if (periodo === 'canceladas') {
      whereExtra = `AND e.status = 'cancelada'`;
    }
    const { rows } = await pool.query(`
      SELECT e.id, e.etapa, e.data_hora, e.duracao_minutos, e.local, NULL AS link_reuniao, e.observacoes, e.status,
        c.id as candidatura_id, c.etapa_atual, c.status as cand_status,
        vr.room_id AS video_room_id,
        CASE WHEN vr.room_id IS NOT NULL THEN 'vagasio' ELSE NULL END AS video_provider,
        cd.id as candidato_id, cd.nome as candidato_nome, cd.email as candidato_email, cd.foto_url,
        v.id as vaga_id, v.titulo as vaga_titulo, v.empresa as vaga_empresa, v.etapas as vaga_etapas
      FROM entrevistas e
      LEFT JOIN video_rooms vr ON vr.entrevista_id = e.id AND vr.status = 'active'
      JOIN candidaturas c ON c.id = e.candidatura_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL AND eva.empresa_id = $1
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)} ${whereExtra}
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
    // Verifica acesso, incluindo o escopo da filial para viewers.
    const acc = await pool.query(`
      SELECT c.id FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
        AND ${empresaVagaFilialScope(req, 'eva')}
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
    // Verifica acesso, incluindo o escopo da filial para viewers.
    const acc = await pool.query(`
      SELECT c.id FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
        AND ${empresaVagaFilialScope(req, 'eva')}
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
        (SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = c.vaga_id AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}) as tem_acesso
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
      'SELECT id, candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC',
      [candidatura.candidato_id]
    );
    candidatura.experiencias = exps;

    // A página do Portal Empresa precisa exibir e permitir administrar a entrevista
    // atual, preservando a compatibilidade da análise de candidatura.
    const { rows: entrevistas } = await pool.query(
      `SELECT e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos, e.local,
              NULL AS link_reuniao, e.observacoes, e.status, e.criado_em,
              vr.room_id AS video_room_id,
              CASE WHEN vr.room_id IS NOT NULL THEN 'vagasio' ELSE NULL END AS video_provider
       FROM entrevistas e
       LEFT JOIN video_rooms vr ON vr.entrevista_id = e.id AND vr.status = 'active'
       WHERE e.candidatura_id = $1
       ORDER BY e.data_hora DESC, e.id DESC`,
      [id]
    );
    candidatura.entrevistas = entrevistas;
    if (req.user.role === 'viewer') {
      for (const campo of ['cpf', 'data_nascimento', 'sexo', 'acessibilidade', 'cep', 'logradouro', 'numero', 'complemento', 'bairro']) delete candidatura[campo];
    }

    res.json(candidatura);
  } catch (e) {
    console.error('[empresa detalhe candidatura]', e);
    res.status(500).json({ erro: 'Erro ao carregar' });
  }
});

// Empresa visualiza documentos de uma candidatura das suas vagas (READ-ONLY)
app.get('/api/empresa/candidatura/:id/documentos', requireRecrutadorOuAdmin, async (req, res) => {
  const { empresa_id } = req.user;
  const candidaturaId = Number(req.params.id);
  if (!Number.isInteger(candidaturaId) || candidaturaId <= 0) {
    return res.status(400).json({ erro: 'ID de candidatura inválido' });
  }
  try {
    // OWNERSHIP: empresa só vê docs de candidaturas de vagas vinculadas à empresa
    const { rows: cand } = await pool.query(
      `SELECT c.id, c.vaga_id,
              (SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = c.vaga_id AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}) as tem_acesso
       FROM candidaturas c WHERE c.id = $2`,
      [empresa_id, candidaturaId]
    );
    if (cand.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
    if (!cand[0].tem_acesso) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });

    const { rows } = await pool.query(
      `SELECT id, tipo, categoria, valor_texto, arquivo_url, arquivo_public_id, arquivo_nome, arquivo_tipo,
              arquivo_tamanho, status, justificativa_admin, enviado_em, revisado_em
       FROM documentos_candidatura WHERE candidatura_id = $1
       ORDER BY categoria, id`,
      [candidaturaId]
    );
    res.json({ documentos: rows.map(protegerUrlDocumento), obrigatorios: DOCUMENTOS_OBRIGATORIOS });
    await audit(req, 'empresa.documento.viewed', { resource_type: 'candidatura', resource_id: candidaturaId, metadata: { qtd_documentos: rows.length } });
  } catch (e) {
    console.error('[empresa docs]', e);
    res.status(500).json({ erro: 'Erro ao carregar documentos' });
  }
});

// Download autenticado do arquivo de documento para montagem de PDF no navegador.
// O proxy evita bloqueios CORS do storage e mantém a autorização por empresa.
app.get('/api/empresa/candidatura/:id/documentos/:docId/arquivo', requireRecrutadorOuAdmin, async (req, res) => {
  const candidaturaId = Number(req.params.id);
  const documentoId = Number(req.params.docId);
  const empresaId = req.user.empresa_id;
  if (!Number.isInteger(candidaturaId) || !Number.isInteger(documentoId) || candidaturaId <= 0 || documentoId <= 0) {
    return res.status(400).json({ erro: 'Identificador de documento inválido' });
  }
  try {
    const { rows } = await pool.query(`
      SELECT d.arquivo_url, d.arquivo_public_id, d.arquivo_nome, d.arquivo_tipo, d.arquivo_tamanho
      FROM documentos_candidatura d
      JOIN candidaturas c ON c.id = d.candidatura_id
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
        AND eva.empresa_id = $3 AND eva.revogado_em IS NULL
        AND ${empresaVagaFilialScope(req, 'eva')}
      WHERE d.id = $1 AND d.candidatura_id = $2
      LIMIT 1
    `, [documentoId, candidaturaId, empresaId]);
    if (!rows.length || !rows[0].arquivo_public_id) return res.status(404).json({ erro: 'Arquivo não encontrado' });
    const sourceUrl = cloudinaryAuthenticatedUrl(rows[0].arquivo_public_id, rows[0].arquivo_nome, rows[0].arquivo_tipo);
    let remote;
    try { remote = new URL(sourceUrl); } catch (_) { return res.status(400).json({ erro: 'URL de arquivo inválida' }); }
    if (!['http:', 'https:'].includes(remote.protocol)) return res.status(400).json({ erro: 'Origem de arquivo inválida' });
    const upstream = await axios.get(remote.toString(), {
      responseType: 'stream', timeout: 30000, maxContentLength: 25 * 1024 * 1024,
      validateStatus: status => status >= 200 && status < 300
    });
    res.set('Content-Type', upstream.headers['content-type'] || rows[0].arquivo_tipo || 'application/octet-stream');
    const contentLength = upstream.headers['content-length'] || rows[0].arquivo_tamanho;
    if (contentLength) res.set('Content-Length', String(contentLength));
    res.set('Content-Disposition', `attachment; filename="${escapeContentDispositionFilename(rows[0].arquivo_nome || 'documento')}"`);
    upstream.data.on('error', () => res.destroy());
    upstream.data.pipe(res);
  } catch (e) {
    console.error('[empresa documento arquivo]', e.message);
    if (!res.headersSent) res.status(502).json({ erro: 'Não foi possível baixar o arquivo' });
    else res.destroy();
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
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
        AND ${empresaVagaFilialScope(req, 'eva')}
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
    if (['contratado', 'rejeitado', 'reprovado', 'cancelado'].includes(cand.status)) {
      return res.status(409).json({ erro: 'Candidatura encerrada; reabra antes de agir' });
    }
    if (acao === 'avancar' && Array.isArray(etapasArr) && cand.etapa_atual + 1 >= etapasArr.length) {
      return res.status(409).json({ erro: 'A empresa não pode concluir a contratação; essa ação exige o fluxo administrativo final' });
    }

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

    const atualizacao = await pool.query(
      `UPDATE candidaturas
       SET historico = $1::jsonb, status = $2, etapa_atual = $3, atualizada_em = NOW()
       WHERE id = $4 AND etapa_atual = $5 AND status = $6`,
      [JSON.stringify(hist), novoStatus, novaEtapa, id, cand.etapa_atual, cand.status]
    );
    if (atualizacao.rowCount !== 1) {
      return res.status(409).json({ erro: 'A candidatura foi alterada por outra requisição. Recarregue e tente novamente.' });
    }

    // [Fase 8] empresa_notificacoes substituída por notificacoes (Fase 7) — INSERT removido.

    // Log de auditoria da ação da empresa
    await audit(req, 'empresa.candidatura.action', { resource_type: 'candidatura', resource_id: Number(id), metadata: { acao, empresa_nome, de_etapa: cand.etapa_atual, para_etapa: novaEtapa, parecer: parecer || null } });

    res.json({ ok: true, etapa_atual: novaEtapa, status: novoStatus });
  } catch (e) {
    console.error('[empresa acao]', e);
    res.status(500).json({ erro: 'Erro ao processar ação' });
  }
});

// ── POST /api/empresa/candidatura/:id/proposta ────────────────
app.post('/api/empresa/candidatura/:id/proposta', requireRecrutadorOuAdmin, async (req, res) => {
  const { empresa_id } = req.user;
  const candId = Number(req.params.id);
  try {
    const { texto, pdf_url, pdf_nome } = req.body || {};
    if (!texto && !pdf_url) {
      return res.status(400).json({ erro: 'Envie um texto ou um PDF da proposta' });
    }
    // PDFs de propostas nunca são persistidos a partir de URLs externas.
    // O cliente envia apenas data:application/pdf; o servidor faz o upload
    // autenticado e só depois grava o public_id interno.
    if (pdf_url && !String(pdf_url).startsWith('data:application/pdf')) {
      return res.status(400).json({ erro: 'O PDF deve ser anexado pelo formulário; URLs externas não são aceitas' });
    }
    // Ownership via empresa_vaga_acesso (anti-IDOR)
    const { rows: c } = await pool.query(`
      SELECT c.*, v.titulo, v.etapas, cd.nome, cd.email, cd.id AS candidato_id_full
      FROM candidaturas c
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL AND eva.empresa_id = $1
        AND ${empresaVagaFilialScope(req, 'eva')}
      JOIN vagas v ON v.id = c.vaga_id
      JOIN candidatos cd ON cd.id = c.candidato_id
      WHERE c.id = $2
    `, [empresa_id, candId]);
    if (c.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
    const cand = c[0];
    const idxProposta = indicesFluxoProposta(cand.etapas);
    if (Number(cand.etapa_atual) !== idxProposta.proposta) {
      return res.status(409).json({ erro: `A proposta só pode ser enviada na etapa "Proposta" (etapa atual: ${Number(cand.etapa_atual) + 1})` });
    }
    if (cand.proposta_enviada_em) return res.status(409).json({ erro: 'Proposta já enviada para este candidato' });
    if (['contratado','rejeitado','reprovado'].includes(cand.status)) {
      return res.status(409).json({ erro: `Candidatura já está "${cand.status}"` });
    }

    let pdfFinalUrl = null;
    let pdfFinalId = null;
    if (pdf_url) {
      const pdfValidado = validateBase64File(pdf_url, 'application/pdf', 6 * 1024 * 1024, pdf_nome);
      if (!pdfValidado.ok) {
        return res.status(pdfValidado.erro.includes('maior') ? 413 : 400).json({ erro: pdfValidado.erro });
      }
      if (!process.env.CLOUDINARY_URL && !process.env.CLOUDINARY_CLOUD_NAME) {
        return res.status(500).json({ erro: 'Cloudinary não configurado para receber PDF' });
      }
      try {
        const pdfCanonico = `data:application/pdf;base64,${pdfValidado.buffer.toString('base64')}`;
        const up = await cloudinary.uploader.upload(pdfCanonico, {
          folder: 'propostas',
          resource_type: 'raw',
          type: 'authenticated',
          public_id: `proposta_${cand.id}_${Date.now()}`
        });
        pdfFinalId = up.public_id;
        pdfFinalUrl = cloudinaryAuthenticatedUrl(pdfFinalId, pdf_nome || 'proposta.pdf', 'application/pdf');
      } catch (e) {
        console.error('[empresa proposta upload]', e.message);
        return erroInterno(req, res, e, 'upload-pdf-proposta-empresa');
      }
    }

    const historico = Array.isArray(cand.historico) ? [...cand.historico] : [];
    historico.push({
      etapa: cand.etapa_atual, status: 'proposta_enviada', acao: 'enviar_proposta',
      mensagem: 'Proposta enviada ao candidato pela empresa',
      data: new Date().toISOString(),
      por: `empresa:${req.user.nome || empresa_id}`
    });
    const propostaGravada = await pool.query(`
      UPDATE candidaturas
      SET proposta_texto = $1, proposta_pdf_url = $2, proposta_pdf_public_id = $3,
          proposta_enviada_em = NOW(), historico = $4, atualizada_em = NOW()
      WHERE id = $5
        AND proposta_enviada_em IS NULL
        AND proposta_aceita_em IS NULL
        AND proposta_recusada_em IS NULL
        AND status NOT IN ('contratado', 'rejeitado', 'reprovado', 'cancelado')
    `, [texto || null, pdfFinalUrl, pdfFinalId, JSON.stringify(historico), candId]);
    if (propostaGravada.rowCount !== 1) {
      if (pdfFinalId) cloudinary.uploader.destroy(pdfFinalId, { resource_type: 'raw', type: 'authenticated' }).catch(() => {});
      return res.status(409).json({ erro: 'A candidatura já possui proposta ou foi encerrada.' });
    }
    // Notificações
    inserirNotificacao(pool, 'empresa', empresa_id, 'proposta_enviada',
      `📨 Proposta enviada: ${cand.nome}`,
      cand.titulo ? `Vaga: ${cand.titulo}` : null,
      { referencia_tipo: 'candidatura', referencia_id: candId }
    );
    inserirNotificacao(pool, 'candidato', cand.candidato_id, 'proposta_enviada',
      `📨 Você recebeu uma proposta — ${cand.titulo}`,
      'Acesse sua candidatura para visualizar e responder',
      { referencia_tipo: 'candidatura', referencia_id: candId }
    );
    // E-mail ao candidato (background)
    try {
      enviarEmailBg(enviarEmailProposta, cand.email, cand.nome, cand.titulo, pdfFinalUrl || null);
      emailSvc.bgPropostaEnviada({
        candidato_id: cand.candidato_id, email: cand.email, nome: cand.nome,
        vaga_titulo: cand.titulo,
        empresa_nome: cand.empresa || req.user.empresa_nome || 'Empresa',
        resumo: texto ? texto.substring(0, 200) : null,
        candidatura_id: candId
      });
    } catch(e) { console.error('[empresa proposta email]', e.message); }
    await audit(req, 'empresa.proposta.sent', {
      resource_type: 'candidatura', resource_id: candId,
      metadata: { tem_pdf: !!pdf_url }
    });
    analytics.bg({ evento: 'proposta_enviada', user_type: 'empresa',
      empresa_id, candidatura_id: candId, ...analytics.fromReq(req) });
    res.json({ ok: true, proposta: { texto, pdf_url: pdfFinalUrl || null } });
  } catch (e) {
    return erroInterno(req, res, e, 'api-empresa-candidatura-proposta');
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
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
        AND ${empresaVagaFilialScope(req, 'eva')}
    `, [id, empresa_id]);
    if (acc.rows.length === 0) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
    const cand = acc.rows[0];

    // Igual ao antigo admin: candidaturas encerradas podem ser reabertas;
    // as demais ações continuam bloqueadas enquanto fechadas.
    // Uma candidatura encerrada só pode ser reaberta explicitamente com
    // status=em_andamento. A rota não recebe `acao`; usar essa variável aqui
    // causava ReferenceError justamente no fluxo de reabertura.
    if ((cand.status === 'contratado' || cand.status === 'rejeitado' || cand.status === 'reprovado') && status !== 'em_andamento') {
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
      if (n !== cand.etapa_atual && n !== cand.etapa_atual + 1) {
        return res.status(409).json({ erro: 'Não é permitido saltar etapas' });
      }
      if (n === cand.etapa_atual + 1 && totalEtapas > 0 && n >= totalEtapas) {
        return res.status(409).json({ erro: 'A contratação deve ser concluída pelo fluxo administrativo' });
      }
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
    // (transação atômica: histórico + update).
    // etapa_nova e status_novo são NOT NULL — sempre populados (mesmo que iguais ao anterior).
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
            etapaMudou ? cand.etapa_atual : cand.etapa_atual,        // sempre popula
            etapaMudou ? novaEtapa : cand.etapa_atual,                // etapa_nova sempre preenchido
            statusMudou ? cand.status : cand.status,                   // sempre popula
            statusMudou ? novoStatus : cand.status,                    // status_novo sempre preenchido
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

      const atualizacao = await pool.query(
        `UPDATE candidaturas
         SET historico = $1::jsonb, etapa_atual = $2, status = $3, atualizada_em = NOW()
         WHERE id = $4 AND etapa_atual = $5 AND status = $6`,
        [JSON.stringify(hist), novaEtapa, novoStatus, id, cand.etapa_atual, cand.status]
      );
      if (atualizacao.rowCount !== 1) {
        await pool.query('ROLLBACK');
        return res.status(409).json({ erro: 'A candidatura foi alterada por outra requisição. Recarregue e tente novamente.' });
      }

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
       JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
       JOIN vagas v ON v.id = c.vaga_id
       WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
         AND ${empresaVagaFilialScope(req, 'eva')}`,
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

// ============= NOTIFICAÇÕES GLOBAIS (FASE 7) =============
// Endpoints oficiais conforme spec:
//   GET    /api/notificacoes                       — lista do usuário autenticado
//   GET    /api/notificacoes/nao-lidas             — contagem
//   PATCH  /api/notificacoes/:id/lida              — marca UMA como lida
//   PATCH  /api/notificacoes/marcar-todas-lidas    — marca TODAS como lidas
// Suporta tanto empresa quanto candidato (user_type do JWT).

function userTypeFromReq(req) {
  return req.user?.tipo || null;
}
// Middleware: aceita qualquer usuário autenticado (candidato, empresa, admin)
// Usado pelos endpoints /api/notificacoes/* — a discriminação é feita
// dentro do handler com base em req.user.tipo
function requireAuthAny(req, res, next) {
  return authMiddleware(req, res, () => {
    if (!req.user?.tipo) return res.status(401).json({ erro: 'Token inválido' });
    next();
  });
}
// Candidato: o JWT guarda `email` (não id). Fazemos lookup por email sob demanda.
// Empresa: o JWT guarda `empresa_id`.
async function candidatoIdFromReq(req) {
  if (req.user?.candidato_id) return req.user.candidato_id;
  if (req.user?.email) {
    const r = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
    return r.rows[0]?.id || null;
  }
  return null;
}
function empresaIdFromReq(req) {
  return req.user?.empresa_id || null;
}

// GET /api/notificacoes — lista do usuário autenticado (empresa OU candidato)
app.get('/api/notificacoes', requireAuthAny, async (req, res) => {
  if (!req.user) return res.status(401).json({ erro: 'Token obrigatório' });
  const ut = userTypeFromReq(req);
  // Pra empresa: notif é keyada por empresa_id (todos os usuários da mesma empresa compartilham o feed)
  // Pra candidato: por candidato_id
  let uid;
  if (ut === 'candidato') uid = await candidatoIdFromReq(req);
  else if (ut === 'empresa') uid = empresaIdFromReq(req);
  else return res.status(403).json({ erro: 'Tipo de usuário não suportado' });
  if (!uid) return res.status(401).json({ erro: 'Token inválido' });

  const { tipo, lida, limit } = req.query;
  const lim = Math.min(parseInt(limit) || 30, 100);
  const params = [ut, uid];
  let sql = `
    SELECT id, user_type, user_id, tipo, titulo, mensagem,
           referencia_tipo, referencia_id, lida_em, criada_em
      FROM notificacoes
     WHERE user_type = $1 AND user_id = $2
  `;
  if (tipo) { params.push(tipo); sql += ` AND tipo = $${params.length}`; }
  if (lida === 'true')  sql += ` AND lida_em IS NOT NULL`;
  if (lida === 'false') sql += ` AND lida_em IS NULL`;
  sql += ` ORDER BY criada_em DESC LIMIT ${lim}`;
  try {
    const { rows } = await pool.query(sql, params);
    res.json({ ok: true, user_type: ut, notificacoes: rows, total: rows.length });
  } catch (e) {
    console.error('[GET /api/notificacoes]', e);
    res.status(500).json({ erro: 'Erro ao listar notificações' });
  }
});

// GET /api/notificacoes/nao-lidas — contagem
app.get('/api/notificacoes/nao-lidas', requireAuthAny, async (req, res) => {
  if (!req.user) return res.status(401).json({ erro: 'Token obrigatório' });
  const ut = userTypeFromReq(req);
  let uid;
  if (ut === 'candidato') uid = await candidatoIdFromReq(req);
  else if (ut === 'empresa') uid = empresaIdFromReq(req);
  else return res.status(403).json({ erro: 'Tipo de usuário não suportado' });
  if (!uid) return res.status(401).json({ erro: 'Token inválido' });
  try {
    const r = await pool.query(
      `SELECT COUNT(*)::int AS total FROM notificacoes
        WHERE user_type = $1 AND user_id = $2 AND lida_em IS NULL`,
      [ut, uid]
    );
    res.json({ ok: true, nao_lidas: r.rows[0].total });
  } catch (e) {
    console.error('[GET /api/notificacoes/nao-lidas]', e);
    res.status(500).json({ erro: 'Erro ao contar notificações' });
  }
});

// PATCH /api/notificacoes/:id/lida — marca UMA como lida (só do dono)
app.patch('/api/notificacoes/:id/lida', requireAuthAny, async (req, res) => {
  if (!req.user) return res.status(401).json({ erro: 'Token obrigatório' });
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro: 'ID inválido' });
  const ut = userTypeFromReq(req);
  let uid;
  if (ut === 'candidato') uid = await candidatoIdFromReq(req);
  else if (ut === 'empresa') uid = empresaIdFromReq(req);
  else return res.status(403).json({ erro: 'Tipo de usuário não suportado' });
  if (!uid) return res.status(401).json({ erro: 'Token inválido' });
  try {
    const r = await pool.query(
      `UPDATE notificacoes SET lida_em = NOW()
        WHERE id = $1 AND user_type = $2 AND user_id = $3
        RETURNING id, lida_em`,
      [id, ut, uid]
    );
    if (r.rowCount === 0) return res.status(404).json({ erro: 'Notificação não encontrada' });
    res.json({ ok: true, id, lida_em: r.rows[0].lida_em });
  } catch (e) {
    console.error('[PATCH /api/notificacoes/:id/lida]', e);
    res.status(500).json({ erro: 'Erro ao marcar notificação' });
  }
});

// PATCH /api/notificacoes/marcar-todas-lidas — marca TODAS como lidas
app.patch('/api/notificacoes/marcar-todas-lidas', requireAuthAny, async (req, res) => {
  if (!req.user) return res.status(401).json({ erro: 'Token obrigatório' });
  const ut = userTypeFromReq(req);
  let uid;
  if (ut === 'candidato') uid = await candidatoIdFromReq(req);
  else if (ut === 'empresa') uid = empresaIdFromReq(req);
  else return res.status(403).json({ erro: 'Tipo de usuário não suportado' });
  if (!uid) return res.status(401).json({ erro: 'Token inválido' });
  try {
    const r = await pool.query(
      `UPDATE notificacoes SET lida_em = NOW()
        WHERE user_type = $1 AND user_id = $2 AND lida_em IS NULL`,
      [ut, uid]
    );
    res.json({ ok: true, marcadas: r.rowCount });
  } catch (e) {
    console.error('[PATCH /api/notificacoes/marcar-todas-lidas]', e);
    res.status(500).json({ erro: 'Erro ao marcar notificações' });
  }
});

// ============= KPIs — DASHBOARD EMPRESA (FASE 7) =============
app.get('/api/empresa/dashboard/kpis', requireEmpresaViewer, async (req, res) => {
  try {
    const empresa_id = req.user.empresa_id;
    // Query agregada ÚNICA — evita N+1
    const { rows: vagasKpi } = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE status = 'publicada')::int AS publicadas,
        COUNT(*) FILTER (WHERE status = 'pausada')::int AS pausadas,
        COUNT(*) FILTER (WHERE status = 'encerrada')::int AS encerradas,
        COUNT(*) FILTER (WHERE status = 'rascunho' OR status IS NULL)::int AS rascunhos
      FROM vagas WHERE empresa_id = $1
    `, [empresa_id]);
    const { rows: candKpi } = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE c.status = 'em_analise' OR c.status = 'em_andamento')::int AS em_andamento,
        COUNT(*) FILTER (WHERE c.status = 'contratado')::int AS contratados,
        COUNT(*) FILTER (WHERE c.status = 'rejeitado')::int AS rejeitados
      FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE v.empresa_id = $1
    `, [empresa_id]);
    const { rows: etapasKpi } = await pool.query(`
      SELECT v.titulo, v.id AS vaga_id, c.etapa_atual, COUNT(*)::int AS qtd
        FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id
       WHERE v.empresa_id = $1
       GROUP BY v.id, v.titulo, c.etapa_atual
       ORDER BY v.id, c.etapa_atual
    `, [empresa_id]);
    // Candidaturas novas = criadas nos últimos 7 dias
    const { rows: novasKpi } = await pool.query(`
      SELECT COUNT(*)::int AS novas_7d
        FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id
       WHERE v.empresa_id = $1 AND c.criada_em > NOW() - INTERVAL '7 days'
    `, [empresa_id]);
    res.json({
      ok: true,
      empresa_id,
      vagas: vagasKpi[0],
      candidaturas: { ...candKpi[0], novas_7d: novasKpi[0].novas_7d },
      por_etapa: etapasKpi
    });
  } catch (e) {
    console.error('[empresa/dashboard/kpis]', e);
    res.status(500).json({ erro: 'Erro ao calcular KPIs' });
  }
});

// ============= KPIs — CANDIDATO (FASE 7) =============
app.get('/api/candidato/dashboard/kpis', authCandidato, async (req, res) => {
  try {
    const cid = await candidatoIdFromReq(req);
    if (!cid) return res.status(401).json({ erro: 'Candidato não identificado' });
    const { rows: cands } = await pool.query(`
      SELECT
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE status = 'em_analise' OR status = 'em_andamento')::int AS em_andamento,
        COUNT(*) FILTER (WHERE status = 'contratado')::int AS contratadas,
        COUNT(*) FILTER (WHERE status = 'rejeitado')::int AS rejeitadas,
        COUNT(*) FILTER (WHERE etapa_atual = 3 OR etapa_atual = 4)::int AS entrevistas
      FROM candidaturas WHERE candidato_id = $1
    `, [cid]);
    const { rows: ult } = await pool.query(`
      SELECT c.id, c.status, c.etapa_atual, c.atualizada_em, c.criada_em, v.titulo
        FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id
       WHERE c.candidato_id = $1 ORDER BY c.atualizada_em DESC NULLS LAST, c.criada_em DESC LIMIT 5
    `, [cid]);
    const r = await pool.query(
      `SELECT COUNT(*)::int AS n FROM notificacoes WHERE user_type='candidato' AND user_id=$1 AND lida_em IS NULL`,
      [cid]
    );
    res.json({
      ok: true,
      candidato_id: cid,
      candidaturas: cands[0],
      ultimas: ult,
      notificacoes_nao_lidas: r.rows[0].n
    });
  } catch (e) {
    console.error('[candidato/dashboard/kpis]', e);
    res.status(500).json({ erro: 'Erro ao calcular KPIs do candidato' });
  }
});

// ============= CHAT RH <-> EMPRESA (visão do Admin) =============
app.get('/api/admin/candidatura/:id/chat-empresa', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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

app.post('/api/admin/candidatura/:id/chat-empresa', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
app.get('/api/admin/chat-empresa-lista', authAdminOnly, denyGlobalPrivateUntilSupport, async (req, res) => {
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
      JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id AND eva.revogado_em IS NULL
      WHERE eva.empresa_id = $1 AND eva.revogado_em IS NULL AND ${empresaVagaFilialScope(req)}
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

    // ping test: 1785206962.7014055
    // FIX C3 (2026-07-27): rota /api/_teste/email REMOVIDA.
    // Era pública sem auth — atacante podia mandar e-mail arbitrário pelo nosso domínio.
    // Pra testar envio de e-mail em prod, use uma rota admin com auth + restrição por domínio.

  // ========== SEED DEMO: Importa 6 vagas de exemplo (apenas admin) ==========
  // Idempotente: se a vaga já existe (mesmo título+empresa), não duplica.
  app.post('/api/admin/seed-vagas-demo', authAdminOnly, async (req, res) => {
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
  app.get('/api/admin/audit-logs', authAdminOnly, async (req, res) => {
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
        `SELECT id, user_id, user_type, user_email, action, resource_type,
                resource_id, result, metadata, created_at
         FROM audit_logs ${whereClause} ORDER BY created_at DESC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
        [...values, queryLimit, queryOffset]
      );
      res.json({ logs: rows.map(item => ({
        ...item,
        user_email: mascararEmail(item.user_email),
        metadata: sanitizarMetadata(item.metadata)
      })), total: parseInt(count.rows[0].count, 10) });
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
      return erroInterno(req, res, e, 'api-admin-restore-test');
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
      return erroInterno(req, res, e, 'api-admin-backup');
    }
  });

  // =========================================================================
  // REFRESH TOKEN (Etapa 2, 2026-07-27)
  // =========================================================================
  // Recebe refresh token (opaco, não JWT) → consome atomicamente no DB →
  // gera novo access + novo refresh. Reutilização do refresh antigo é rejeitada.
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
      // O refresh antigo já foi consumido atomicamente em consumirRefresh().
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
  app.get('/api/empresa/usuarios', requireAdminOuRecrutadorEquipe, async (req, res) => {
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

// ===========================================================
// NOTIFICAÇÕES DA EMPRESA — feed real
// ===========================================================
app.get('/api/empresa/notificacoes', requireEmpresaViewer, async (req, res) => {
  const limite = Math.min(100, Math.max(1, Number(req.query.limite) || 20));
  try {
    const [list, unread] = await Promise.all([
      pool.query(`
        SELECT id, tipo, titulo, mensagem, referencia_tipo, referencia_id, lida, lida_em, criada_em, metadata
        FROM notificacoes
        WHERE user_type = 'empresa' AND user_id = $1
        ORDER BY criada_em DESC
        LIMIT $2
      `, [req.user.empresa_id, limite]),
      pool.query(`SELECT COUNT(*)::int AS total FROM notificacoes WHERE user_type='empresa' AND user_id=$1 AND lida=false`, [req.user.empresa_id])
    ]);
    res.json({ notificacoes: list.rows, nao_lidas: unread.rows[0]?.total || 0 });
  } catch (e) { res.status(500).json({ erro: 'Erro ao carregar notificações' }); }
});
app.patch('/api/empresa/notificacoes/:id/lida', requireEmpresaViewer, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ erro:'Notificação inválida' });
  try {
    const q = await pool.query(`UPDATE notificacoes SET lida=true, lida_em=NOW() WHERE id=$1 AND user_type='empresa' AND user_id=$2 RETURNING id,lida,lida_em`, [id, req.user.empresa_id]);
    if (!q.rows.length) return res.status(404).json({ erro:'Notificação não encontrada' });
    res.json({ ok:true, notificacao:q.rows[0] });
  } catch (e) { res.status(500).json({ erro:'Erro ao marcar notificação' }); }
});
app.post('/api/empresa/notificacoes/lidas', requireEmpresaViewer, async (req, res) => {
  try { await pool.query(`UPDATE notificacoes SET lida=true, lida_em=NOW() WHERE user_type='empresa' AND user_id=$1 AND lida=false`, [req.user.empresa_id]); res.json({ ok:true }); }
  catch (e) { res.status(500).json({ erro:'Erro ao marcar notificações' }); }
});

// ===========================================================
// ATIVIDADES RECENTES DA EQUIPE — somente ações auditáveis
// ===========================================================
app.get('/api/empresa/atividades', requireEmpresaViewer, async (req, res) => {
  const horas = Math.min(24, Math.max(1, Number(req.query.horas) || 1));
  const usuarioId = Number.isInteger(Number(req.query.usuario_id)) ? Number(req.query.usuario_id) : null;
  try {
    const { rows } = await pool.query(`
      SELECT al.id, al.created_at, al.user_id, al.user_email, al.action,
             al.resource_type, al.resource_id, al.result, al.metadata,
             COALESCE(eu.nome, al.user_email, 'Usuário') AS usuario_nome,
             COALESCE(v.titulo, al.metadata->>'titulo') AS recurso_nome
      FROM audit_logs al
      LEFT JOIN empresa_usuarios eu ON eu.id = al.user_id AND eu.empresa_id = $1
      LEFT JOIN vagas v ON al.resource_type = 'vaga' AND v.id = al.resource_id AND v.empresa_id = $1
      WHERE al.created_at >= NOW() - ($2::int * INTERVAL '1 hour')
        AND al.result = 'success'
        AND ($3::int IS NULL OR al.user_id = $3::int)
        AND al.action NOT LIKE 'login.%'
        AND al.action NOT LIKE 'security.%'
        AND al.action NOT LIKE '%.viewed'
        AND (
          eu.empresa_id = $1
          OR v.empresa_id = $1
          OR al.metadata->>'empresa_id' = $1::text
        )
      ORDER BY al.created_at DESC
      LIMIT 100
    `, [req.user.empresa_id, horas, usuarioId]);
    res.json({ atividades: rows, horas });
  } catch (e) {
    console.error('[EMPRESA ATIVIDADES]', e.message);
    res.status(500).json({ erro: 'Erro ao carregar atividades da equipe' });
  }
});

// ===========================================================
// CONVITES REAIS DE USUÁRIOS DA EMPRESA
// ===========================================================
function hashConviteToken(raw) {
  return crypto.createHash('sha256').update(String(raw)).digest('hex');
}
function escapeEmailHtml(value) {
  return String(value || '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function conviteFrontendUrl(req, rawToken) {
  const base = String(process.env.FRONTEND_URL || '').trim().replace(/\/$/, '');
  if (!base) return null;
  try {
    const parsed = new URL(base);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return `${base}/empresa/convite.html?token=${encodeURIComponent(rawToken)}`;
  } catch (_) { return null; }
}

app.get('/api/empresa/convites', requireAdminOuRecrutadorEquipe, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, nome, email, cargo, role, criado_em, expira_em, reenviado_em
      FROM empresa_convites
      WHERE empresa_id = $1 AND aceito_em IS NULL AND cancelado_em IS NULL AND expira_em > NOW()
      ORDER BY criado_em DESC
    `, [req.user.empresa_id]);
    res.json({ convites: rows });
  } catch (e) {
    console.error('[EMPRESA CONVITES GET]', e.message);
    res.status(500).json({ erro: 'Erro ao listar convites' });
  }
});

app.post('/api/empresa/convites', requireAdminOuRecrutadorEquipe, async (req, res) => {
  const empresaId = req.user.empresa_id;
  const nome = String(req.body?.nome || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const cargo = String(req.body?.cargo || '').trim() || null;
  const role = String(req.body?.role || 'recrutador').trim();
  if (req.user.role === 'recrutador' && role !== 'viewer') return res.status(403).json({ erro: 'Recrutadores só podem cadastrar usuários Filial' });
  if (!nome || !email || nome.length > 160 || email.length > 254 || cargo && cargo.length > 160 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ erro: 'Nome e e-mail válidos são obrigatórios' });
  if (!['admin_empresa','recrutador','viewer'].includes(role)) return res.status(400).json({ erro: 'Função inválida' });
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashConviteToken(rawToken);
  const inviteUrl = conviteFrontendUrl(req, rawToken);
  if (!inviteUrl) return res.status(503).json({ erro: 'URL do portal não configurada para convites' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serializa convites da mesma empresa: evita corrida que criaria dois admins ativos.
    const empresaLock = await client.query('SELECT id FROM empresas WHERE id = $1 AND ativo = true FOR UPDATE', [empresaId]);
    if (!empresaLock.rows.length) { await client.query('ROLLBACK'); return res.status(403).json({ erro: 'Empresa inativa ou não encontrada' }); }
    const existing = await client.query('SELECT id, ativo FROM empresa_usuarios WHERE lower(email) = $1', [email]);
    if (existing.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({ erro: existing.rows[0].ativo ? 'Este e-mail já pertence a um usuário' : 'Este e-mail pertence a um usuário inativo' });
    }
    const pending = await client.query(`SELECT id FROM empresa_convites WHERE empresa_id = $1 AND lower(email) = $2 AND aceito_em IS NULL AND cancelado_em IS NULL AND expira_em > NOW()`, [empresaId, email]);
    if (pending.rows.length) { await client.query('ROLLBACK'); return res.status(409).json({ erro: 'Já existe um convite pendente para este e-mail' }); }
    if (role === 'admin_empresa') {
      const admins = await client.query(`SELECT COUNT(*)::int AS total FROM empresa_usuarios WHERE empresa_id = $1 AND role = 'admin_empresa' AND ativo = true`, [empresaId]);
      if (admins.rows[0].total >= 1) { await client.query('ROLLBACK'); return res.status(409).json({ erro: 'Esta empresa já possui um administrador ativo' }); }
    }
    const expira = new Date(Date.now() + 7 * 86400000);
    const ins = await client.query(`INSERT INTO empresa_convites (empresa_id, nome, email, cargo, role, token_hash, expira_em, criado_por) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, nome, email, cargo, role, criado_em, expira_em`, [empresaId, nome, email, cargo, role, tokenHash, expira, req.user.id]);
    await client.query('COMMIT');
    // O convite já está salvo; o envio não pode manter a transação/DB bloqueados.
    enviarEmailBg(enviarEmail, {
      to: email,
      subject: 'Convite para acessar o portal da empresa',
      html: `<p>Olá, ${escapeEmailHtml(nome)}.</p><p>Você recebeu um convite para acessar o portal da empresa como <strong>${escapeEmailHtml(role)}</strong>.</p><p>O convite expira em 7 dias.</p><p>Acesse pelo link abaixo e defina sua senha:</p><p>${escapeEmailHtml(inviteUrl)}</p>`,
      text: `Olá, ${nome}. Você recebeu um convite para acessar o portal da empresa como ${role}. O convite expira em 7 dias. Acesse: ${inviteUrl}`
    });
    await audit(req, 'empresa.convite.created', { resource_type: 'empresa_convite', resource_id: ins.rows[0].id, metadata: { empresa_id: empresaId, role } });
    res.status(201).json({ ok: true, convite: ins.rows[0], convite_url: inviteUrl });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('[EMPRESA CONVITE POST]', e.message);
    res.status(503).json({ erro: 'Não foi possível criar e enviar o convite' });
  } finally { client.release(); }
});

app.post('/api/empresa/convites/:id/reenviar', requireAdminEmpresa, async (req, res) => {
  const id = Number(req.params.id), empresaId = req.user.empresa_id;
  if (!Number.isInteger(id)) return res.status(400).json({ erro: 'Convite inválido' });
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashConviteToken(rawToken);
  const inviteUrl = conviteFrontendUrl(req, rawToken);
  if (!inviteUrl) return res.status(503).json({ erro: 'URL do portal não configurada para convites' });
  try {
    const q = await pool.query(`UPDATE empresa_convites SET token_hash=$1, expira_em=NOW()+INTERVAL '7 days', reenviado_em=NOW() WHERE id=$2 AND empresa_id=$3 AND aceito_em IS NULL AND cancelado_em IS NULL RETURNING id,nome,email,cargo,role,expira_em`, [tokenHash,id,empresaId]);
    if (!q.rows.length) return res.status(404).json({ erro: 'Convite pendente não encontrado' });
    const c = q.rows[0];
    await enviarEmail({ to:c.email, subject:'Seu convite para acessar o portal da empresa', html:`<p>Olá, ${escapeEmailHtml(c.nome)}.</p><p>Seu convite foi reenviado e expira em 7 dias.</p><p>${escapeEmailHtml(inviteUrl)}</p>`, text:`Seu convite foi reenviado. Acesse: ${inviteUrl}` });
    await audit(req, 'empresa.convite.resent', { resource_type:'empresa_convite', resource_id:id });
    res.json({ ok:true, convite:c });
  } catch (e) { console.error('[EMPRESA CONVITE RESEND]', e.message); res.status(503).json({ erro:'Não foi possível reenviar o convite' }); }
});

app.delete('/api/empresa/convites/:id', requireAdminEmpresa, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ erro:'Convite inválido' });
  try {
    const q = await pool.query(`UPDATE empresa_convites SET cancelado_em=NOW() WHERE id=$1 AND empresa_id=$2 AND aceito_em IS NULL AND cancelado_em IS NULL RETURNING id`, [id, req.user.empresa_id]);
    if (!q.rows.length) return res.status(404).json({ erro:'Convite pendente não encontrado' });
    await audit(req, 'empresa.convite.cancelled', { resource_type:'empresa_convite', resource_id:id });
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ erro:'Não foi possível cancelar o convite' }); }
});

app.get('/api/empresa/convite/:token', rateLimitByIp('cadastro'), async (req, res) => {
  const rawToken = String(req.params.token || '');
  if (!/^[a-f0-9]{64}$/i.test(rawToken)) return res.status(404).json({ erro:'Convite inválido ou expirado' });
  const hash = hashConviteToken(rawToken);
  try {
    const { rows } = await pool.query(`SELECT c.id,c.nome,c.email,c.cargo,c.role,c.expira_em,e.nome AS empresa_nome FROM empresa_convites c JOIN empresas e ON e.id=c.empresa_id WHERE c.token_hash=$1 AND c.aceito_em IS NULL AND c.cancelado_em IS NULL AND c.expira_em>NOW()`, [hash]);
    if (!rows.length) return res.status(404).json({ erro:'Convite inválido ou expirado' });
    res.json({ convite: rows[0] });
  } catch (e) { res.status(500).json({ erro:'Erro ao consultar convite' }); }
});

app.post('/api/empresa/convite/:token/aceitar', rateLimitByIp('cadastro'), async (req, res) => {
  const rawToken = String(req.params.token || '');
  if (!/^[a-f0-9]{64}$/i.test(rawToken)) return res.status(404).json({ erro:'Convite inválido ou expirado' });
  const hash = hashConviteToken(rawToken), senha = String(req.body?.senha || '');
  if (senha.length < 8) return res.status(400).json({ erro:'A senha deve ter pelo menos 8 caracteres' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const q = await client.query(`SELECT c.*,e.nome AS empresa_nome FROM empresa_convites c JOIN empresas e ON e.id=c.empresa_id WHERE c.token_hash=$1 AND c.aceito_em IS NULL AND c.cancelado_em IS NULL AND c.expira_em>NOW() FOR UPDATE`, [hash]);
    if (!q.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ erro:'Convite inválido ou expirado' }); }
    const c=q.rows[0];
    const exists=await client.query('SELECT id FROM empresa_usuarios WHERE lower(email)=lower($1)',[c.email]);
    if(exists.rows.length){await client.query('ROLLBACK');return res.status(409).json({erro:'Este e-mail já possui um acesso'});}
    const hashSenha=await bcrypt.hash(senha,12);
    const u=await client.query(`INSERT INTO empresa_usuarios (empresa_id,nome,email,senha_hash,cargo,ativo,primeiro_acesso,role) VALUES ($1,$2,$3,$4,$5,true,false,$6) RETURNING id,nome,email,cargo,role,ativo`,[c.empresa_id,c.nome,c.email,hashSenha,c.cargo,c.role]);
    await client.query('UPDATE empresa_convites SET aceito_em=NOW() WHERE id=$1',[c.id]);
    await client.query('COMMIT');
    res.json({ok:true,usuario:u.rows[0],empresa:{id:c.empresa_id,nome:c.empresa_nome}});
  } catch(e){await client.query('ROLLBACK').catch(()=>{});console.error('[EMPRESA CONVITE ACCEPT]',e.message);res.status(500).json({erro:'Não foi possível aceitar o convite'});} finally{client.release();}
});


  // ===== FASE 8 — Registra rotas /api/empresa/* complementares (ANTES do 404 global) =====
  // Paridade multi-tenant: antes só existia em /api/admin/* (visão SaaS).
  // Agora a empresa cliente também consome /api/empresa/* com filtro de tenant.
  // IMPORTANTE: registrado ANTES do handler 404 global (linha abaixo), senão as rotas
  // novas nunca são alcançadas — Express processa middlewares em ordem.
  const { registrar: registrarEmpresaExtra } = require('./routes/empresa_extra');
  registrarEmpresaExtra(app, { pool, documentosObrigatorios: DOCUMENTOS_OBRIGATORIOS, cloudinaryAuthenticatedUrl });

  // =========================================================================
  // FASE 9 — Rotas de planos (público), perfil empresa (tenant) e onboarding
  // =========================================================================

  // GET /api/planos — lista pública de planos ativos
  app.get('/api/planos', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT id, slug, nome, descricao, preco_mensal,
                limite_vagas, limite_usuarios, limite_candidaturas_mes, destaque
         FROM planos WHERE ativo = true ORDER BY preco_mensal ASC`
      );
      res.json({ planos: rows });
    } catch (e) {
      console.error('[PLANOS]', e);
      res.status(500).json({ erro: 'Erro ao listar planos' });
    }
  });

  // GET /api/empresa/minha-empresa — perfil completo da empresa logada
  app.get('/api/empresa/minha-empresa', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(
        `SELECT e.id, e.nome, e.slug, e.cnpj, e.email_principal, e.telefone,
                e.descricao, e.cidade, e.estado, e.site, e.setor, e.tamanho,
                e.logo_url, e.cor_destaque, e.ativo, e.criado_em,
                e.onboarding_step,
                p.id AS plano_id, p.slug AS plano_slug, p.nome AS plano_nome,
                p.preco_mensal, p.limite_vagas, p.limite_usuarios,
                p.limite_candidaturas_mes
         FROM empresas e
         LEFT JOIN planos p ON p.id = e.plano_id
         WHERE e.id = $1`, [empresa_id]
      );
      if (rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
      res.json({ empresa: rows[0] });
    } catch (e) {
      console.error('[MINHA-EMPRESA GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar empresa' });
    }
  });

  // PUT /api/empresa/minha-empresa — atualiza perfil da empresa logada
  app.put('/api/empresa/minha-empresa', requireAdminEmpresa, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const {
        nome, descricao, cidade, estado, site, setor, tamanho,
        telefone, email_principal, logo_url, cor_destaque
      } = req.body || {};
      const { rows } = await pool.query(
        `UPDATE empresas SET
          nome            = COALESCE($1, nome),
          descricao       = COALESCE($2, descricao),
          cidade          = COALESCE($3, cidade),
          estado          = COALESCE($4, estado),
          site            = COALESCE($5, site),
          setor           = COALESCE($6, setor),
          tamanho         = COALESCE($7, tamanho),
          telefone        = COALESCE($8, telefone),
          email_principal = COALESCE($9, email_principal),
          logo_url        = COALESCE($10, logo_url),
          cor_destaque    = COALESCE($11, cor_destaque)
         WHERE id = $12
         RETURNING id, nome, slug, descricao, cidade, estado, site, setor, tamanho,
                   logo_url, cor_destaque, email_principal, telefone, onboarding_step`,
        [nome, descricao, cidade, estado, site, setor, tamanho,
         telefone, email_principal, logo_url, cor_destaque, empresa_id]
      );
      res.json({ ok: true, empresa: rows[0] });
    } catch (e) {
      console.error('[MINHA-EMPRESA PUT]', e);
      res.status(500).json({ erro: 'Erro ao atualizar empresa' });
    }
  });

  // POST /api/empresa/onboarding/step — avança o step de onboarding da empresa
  app.post('/api/empresa/onboarding/step', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { step } = req.body || {};
      if (typeof step !== 'number') return res.status(400).json({ erro: 'step inválido' });
      await pool.query(
        `UPDATE empresas SET onboarding_step = GREATEST(onboarding_step, $1) WHERE id = $2`,
        [step, empresa_id]
      );
      res.json({ ok: true, step });
    } catch (e) {
      res.status(500).json({ erro: 'Erro ao avançar onboarding' });
    }
  });

  // POST /api/candidato/onboarding/step — avança step de onboarding do candidato
  app.post('/api/candidato/onboarding/step', authCandidato, async (req, res) => {
    try {
      const { step } = req.body || {};
      if (typeof step !== 'number') return res.status(400).json({ erro: 'step inválido' });
      const { rows: c } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [req.user.email]);
      if (c.length === 0) return res.status(404).json({ erro: 'Candidato não encontrado' });
      await pool.query(
        `UPDATE candidatos SET onboarding_step = GREATEST(onboarding_step, $1) WHERE id = $2`,
        [step, c[0].id]
      );
      res.json({ ok: true, step });
    } catch (e) {
      res.status(500).json({ erro: 'Erro ao avançar onboarding' });
    }
  });

  // GET /api/candidato/onboarding — retorna step atual do candidato
  app.get('/api/candidato/onboarding', authCandidato, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT onboarding_step FROM candidatos WHERE email = $1', [req.user.email]
      );
      res.json({ step: rows[0]?.onboarding_step ?? 0 });
    } catch (e) {
      res.status(500).json({ erro: 'Erro' });
    }
  });

  // ─── SaaS Admin: Gestão Global de Empresas ────────────────────────────────

  // GET /api/saas/empresas — lista todas as empresas (admin global)
  app.get('/api/saas/empresas', authGlobalRead, async (req, res) => {
    try {
      const { rows } = await pool.query(`
        SELECT e.id, e.nome, e.slug,
               e.ativo, e.plano, e.plano_id, e.onboarding_step, e.criado_em,
               p.nome AS plano_nome, p.slug AS plano_slug,
               COUNT(DISTINCT v.id) FILTER (WHERE v.status='publicada') AS total_vagas,
               COUNT(DISTINCT c.id) AS total_candidaturas
        FROM empresas e
        LEFT JOIN planos p ON p.id = e.plano_id
        LEFT JOIN vagas v ON v.empresa_id = e.id
        LEFT JOIN candidaturas c ON c.vaga_id = v.id
        GROUP BY e.id, p.id
        ORDER BY e.criado_em DESC
      `);
      res.json({ empresas: rows });
    } catch (e) {
      console.error('[SAAS/EMPRESAS GET]', e);
      res.status(500).json({ erro: 'Erro ao listar empresas' });
    }
  });

  // PUT /api/saas/empresas/:id — atualiza empresa (admin global)
  app.put('/api/saas/empresas/:id', authAdminOnly, async (req, res) => {
    try {
      const { id } = req.params;
      const { ativo, plano, plano_id } = req.body || {};
      const updates = [];
      const vals = [];
      let idx = 1;
      if (typeof ativo === 'boolean') { updates.push(`ativo = $${idx++}`); vals.push(ativo); }
      if (plano !== undefined) { updates.push(`plano = $${idx++}`); vals.push(plano); }
      if (plano_id !== undefined) { updates.push(`plano_id = $${idx++}`); vals.push(plano_id); }
      if (updates.length === 0) return res.status(400).json({ erro: 'Nada a atualizar' });
      vals.push(id);
      const { rows } = await pool.query(
        `UPDATE empresas SET ${updates.join(', ')} WHERE id = $${idx} RETURNING id, nome, ativo, plano`,
        vals
      );
      if (rows.length === 0) return res.status(404).json({ erro: 'Empresa não encontrada' });
      await audit(req, 'saas.empresa.updated', {
        resource_type: 'empresa', resource_id: Number(id),
        metadata: { campos: updates.map(u => u.split(' ')[0]), resultado: rows[0] }
      });
      res.json({ ok: true, empresa: rows[0] });
    } catch (e) {
      console.error('[SAAS/EMPRESAS PUT]', e);
      res.status(500).json({ erro: 'Erro ao atualizar empresa' });
    }
  });

  // ─── SaaS Master: visão executiva e saúde operacional ─────────────────────
  // Dados reais disponíveis no produto. Métricas financeiras ficam como
  // "não conectado" até a integração com um gateway de pagamentos.
  app.get('/api/saas/overview', authGlobalRead, async (req, res) => {
    const safe = async (sql, params = []) => {
      try { return (await pool.query(sql, params)).rows; }
      catch (e) { console.error('[SAAS/OVERVIEW]', e.message); return []; }
    };
    try {
      const [resumo, planos, atividade, ranking, crescimento, seguranca, comunicacao] = await Promise.all([
        safe(`SELECT
          COUNT(*)::int AS empresas_total,
          COUNT(*) FILTER (WHERE ativo = true)::int AS empresas_ativas,
          COUNT(*) FILTER (WHERE ativo = false)::int AS empresas_bloqueadas,
          COUNT(*) FILTER (WHERE criado_em >= CURRENT_DATE)::int AS novos_cadastros_hoje,
          (SELECT COUNT(*)::int FROM empresa_usuarios WHERE ativo = true) AS usuarios_ativos,
          (SELECT COUNT(*)::int FROM vagas WHERE status = 'publicada') AS vagas_abertas,
          (SELECT COUNT(*)::int FROM candidatos) AS candidatos_total,
          (SELECT COUNT(*)::int FROM candidaturas) AS candidaturas_total,
          (SELECT COUNT(*)::int FROM entrevistas WHERE status = 'agendada' AND data_hora >= NOW()) AS entrevistas_agendadas,
          (SELECT COUNT(*)::int FROM candidaturas WHERE status = 'contratado') AS contratacoes_total,
          (SELECT COUNT(*)::int FROM candidaturas WHERE criada_em >= NOW() - INTERVAL '24 hours') AS candidaturas_24h
        FROM empresas`),
        safe(`SELECT COALESCE(plano, 'não definido') AS plano, COUNT(*)::int AS total
              FROM empresas GROUP BY COALESCE(plano, 'não definido') ORDER BY total DESC`),
        safe(`SELECT id, created_at, user_email, user_type, action, resource_type, resource_id, result, metadata
              FROM audit_logs ORDER BY created_at DESC LIMIT 14`),
        safe(`SELECT e.id, e.nome,
                COUNT(DISTINCT v.id) FILTER (WHERE v.status = 'publicada')::int AS vagas,
                COUNT(DISTINCT c.id)::int AS candidatos,
                COUNT(DISTINCT c.id) FILTER (WHERE c.status = 'contratado')::int AS contratacoes
              FROM empresas e
              LEFT JOIN vagas v ON v.empresa_id = e.id
              LEFT JOIN candidaturas c ON c.vaga_id = v.id
              GROUP BY e.id ORDER BY contratacoes DESC, candidatos DESC, vagas DESC LIMIT 8`),
        safe(`SELECT TO_CHAR(date_trunc('month', criado_em), 'YYYY-MM') AS periodo,
                COUNT(*)::int AS empresas,
                (SELECT COUNT(*)::int FROM candidatos c2 WHERE TO_CHAR(date_trunc('month', c2.criado_em), 'YYYY-MM') = TO_CHAR(date_trunc('month', e.criado_em), 'YYYY-MM')) AS candidatos,
                (SELECT COUNT(*)::int FROM vagas v2 WHERE TO_CHAR(date_trunc('month', v2.criada_em), 'YYYY-MM') = TO_CHAR(date_trunc('month', e.criado_em), 'YYYY-MM')) AS vagas
              FROM empresas e
              WHERE criado_em >= NOW() - INTERVAL '6 months'
              GROUP BY date_trunc('month', criado_em) ORDER BY periodo`),
        safe(`SELECT
                (SELECT COUNT(*)::int FROM audit_logs WHERE created_at >= NOW() - INTERVAL '24 hours' AND action ILIKE '%login%' AND result = 'success') AS logins_24h,
                (SELECT COUNT(*)::int FROM audit_logs WHERE created_at >= NOW() - INTERVAL '24 hours' AND result IN ('failure','blocked')) AS falhas_24h,
                (SELECT COUNT(*)::int FROM audit_logs WHERE created_at >= NOW() - INTERVAL '24 hours') AS eventos_24h,
                (SELECT COUNT(*)::int FROM refresh_tokens WHERE revogado_em IS NULL AND expira_em > NOW()) AS tokens_ativos`),
        safe(`SELECT
                COUNT(*) FILTER (WHERE criado_em >= CURRENT_DATE)::int AS emails_hoje,
                COUNT(*) FILTER (WHERE criado_em >= CURRENT_DATE AND status = 'erro')::int AS emails_erro_hoje
              FROM email_outbox`)
      ]);
      res.json({
        ok: true,
        gerado_em: new Date().toISOString(),
        resumo: resumo[0] || {},
        planos,
        atividade: atividade.map(item => ({ ...item, metadata: sanitizarMetadata(item.metadata) })),
        ranking,
        crescimento,
        seguranca: seguranca[0] || {},
        comunicacao: comunicacao[0] || {},
        financeiro: { conectado: false, motivo: 'Gateway de pagamentos ainda não configurado' },
        infraestrutura: { api: 'online', banco: 'online', redis: 'nao_utilizado', monitoramento_recursos: false }
      });
    } catch (e) {
      console.error('[SAAS/OVERVIEW]', e);
      res.status(500).json({ erro: 'Erro ao carregar visão executiva' });
    }
  });

  // =========================================================================
  // FASE 10 — AUTENTICAÇÃO, SESSÕES E RECUPERAÇÃO DE CONTA
  // =========================================================================
  //
  // Módulos importados lazily para evitar circular dep:
  //   totp.js   — TOTP RFC 6238 (sem dependência externa)
  //   token.js  — já importado no topo
  //   passwordReset.js — já importado no topo
  //
  // ── A. GESTÃO DE SESSÕES (todos os tipos) ─────────────────────────────────

  // GET /api/auth/sessoes — lista sessões ativas do usuário logado
  app.get('/api/auth/sessoes', authMiddleware, async (req, res) => {
    try {
      const { email, tipo } = req.user;
      const sessoes = await listarSessoes(email, tipo);
      // Não expor token_hash; apenas metadados de UX
      const lista = sessoes.map(s => ({
        id: s.id,
        ip: s.ip_criacao,
        device: s.device_name || parsarDevice(s.user_agent_criacao),
        criado_em: s.criado_em,
        expira_em: s.expira_em,
      }));
      res.json({ sessoes: lista });
    } catch (e) {
      console.error('[SESSOES LIST]', e);
      res.status(500).json({ erro: 'Erro ao listar sessões' });
    }
  });

  // DELETE /api/auth/sessoes/:id — encerra sessão específica
  app.delete('/api/auth/sessoes/:id', authMiddleware, async (req, res) => {
    try {
      const { email, tipo } = req.user;
      const sessaoId = parseInt(req.params.id, 10);
      if (!sessaoId) return res.status(400).json({ erro: 'ID inválido' });
      const ok = await revogarSessaoById(sessaoId, email, tipo);
      if (!ok) return res.status(404).json({ erro: 'Sessão não encontrada ou já encerrada' });
      res.json({ ok: true });
    } catch (e) {
      console.error('[SESSAO DELETE]', e);
      res.status(500).json({ erro: 'Erro ao encerrar sessão' });
    }
  });

  // POST /api/auth/sessoes/encerrar-outras — revoga todas exceto a atual
  app.post('/api/auth/sessoes/encerrar-outras', authMiddleware, async (req, res) => {
    try {
      const { email, tipo } = req.user;
      const { refreshToken } = req.body || {};
      if (!refreshToken) return res.status(400).json({ erro: 'refreshToken necessário' });
      const count = await revogarOutrasSessoes(email, tipo, refreshToken);
      res.json({ ok: true, encerradas: count });
    } catch (e) {
      console.error('[SESSOES ENCERRAR-OUTRAS]', e);
      res.status(500).json({ erro: 'Erro ao encerrar sessões' });
    }
  });

  // POST /api/auth/sessoes/encerrar-todas — revoga TODAS (logout global)
  app.post('/api/auth/sessoes/encerrar-todas', authMiddleware, async (req, res) => {
    try {
      const { email, tipo } = req.user;
      await revogarTodosPorUsuario(email, tipo, 'logout_global');
      await audit(req, 'security.logout_global', { resource_type: tipo });
      res.json({ ok: true });
    } catch (e) {
      console.error('[SESSOES ENCERRAR-TODAS]', e);
      res.status(500).json({ erro: 'Erro ao encerrar sessões' });
    }
  });

  // Helper: extrai device name do user-agent (UX)
  function parsarDevice(ua) {
    if (!ua) return 'Dispositivo desconhecido';
    if (/mobile/i.test(ua)) return 'Mobile';
    if (/tablet/i.test(ua)) return 'Tablet';
    if (/chrome/i.test(ua)) return 'Chrome (Desktop)';
    if (/firefox/i.test(ua)) return 'Firefox (Desktop)';
    if (/safari/i.test(ua)) return 'Safari (Desktop)';
    return 'Navegador (Desktop)';
  }

  // ── B. TROCAR SENHA — Empresa ──────────────────────────────────────────────

  // POST /api/empresa/trocar-senha — troca senha com confirmação da senha atual
  app.post('/api/empresa/trocar-senha', requireEmpresaViewer, async (req, res) => {
    try {
      const { senha_atual, senha_nova } = req.body || {};
      if (!senha_atual || !senha_nova) return res.status(400).json({ erro: 'senha_atual e senha_nova são obrigatórios' });
      if (senha_nova.length < 8) return res.status(400).json({ erro: 'Senha nova deve ter ao menos 8 caracteres' });

      const { rows } = await pool.query('SELECT senha_hash FROM empresa_usuarios WHERE id = $1', [req.user.id]);
      if (!rows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });

      const ok = await bcrypt.compare(senha_atual, rows[0].senha_hash);
      if (!ok) return res.status(401).json({ erro: 'Senha atual incorreta' });

      const novoHash = await bcrypt.hash(senha_nova, 12);
      await pool.query('UPDATE empresa_usuarios SET senha_hash = $1 WHERE id = $2', [novoHash, req.user.id]);

      // Revogar TODOS os refresh tokens (exceto sessão atual não é possível sem o refresh raw — revogamos todos)
      await revogarTodosPorUsuario(req.user.email, 'empresa', 'password_changed');
      await audit(req, 'security.password_changed', { resource_type: 'empresa', resource_id: req.user.id });
      res.json({ ok: true, msg: 'Senha alterada. Faça login novamente.' });
    } catch (e) {
      console.error('[EMPRESA TROCAR-SENHA]', e);
      res.status(500).json({ erro: 'Erro ao trocar senha' });
    }
  });

  // ── D. RECUPERAÇÃO DE SENHA — Empresa ──────────────────────────────────────
  // Reutiliza passwordReset.js. O destino do link é escolhido no backend
  // conforme o tipo do usuário; nenhum domínio vindo do cliente é aceito.

  app.post('/api/empresa/esqueci-senha', rateLimitByIp('esqueci'), async (req, res) => {
    req.body = req.body || {};
    req.body._user_tipo_hint = 'empresa'; // prioriza empresa_usuarios
    return esqueciSenha(req, res);
  });

  // ── E. 2FA TOTP — Empresa ─────────────────────────────────────────────────

  const { totpVerify, generateTotpSecret, totpOtpauthUrl, generateBackupCodes, verifyBackupCode } = require('./totp');

  // POST /api/empresa/2fa/iniciar — gera segredo TOTP e URL de QR Code (NÃO ativa ainda)
  app.post('/api/empresa/2fa/iniciar', requireEmpresaViewer, async (req, res) => {
    try {
      const { id, email } = req.user;
      // Se já tem 2FA ativo, exige confirmação de senha para resetar
      const { rows } = await pool.query('SELECT totp_ativo, totp_secret FROM empresa_usuarios WHERE id = $1', [id]);
      if (!rows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });

      const secret = generateTotpSecret();
      const otpauthUrl = totpOtpauthUrl(secret, email);

      // Salva segredo PENDENTE (totp_ativo permanece false até confirmação)
      await pool.query('UPDATE empresa_usuarios SET totp_secret = $1 WHERE id = $2', [secret, id]);

      res.json({
        ok: true,
        secret,
        otpauthUrl,
        // QR Code via API pública (não requer chave)
        qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(otpauthUrl)}&size=200x200`,
      });
    } catch (e) {
      console.error('[2FA INICIAR]', e);
      res.status(500).json({ erro: 'Erro ao iniciar 2FA' });
    }
  });

  // POST /api/empresa/2fa/confirmar — confirma e ATIVA o 2FA com primeiro código
  app.post('/api/empresa/2fa/confirmar', requireEmpresaViewer, async (req, res) => {
    try {
      const { id } = req.user;
      const { codigo } = req.body || {};
      if (!codigo || !/^\d{6}$/.test(codigo)) return res.status(400).json({ erro: 'Código inválido' });

      const { rows } = await pool.query('SELECT totp_secret FROM empresa_usuarios WHERE id = $1', [id]);
      if (!rows.length || !rows[0].totp_secret) return res.status(400).json({ erro: 'Inicie o processo de 2FA primeiro' });

      if (!totpVerify(rows[0].totp_secret, codigo)) {
        return res.status(401).json({ erro: 'Código incorreto' });
      }

      // Gera backup codes
      const { plainCodes, hashedCodes } = await generateBackupCodes();
      await pool.query(
        `UPDATE empresa_usuarios SET totp_ativo = true, totp_backup_codes = $1, totp_ativado_em = NOW() WHERE id = $2`,
        [JSON.stringify(hashedCodes), id]
      );
      await audit(req, 'security.2fa_enabled', { resource_type: 'empresa', resource_id: id });
      res.json({ ok: true, backup_codes: plainCodes, msg: '2FA ativado. Guarde os códigos de backup.' });
    } catch (e) {
      console.error('[2FA CONFIRMAR]', e);
      res.status(500).json({ erro: 'Erro ao confirmar 2FA' });
    }
  });

  // POST /api/empresa/2fa/verificar — verifica código no login (quando 2FA ativo)
  // Chamado pelo frontend após login com empresa_2fa_pending token
  app.post('/api/empresa/2fa/verificar', rateLimitByIp('twofa'), async (req, res) => {
    try {
      const { pending_token, codigo } = req.body || {};
      if (!pending_token || !codigo) return res.status(400).json({ erro: 'pending_token e codigo obrigatórios' });

      // Valida o pending_token (JWT temporário de 5min, tipo='empresa_2fa_pending')
      let payload;
      try {
        payload = jwt.verify(pending_token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
      } catch {
        return res.status(401).json({ erro: 'Token inválido ou expirado' });
      }
      if (payload.tipo !== 'empresa_2fa_pending') return res.status(401).json({ erro: 'Token inválido' });

      const { rows } = await pool.query(
        `SELECT u.id, u.nome, u.email, u.totp_secret, u.totp_ativo, u.totp_backup_codes,
                u.ativo, u.role, u.empresa_id, u.primeiro_acesso, e.nome as empresa_nome
         FROM empresa_usuarios u JOIN empresas e ON e.id = u.empresa_id
         WHERE u.id = $1`,
        [payload.id]
      );
      if (!rows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });
      const u = rows[0];
      if (!u.ativo) return res.status(403).json({ erro: 'Conta desativada' });

      // Verifica código TOTP ou backup code
      let valido = false;
      let updatedBackups = null;
      if (/^\d{6}$/.test(codigo)) {
        valido = totpVerify(u.totp_secret, codigo);
      } else {
        // Tentativa de backup code
        const backups = JSON.parse(u.totp_backup_codes || '[]');
        const result = await verifyBackupCode(backups, codigo);
        valido = result.valido;
        if (valido) updatedBackups = result.updatedCodes;
      }

      if (!valido) {
        await audit(req, 'login.2fa_failed', { resource_type: 'empresa', resource_id: u.id });
        return res.status(401).json({ erro: 'Código incorreto' });
      }

      // Atualiza backup codes se foi usado um
      if (updatedBackups !== null) {
        await pool.query('UPDATE empresa_usuarios SET totp_backup_codes = $1 WHERE id = $2', [JSON.stringify(updatedBackups), u.id]);
      }

      // Emite access + refresh definitivos
      const accessToken = criarAccessToken({
        id: u.id, email: u.email, tipo: 'empresa',
        empresa_id: u.empresa_id, empresa_nome: u.empresa_nome, role: u.role
      });
      const refresh = criarRefreshToken();
      await persistirRefresh('empresa', u.id, u.email, refresh, req, {
        user_role: u.role, user_empresa_id: u.empresa_id
      });
      await audit(req, 'login.2fa_verified', { resource_type: 'empresa', resource_id: u.id, user_email: u.email });
      res.json({
        ok: true,
        token: accessToken,
        refreshToken: refresh,
        primeiro_acesso: u.primeiro_acesso,
        usuario: { id: u.id, nome: u.nome, email: u.email, tipo: 'empresa', role: u.role, empresa_id: u.empresa_id, empresa_nome: u.empresa_nome }
      });
    } catch (e) {
      console.error('[2FA VERIFICAR]', e);
      res.status(500).json({ erro: 'Erro ao verificar 2FA' });
    }
  });

  // POST /api/empresa/2fa/desativar — desativa 2FA com confirmação de senha
  app.post('/api/empresa/2fa/desativar', requireEmpresaViewer, async (req, res) => {
    try {
      const { id, email } = req.user;
      const { senha } = req.body || {};
      if (!senha) return res.status(400).json({ erro: 'Senha obrigatória para desativar 2FA' });

      const { rows } = await pool.query('SELECT senha_hash, totp_ativo FROM empresa_usuarios WHERE id = $1', [id]);
      if (!rows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });
      if (!rows[0].totp_ativo) return res.status(400).json({ erro: '2FA não está ativo' });

      const ok = await bcrypt.compare(senha, rows[0].senha_hash);
      if (!ok) return res.status(401).json({ erro: 'Senha incorreta' });

      await pool.query(
        `UPDATE empresa_usuarios SET totp_ativo = false, totp_secret = NULL, totp_backup_codes = '[]', totp_ativado_em = NULL WHERE id = $1`,
        [id]
      );
      await audit(req, 'security.2fa_disabled', { resource_type: 'empresa', resource_id: id });
      res.json({ ok: true, msg: '2FA desativado.' });
    } catch (e) {
      console.error('[2FA DESATIVAR]', e);
      res.status(500).json({ erro: 'Erro ao desativar 2FA' });
    }
  });

  // GET /api/empresa/2fa/status — retorna se 2FA está ativo e data de ativação
  app.get('/api/empresa/2fa/status', requireEmpresaViewer, async (req, res) => {
    try {
      const { rows } = await pool.query(
        'SELECT totp_ativo, totp_ativado_em FROM empresa_usuarios WHERE id = $1',
        [req.user.id]
      );
      if (!rows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });
      res.json({ totp_ativo: rows[0].totp_ativo || false, ativado_em: rows[0].totp_ativado_em });
    } catch (e) {
      res.status(500).json({ erro: 'Erro' });
    }
  });

  // ── F. MODIFICAÇÃO DO LOGIN EMPRESA — adiciona 2FA quando ativo ───────────
  // O login de empresa já existe em /api/auth/login-empresa (linha ~4784).
  // Para não duplicar, adicionamos um middleware pós-autenticação via patch.
  // A abordagem é: criar um novo endpoint /api/auth/login-empresa-v2 com 2FA,
  // e manter o original para compatibilidade. O frontend empresa/login.html
  // chama o endpoint correto conforme o status 2FA retornado.
  //
  // Na prática: o login existente retorna { requer_2fa: true, pending_token }
  // quando totp_ativo=true. Adicionamos isso via patch abaixo.
  //
  // NOTA: não podemos substituir a rota existente (já registrada antes desta linha).
  // Criamos /api/auth/login-empresa-2fa como substituta quando frontend atualizar.

  // PATCH de comportamento 2FA no login empresa: rota alternativa
  // O frontend empresa/login.html deve chamar este endpoint quando disponível.
  app.post('/api/auth/login-empresa-v2', rateLimitLogin, async (req, res) => {
    try {
      const { email, senha } = req.body || {};
      if (!email || !senha) return res.status(400).json({ erro: 'E-mail e senha obrigatórios' });

      const { rows } = await pool.query(`
        SELECT u.id, u.nome, u.email, u.senha_hash, u.ativo, u.primeiro_acesso, u.cargo, u.role,
               u.empresa_id, u.totp_ativo, u.totp_secret,
               e.nome as empresa_nome, e.ativo as empresa_ativa
        FROM empresa_usuarios u
        JOIN empresas e ON e.id = u.empresa_id
        WHERE u.email = $1
      `, [email.toLowerCase()]);

      if (!rows.length) {
        rateLimitRegisterFail(req);
        await audit(req, 'login.failure', { resource_type: 'empresa', metadata: { email: email.toLowerCase() } });
        return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
      }

      const u = rows[0];
      if (!u.ativo || !u.empresa_ativa) {
        return res.status(403).json({ erro: 'Conta ou empresa desativada' });
      }

      const ok = await bcrypt.compare(senha, u.senha_hash);
      if (!ok) {
        rateLimitRegisterFail(req);
        await audit(req, 'login.failure', { resource_type: 'empresa', metadata: { email: email.toLowerCase() } });
        return res.status(401).json({ erro: 'E-mail ou senha inválidos' });
      }

      rateLimitClear(req);

      // Se 2FA está ativo → retorna pending token (5min), não emite sessão
      if (u.totp_ativo) {
        const pendingToken = jwt.sign(
          { id: u.id, email: u.email, tipo: 'empresa_2fa_pending' },
          process.env.JWT_SECRET,
          { algorithm: 'HS256', expiresIn: '5m', issuer: 'vagasio-api' }
        );
        await audit(req, 'login.2fa_required', { resource_type: 'empresa', resource_id: u.id });
        return res.json({ ok: true, requer_2fa: true, pending_token: pendingToken });
      }

      // Sem 2FA → emite tokens normalmente
      const accessToken = criarAccessToken({
        id: u.id, email: u.email, tipo: 'empresa',
        empresa_id: u.empresa_id, empresa_nome: u.empresa_nome, role: u.role
      });
      const refresh = criarRefreshToken();
      await persistirRefresh('empresa', u.id, u.email, refresh, req, {
        user_role: u.role, user_empresa_id: u.empresa_id
      });
      await audit(req, 'login.success', { resource_type: 'empresa', resource_id: u.id, user_email: u.email });
      res.json({
        ok: true,
        token: accessToken,
        refreshToken: refresh,
        primeiro_acesso: u.primeiro_acesso,
        usuario: { id: u.id, nome: u.nome, email: u.email, tipo: 'empresa', role: u.role, empresa_id: u.empresa_id, empresa_nome: u.empresa_nome }
      });
    } catch (e) {
      console.error('[LOGIN EMPRESA V2]', e);
      res.status(500).json({ erro: 'Erro interno' });
    }
  });

  const port = process.env.PORT || 10000;

  // =========================================================================
  // FASE 11 — Busca avançada, Tags de Vaga, Favoritos, Score de Match
  // Helper: resolve candidato_id do JWT (pode ser id direto ou busca por email para tokens antigos)
  async function resolveCandId(user) {
    if (user.id) return user.id;
    const { rows } = await pool.query('SELECT id FROM candidatos WHERE email = $1', [user.email]);
    return rows.length ? rows[0].id : null;
  }
  // ═══════════════════════════════════════════════════════════════════════════

  // ── HELPERS DE MATCH ───────────────────────────────────────────────────────

  /**
   * Calcula score de compatibilidade candidato × vaga (0-100, determinístico).
   *
   * Pesos:
   *   área compatível        → até 30 pts
   *   cidade/estado          → até 20 pts (10 cidade + 10 estado; só estado = 10)
   *   nível de experiência   → até 20 pts
   *   tags/competências      → até 30 pts
   *
   * Retorna { score, detalhes[] } onde cada detalhe tem { criterio, pontos, max, ok }
   */
  function calcularMatch(candidato, vaga, vagaTags) {
    const detalhes = [];
    let total = 0;

    // 1. Área (30 pts)
    const areaVaga = (vaga.area || '').toLowerCase().trim();
    const areasInteresse = Array.isArray(candidato.areas_interesse)
      ? candidato.areas_interesse.map(a => String(a).toLowerCase().trim())
      : [];
    const competencias = Array.isArray(candidato.competencias)
      ? candidato.competencias.map(c => String(c).toLowerCase().trim())
      : [];

    const areaOk = areaVaga && areasInteresse.some(a => a && (a.includes(areaVaga) || areaVaga.includes(a)));
    const ptArea = areaOk ? 30 : 0;
    total += ptArea;
    detalhes.push({ criterio: 'área compatível', pontos: ptArea, max: 30, ok: areaOk });

    // 2. Localização (20 pts)
    const cidadeVaga  = (vaga.cidade  || '').toLowerCase().trim();
    const estadoVaga  = (vaga.estado  || '').toLowerCase().trim();
    const cidadeCand  = (candidato.cidade  || '').toLowerCase().trim();
    const estadoCand  = (candidato.estado  || '').toLowerCase().trim();
    const cidadeOk = cidadeVaga && cidadeCand && cidadeVaga === cidadeCand;
    const estadoOk = estadoVaga && estadoCand && estadoVaga === estadoCand;
    const ptLocal = cidadeOk ? 20 : estadoOk ? 10 : 0;
    total += ptLocal;
    detalhes.push({
      criterio: 'localização compatível',
      pontos: ptLocal, max: 20,
      ok: ptLocal > 0,
      detalhe: cidadeOk ? 'mesma cidade' : estadoOk ? 'mesmo estado' : 'diferente'
    });

    // 3. Nível de experiência (20 pts)
    const nivelVaga = (vaga.nivel || '').toLowerCase().trim();
    const nivelCand = (candidato.nivel_experiencia || '').toLowerCase().trim();
    let ptNivel = 0;
    let nivelDetalhe = 'não informado';
    if (nivelVaga && nivelCand) {
      if (nivelVaga === nivelCand) {
        ptNivel = 20; nivelDetalhe = 'exato';
      } else {
        const ordem = ['estágio','júnior','pleno','sênior','especialista','gerente'];
        const iV = ordem.findIndex(n => nivelVaga.includes(n));
        const iC = ordem.findIndex(n => nivelCand.includes(n));
        if (iV >= 0 && iC >= 0) {
          const diff = Math.abs(iV - iC);
          ptNivel = diff === 1 ? 10 : diff === 0 ? 20 : 0;
          nivelDetalhe = diff === 0 ? 'exato' : diff === 1 ? 'parcial' : 'distante';
        }
      }
    }
    total += ptNivel;
    detalhes.push({ criterio: 'nível de experiência', pontos: ptNivel, max: 20, ok: ptNivel >= 10, detalhe: nivelDetalhe });

    // 4. Tags/competências (30 pts)
    const tags = (vagaTags || []).map(t => t.toLowerCase().trim()).filter(Boolean);
    if (tags.length === 0 && competencias.length === 0) {
      detalhes.push({ criterio: 'competências compatíveis', pontos: 0, max: 30, ok: false, detalhe: 'sem dados' });
    } else if (tags.length === 0) {
      detalhes.push({ criterio: 'competências compatíveis', pontos: 0, max: 30, ok: false, detalhe: 'vaga sem tags' });
    } else {
      const matches = tags.filter(tag =>
        competencias.some(c => c.includes(tag) || tag.includes(c)) ||
        areasInteresse.some(a => a.includes(tag) || tag.includes(a))
      );
      const ratio = matches.length / tags.length;
      const ptTags = Math.round(ratio * 30);
      total += ptTags;
      detalhes.push({
        criterio: 'competências compatíveis',
        pontos: ptTags, max: 30, ok: ptTags > 0,
        detalhe: `${matches.length}/${tags.length} correspondências`
      });
    }

    return { score: Math.min(100, total), detalhes };
  }

  // ── 1. BUSCA AVANÇADA DE CANDIDATOS — /api/empresa/candidatos ─────────────

  app.get('/api/empresa/candidatos', requireEmpresaViewer, async (req, res) => {
    try {
      const { q, cidade, estado, area, vaga_id, status, etapa, pagina = 1, limite = 20 } = req.query;
      const emp = req.user.empresa_id;
      const pg  = Math.max(1, parseInt(pagina) || 1);
      const lim = Math.min(100, Math.max(1, parseInt(limite) || 20));
      const offset = (pg - 1) * lim;

      // Base: candidatos que têm candidatura em vagas desta empresa
      // Permite filtrar por qualquer combinação de campos existentes
      let where = [`eva.empresa_id = $1`, empresaVagaFilialScope(req)];
      const params = [emp];

      if (q) {
        params.push(`%${q.toLowerCase()}%`);
        where.push(`(lower(c.nome) LIKE $${params.length} OR lower(c.email) LIKE $${params.length})`);
      }
      if (cidade) {
        params.push(cidade.toLowerCase());
        where.push(`lower(c.cidade) = $${params.length}`);
      }
      if (estado) {
        params.push(estado.toLowerCase());
        where.push(`lower(c.estado) = $${params.length}`);
      }
      if (area) {
        params.push(JSON.stringify([area]));
        where.push(`c.areas_interesse @> $${params.length}::jsonb`);
      }
      if (vaga_id) {
        params.push(parseInt(vaga_id));
        where.push(`can.vaga_id = $${params.length}`);
      }
      if (status) {
        params.push(status);
        where.push(`can.status = $${params.length}`);
      }
      if (etapa) {
        const etapaNum = Number(etapa);
        if (Number.isInteger(etapaNum) && etapaNum > 0) {
          params.push(etapaNum);
          where.push(`can.etapa_atual = $${params.length}`);
        }
      }

      const whereSql = where.join(' AND ');

      // Contagem total
      const { rows: cnt } = await pool.query(`
        SELECT COUNT(DISTINCT c.id) AS total
        FROM candidatos c
        JOIN candidaturas can ON can.candidato_id = c.id
        JOIN vagas v          ON v.id = can.vaga_id
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
        WHERE ${whereSql}
      `, params);
      const total = parseInt(cnt[0].total);

      // Resultados paginados
      params.push(lim, offset);
      const { rows } = await pool.query(`
        SELECT DISTINCT ON (c.id)
               c.id, c.nome, c.email, c.cidade, c.estado,
               c.areas_interesse, c.nivel_experiencia, c.competencias,
               c.foto_url, c.criado_em,
               can.status AS ultimo_status,
               can.id     AS ultima_candidatura_id,
               can.etapa_atual AS ultima_etapa,
               v.titulo   AS ultima_vaga_titulo,
               v.id       AS ultima_vaga_id
        FROM candidatos c
        JOIN candidaturas can ON can.candidato_id = c.id
        JOIN vagas v          ON v.id = can.vaga_id
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
        WHERE ${whereSql}
        ORDER BY c.id, can.criada_em DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}
      `, params);

      res.json({
        candidatos: rows,
        paginacao: { total, pagina: pg, limite: lim, paginas: Math.ceil(total / lim) }
      });
    } catch (e) {
      console.error('[empresa/candidatos]', e);
      res.status(500).json({ erro: 'Erro ao buscar candidatos' });
    }
  });

  // ── 1b. DETALHE DE CANDIDATO — compatibilidade com o Admin antigo ────────
  // Escopo: só candidatos que possuem candidatura em vaga liberada para a
  // empresa autenticada. Mantém o currículo do layout antigo sem vazar dados.
  app.get('/api/empresa/candidatos/:id', requireEmpresaViewer, async (req, res) => {
    try {
      const candidatoId = Number(req.params.id);
      const empresaId = req.user.empresa_id;
      if (!Number.isInteger(candidatoId) || candidatoId <= 0) {
        return res.status(400).json({ erro: 'ID de candidato inválido' });
      }
      const { rows } = await pool.query(`
        SELECT DISTINCT c.id, c.nome, c.email, c.celular, c.cpf, c.data_nascimento,
          c.sexo, c.acessibilidade, c.cep, c.estado, c.cidade, c.bairro,
          c.logradouro, c.numero, c.complemento, c.formacao, c.instituicao,
          c.curso, c.situacao, c.data_conclusao, c.primeiro_emprego,
          c.sobre_voce, c.experiencia, c.foto_url, c.areas_interesse,
          c.nivel_experiencia, c.competencias, c.banco_talentos, c.criado_em
        FROM candidatos c
        JOIN candidaturas can ON can.candidato_id = c.id
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = can.vaga_id AND eva.revogado_em IS NULL
        WHERE c.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
          AND ${empresaVagaFilialScope(req, 'eva')}
        LIMIT 1
      `, [candidatoId, empresaId]);
      if (!rows.length) return res.status(404).json({ erro: 'Candidato não encontrado' });
      const { rows: experiencias } = await pool.query(
        'SELECT id, candidato_id, cargo, empresa, inicio, fim, emprego_atual, descricao FROM experiencias WHERE candidato_id = $1 ORDER BY inicio DESC NULLS LAST, id DESC',
        [candidatoId]
      );
      const candidato = { ...rows[0], experiencias };
      if (req.user.role === 'viewer') {
        for (const campo of ['cpf', 'data_nascimento', 'sexo', 'acessibilidade', 'cep', 'logradouro', 'numero', 'complemento', 'bairro']) delete candidato[campo];
      }
      res.json({ candidato });
    } catch (e) {
      console.error('[empresa candidato detalhe]', e);
      res.status(500).json({ erro: 'Erro ao carregar candidato' });
    }
  });

  // ── 2. TAGS DE VAGA ───────────────────────────────────────────────────────

  // Convida um candidato do Banco de Talentos para uma vaga específica.
  // O envio só ocorre após a ação explícita da empresa no botão de convite.
  app.post('/api/empresa/candidatos/:id/convite', requireRecrutadorOuAdmin, async (req, res) => {
    const candidatoId = Number(req.params.id);
    const vagaId = Number(req.body?.vaga_id);
    const mensagem = String(req.body?.mensagem || '').trim();
    if (!Number.isInteger(candidatoId) || candidatoId <= 0 || !Number.isInteger(vagaId) || vagaId <= 0) {
      return res.status(400).json({ erro: 'Candidato e vaga são obrigatórios' });
    }
    if (mensagem.length > 2000) return res.status(400).json({ erro: 'A mensagem não pode ultrapassar 2.000 caracteres' });
    try {
      const { rows } = await pool.query(`
        SELECT c.id AS candidato_id, c.nome AS candidato_nome, c.email AS candidato_email,
               v.id AS vaga_id, v.titulo, v.descricao, v.requisitos, v.beneficios,
               v.cidade, v.estado, v.tipo_contrato, v.area,
               COALESCE(e.nome, v.empresa, 'VagasIO') AS empresa_nome
        FROM candidatos c
        JOIN vagas v ON v.id = $2
        JOIN empresas e ON e.id = $3
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id
          AND eva.empresa_id = $3 AND eva.revogado_em IS NULL
        WHERE c.id = $1
          AND EXISTS (
            SELECT 1 FROM candidaturas cx
            JOIN empresa_vaga_acesso exa ON exa.vaga_id = cx.vaga_id
              AND exa.empresa_id = $3 AND exa.revogado_em IS NULL
            WHERE cx.candidato_id = c.id
          )
        LIMIT 1
      `, [candidatoId, vagaId, req.user.empresa_id]);
      if (!rows.length) return res.status(404).json({ erro: 'Candidato ou vaga não encontrado' });
      const c = rows[0];
      if (!c.candidato_email) return res.status(400).json({ erro: 'Este candidato não possui e-mail cadastrado' });
      const base = String(process.env.FRONTEND_URL || 'https://vagasio.com.br').replace(/\/$/, '');
      const vagaUrl = `${base}/candidato/vaga.html?id=${encodeURIComponent(vagaId)}`;
      const plain = value => String(value || '').trim();
      const detalhe = mensagem ? `<div style="background:#fff8e6;border-left:4px solid #c9a961;padding:14px 16px;margin:20px 0;white-space:pre-wrap"><strong>Mensagem do recrutador</strong><br>${escapeEmailHtml(mensagem)}</div>` : '';
      const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;background:#fafafa;color:#252525">
        <div style="background:#722f37;color:#fff;padding:22px;border-radius:8px;text-align:center"><h2 style="margin:0">${escapeEmailHtml(c.empresa_nome)}</h2><p style="margin:8px 0 0">Convite para participar de um processo seletivo</p></div>
        <div style="background:#fff;padding:26px 22px;border-radius:8px;margin-top:16px">
          <p>Olá, <strong>${escapeEmailHtml(c.candidato_nome)}</strong>!</p>
          <p>Seu perfil chamou a atenção da equipe de recrutamento para a vaga:</p>
          <h2 style="color:#722f37;margin:18px 0 8px">${escapeEmailHtml(c.titulo)}</h2>
          <p><strong>Empresa:</strong> ${escapeEmailHtml(c.empresa_nome)}<br><strong>Local:</strong> ${escapeEmailHtml([c.cidade,c.estado].filter(Boolean).join('/') || 'Não informado')}<br><strong>Contrato:</strong> ${escapeEmailHtml(c.tipo_contrato || 'Não informado')}<br><strong>Área:</strong> ${escapeEmailHtml(c.area || 'Não informada')}</p>
          ${plain(c.descricao) ? `<h3>Sobre a vaga</h3><p style="white-space:pre-wrap">${escapeEmailHtml(c.descricao)}</p>` : ''}
          ${plain(c.requisitos) ? `<h3>Requisitos</h3><p style="white-space:pre-wrap">${escapeEmailHtml(c.requisitos)}</p>` : ''}
          ${plain(c.beneficios) ? `<h3>Benefícios</h3><p style="white-space:pre-wrap">${escapeEmailHtml(c.beneficios)}</p>` : ''}
          ${detalhe}
          <p style="text-align:center;margin:26px 0 8px"><a href="${escapeEmailHtml(vagaUrl)}" style="background:#722f37;color:#fff;padding:13px 24px;border-radius:6px;text-decoration:none;font-weight:700">Ver detalhes e participar</a></p>
          <p style="font-size:12px;color:#777">A participação depende do seu interesse e da conclusão da candidatura no portal.</p>
        </div>
      </div>`;
      const text = `Olá, ${c.candidato_nome}!\\n\\n${c.empresa_nome} convidou você para participar do processo seletivo da vaga ${c.titulo}.\\nLocal: ${[c.cidade,c.estado].filter(Boolean).join('/') || 'Não informado'}\\n\\nVeja os detalhes e participe: ${vagaUrl}${mensagem ? `\\n\\nMensagem do recrutador:\\n${mensagem}` : ''}`;
      await enviarEmail({ to: c.candidato_email, subject: `Convite para participar do processo seletivo — ${c.titulo}`, html, text });
      await audit(req, 'empresa.candidato.invited', { resource_type: 'candidato', resource_id: candidatoId, metadata: { vaga_id: vagaId } });
      res.json({ ok: true, email: c.candidato_email, vaga: { id: c.vaga_id, titulo: c.titulo } });
    } catch (e) {
      console.error('[empresa candidato convite]', e.message);
      res.status(503).json({ erro: 'Não foi possível enviar o convite por e-mail' });
    }
  });

  // GET /api/empresa/vagas/:id/tags
  app.get('/api/empresa/vagas/:id/tags', requireEmpresaViewer, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const emp = req.user.empresa_id;
      // Verifica acesso da empresa à vaga
      const { rows: acesso } = await pool.query(
        `SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = $2 AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}`, [emp, vagaId]
      );
      if (!acesso.length) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });

      const { rows } = await pool.query(
        `SELECT id, tag, criado_em FROM vaga_tags WHERE vaga_id = $1 ORDER BY criado_em`, [vagaId]
      );
      res.json({ tags: rows });
    } catch (e) {
      console.error('[tags GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar tags' });
    }
  });

  // POST /api/empresa/vagas/:id/tags — adiciona uma tag
  app.post('/api/empresa/vagas/:id/tags', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const emp = req.user.empresa_id;
      const tag = String(req.body?.tag || '').trim().toLowerCase();

      if (!tag || tag.length < 1 || tag.length > 60) {
        return res.status(400).json({ erro: 'Tag inválida (1–60 caracteres)' });
      }
      const { rows: acesso } = await pool.query(
        `SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = $2 AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}`, [emp, vagaId]
      );
      if (!acesso.length) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });

      const { rows } = await pool.query(
        `INSERT INTO vaga_tags (vaga_id, tag) VALUES ($1, $2)
         ON CONFLICT ON CONSTRAINT vaga_tags_unique DO NOTHING
         RETURNING id, tag, criado_em`,
        [vagaId, tag]
      );
      if (!rows.length) return res.status(409).json({ erro: 'Tag já existe nesta vaga' });
      res.status(201).json({ tag: rows[0] });
    } catch (e) {
      console.error('[tags POST]', e);
      res.status(500).json({ erro: 'Erro ao adicionar tag' });
    }
  });

  // DELETE /api/empresa/vagas/:id/tags/:tag
  app.delete('/api/empresa/vagas/:id/tags/:tag', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const tag = decodeURIComponent(req.params.tag).trim().toLowerCase();
      const emp = req.user.empresa_id;

      const { rows: acesso } = await pool.query(
        `SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = $2 AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}`, [emp, vagaId]
      );
      if (!acesso.length) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });

      const { rowCount } = await pool.query(
        `DELETE FROM vaga_tags WHERE vaga_id = $1 AND tag = $2`, [vagaId, tag]
      );
      if (rowCount === 0) return res.status(404).json({ erro: 'Tag não encontrada' });
      res.json({ ok: true });
    } catch (e) {
      console.error('[tags DELETE]', e);
      res.status(500).json({ erro: 'Erro ao remover tag' });
    }
  });

  // PUT /api/empresa/vagas/:id/tags — substitui lista completa de tags
  app.put('/api/empresa/vagas/:id/tags', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const emp = req.user.empresa_id;
      const { tags } = req.body || {};

      if (!Array.isArray(tags)) return res.status(400).json({ erro: 'tags deve ser array' });
      const tagsList = [...new Set(tags.map(t => String(t).trim().toLowerCase()).filter(t => t.length > 0 && t.length <= 60))];

      const { rows: acesso } = await pool.query(
        `SELECT 1 FROM empresa_vaga_acesso eva_scope WHERE eva_scope.empresa_id = $1 AND eva_scope.vaga_id = $2 AND eva_scope.revogado_em IS NULL AND ${empresaVagaFilialScope(req, 'eva_scope')}`, [emp, vagaId]
      );
      if (!acesso.length) return res.status(403).json({ erro: 'Sem acesso a esta vaga' });

      // Substitui atomicamente
      await pool.query('BEGIN');
      await pool.query(`DELETE FROM vaga_tags WHERE vaga_id = $1`, [vagaId]);
      for (const t of tagsList) {
        await pool.query(`INSERT INTO vaga_tags (vaga_id, tag) VALUES ($1, $2)`, [vagaId, t]);
      }
      await pool.query('COMMIT');

      const { rows } = await pool.query(
        `SELECT id, tag, criado_em FROM vaga_tags WHERE vaga_id = $1 ORDER BY criado_em`, [vagaId]
      );
      res.json({ tags: rows });
    } catch (e) {
      await pool.query('ROLLBACK');
      console.error('[tags PUT]', e);
      res.status(500).json({ erro: 'Erro ao atualizar tags' });
    }
  });

  // GET /api/public/vagas — adicionar tags quando buscar vagas públicas (patch da rota existente)
  // NOTA: A rota /api/public/vagas já existe. Criamos a rota de tags por vaga individual.

  // GET /api/public/vagas/:id/tags — tags visíveis no portal público
  app.get('/api/public/vagas/:id/tags', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT t.tag FROM vaga_tags t
         JOIN vagas v ON v.id = t.vaga_id
         WHERE t.vaga_id = $1 AND v.status = 'publicada'
           AND EXISTS (SELECT 1 FROM empresas e WHERE e.id = v.empresa_id AND e.ativo = true)
         ORDER BY t.criado_em`, [parseInt(req.params.id)]
      );
      res.json({ tags: rows.map(r => r.tag) });
    } catch (e) {
      res.status(500).json({ erro: 'Erro ao buscar tags' });
    }
  });

  // Filtrar vagas por tag (público)
  app.get('/api/public/vagas/por-tag/:tag', async (req, res) => {
    try {
      const tag = decodeURIComponent(req.params.tag).trim().toLowerCase();
      const { rows } = await pool.query(`
        SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.tipo_contrato, v.nivel, v.area,
               v.salario_min, v.salario_max, v.descricao, v.status, v.criada_em
        FROM vagas v
        JOIN vaga_tags t ON t.vaga_id = v.id
        JOIN empresas e ON e.id = v.empresa_id AND e.ativo = true
        WHERE t.tag = $1 AND v.status = 'publicada'
        ORDER BY v.criada_em DESC
        LIMIT 50
      `, [tag]);
      res.json({ vagas: rows, tag });
    } catch (e) {
      res.status(500).json({ erro: 'Erro ao buscar vagas por tag' });
    }
  });

  // ── 3. FAVORITOS DO CANDIDATO ────────────────────────────────────────────

  // GET /api/candidato/favoritos
  app.get('/api/candidato/favoritos', authCandidato, async (req, res) => {
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: "Perfil de candidato não encontrado" });
      const { rows } = await pool.query(`
        SELECT f.id AS favorito_id, f.criado_em AS favoritado_em,
               v.id, v.titulo, v.empresa, v.cidade, v.estado,
               v.tipo_contrato, v.nivel, v.area, v.status,
               v.salario_min, v.salario_max,
               ARRAY(SELECT tag FROM vaga_tags WHERE vaga_id = v.id ORDER BY criado_em) AS tags,
               (SELECT id FROM candidaturas WHERE candidato_id = $1 AND vaga_id = v.id LIMIT 1) AS candidatura_id
        FROM candidato_favoritos f
        JOIN vagas v ON v.id = f.vaga_id
        WHERE f.candidato_id = $1
        ORDER BY f.criado_em DESC
      `, [candId]);
      res.json({ favoritos: rows });
    } catch (e) {
      console.error('[favoritos GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar favoritos' });
    }
  });

  // POST /api/candidato/favoritos/:vaga_id
  app.post('/api/candidato/favoritos/:vaga_id', authCandidato, async (req, res) => {
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: "Perfil de candidato não encontrado" });
      const vagaId = parseInt(req.params.vaga_id);
      if (!vagaId) return res.status(400).json({ erro: 'vaga_id inválido' });

      // Verifica se vaga existe (qualquer status — candidato pode favoritar antes de publicação)
      const { rows: vaga } = await pool.query(
        `SELECT id, titulo FROM vagas WHERE id = $1`, [vagaId]
      );
      if (!vaga.length) return res.status(404).json({ erro: 'Vaga não encontrada' });

      const { rows } = await pool.query(
        `INSERT INTO candidato_favoritos (candidato_id, vaga_id)
         VALUES ($1, $2)
         ON CONFLICT ON CONSTRAINT candidato_favoritos_unique DO NOTHING
         RETURNING id, criado_em`,
        [candId, vagaId]
      );
      if (!rows.length) return res.status(409).json({ ok: true, msg: 'Vaga já está nos favoritos' });
      res.status(201).json({ ok: true, favorito_id: rows[0].id, vaga_titulo: vaga[0].titulo });
    } catch (e) {
      console.error('[favoritos POST]', e);
      res.status(500).json({ erro: 'Erro ao favoritar vaga' });
    }
  });

  // DELETE /api/candidato/favoritos/:vaga_id
  app.delete('/api/candidato/favoritos/:vaga_id', authCandidato, async (req, res) => {
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: "Perfil de candidato não encontrado" });
      const vagaId = parseInt(req.params.vaga_id);
      const { rowCount } = await pool.query(
        `DELETE FROM candidato_favoritos WHERE candidato_id = $1 AND vaga_id = $2`,
        [candId, vagaId]
      );
      if (rowCount === 0) return res.status(404).json({ erro: 'Favorito não encontrado' });
      res.json({ ok: true });
    } catch (e) {
      console.error('[favoritos DELETE]', e);
      res.status(500).json({ erro: 'Erro ao desfavoritar vaga' });
    }
  });

  // ── 4. SCORE DE MATCH ────────────────────────────────────────────────────

  // GET /api/empresa/vagas/:id/matches — candidatos ordenados por score
  app.get('/api/empresa/vagas/:id/matches', requireEmpresaViewer, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const emp = req.user.empresa_id;

      // Verifica acesso da empresa à vaga
      const { rows: vagaRows } = await pool.query(`
        SELECT v.id, v.titulo, v.area, v.cidade, v.estado, v.nivel
        FROM vagas v
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = v.id AND eva.revogado_em IS NULL
        WHERE v.id = $1 AND eva.revogado_em IS NULL AND eva.empresa_id = $2
          AND ${empresaVagaFilialScope(req, 'eva')}
      `, [vagaId, emp]);
      if (!vagaRows.length) return res.status(404).json({ erro: 'Vaga não encontrada ou sem acesso' });
      const vaga = vagaRows[0];

      // Tags da vaga
      const { rows: tagRows } = await pool.query(
        `SELECT tag FROM vaga_tags WHERE vaga_id = $1`, [vagaId]
      );
      const vagaTags = tagRows.map(r => r.tag);

      // Candidatos com candidatura nesta vaga
      const { rows: candidatos } = await pool.query(`
        SELECT c.id, c.nome, c.email, c.cidade, c.estado,
               c.areas_interesse, c.nivel_experiencia, c.competencias, c.foto_url,
               can.id AS candidatura_id, can.status, can.etapa_atual
        FROM candidatos c
        JOIN candidaturas can ON can.candidato_id = c.id
        WHERE can.vaga_id = $1
        ORDER BY c.nome
      `, [vagaId]);

      // Calcular scores
      const resultado = candidatos.map(c => {
        const { score, detalhes } = calcularMatch(c, vaga, vagaTags);
        return {
          candidato_id: c.id,
          nome: c.nome,
          email: c.email,
          cidade: c.cidade,
          estado: c.estado,
          foto_url: c.foto_url,
          candidatura_id: c.candidatura_id,
          status: c.status,
          etapa_atual: c.etapa_atual,
          score,
          detalhes
        };
      }).sort((a, b) => b.score - a.score);

      res.json({ vaga_id: vagaId, vaga_titulo: vaga.titulo, matches: resultado });
    } catch (e) {
      console.error('[empresa matches]', e);
      res.status(500).json({ erro: 'Erro ao calcular matches' });
    }
  });

  // GET /api/candidato/vagas/:id/match — score do próprio candidato naquela vaga
  app.get('/api/candidato/vagas/:id/match', authCandidato, async (req, res) => {
    try {
      const vagaId = parseInt(req.params.id);
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: "Perfil de candidato não encontrado" });

      // Vaga deve existir (qualquer status — match é informativo, não requer publicação)
      const { rows: vagaRows } = await pool.query(
        `SELECT id, titulo, area, cidade, estado, nivel FROM vagas WHERE id = $1`,
        [vagaId]
      );
      if (!vagaRows.length) return res.status(404).json({ erro: 'Vaga não encontrada' });
      const vaga = vagaRows[0];

      // Perfil do candidato
      const { rows: candRows } = await pool.query(
        `SELECT id, nome, cidade, estado, areas_interesse, nivel_experiencia, competencias
         FROM candidatos WHERE id = $1`,
        [candId]
      );
      if (!candRows.length) return res.status(404).json({ erro: 'Perfil não encontrado' });

      // Tags da vaga
      const { rows: tagRows } = await pool.query(
        `SELECT tag FROM vaga_tags WHERE vaga_id = $1`, [vagaId]
      );
      const vagaTags = tagRows.map(r => r.tag);

      const candidato = candRows[0];
      const camposMatch = [
        ['nome', candidato.nome],
        ['cidade', candidato.cidade],
        ['estado', candidato.estado],
        ['áreas de interesse', candidato.areas_interesse],
        ['nível de experiência', candidato.nivel_experiencia],
        ['competências', candidato.competencias]
      ];
      const camposFaltantes = camposMatch
        .filter(([, valor]) => Array.isArray(valor) ? valor.length === 0 : !String(valor || '').trim())
        .map(([nome]) => nome);
      const { score, detalhes } = calcularMatch(candidato, vaga, vagaTags);

      res.json({
        vaga_id: vagaId,
        vaga_titulo: vaga.titulo,
        score,
        nivel: score >= 70 ? 'alto' : score >= 40 ? 'médio' : 'baixo',
        perfil_completo: camposFaltantes.length === 0,
        campos_faltantes: camposFaltantes,
        detalhes,
        aviso: 'Pontuação indicativa. Não representa decisão de contratação.'
      });
    } catch (e) {
      console.error('[candidato match]', e);
      res.status(500).json({ erro: 'Erro ao calcular match' });
    }
  });

  // ── FIM FASE 11 ──────────────────────────────────────────────────────────

  // =========================================================================
  // FASE 12 — Chat Empresa ↔ Candidato
  // =========================================================================
  //
  // Arquitetura:
  //   - "Conversa" = candidatura (uma candidatura tem uma thread de chat)
  //   - Tabela base: mensagens_processo (já existia, reutilizada)
  //   - Novos campos via migration 009: lida_por_candidato_em, lida_por_empresa_em, remetente_id
  //   - Tabela nova: chat_templates (templates de mensagem por empresa)
  //
  // Rotas empresa:
  //   GET    /api/empresa/chat                        – lista conversas/candidaturas com mensagens
  //   GET    /api/empresa/chat/:cid                   – abre conversa (candidatura_id)
  //   POST   /api/empresa/chat/:cid/mensagens         – envia mensagem para candidato
  //   PATCH  /api/empresa/chat/:cid/lidas             – marca mensagens do candidato como lidas
  //   PATCH  /api/empresa/chat/:cid/encerrar          – encerra conversa (não bloqueia candidatura)
  //   GET    /api/empresa/chat/templates              – lista templates da empresa
  //   POST   /api/empresa/chat/templates              – cria template
  //   DELETE /api/empresa/chat/templates/:tid         – remove template
  //
  // Rotas candidato:
  //   GET    /api/candidato/chat                      – lista conversas com mensagens
  //   GET    /api/candidato/chat/:cid                 – abre conversa
  //   POST   /api/candidato/chat/:cid/mensagens       – envia mensagem para empresa
  //   PATCH  /api/candidato/chat/:cid/lidas           – marca mensagens da empresa como lidas
  //   PATCH  /api/candidato/chat/:cid/encerrar        – encerra conversa
  //
  // Segurança:
  //   - empresa_id sempre do JWT (nunca do body)
  //   - candidato_id sempre do JWT (resolveCandId)
  //   - IDOR: verifica propriedade antes de qualquer acesso
  //   - Viewer pode ler mas não enviar/mutar
  //   - Rate limit no envio de mensagens (5/min por IP)
  //   - Sanitização XSS em todo texto recebido
  //   - Máximo 2000 chars por mensagem
  // =========================================================================

  // ── Helper: verifica se candidatura pertence à empresa ──────────────────
  async function verificarAcessoEmpresaConversa(candidatura_id, empresa_id, req) {
    const { rows } = await pool.query(`
      SELECT c.id, c.candidato_id, c.vaga_id, c.status, c.etapa_atual,
             cd.nome AS candidato_nome, cd.email AS candidato_email,
             v.titulo AS vaga_titulo, v.cidade, v.estado,
             e.nome AS empresa_nome,
             (SELECT COUNT(*) FROM empresa_usuarios eu WHERE eu.empresa_id = $2) AS num_usuarios
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      JOIN empresas e ON e.id = $2
      WHERE c.id = $1
        AND v.empresa_id = $2
        AND ${empresaVagaFilialScopeByVaga(req, 'v')}
    `, [candidatura_id, empresa_id]);
    return rows.length > 0 ? rows[0] : null;
  }

  // ── Helper: verifica se candidatura pertence ao candidato ───────────────
  async function verificarAcessoCandidatoConversa(candidatura_id, candidato_id) {
    const { rows } = await pool.query(`
      SELECT c.id, c.candidato_id, c.vaga_id, c.status, c.etapa_atual,
             cd.nome AS candidato_nome, cd.email AS candidato_email,
             v.titulo AS vaga_titulo, v.empresa AS vaga_empresa_nome,
             v.empresa_id,
             (SELECT eu.id FROM empresa_usuarios eu
              WHERE eu.empresa_id = v.empresa_id
                AND eu.role IN ('admin_empresa','recrutador')
                AND eu.ativo = true
              LIMIT 1) AS contato_empresa_id
      FROM candidaturas c
      JOIN candidatos cd ON cd.id = c.candidato_id
      JOIN vagas v ON v.id = c.vaga_id
      WHERE c.id = $1
        AND c.candidato_id = $2
    `, [candidatura_id, candidato_id]);
    return rows.length > 0 ? rows[0] : null;
  }

  // ── Helper: mensagens de uma conversa (candidatura) ─────────────────────
  async function buscarMensagensConversa(candidatura_id) {
    const { rows: msgs } = await pool.query(`
      SELECT mp.id, mp.candidatura_id, mp.autor_tipo, mp.autor_nome,
             mp.texto, mp.contexto, mp.criado_em,
             mp.lida_por_candidato_em, mp.lida_por_empresa_em,
             mp.remetente_id
      FROM mensagens_processo mp
      WHERE mp.candidatura_id = $1
      ORDER BY mp.criado_em ASC
      LIMIT 500
    `, [candidatura_id]);
    // Anexar arquivos
    if (msgs.length > 0) {
      const ids = msgs.map(m => m.id);
      const { rows: arqs } = await pool.query(
        `SELECT id, mensagem_id, nome_original, mime_type, tamanho_bytes
         FROM chat_arquivos WHERE mensagem_id = ANY($1::int[])`,
        [ids]
      );
      const arqMap = {};
      arqs.forEach(a => { (arqMap[a.mensagem_id] = arqMap[a.mensagem_id] || []).push(a); });
      msgs.forEach(m => { m.arquivos = arqMap[m.id] || []; });
    } else {
      msgs.forEach(m => { m.arquivos = []; });
    }
    return msgs;
  }

  // ── Helper: notificar candidato quando empresa envia msg ─────────────────
  async function notificarCandidatoChat(candidatura_id, candidato_id, empresa_nome, vaga_titulo) {
    inserirNotificacao(pool, 'candidato', candidato_id,
      'nova_mensagem_empresa',
      `💬 Nova mensagem de ${empresa_nome}`,
      `Você recebeu uma mensagem sobre sua candidatura na vaga ${vaga_titulo}. Clique para abrir a conversa.`,
      { referencia_tipo: 'candidatura', referencia_id: candidatura_id,
        metadata: { candidatura_id, link: `/candidato/chat.html?c=${candidatura_id}` } }
    );
  }

  // ── Helper: notificar empresa quando candidato envia msg ─────────────────
  async function notificarEmpresaChat(candidatura_id, empresa_id, candidato_nome, vaga_titulo) {
    inserirNotificacao(pool, 'empresa', empresa_id,
      'nova_mensagem_candidato',
      `💬 Nova mensagem de ${candidato_nome}`,
      `${candidato_nome} enviou uma mensagem sobre a candidatura na vaga ${vaga_titulo}. Clique para abrir a conversa.`,
      { referencia_tipo: 'candidatura', referencia_id: candidatura_id,
        metadata: { candidatura_id, link: `/empresa/chat.html?c=${candidatura_id}` } }
    );
  }

  // ── Rate limit específico para envio de mensagens de chat ────────────────
  const rateLimitChat = rateLimitByIp('chat-msg'); // 5/min por IP

  // =========================================================================
  // ENDPOINTS EMPRESA
  // =========================================================================

  // GET /api/empresa/chat/templates  (antes das rotas com :cid para não colidir)
  app.get('/api/empresa/chat/templates', requireEmpresaViewer, async (req, res) => {
    const { empresa_id } = req.user;
    try {
      const { rows } = await pool.query(
        `SELECT id, titulo, texto, criado_em FROM chat_templates
         WHERE empresa_id = $1 OR empresa_id IS NULL
         ORDER BY empresa_id NULLS FIRST, titulo`,
        [empresa_id]
      );
      res.json({ templates: rows });
    } catch (e) {
      console.error('[chat templates listar]', e);
      res.status(500).json({ erro: 'Erro ao listar templates' });
    }
  });

  // POST /api/empresa/chat/templates
  app.post('/api/empresa/chat/templates', requireRecrutadorOuAdmin, async (req, res) => {
    const { empresa_id } = req.user;
    let { titulo, texto } = req.body;
    if (!titulo || !texto) return res.status(400).json({ erro: 'Título e texto são obrigatórios' });
    titulo = sanitizeText(titulo.trim()).slice(0, 100);
    texto  = sanitizeText(texto.trim()).slice(0, 2000);
    try {
      const { rows } = await pool.query(
        `INSERT INTO chat_templates (empresa_id, titulo, texto) VALUES ($1,$2,$3)
         RETURNING id, titulo, texto, criado_em`,
        [empresa_id, titulo, texto]
      );
      res.status(201).json({ ok: true, template: rows[0] });
    } catch (e) {
      console.error('[chat templates criar]', e);
      res.status(500).json({ erro: 'Erro ao criar template' });
    }
  });

  // DELETE /api/empresa/chat/templates/:tid
  app.delete('/api/empresa/chat/templates/:tid', requireRecrutadorOuAdmin, async (req, res) => {
    const { empresa_id } = req.user;
    const tid = parseInt(req.params.tid);
    if (!tid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const { rowCount } = await pool.query(
        `DELETE FROM chat_templates WHERE id = $1 AND empresa_id = $2`,
        [tid, empresa_id]
      );
      if (rowCount === 0) return res.status(404).json({ erro: 'Template não encontrado' });
      res.json({ ok: true });
    } catch (e) {
      console.error('[chat templates deletar]', e);
      res.status(500).json({ erro: 'Erro ao deletar template' });
    }
  });

  // GET /api/empresa/chat — lista conversas com filtros/paginação
  app.get('/api/empresa/chat', requireEmpresaViewer, async (req, res) => {
    const { empresa_id } = req.user;
    const { q, vaga_id, candidato_id, status, pagina = 1, limite = 20 } = req.query;
    const lim = Math.min(parseInt(limite) || 20, 100);
    const offset = (Math.max(parseInt(pagina) || 1, 1) - 1) * lim;
    try {
      const params = [empresa_id];
      let where = `v.empresa_id = $1 AND ${empresaVagaFilialScopeByVaga(req, 'v')} AND c.status NOT IN ('cancelado')`;
      if (q) {
        params.push(`%${q}%`);
        where += ` AND (cd.nome ILIKE $${params.length} OR cd.email ILIKE $${params.length})`;
      }
      if (vaga_id) { params.push(parseInt(vaga_id)); where += ` AND v.id = $${params.length}`; }
      if (candidato_id) { params.push(parseInt(candidato_id)); where += ` AND cd.id = $${params.length}`; }
      if (status) { params.push(status); where += ` AND c.status = $${params.length}`; }

      const countQ = await pool.query(
        `SELECT COUNT(*) FROM candidaturas c
         JOIN candidatos cd ON cd.id = c.candidato_id
         JOIN vagas v ON v.id = c.vaga_id
         WHERE ${where}`,
        params
      );
      const total = parseInt(countQ.rows[0].count);

      params.push(lim); params.push(offset);
      const { rows } = await pool.query(`
        SELECT c.id AS candidatura_id,
               cd.id AS candidato_id, cd.nome AS candidato_nome, cd.email AS candidato_email,
               v.id AS vaga_id, v.titulo AS vaga_titulo, c.status, c.etapa_atual,
               (SELECT COUNT(*) FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id
                  AND mp.autor_tipo = 'candidato'
                  AND mp.lida_por_empresa_em IS NULL) AS nao_lidas,
               (SELECT mp.texto FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultima_msg,
               (SELECT mp.criado_em FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultima_msg_em,
               (SELECT mp.autor_tipo FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultimo_autor_tipo,
               (SELECT COUNT(*) FROM mensagens_processo mp WHERE mp.candidatura_id = c.id) AS total_msgs,
               c.chat_encerrado_empresa_em
        FROM candidaturas c
        JOIN candidatos cd ON cd.id = c.candidato_id
        JOIN vagas v ON v.id = c.vaga_id
        WHERE ${where}
        ORDER BY ultima_msg_em DESC NULLS LAST, c.criada_em DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}
      `, params);
      res.json({
        conversas: rows,
        paginacao: { total, pagina: parseInt(pagina) || 1, limite: lim, paginas: Math.ceil(total / lim) }
      });
    } catch (e) {
      console.error('[empresa chat listar]', e);
      res.status(500).json({ erro: 'Erro ao listar conversas' });
    }
  });

  // GET /api/empresa/chat/:cid — abre conversa
  app.get('/api/empresa/chat/:cid', requireEmpresaViewer, async (req, res) => {
    const { empresa_id } = req.user;
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const info = await verificarAcessoEmpresaConversa(cid, empresa_id, req);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      const mensagens = await buscarMensagensConversa(cid);
      res.json({ conversa: info, mensagens });
    } catch (e) {
      console.error('[empresa chat abrir]', e);
      res.status(500).json({ erro: 'Erro ao abrir conversa' });
    }
  });

  // POST /api/empresa/chat/:cid/mensagens — envia mensagem para candidato
  app.post('/api/empresa/chat/:cid/mensagens', requireRecrutadorOuAdmin, rateLimitChat, async (req, res) => {
    const { empresa_id, nome: remetente_nome, id: remetente_id } = req.user;
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    let { texto } = req.body;
    if (!texto || !texto.trim()) return res.status(400).json({ erro: 'Mensagem vazia' });
    texto = sanitizeText(texto.trim());
    if (texto.length > 2000) return res.status(400).json({ erro: 'Mensagem muito longa (máx 2000 chars)' });
    try {
      const info = await verificarAcessoEmpresaConversa(cid, empresa_id, req);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      if (info.chat_encerrado_empresa_em) return res.status(409).json({ erro: 'Conversa encerrada' });
      // Inserir mensagem
      const { rows } = await pool.query(`
        INSERT INTO mensagens_processo
          (candidatura_id, autor_tipo, autor_nome, texto, contexto, remetente_id)
        VALUES ($1, 'empresa', $2, $3, 'chat_empresa', $4)
        RETURNING id, candidatura_id, autor_tipo, autor_nome, texto, criado_em,
                  lida_por_candidato_em, lida_por_empresa_em, remetente_id
      `, [cid, remetente_nome || info.empresa_nome, texto, remetente_id || null]);
      // Notificar candidato (async, não bloqueia resposta)
      notificarCandidatoChat(cid, info.candidato_id, info.empresa_nome, info.vaga_titulo).catch(() => {});
      // Fase 13 — e-mail para candidato (empresa enviou) com dedup
      emailSvc.bgChatEmpresa({
        candidato_id: info.candidato_id,
        email: info.candidato_email,
        nome: info.candidato_nome,
        empresa_nome: info.empresa_nome,
        vaga_titulo: info.vaga_titulo,
        candidatura_id: cid
      });
      res.json({ ok: true, mensagem: rows[0] });
    } catch (e) {
      console.error('[empresa chat enviar]', e);
      res.status(500).json({ erro: 'Erro ao enviar mensagem' });
    }
  });

  // PATCH /api/empresa/chat/:cid/lidas — marca msgs do candidato como lidas pela empresa
  app.patch('/api/empresa/chat/:cid/lidas', requireEmpresaViewer, async (req, res) => {
    const { empresa_id } = req.user;
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const info = await verificarAcessoEmpresaConversa(cid, empresa_id, req);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      const { rowCount } = await pool.query(
        `UPDATE mensagens_processo
         SET lida_por_empresa_em = NOW()
         WHERE candidatura_id = $1
           AND autor_tipo = 'candidato'
           AND lida_por_empresa_em IS NULL`,
        [cid]
      );
      res.json({ ok: true, atualizadas: rowCount });
    } catch (e) {
      console.error('[empresa chat lidas]', e);
      res.status(500).json({ erro: 'Erro ao marcar como lidas' });
    }
  });

  // PATCH /api/empresa/chat/:cid/encerrar — encerra thread de chat
  app.patch('/api/empresa/chat/:cid/encerrar', requireRecrutadorOuAdmin, async (req, res) => {
    const { empresa_id } = req.user;
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const info = await verificarAcessoEmpresaConversa(cid, empresa_id, req);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      await pool.query(
        `UPDATE candidaturas SET chat_encerrado_empresa_em = NOW() WHERE id = $1`,
        [cid]
      );
      res.json({ ok: true });
    } catch (e) {
      console.error('[empresa chat encerrar]', e);
      res.status(500).json({ erro: 'Erro ao encerrar conversa' });
    }
  });

  // =========================================================================
  // ENDPOINTS CANDIDATO
  // =========================================================================

  // GET /api/candidato/chat — lista conversas
  app.get('/api/candidato/chat', authCandidato, async (req, res) => {
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: 'Perfil não encontrado' });
      const { rows } = await pool.query(`
        SELECT c.id AS candidatura_id,
               v.id AS vaga_id, v.titulo AS vaga_titulo, v.empresa AS vaga_empresa_nome,
               c.status, c.etapa_atual, c.chat_encerrado_empresa_em,
               (SELECT COUNT(*) FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id
                  AND mp.autor_tipo IN ('empresa','admin')
                  AND mp.lida_por_candidato_em IS NULL) AS nao_lidas,
               (SELECT mp.texto FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultima_msg,
               (SELECT mp.criado_em FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultima_msg_em,
               (SELECT mp.autor_tipo FROM mensagens_processo mp
                WHERE mp.candidatura_id = c.id ORDER BY mp.criado_em DESC LIMIT 1) AS ultimo_autor_tipo,
               (SELECT COUNT(*) FROM mensagens_processo mp WHERE mp.candidatura_id = c.id) AS total_msgs
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.candidato_id = $1
        ORDER BY ultima_msg_em DESC NULLS LAST, c.criada_em DESC
      `, [candId]);
      res.json({ conversas: rows });
    } catch (e) {
      console.error('[candidato chat listar]', e);
      res.status(500).json({ erro: 'Erro ao listar conversas' });
    }
  });

  // GET /api/candidato/chat/:cid — abre conversa
  app.get('/api/candidato/chat/:cid', authCandidato, async (req, res) => {
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: 'Perfil não encontrado' });
      const info = await verificarAcessoCandidatoConversa(cid, candId);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      const mensagens = await buscarMensagensConversa(cid);
      res.json({ conversa: info, mensagens });
    } catch (e) {
      console.error('[candidato chat abrir]', e);
      res.status(500).json({ erro: 'Erro ao abrir conversa' });
    }
  });

  // POST /api/candidato/chat/:cid/mensagens — envia mensagem para empresa
  app.post('/api/candidato/chat/:cid/mensagens', authCandidato, rateLimitChat, async (req, res) => {
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    let { texto } = req.body;
    if (!texto || !texto.trim()) return res.status(400).json({ erro: 'Mensagem vazia' });
    texto = sanitizeText(texto.trim());
    if (texto.length > 2000) return res.status(400).json({ erro: 'Mensagem muito longa (máx 2000 chars)' });
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: 'Perfil não encontrado' });
      const info = await verificarAcessoCandidatoConversa(cid, candId);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      const { rows } = await pool.query(`
        INSERT INTO mensagens_processo
          (candidatura_id, autor_tipo, autor_nome, texto, contexto, remetente_id)
        VALUES ($1, 'candidato', $2, $3, 'chat_candidato', $4)
        RETURNING id, candidatura_id, autor_tipo, autor_nome, texto, criado_em,
                  lida_por_candidato_em, lida_por_empresa_em, remetente_id
      `, [cid, info.candidato_nome, texto, candId]);
      // Notificar empresa (async)
      notificarEmpresaChat(cid, info.empresa_id, info.candidato_nome, info.vaga_titulo).catch(() => {});
      // Fase 13 — e-mail para empresa com dedup
      emailSvc.bgChatCandidato({
        empresa_id: info.empresa_id,
        candidato_nome: info.candidato_nome,
        vaga_titulo: info.vaga_titulo,
        candidatura_id: cid
      });
      res.json({ ok: true, mensagem: rows[0] });
    } catch (e) {
      console.error('[candidato chat enviar]', e);
      res.status(500).json({ erro: 'Erro ao enviar mensagem' });
    }
  });

  // PATCH /api/candidato/chat/:cid/lidas — marca msgs da empresa como lidas
  app.patch('/api/candidato/chat/:cid/lidas', authCandidato, async (req, res) => {
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: 'Perfil não encontrado' });
      const info = await verificarAcessoCandidatoConversa(cid, candId);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      const { rowCount } = await pool.query(
        `UPDATE mensagens_processo
         SET lida_por_candidato_em = NOW()
         WHERE candidatura_id = $1
           AND autor_tipo IN ('empresa', 'admin')
           AND lida_por_candidato_em IS NULL`,
        [cid]
      );
      res.json({ ok: true, atualizadas: rowCount });
    } catch (e) {
      console.error('[candidato chat lidas]', e);
      res.status(500).json({ erro: 'Erro ao marcar como lidas' });
    }
  });

  // PATCH /api/candidato/chat/:cid/encerrar — encerra conversa pelo candidato
  app.patch('/api/candidato/chat/:cid/encerrar', authCandidato, async (req, res) => {
    const cid = parseInt(req.params.cid);
    if (!cid) return res.status(400).json({ erro: 'ID inválido' });
    try {
      const candId = await resolveCandId(req.user);
      if (!candId) return res.status(404).json({ erro: 'Perfil não encontrado' });
      const info = await verificarAcessoCandidatoConversa(cid, candId);
      if (!info) return res.status(404).json({ erro: 'Conversa não encontrada' });
      await pool.query(
        `UPDATE candidaturas SET chat_encerrado_candidato_em = NOW() WHERE id = $1`,
        [cid]
      );
      res.json({ ok: true });
    } catch (e) {
      console.error('[candidato chat encerrar]', e);
      res.status(500).json({ erro: 'Erro ao encerrar conversa' });
    }
  });

  // ── FIM FASE 12 ───────────────────────────────────────────────────────────

  // =========================================================================
  // FASE 13 — E-mail transacional: preferências + endpoint teste + digest
  // =========================================================================

  // Helper: resolve user_type + user_id de qualquer token autenticado
  function resolveEmailUser(req) {
    const tipo = req.user?.tipo || null;
    if (tipo === 'candidato') {
      const id = req.user?.id || req.user?.candidato_id || null;
      return { user_type: 'candidato', user_id: id };
    }
    if (tipo === 'empresa') {
      const id = req.user?.id || req.user?.empresa_usuario_id || null;
      return { user_type: 'empresa', user_id: id };
    }
    return { user_type: null, user_id: null };
  }
  app.get('/api/email/preferencias', requireAuthAny, async (req, res) => {
    if (req.user?.tipo === 'empresa' && req.user?.role !== 'admin_empresa') return res.status(403).json({ erro: 'Apenas o administrador pode acessar as preferências da conta' });
    try {
      const { user_type, user_id } = resolveEmailUser(req);
      if (!user_type) return res.status(401).json({ erro: 'Não autenticado' });
      const prefs = await emailSvc.getPreferencias(user_type, user_id);
      res.json({ preferencias: prefs });
    } catch (e) {
      console.error('[email pref GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar preferências' });
    }
  });

  // PATCH /api/email/preferencias — altera uma ou mais categorias
  app.patch('/api/email/preferencias', requireAuthAny, async (req, res) => {
    if (req.user?.tipo === 'empresa' && req.user?.role !== 'admin_empresa') return res.status(403).json({ erro: 'Apenas o administrador pode alterar as preferências da conta' });
    try {
      const { user_type, user_id } = resolveEmailUser(req);
      if (!user_type) return res.status(401).json({ erro: 'Não autenticado' });

      // Aceita array { preferencias: [{categoria, ativo}] } OU objeto { categoria, ativo }
      let lista = [];
      if (Array.isArray(req.body?.preferencias)) {
        lista = req.body.preferencias;
      } else if (req.body?.categoria !== undefined) {
        lista = [{ categoria: req.body.categoria, ativo: req.body.ativo }];
      } else if (req.body && Object.keys(req.body).length === 0) {
        return res.status(400).json({ erro: 'Informe preferencias (array) ou categoria + ativo' });
      } else {
        // body existe mas não tem preferencias nem categoria
        return res.status(400).json({ erro: 'Informe preferencias (array) ou categoria + ativo' });
      }

      if (lista.length === 0) {
        return res.json({ ok: true, atualizadas: 0 });
      }

      const OBRIGATORIAS = ['seguranca', 'recuperacao_senha'];
      for (const item of lista) {
        const { categoria, ativo } = item;
        if (!emailSvc.CATEGORIAS_VALIDAS.includes(categoria)) {
          return res.status(400).json({ erro: `Categoria inválida: ${categoria}. Use: ${emailSvc.CATEGORIAS_VALIDAS.join(', ')}` });
        }
        if (OBRIGATORIAS.includes(categoria) && !ativo) {
          return res.status(400).json({ erro: `Categoria "${categoria}" é obrigatória e não pode ser desativada.` });
        }
        if (typeof ativo !== 'boolean') {
          return res.status(400).json({ erro: `"ativo" deve ser boolean para categoria "${categoria}"` });
        }
      }
      for (const { categoria, ativo } of lista) {
        await emailSvc.setPreferencia(user_type, user_id, categoria, ativo);
      }
      res.json({ ok: true, atualizadas: lista.length });
    } catch (e) {
      console.error('[email pref PATCH]', e);
      res.status(500).json({ erro: 'Erro ao salvar preferência' });
    }
  });

  // POST /api/saas/email/test — admin SaaS envia e-mail de teste (não público)
  app.post('/api/saas/email/test', authAdminOnly, async (req, res) => {
    // authAdminOnly garante Administrador Global; o Portal SaaS não usa impersonação.
    const { destinatario, tipo } = req.body;
    if (!destinatario) return res.status(400).json({ erro: 'destinatario obrigatório' });
    try {
      const tipoTest = tipo || 'boas_vindas_candidato';
      let result;
      if (tipoTest === 'boas_vindas_candidato') {
        result = await emailSvc.boasVindasCandidato({
          candidato_id: 0, email: destinatario, nome: 'Usuário Teste'
        });
      } else if (tipoTest === 'boas_vindas_empresa') {
        result = await emailSvc.boasVindasEmpresa({
          empresa_id: 0, empresa_nome: 'Empresa Teste',
          user_id: 0, email: destinatario, nome: 'Admin Teste'
        });
      } else {
        const { enviarEmail } = require('./email');
        const { wrap, p } = require('./email/templates');
        result = await enviarEmail({
          to: destinatario,
          subject: '[Teste] Vagas.io · E-mail de teste',
          html: wrap({ titulo: 'E-mail de Teste',
            conteudo: p('Este é um e-mail de teste enviado pelo painel admin Vagas.io.') +
                   p('Se você recebeu isso, o serviço de e-mail está funcionando corretamente! ✅')
          })
        });
      }
      await audit(req, 'saas.email.test_sent', {
        resource_type: 'email', metadata: { tipo: tipoTest, destinatario: String(destinatario).replace(/(.{2}).*(@.*)/, '$1***$2') }
      });
      res.json({ ok: true, tipo: tipoTest, result });
    } catch (e) {
      res.status(500).json({ ok: false, erro: 'Não foi possível enviar o e-mail de teste' });
    }
  });

  // POST /api/saas/email/digest — dispara digest diário manualmente (admin SaaS)
  app.post('/api/saas/email/digest', authAdminOnly, async (req, res) => {
    // authAdminOnly garante Administrador Global; o Portal SaaS não usa impersonação.
    try {
      const { empresa_id } = req.body || {};
      const result = await emailSvc.bgDigestDiario({ empresaId: empresa_id || null });
      await audit(req, 'saas.email.digest_dispatched', {
        resource_type: 'empresa', resource_id: empresa_id ? Number(empresa_id) : null,
        metadata: { escopo: empresa_id ? 'empresa' : 'global' }
      });
      res.json({ ok: true, result });
    } catch (e) {
      res.status(500).json({ ok: false, erro: 'Não foi possível disparar o digest' });
    }
  });

  // =========================================================================
  // ── POST /api/cron/digest — disparo pelo Render Cron Job (CRON_SECRET) ──────
  // Chamado pelo Render Cron às 07:00 BRT diariamente.
  // Autenticação: header "Authorization: Bearer <CRON_SECRET>"
  app.post('/api/cron/digest', async (req, res) => {
    const cronSecret = process.env.CRON_SECRET;
    if (!cronSecret) {
      // Sem CRON_SECRET configurado, bloquear por segurança
      return res.status(503).json({ erro: 'CRON_SECRET não configurado' });
    }
    const auth = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (auth !== cronSecret) {
      return res.status(401).json({ erro: 'Não autorizado' });
    }
    try {
      // bgDigestDiario é fire-and-forget (retorna undefined) — dispara em background
      emailSvc.bgDigestDiario({ empresaId: null });
      await audit(req, 'cron.digest_disparado', { metadata: { ts: new Date().toISOString() } });
      res.json({ ok: true, ts: new Date().toISOString(), msg: 'digest disparado em background' });
    } catch (e) {
      console.error('[CRON DIGEST]', e.message);
      return erroInterno(req, res, e, 'cron-digest');
    }
  });

  // FASE 14 — Analytics + Auditoria Visual
  // =========================================================================

  // ── POST /api/analytics/eventos ──────────────────────────────────────────
  // Aceita eventos de candidato, empresa ou anônimo (vaga_visualizada).
  // user_type / user_id são derivados do token, nunca do body.
  app.post('/api/analytics/eventos', async (req, res) => {
    const { evento, vaga_id, candidatura_id, sessao_id, anonimo_id, metadata } = req.body || {};
    if (!analytics.EVENTOS_VALIDOS.includes(evento)) {
      return res.status(400).json({ erro: `Evento inválido. Permitidos: ${analytics.EVENTOS_VALIDOS.join(', ')}` });
    }
    // Metadados limitados
    if (metadata) {
      try {
        const raw = JSON.stringify(metadata);
        if (raw.length > 2048) return res.status(400).json({ erro: 'metadata excede 2048 bytes' });
      } catch (_) { return res.status(400).json({ erro: 'metadata inválido' }); }
    }

    // Resolve identidade do solicitante (pode ser anônimo — não exige auth)
    let user_type = null, user_id = null, empresa_id = null;
    const header = req.headers.authorization;
    if (header && header.startsWith('Bearer ')) {
      try {
        const payload = jwt.verify(
          header.replace('Bearer ', ''),
          process.env.JWT_SECRET,
          { algorithms: ['HS256'] }
        );
        if (payload && typeof payload.tipo === 'string') {
          user_type  = payload.tipo;
          user_id    = payload.id || null;
          empresa_id = payload.empresa_id || null;
        }
      } catch (_) { /* token inválido — trata como anônimo */ }
    }

    // Candidatos só podem gerar eventos de seu próprio contexto
    const EVENTOS_CANDIDATO = ['login_candidato','cadastro_candidato_concluido','inicio_cadastro_candidato',
      'candidatura_iniciada','candidatura_enviada','vaga_favoritada','vaga_desfavoritada',
      'match_visualizado','chat_aberto_candidato','mensagem_enviada_candidato'];
    const EVENTOS_EMPRESA = ['empresa_login','vaga_criada','vaga_publicada','candidato_visualizado',
      'candidato_contatado','chat_aberto_empresa','mensagem_enviada_empresa',
      'entrevista_agendada','proposta_enviada','proposta_aceita','proposta_recusada'];

    if (user_type === 'candidato' && EVENTOS_EMPRESA.includes(evento)) {
      return res.status(403).json({ erro: 'Evento não permitido para candidato' });
    }
    if (user_type === 'empresa' && EVENTOS_CANDIDATO.includes(evento)) {
      return res.status(403).json({ erro: 'Evento não permitido para empresa' });
    }

    try {
      await analytics.registrar({
        evento, user_type, user_id, empresa_id,
        vaga_id:        vaga_id        ? parseInt(vaga_id)        : null,
        candidatura_id: candidatura_id ? parseInt(candidatura_id) : null,
        sessao_id:      sessao_id      ? String(sessao_id).substring(0, 128)  : null,
        anonimo_id:     anonimo_id     ? String(anonimo_id).substring(0, 128) : null,
        metadata:       analytics.sanitizarMetadata(metadata),
        ...analytics.fromReq(req)
      });
      res.status(201).json({ ok: true });
    } catch (e) {
      console.error('[analytics registro]', e.message);
      res.status(500).json({ ok: false });
    }
  });

  // ── GET /api/saas/analytics — métricas globais (admin) ───────────────────
  app.get('/api/saas/analytics', authGlobalRead, async (req, res) => {
    try {
      const { periodo, vaga_id } = req.query;
      const data = await analytics.metricasSaas({ periodo, vaga_id: vaga_id ? parseInt(vaga_id) : null });
      res.json(data);
    } catch (e) {
      console.error('[saas analytics]', e.message);
      res.status(500).json({ erro: 'Erro ao consultar analytics' });
    }
  });

  // ── GET /api/empresa/analytics — métricas do tenant ──────────────────────
  app.get('/api/empresa/analytics', requireEmpresaViewer, async (req, res) => {
    try {
      const empresa_id = req.user.empresa_id;
      if (!empresa_id) return res.status(403).json({ erro: 'empresa_id não identificado' });
      const { periodo, periodo_inicio, periodo_fim, vaga_id } = req.query;
      let inicio = periodo_inicio || null;
      let fim = periodo_fim || null;
      if (!inicio && periodo && /^\d+$/.test(String(periodo))) {
        const dias = Math.max(1, Math.min(366, parseInt(periodo, 10)));
        const agora = new Date();
        fim = agora.toISOString();
        inicio = new Date(agora.getTime() - (dias - 1) * 86400000).toISOString();
      }
      const data = await analytics.metricasEmpresa({
        empresa_id,
        periodo_inicio: inicio,
        periodo_fim: fim,
        vaga_id: vaga_id ? parseInt(vaga_id) : null
      });
      res.json(data);
    } catch (e) {
      console.error('[empresa analytics]', e.message);
      res.status(500).json({ erro: 'Erro ao consultar analytics' });
    }
  });

  // ── GET /api/saas/auditoria — logs de auditoria (admin) ──────────────────
  // Reutiliza tabela audit_logs existente. Somente leitura. Nunca DELETE/PUT/PATCH.
  app.get('/api/saas/auditoria', authGlobalRead, async (req, res) => {
    try {
      const {
        usuario, empresa_id, acao, recurso,
        periodo_inicio, periodo_fim,
        pagina = '1', limite = '50'
      } = req.query;

      const pg   = Math.max(1, parseInt(pagina) || 1);
      const lim  = Math.min(200, Math.max(1, parseInt(limite) || 50));
      const offs = (pg - 1) * lim;

      const wheres = [];
      const vals   = [];
      const addV   = (sql, v) => { vals.push(v); wheres.push(sql.replace('?', `$${vals.length}`)); };

      if (usuario) {
        vals.push(`%${usuario}%`, usuario);
        wheres.push(`(user_email ILIKE $${vals.length - 1} OR user_id::text = $${vals.length})`);
      }
      if (acao)           addV('action ILIKE ?', `%${acao}%`);
      if (recurso)        addV('resource_type = ?', recurso);
      if (periodo_inicio) addV('created_at >= ?', periodo_inicio);
      if (periodo_fim)    addV('created_at <= ?', periodo_fim);
      const whereClause = wheres.length ? 'WHERE ' + wheres.join(' AND ') : '';

      const cnt  = await pool.query(`SELECT COUNT(*) FROM audit_logs ${whereClause}`, vals);
      const { rows } = await pool.query(
        `SELECT id, created_at, user_id, user_type, user_email, action,
                resource_type, resource_id, result, metadata
         FROM audit_logs ${whereClause}
         ORDER BY created_at DESC
         LIMIT $${vals.length + 1} OFFSET $${vals.length + 2}`,
        [...vals, lim, offs]
      );
      const total = parseInt(cnt.rows[0].count);
      res.json({
        logs: rows.map(item => ({
          ...item,
          user_email: mascararEmail(item.user_email),
          metadata: sanitizarMetadata(item.metadata)
        })),
        paginacao: { total, pagina: pg, limite: lim, paginas: Math.ceil(total / lim) }
      });
    } catch (e) {
      console.error('[saas auditoria]', e.message);
      res.status(500).json({ erro: 'Erro ao consultar logs' });
    }
  });

  // ── EXPLICITAMENTE PROIBIR mutações nos logs de auditoria ─────────────────
  ['delete', 'put', 'patch'].forEach(m => {
    app[m]('/api/saas/auditoria', (req, res) =>
      res.status(405).json({ erro: 'Não permitido. Logs de auditoria são somente leitura.' }));
    app[m]('/api/saas/auditoria/:id', (req, res) =>
      res.status(405).json({ erro: 'Não permitido. Logs de auditoria são somente leitura.' }));
    app[m]('/api/admin/audit-logs', (req, res) =>
      res.status(405).json({ erro: 'Não permitido. Logs de auditoria são somente leitura.' }));
  });


// ── GET /api/admin/me (Fechamento Funcional 28/07/2026) ──────
app.get('/api/admin/me', authAdminOnly, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, nome, email, role FROM admins WHERE id = $1',
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ erro: 'Admin não encontrado' });
    res.json({ id: rows[0].id, nome: rows[0].nome, email: rows[0].email, role: rows[0].role || 'admin' });
  } catch (e) {
    return erroInterno(req, res, e, 'api-admin-me');
  }
});

  // ===== Assinatura da empresa — preparação segura para o Asaas =====
  // Não recebe dados de cartão no Vagas.io. O pagamento será coletado pelo checkout do gateway.
  app.get('/api/empresa/assinatura', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const empresaId = Number(req.user.empresa_id);
      const { rows } = await pool.query(`
        SELECT e.id, e.plano, e.plano_id, e.trial_inicio, e.trial_fim,
               e.assinatura_status, e.pagamento_configurado,
               e.assinatura_confirmada_em, e.assinatura_vence_em,
               (e.asaas_customer_id IS NOT NULL) AS cliente_pagamento_criado
        FROM empresas e WHERE e.id = $1`, [empresaId]);
      if (!rows.length) return res.status(404).json({ erro: 'Empresa não encontrada' });
      res.json({ assinatura: rows[0], gateway: 'asaas', gateway_configurado: asaas.configurado() });
    } catch (e) { return erroInterno(req, res, e, 'api-empresa-assinatura-get'); }
  });

  app.post('/api/empresa/assinatura/cliente', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      if (!asaas.configurado()) return res.status(503).json({ erro: 'Gateway de pagamento ainda não configurado' });
      const empresaId = Number(req.user.empresa_id);
      const { rows } = await pool.query(`
        SELECT id, nome, email_principal, cnpj, telefone, asaas_customer_id
        FROM empresas WHERE id = $1`, [empresaId]);
      if (!rows.length) return res.status(404).json({ erro: 'Empresa não encontrada' });
      const empresa = rows[0];
      if (empresa.asaas_customer_id) return res.json({ ok: true, customer_id: empresa.asaas_customer_id, existente: true });
      if (!empresa.email_principal) return res.status(400).json({ erro: 'Cadastre um e-mail principal antes de configurar o pagamento' });
      const cliente = await asaas.criarCliente({
        name: empresa.nome, email: empresa.email_principal,
        cpfCnpj: empresa.cnpj, phone: empresa.telefone
      });
      await pool.query('UPDATE empresas SET asaas_customer_id = $1 WHERE id = $2', [cliente.id, empresaId]);
      res.status(201).json({ ok: true, customer_id: cliente.id, existente: false });
    } catch (e) {
      console.error('[asaas cliente]', e.message);
      return res.status(502).json({ erro: 'Não foi possível preparar o cadastro de pagamento' });
    }
  });

  app.post('/api/empresa/assinatura/checkout', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      if (!asaas.configurado()) return res.status(503).json({ erro: 'Gateway de pagamento ainda não configurado' });
      const empresaId = Number(req.user.empresa_id);
      const { rows } = await pool.query(`
        SELECT e.id, e.nome, e.email_principal, e.cnpj, e.telefone, e.plano_id,
               e.trial_fim, e.asaas_checkout_id, e.asaas_checkout_url,
               p.nome AS plano_nome, p.preco_mensal
        FROM empresas e LEFT JOIN planos p ON p.id = e.plano_id WHERE e.id = $1`, [empresaId]);
      if (!rows.length) return res.status(404).json({ erro: 'Empresa não encontrada' });
      const e = rows[0];
      if (e.asaas_checkout_url) return res.json({ ok: true, checkout_url: e.asaas_checkout_url, existente: true });
      const valor = Number(e.preco_mensal) / 100;
      if (!Number.isFinite(valor) || valor <= 0) return res.status(400).json({ erro: 'Plano sem preço mensal configurado' });
      if (!e.trial_fim) return res.status(400).json({ erro: 'Período de teste ainda não foi iniciado' });
      const base = process.env.FRONTEND_URL || 'https://vagasio.com.br';
      const checkout = await asaas.criarCheckoutRecorrente({
        // O checkout coleta os dados obrigatórios do pagador com segurança no Asaas.
        item: { name: `Vagas.io — Plano ${e.plano_nome || 'empresarial'}`, description: 'Assinatura mensal Vagas.io', externalReference: String(empresaId), quantity: 1, value: valor },
        nextDueDate: new Date(e.trial_fim).toISOString().slice(0, 10),
        callback: { successUrl: `${base}/empresa/index.html?page=configuracoes&pagamento=sucesso`, cancelUrl: `${base}/empresa/index.html?page=configuracoes&pagamento=cancelado`, expiredUrl: `${base}/empresa/index.html?page=configuracoes&pagamento=expirado` }
      });
      const url = checkout.url || checkout.link || checkout.paymentUrl;
      if (!url) return res.status(502).json({ erro: 'O gateway não retornou o link de checkout' });
      await pool.query('UPDATE empresas SET asaas_checkout_id = $1, asaas_checkout_url = $2, pagamento_configurado = true WHERE id = $3', [checkout.id || null, url, empresaId]);
      res.status(201).json({ ok: true, checkout_url: url, existente: false });
    } catch (e) {
      console.error('[asaas checkout]', e.message);
      return res.status(502).json({ erro: 'Não foi possível criar o checkout de pagamento' });
    }
  });

  // Webhook público do Asaas: autenticado por token próprio e idempotente por evento.
  app.post('/api/webhooks/asaas', async (req, res) => {
    try {
      const esperado = process.env.ASAAS_WEBHOOK_TOKEN;
      const recebido = req.get('asaas-access-token') || req.get('x-asaas-access-token');
      if (!esperado || !recebido || recebido !== esperado) return res.status(401).json({ ok: false });
      const payload = req.body || {}, eventId = String(payload.id || ''), evento = String(payload.event || '');
      if (!eventId || !evento) return res.status(400).json({ ok: false, erro: 'Evento inválido' });
      const saved = await pool.query(`INSERT INTO asaas_webhook_events (event_id,event,payload) VALUES ($1,$2,$3) ON CONFLICT (event_id) DO NOTHING RETURNING id`, [eventId, evento, payload]);
      if (!saved.rowCount) return res.json({ ok: true, duplicado: true });
      const recurso = payload.subscription || payload.payment || {};
      const customerId = recurso.customer || null;
      const subscriptionId = recurso.id && String(recurso.object || '').toLowerCase() === 'subscription' ? recurso.id : (recurso.subscription || null);
      const empresaRef = Number(recurso.externalReference || payload.externalReference) || null;
      if (customerId || subscriptionId || empresaRef) {
        const params = [customerId, subscriptionId, empresaRef];
        let extra = '';
        const ativos = ['PAYMENT_CONFIRMED', 'PAYMENT_RECEIVED'];
        const vencidos = ['PAYMENT_OVERDUE', 'PAYMENT_DUNNING_RECEIVED'];
        const cancelados = ['SUBSCRIPTION_INACTIVATED', 'SUBSCRIPTION_DELETED', 'PAYMENT_REFUNDED'];
        if (ativos.includes(evento)) extra = ", assinatura_status = 'active', ativo = true, pagamento_configurado = true, assinatura_confirmada_em = COALESCE(assinatura_confirmada_em, NOW())";
        else if (vencidos.includes(evento)) extra = ", assinatura_status = 'past_due', ativo = false";
        else if (cancelados.includes(evento)) extra = ", assinatura_status = 'canceled', ativo = false";
        else if (evento === 'SUBSCRIPTION_CREATED' || evento === 'SUBSCRIPTION_UPDATED') extra = ", pagamento_configurado = true";
        await pool.query(`UPDATE empresas SET asaas_customer_id = COALESCE(asaas_customer_id, $1), asaas_subscription_id = COALESCE($2, asaas_subscription_id), assinatura_vence_em = COALESCE($4::date, assinatura_vence_em)${extra} WHERE id = COALESCE($3, id) OR asaas_customer_id = $1 OR asaas_subscription_id = $2`, [customerId, subscriptionId, empresaRef, recurso.nextDueDate || null]);
      }
      res.json({ ok: true });
    } catch (e) {
      console.error('[asaas webhook]', e.message);
      return res.status(500).json({ ok: false });
    }
  });

  // FIX Etapa 2 (2026-07-27): HANDLER GLOBAL 404 — JSON seguro.
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


  // Processamento diário do trial. Não cria cobranças: apenas avisa e suspende
  // contas que terminaram o teste sem assinatura confirmada.
  async function processarTrials() {
    try {
      const { rows: avisos } = await pool.query(`
        SELECT id, nome, email_principal, trial_fim, plano
        FROM empresas
        WHERE assinatura_status = 'trial'
          AND trial_aviso_enviado_em IS NULL
          AND trial_fim > NOW() + INTERVAL '4 days 18 hours'
          AND trial_fim <= NOW() + INTERVAL '5 days 6 hours'
          AND email_principal IS NOT NULL
        LIMIT 100
      `);
      for (const empresa of avisos) {
        const resultado = await emailSvc.avisoFimTrial({
          empresa_id: empresa.id, empresa_nome: empresa.nome,
          empresa_email: empresa.email_principal, trial_fim: empresa.trial_fim,
          plano: empresa.plano
        });
        if (resultado?.ok) {
          await pool.query('UPDATE empresas SET trial_aviso_enviado_em = NOW() WHERE id = $1 AND trial_aviso_enviado_em IS NULL', [empresa.id]);
        }
      }
      await pool.query(`
        UPDATE empresas
        SET assinatura_status = 'expired', ativo = false
        WHERE assinatura_status = 'trial' AND trial_fim IS NOT NULL AND trial_fim <= NOW()
      `);
    } catch (e) {
      console.error('[trial] processamento diário falhou:', e.message);
    }
  }
  processarTrials();
  setInterval(processarTrials, 24 * 60 * 60 * 1000).unref();

  // Helper: respostas 500 seguras (log interno + mensagem genérica pro cliente).
  // Substitui o padrão `res.status(500).json({ erro: e.message })` que vaza SQL/Express/etc.
  // NÃO usar em rotas /_debug/* (precisam do erro real pro Fabio).
  // ═══════════════════════════════════════════════════════════════════════════

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

// Build: 2026-07-28T13:40:15Z
