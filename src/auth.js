const jwt = require('jsonwebtoken');
const { audit } = require('./audit');
const { pool } = require('./db');

// Opções padrão para verificação de tokens — força HS256 explicitamente
// (evita o bug "alg=none" e força que o algoritmo declarado no header seja respeitado)
const JWT_VERIFY_OPTIONS = {
  algorithms: ['HS256'],
  // exp é validado automaticamente pela lib quando presente no payload
};

// Só registra audit se for rota crítica (admin, empresa, auth)
function rotaCritica(path) {
  return path.startsWith('/api/admin/') || path.startsWith('/api/empresa/') || path.startsWith('/api/auth/');
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) {
    if (rotaCritica(req.path || req.originalUrl || '')) {
      audit(req, 'security.unauthorized', { result: 'blocked', metadata: { motivo: 'token_ausente', rota: req.path } });
    }
    return res.status(401).json({ erro: 'Token ausente' });
  }
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, JWT_VERIFY_OPTIONS);
    // Defesa em profundidade: garante que o tipo esteja presente e seja string
    if (!req.user || typeof req.user.tipo !== 'string') {
      if (rotaCritica(req.path || req.originalUrl || '')) {
        audit(req, 'security.unauthorized', { result: 'blocked', metadata: { motivo: 'token_invalido_payload', rota: req.path } });
      }
      return res.status(401).json({ erro: 'Token inválido' });
    }
    next();
  } catch (e) {
    if (rotaCritica(req.path || req.originalUrl || '')) {
      audit(req, 'security.unauthorized', { result: 'blocked', metadata: { motivo: 'token_invalido_assinatura', rota: req.path } });
    }
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

function authCandidato(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'candidato') return res.status(403).json({ erro: 'Acesso apenas de candidato' });
    next();
  });
}

function authAdmin(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin' && req.user.tipo !== 'recrutador') {
      return res.status(403).json({ erro: 'Acesso apenas de admin/recrutador' });
    }
    next();
  });
}

function authEmpresa(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'empresa') {
      return res.status(403).json({ erro: 'Acesso apenas de empresa' });
    }
    next();
  });
}

// Permissão total: só admin (recrutador NÃO pode criar usuários / mexer em config)
function authAdminOnly(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Acesso apenas de admin' });
    }
    next();
  });
}

// Aceita candidato OU empresa OU admin/recrutador (para recursos compartilhados,
// ex: chat onde o candidato e o admin/empresa conversam).
// O controle de OWNERSHIP é feito por recurso, não aqui.
function authCandidatoOrEmpresaOrAdmin(req, res, next) {
  return authMiddleware(req, res, () => {
    const tiposValidos = ['candidato', 'empresa', 'admin', 'recrutador'];
    if (!tiposValidos.includes(req.user.tipo)) {
      return res.status(403).json({ erro: 'Acesso não autorizado' });
    }
    next();
  });
}

// FIX C4 (2026-07-27): substitui o middleware LOCAL frouxo em server.js.
// Aceita APENAS candidato OU admin/recrutador — nunca empresa.
// Usa authMiddleware (que valida HS256 + tipo string).
function authCandidatoOrAdminStrict(req, res, next) {
  return authMiddleware(req, res, () => {
    const tiposValidos = ['candidato', 'admin', 'recrutador'];
    if (!tiposValidos.includes(req.user.tipo)) {
      return res.status(403).json({ erro: 'Acesso restrito a candidato ou admin' });
    }
    next();
  });
}

// =============================================================
// RBAC — FASE 2 (28/07/2026)
// Roles de usuarios de empresa:
//   - admin_empresa: tudo (gerencia usuarios + recursos da empresa)
//   - recrutador:    leitura + operacao (vagas, candidatos, chat)
//   - viewer:        apenas leitura
// =============================================================

const EMPRESA_ROLES = Object.freeze({
  ADMIN: 'admin_empresa',
  RECRUTADOR: 'recrutador',
  VIEWER: 'viewer'
});

function isEmpresaRole(role) {
  return role === EMPRESA_ROLES.ADMIN
      || role === EMPRESA_ROLES.RECRUTADOR
      || role === EMPRESA_ROLES.VIEWER;
}

// JWTs are short-lived, but an account can be disabled while one is still valid.
// Re-check the user and tenant on every Empresa request so deactivated access
// cannot use the remaining access-token window.
async function ensureEmpresaAccessAtivo(req, res, next) {
  try {
    const id = Number(req.user?.id), empresaId = Number(req.user?.empresa_id);
    if (!Number.isInteger(id) || id <= 0 || !Number.isInteger(empresaId) || empresaId <= 0) {
      return res.status(401).json({ erro: 'Token inválido: identidade empresarial ausente' });
    }
    const q = await pool.query(`
      SELECT 1
      FROM empresa_usuarios u
      JOIN empresas e ON e.id = u.empresa_id
      WHERE u.id = $1 AND u.empresa_id = $2 AND u.ativo = true AND e.ativo = true
    `, [id, empresaId]);
    if (!q.rowCount) return res.status(401).json({ erro: 'Acesso empresarial inativo' });
    return next();
  } catch (e) {
    console.error('[AUTH EMPRESA ACCESS]', e.message);
    return res.status(503).json({ erro: 'Não foi possível validar o acesso empresarial' });
  }
}

// Apenas admin_empresa pode chamar (gerenciar usuarios, configs).
// Exige: token tipo=empresa + role=admin_empresa + empresa_id no JWT.
function requireAdminEmpresa(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'empresa') {
      return res.status(403).json({ erro: 'Acesso apenas para usuarios de empresa' });
    }
    if (req.user.role !== EMPRESA_ROLES.ADMIN) {
      return res.status(403).json({ erro: 'Operacao restrita a admin_empresa' });
    }
    if (!req.user.empresa_id || typeof req.user.empresa_id !== 'number') {
      return res.status(401).json({ erro: 'Token invalido: empresa_id ausente' });
    }
    return ensureEmpresaAccessAtivo(req, res, next);
  });
}

// admin_empresa OU recrutador: leituras ja passam (podem tudo operacional)
// Usado em POST/PUT/PATCH de vagas, candidatos, chat etc.
function requireRecrutadorOuAdmin(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'empresa') {
      return res.status(403).json({ erro: 'Acesso apenas para usuarios de empresa' });
    }
    if (req.user.role !== EMPRESA_ROLES.ADMIN
        && req.user.role !== EMPRESA_ROLES.RECRUTADOR) {
      return res.status(403).json({ erro: 'Operacao restrita a admin_empresa ou recrutador' });
    }
    if (!req.user.empresa_id || typeof req.user.empresa_id !== 'number') {
      return res.status(401).json({ erro: 'Token invalido: empresa_id ausente' });
    }
    return ensureEmpresaAccessAtivo(req, res, next);
  });
}

// Viewer ou superior: usado em GETs. authEmpresa passa por todos os 3 roles
// mas exige tipo=empresa. Viewers podem ler tudo da propria empresa.
function requireEmpresaViewer(req, res, next) {
  return authMiddleware(req, res, () => {
    if (req.user.tipo !== 'empresa') {
      return res.status(403).json({ erro: 'Acesso apenas para usuarios de empresa' });
    }
    if (!isEmpresaRole(req.user.role)) {
      return res.status(403).json({ erro: 'Role invalida para esta operacao' });
    }
    if (!req.user.empresa_id || typeof req.user.empresa_id !== 'number') {
      return res.status(401).json({ erro: 'Token invalido: empresa_id ausente' });
    }
    return ensureEmpresaAccessAtivo(req, res, next);
  });
}

module.exports = {
  authMiddleware,
  authCandidato,
  authAdmin,
  authEmpresa,
  authAdminOnly,
  authCandidatoOrEmpresaOrAdmin,
  authCandidatoOrAdminStrict,
  requireAdminEmpresa,
  requireRecrutadorOuAdmin,
  requireEmpresaViewer,
  EMPRESA_ROLES,
  JWT_VERIFY_OPTIONS
};