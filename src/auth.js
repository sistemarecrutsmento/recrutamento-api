const jwt = require('jsonwebtoken');
const { audit } = require('./audit');

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

module.exports = {
  authMiddleware,
  authCandidato,
  authAdmin,
  authEmpresa,
  authAdminOnly,
  authCandidatoOrEmpresaOrAdmin,
  JWT_VERIFY_OPTIONS
};