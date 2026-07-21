const jwt = require('jsonwebtoken');

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ erro: 'Token ausente' });
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
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

module.exports = { authMiddleware, authCandidato, authAdmin, authEmpresa, authAdminOnly };
