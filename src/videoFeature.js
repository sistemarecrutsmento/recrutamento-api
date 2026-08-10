'use strict';

// VagasIO video-call rollout. Disabled and undiscoverable by default.
const ENABLED = process.env.VAGASIO_VIDEO_CALLS === '1';
const INTERNAL_IDS = new Set(String(process.env.VAGASIO_VIDEO_INTERNAL_USER_IDS || '').split(',').map(v => v.trim()).filter(Boolean));
const INTERNAL_EMAILS = new Set(String(process.env.VAGASIO_VIDEO_INTERNAL_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean));

function isInternal(user) {
  if (!user || !['candidato', 'empresa', 'admin', 'recrutador'].includes(user.tipo)) return false;
  return INTERNAL_IDS.has(String(user.id)) || INTERNAL_EMAILS.has(String(user.email || '').toLowerCase());
}
function roleFor(user) {
  if (user?.tipo === 'candidato') return 'candidate';
  if (user?.tipo === 'empresa' || user?.tipo === 'recrutador') return 'recruiter';
  if (user?.tipo === 'admin') return 'admin';
  return null;
}
function getConfig(user) {
  if (!ENABLED || !isInternal(user)) return { ok: false, status: 404, erro: 'Recurso não disponível' };
  const signal = process.env.VAGASIO_VIDEO_SIGNAL_URL;
  if (!signal || !/^wss:\/\//i.test(signal)) return { ok: false, status: 503, erro: 'Serviço de vídeo indisponível' };
  return { ok: true, config: { enabled: true, signalUrl: signal, role: roleFor(user), maxParticipants: 2, tokenTtlSeconds: 300 } };
}
module.exports = { getConfig, isInternal, roleFor };
