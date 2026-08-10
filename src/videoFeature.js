'use strict';

// VagasIO video-call rollout guard. Never enabled by default.
const ENABLED = process.env.VAGASIO_VIDEO_CALLS === '1';
const INTERNAL_IDS = new Set(
  String(process.env.VAGASIO_VIDEO_INTERNAL_USER_IDS || '')
    .split(',').map(v => v.trim()).filter(Boolean)
);
const INTERNAL_EMAILS = new Set(
  String(process.env.VAGASIO_VIDEO_INTERNAL_EMAILS || '')
    .split(',').map(v => v.trim().toLowerCase()).filter(Boolean)
);

function isInternal(user) {
  if (!user || !['candidato', 'empresa', 'admin', 'recrutador'].includes(user.tipo)) return false;
  return INTERNAL_IDS.has(String(user.id)) || INTERNAL_EMAILS.has(String(user.email || '').toLowerCase());
}

function getConfig(user) {
  // Return not-found while disabled so the capability is not discoverable.
  if (!ENABLED) return { ok: false, status: 404, erro: 'Recurso não disponível' };
  if (!isInternal(user)) return { ok: false, status: 404, erro: 'Recurso não disponível' };
  const signal = process.env.VAGASIO_VIDEO_SIGNAL_URL;
  if (!signal || !/^wss:\/\//i.test(signal)) return { ok: false, status: 503, erro: 'Serviço de vídeo indisponível' };
  return { ok: true, config: { enabled: true, signalUrl: signal, maxParticipants: 2, tokenTtlSeconds: 300 } };
}
module.exports = { getConfig, isInternal };
