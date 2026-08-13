function booleanEnv(nome, padrao = false) {
  const valor = process.env[nome];
  if (valor === undefined) return padrao;
  return ['1', 'true', 'yes', 'sim', 'on'].includes(String(valor).toLowerCase());
}

function ambientesPermitidos() {
  return String(process.env.TRIAGEM_IA_ALLOWED_ENVIRONMENTS || 'staging,preview')
    .split(',')
    .map(item => item.trim().toLowerCase())
    .filter(Boolean);
}

function triagemAmbienteAutorizado({ ambiente = process.env.NODE_ENV } = {}) {
  const ambienteNormalizado = String(ambiente || '').trim().toLowerCase();
  if (!ambienteNormalizado || ambienteNormalizado === 'production') return false;
  return ambientesPermitidos().includes(ambienteNormalizado);
}

function obterConfigTriagem() {
  return {
    enabled: booleanEnv('TRIAGEM_IA_ENABLED', false),
    previewOnly: booleanEnv('TRIAGEM_IA_PREVIEW_ONLY', true),
    automatic: booleanEnv('TRIAGEM_IA_AUTO', false),
    batch: booleanEnv('TRIAGEM_IA_BATCH', false),
    allowedEnvironments: ambientesPermitidos(),
    maxTokens: Number(process.env.TRIAGEM_IA_MAX_TOKENS || 5000),
    maxPorMinuto: Number(process.env.TRIAGEM_IA_MAX_POR_MINUTO || 5),
    maxPorDiaEmpresa: Number(process.env.TRIAGEM_IA_MAX_POR_DIA_EMPRESA || 100)
  };
}

function triagemDisponivel({ ambiente = process.env.NODE_ENV } = {}) {
  const config = obterConfigTriagem();
  if (!config.enabled) return false;
  return triagemAmbienteAutorizado({ ambiente });
}

module.exports = {
  obterConfigTriagem,
  triagemAmbienteAutorizado,
  triagemDisponivel
};
