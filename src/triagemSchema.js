const STATUS_VALIDOS = new Set([
  'atendido',
  'parcialmente_atendido',
  'nao_identificado',
  'nao_informado',
  'nao_atendido'
]);

const TIPOS_VALIDOS = new Set(['obrigatorio', 'desejavel']);
const CONFIANCAS_VALIDAS = new Set(['alta', 'media', 'baixa']);
const FONTES_VALIDAS = new Set([
  'formacao',
  'experiencia',
  'competencias',
  'curriculo',
  'resposta_candidatura',
  'perfil',
  'dados_disponiveis'
]);

function texto(valor) {
  return typeof valor === 'string' ? valor.trim() : '';
}

function erroScore(codigo) {
  const erro = new Error(codigo);
  erro.code = 'TRIAGEM_SCORE_INVALIDO';
  return erro;
}

function normalizarEvidencia(evidencia) {
  if (!evidencia || typeof evidencia !== 'object') return null;
  const fonte = texto(evidencia.fonte);
  const descricao = texto(evidencia.descricao);
  if (!FONTES_VALIDAS.has(fonte) || !descricao) return null;
  return {
    fonte,
    descricao,
    tipo: texto(evidencia.tipo) || undefined,
    cargo: texto(evidencia.cargo) || undefined,
    empresa: texto(evidencia.empresa) || undefined,
    periodo: texto(evidencia.periodo) || undefined,
    forca: Number.isFinite(Number(evidencia.forca)) ? Math.max(0, Math.min(5, Number(evidencia.forca))) : undefined
  };
}

function normalizarRequisito(requisito, indice) {
  if (!requisito || typeof requisito !== 'object') return null;
  const id = texto(requisito.id) || `req-${String(indice + 1).padStart(3, '0')}`;
  const status = texto(requisito.status);
  const tipo = texto(requisito.tipo);
  const pesoNumerico = Number(requisito.peso);
  const evidencias = Array.isArray(requisito.evidencias)
    ? requisito.evidencias.map(normalizarEvidencia).filter(Boolean)
    : [];

  if (!status || !STATUS_VALIDOS.has(status)) return null;
  if (!TIPOS_VALIDOS.has(tipo)) return null;

  const score = Number(requisito.score);
  return {
    id,
    descricao: texto(requisito.descricao),
    tipo,
    categoria: texto(requisito.categoria) || 'outros',
    tipo_requisito: texto(requisito.tipo_requisito) || undefined,
    criticidade: ['critico', 'importante', 'padrao'].includes(texto(requisito.criticidade)) ? texto(requisito.criticidade) : undefined,
    experiencia_tipo: texto(requisito.experiencia_tipo) || undefined,
    peso: Number.isFinite(pesoNumerico) && pesoNumerico > 0 ? pesoNumerico : 1,
    status,
    score: Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : undefined,
    evidencias,
    justificativa: texto(requisito.justificativa),
    confianca: CONFIANCAS_VALIDAS.has(requisito.confianca)
      ? requisito.confianca
      : 'baixa',
    confianca_score: Number.isFinite(Number(requisito.confianca_score))
      ? Math.max(0, Math.min(100, Number(requisito.confianca_score)))
      : undefined
  };
}

function normalizarAnalise(resultado) {
  if (!resultado || typeof resultado !== 'object') return null;
  const requisitos = Array.isArray(resultado.requisitos)
    ? resultado.requisitos.map(normalizarRequisito).filter(Boolean)
    : [];

  return {
    requisitos,
    score_compatibilidade: Number.isFinite(Number(resultado.score_compatibilidade)) ? Math.max(0, Math.min(100, Number(resultado.score_compatibilidade))) : undefined,
    confianca_score: Number.isFinite(Number(resultado.confianca_score)) ? Math.max(0, Math.min(100, Number(resultado.confianca_score))) : undefined,
    dimensoes: resultado.dimensoes && typeof resultado.dimensoes === 'object' ? resultado.dimensoes : {},
    conflitos: Array.isArray(resultado.conflitos) ? resultado.conflitos.map(texto).filter(Boolean) : [],
    pontos_atencao: Array.isArray(resultado.pontos_atencao)
      ? resultado.pontos_atencao
          .filter(item => item && typeof item === 'object')
          .map(item => ({
            descricao: texto(item.descricao),
            fonte: texto(item.fonte) || 'dados_disponiveis'
          }))
          .filter(item => item.descricao)
      : [],
    resumo: texto(resultado.resumo),
    avisos: Array.isArray(resultado.avisos)
      ? resultado.avisos.map(texto).filter(Boolean)
      : []
  };
}

function validarAnalise(resultado) {
  const normalizada = normalizarAnalise(resultado);
  if (!normalizada) return { valida: false, erros: ['resultado_invalido'] };

  const erros = [];
  const ids = new Set();
  if (normalizada.requisitos.length === 0) erros.push('requisitos_ausentes');

  for (const requisito of normalizada.requisitos) {
    if (ids.has(requisito.id)) erros.push(`${requisito.id}:id_duplicado`);
    ids.add(requisito.id);
    if (!requisito.descricao) erros.push(`${requisito.id}:descricao_ausente`);
    if (requisito.status === 'atendido' && requisito.evidencias.length === 0) {
      erros.push(`${requisito.id}:evidencia_ausente`);
    }
  }

  return { valida: erros.length === 0, erros, resultado: normalizada };
}

function calcularScore(requisitos) {
  if (!Array.isArray(requisitos) || requisitos.length === 0) {
    throw erroScore('requisitos_ausentes');
  }

  let pontos = 0;
  let pesoTotal = 0;
  let obrigatoriosNaoAtendidos = 0;
  const ids = new Set();

  for (const requisito of requisitos) {
    if (!requisito || typeof requisito !== 'object') throw erroScore('requisito_invalido');
    if (requisito.id !== undefined) {
      if (ids.has(requisito.id)) throw erroScore('id_duplicado');
      ids.add(requisito.id);
    }
    const peso = Number(requisito.peso);
    if (!Number.isFinite(peso) || peso <= 0) throw erroScore('peso_invalido');
    if (!STATUS_VALIDOS.has(requisito.status)) throw erroScore('status_invalido');
    if (!TIPOS_VALIDOS.has(requisito.tipo)) throw erroScore('tipo_invalido');

    pesoTotal += peso;
    if (requisito.tipo === 'obrigatorio' && requisito.status === 'nao_atendido') {
      obrigatoriosNaoAtendidos += 1;
    }
    if (Number.isFinite(Number(requisito.score))) {
      pontos += peso * (Number(requisito.score) / 100);
    } else {
      if (requisito.status === 'atendido') pontos += peso;
      if (requisito.status === 'parcialmente_atendido') pontos += peso * 0.5;
    }
  }

  if (!Number.isFinite(pesoTotal) || pesoTotal <= 0 || !Number.isFinite(pontos)) {
    throw erroScore('score_nao_finito');
  }

  const score = Math.round((pontos / pesoTotal) * 100);
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw erroScore('score_fora_do_intervalo');
  }

  return {
    score,
    nivel: score >= 80 ? 'alta' : score >= 60 ? 'moderada' : 'baixa',
    obrigatorios_nao_atendidos: obrigatoriosNaoAtendidos,
    requisitos_avaliados: requisitos.length
  };
}

module.exports = {
  STATUS_VALIDOS,
  normalizarAnalise,
  validarAnalise,
  calcularScore
};
