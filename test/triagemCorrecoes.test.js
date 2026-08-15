const test = require('node:test');
const assert = require('node:assert/strict');

const {
  calcularScore,
  validarAnalise
} = require('../src/triagemSchema');
const {
  cacheCompativel,
  montarRequisitos,
  registrarRotasTriagem
} = require('../src/triagemRoutes');
const { triagemAmbienteAutorizado, triagemDisponivel } = require('../src/triagemConfig');
const { PROMPT_VERSION, SCHEMA_VERSION } = require('../src/triagemService');

function requisito(overrides = {}) {
  return {
    id: 'req-001',
    descricao: 'Requisito',
    tipo: 'obrigatorio',
    peso: 100,
    status: 'atendido',
    evidencias: [{ fonte: 'perfil', descricao: 'Evidência' }],
    ...overrides
  };
}

function analiseCache(overrides = {}) {
  return {
    candidatura_id: 10,
    hash_entrada: 'hash-a',
    modelo: 'modelo-a',
    versao_prompt: PROMPT_VERSION,
    versao_schema: SCHEMA_VERSION,
    status: 'concluida',
    analise_atual: true,
    ...overrides
  };
}

test('cache exige candidatura, hash, modelo e versões iguais', () => {
  const chave = { candidaturaId: 10, hash: 'hash-a', modelo: 'modelo-a' };
  assert.equal(cacheCompativel(analiseCache(), chave), true);
  for (const alteracao of [
    { candidatura_id: 11 },
    { hash_entrada: 'hash-b' },
    { modelo: 'modelo-b' },
    { versao_prompt: 'triagem-v2' },
    { versao_schema: 'triagem-schema-v2' },
    { status: 'erro' },
    { analise_atual: false }
  ]) {
    assert.equal(cacheCompativel(analiseCache(alteracao), chave), false);
  }
});

test('reanálise explícita possui rota separada e mesma autorização', () => {
  const rotas = [];
  const app = {
    get: (...args) => rotas.push(['GET', ...args]),
    post: (...args) => rotas.push(['POST', ...args])
  };
  const middleware = () => {};
  registrarRotasTriagem({
    app,
    pool: {},
    requireEmpresaViewer: middleware,
    requireRecrutadorOuAdmin: middleware,
    empresaVagaFilialScope: () => 'TRUE',
    audit: async () => {}
  });
  const reanalise = rotas.find(r => r[1] === '/api/empresa/candidatura/:id/analise-ia/reanalisar');
  const normal = rotas.find(r => r[1] === '/api/empresa/candidatura/:id/analise-ia');
  assert.ok(reanalise);
  assert.equal(reanalise[2], middleware);
  assert.equal(normal[2], middleware);
});

test('pesos das tags são distribuídos somente entre tags válidas', () => {
  const requisitos = montarRequisitos({ requisitos: '' }, [{ tag: '' }, { tag: 'SQL' }, { tag: '  ' }, { tag: 'Node' }]);
  assert.deepEqual(requisitos.map(r => r.peso), [15, 15]);
});

test('schema rejeita requisitos ausentes e duplicados', () => {
  assert.equal(validarAnalise({ requisitos: [] }).valida, false);
  assert.ok(validarAnalise({ requisitos: [] }).erros.includes('requisitos_ausentes'));
  const duplicado = validarAnalise({ requisitos: [requisito(), requisito()] });
  assert.equal(duplicado.valida, false);
  assert.ok(duplicado.erros.includes('req-001:id_duplicado'));
});

test('score mantém regras funcionais e rejeita pesos inválidos', () => {
  assert.equal(calcularScore([requisito()]).score, 100);
  assert.equal(calcularScore([requisito({ status: 'parcialmente_atendido' })]).score, 50);
  assert.equal(calcularScore([requisito({ status: 'nao_identificado' })]).score, 0);
  assert.equal(calcularScore([requisito({ status: 'nao_atendido', evidencias: [] })]).score, 0);
  for (const peso of [0, -1, NaN, Infinity]) {
    assert.throws(() => calcularScore([requisito({ peso })]), /peso_invalido/);
  }
  assert.throws(() => calcularScore([]), /requisitos_ausentes/);
});

test('produção exige allow-list e flag explícitos; preview segue disponível', () => {
  const anteriores = {
    enabled: process.env.TRIAGEM_IA_ENABLED,
    preview: process.env.TRIAGEM_IA_PREVIEW_ONLY,
    ambientes: process.env.TRIAGEM_IA_ALLOWED_ENVIRONMENTS
  };
  process.env.TRIAGEM_IA_ALLOWED_ENVIRONMENTS = 'staging,preview';
  process.env.TRIAGEM_IA_PREVIEW_ONLY = 'true';
  assert.equal(triagemAmbienteAutorizado({ ambiente: 'production' }), false);
  assert.equal(triagemAmbienteAutorizado({ ambiente: 'development' }), false);
  assert.equal(triagemAmbienteAutorizado({ ambiente: '' }), false);
  assert.equal(triagemAmbienteAutorizado({ ambiente: 'staging' }), true);
  assert.equal(triagemAmbienteAutorizado({ ambiente: 'preview' }), true);
  process.env.TRIAGEM_IA_ENABLED = 'true';
  assert.equal(triagemDisponivel({ ambiente: 'production' }), false);
  process.env.TRIAGEM_IA_ALLOWED_ENVIRONMENTS = 'production';
  process.env.TRIAGEM_IA_PREVIEW_ONLY = 'false';
  assert.equal(triagemAmbienteAutorizado({ ambiente: 'production' }), true);
  assert.equal(triagemDisponivel({ ambiente: 'production' }), true);
  for (const [key, value] of Object.entries(anteriores)) {
    const envKey = { enabled: 'TRIAGEM_IA_ENABLED', preview: 'TRIAGEM_IA_PREVIEW_ONLY', ambientes: 'TRIAGEM_IA_ALLOWED_ENVIRONMENTS' }[key];
    if (value === undefined) delete process.env[envKey]; else process.env[envKey] = value;
  }
});
