const test = require('node:test');
const assert = require('node:assert/strict');
const { analisarLocal } = require('../src/iaService');

const vaga = (descricao, tags = []) => ({
  vaga: { titulo: 'Supervisor de Operações', nivel: 'supervisor' },
  requisitos: [{ id: 'req-texto-vaga', descricao, tipo: 'obrigatorio', peso: 70 }, ...tags.map((tag, i) => ({ id: `req-tag-${i}`, descricao: tag, tipo: 'desejavel', peso: 30 / tags.length }))],
  candidato: {}
});
const exp = (descricao, cargo = 'Supervisor de Operações', inicio = '2021-01', fim = '2025-01') => ({ cargo, empresa: 'Empresa X', inicio, fim, emprego_atual: false, descricao });

const run = (desc, candidato) => analisarLocal({ ...vaga(desc, ['Excel']), candidato });

test('candidato com evidência profissional forte pontua acima de menção isolada', () => {
  const forte = run('Experiência com liderança de equipes e Excel', { competencias: [], experiencias: [exp('Gestão de equipe de 20 colaboradores, análise de indicadores e uso diário de Excel.') ] });
  const fraco = run('Experiência com liderança de equipes e Excel', { competencias: ['Excel', 'liderança'] });
  assert.ok(forte.score_compatibilidade > fraco.score_compatibilidade);
  assert.ok(forte.confianca_score > 0);
});

test('ausência de informação não vira atendido nem inventa evidência', () => {
  const r = run('Inglês avançado', { competencias: [], experiencias: [] });
  assert.equal(r.requisitos[0].status, 'nao_informado');
  assert.equal(r.requisitos[0].evidencias.length, 0);
});

test('tempo mínimo diferencia duração parcial e suficiente', () => {
  const curto = run('mínimo de 3 anos de experiência em gestão de equipes', { experiencias: [exp('Gestão de equipe', 'Supervisor', '2022-01', '2023-01')] });
  const longo = run('mínimo de 3 anos de experiência em gestão de equipes', { experiencias: [exp('Gestão de equipe e indicadores', 'Supervisor', '2020-01', '2025-01')] });
  assert.ok(longo.score_compatibilidade > curto.score_compatibilidade);
});

test('mesmos dados produzem resultado determinístico', () => {
  const c = { competencias: ['Microsoft Excel'], experiencias: [exp('Elaboração de relatórios utilizando Excel.')] };
  assert.deepEqual(run('Excel avançado', c), run('Excel avançado', c));
});

test('tags desejáveis não são eliminatórias', () => {
  const r = run('Experiência com operações', { experiencias: [exp('Operações e atendimento', 'Assistente Operacional')] });
  assert.ok(r.requisitos.some(x => x.tipo === 'desejavel'));
  assert.equal(r.obrigatorios_nao_atendidos, 0);
});

test('vaga sem requisitos não cria critério profissional inventado', () => {
  const r = analisarLocal({ vaga: { titulo: 'Vaga aberta' }, requisitos: [{ id: 'req-compatibilidade-geral', descricao: 'Compatibilidade geral com a vaga com base nos dados disponíveis', tipo: 'obrigatorio', peso: 100 }], candidato: {} });
  assert.equal(r.requisitos.length, 1);
  assert.equal(r.requisitos[0].status, 'nao_informado');
});
