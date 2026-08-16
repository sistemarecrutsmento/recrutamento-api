const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const html = fs.readFileSync(path.join(root, 'vagas/empresa/analisar.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'vagas/empresa/app.js'), 'utf8');
const server = fs.readFileSync(path.join(__dirname, '../src/server.js'), 'utf8');
const extra = fs.readFileSync(path.join(__dirname, '../src/routes/empresa_extra.js'), 'utf8');

test('empresa action clients use canonical protected endpoint and payload', () => {
  assert.match(html, /candidatura\/' \+ id \+ \'\/acao/);
  assert.match(html, /JSON\.stringify\(\{ acao: acao === \'aprovar-triagem\' \? \'avancar\' : acao \}\)/);
  assert.doesNotMatch(html, /candidatura\/' \+ id \+ \'\/status/);
  assert.doesNotMatch(app, /candidatura\/['+ ]*id['+ ]*\/status/);
});

test('canonical server contract remains stage and optimistic-concurrency protected', () => {
  assert.match(server, /app\.post\('\/api\/empresa\/candidatura\/:id\/acao', requireRecrutadorOuAdmin/);
  assert.match(server, /ehEtapaEmpresa/);
  assert.match(server, /WHERE id = \$4 AND etapa_atual = \$5 AND status = \$6/);
  assert.match(server, /comentario \|\| motivo/);
});

test('legacy status route cannot execute an unsafe second implementation', () => {
  assert.match(extra, /status \(deprecated compatibility guard\)/);
  assert.match(extra, /res\.status\(410\)/);
  assert.doesNotMatch(extra, /UPDATE candidaturas SET etapa_atual/);
});
