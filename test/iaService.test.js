const test = require('node:test');
const assert = require('node:assert/strict');

const { completarJSON } = require('../src/iaService');

test('falha de forma explícita quando GROQ_API_KEY não está configurada', async () => {
  const anterior = process.env.GROQ_API_KEY;
  delete process.env.GROQ_API_KEY;

  try {
    await assert.rejects(
      completarJSON({ system: 'teste', user: 'teste' }),
      error => error?.code === 'IA_API_KEY_MISSING'
    );
  } finally {
    if (anterior === undefined) delete process.env.GROQ_API_KEY;
    else process.env.GROQ_API_KEY = anterior;
  }
});

test('envia prompt para Groq e interpreta JSON retornado', async () => {
  const anterior = process.env.GROQ_API_KEY;
  const fetchAnterior = global.fetch;
  process.env.GROQ_API_KEY = 'chave-de-teste';
  let requisicao;

  global.fetch = async (url, options) => {
    requisicao = { url, options };
    return {
      ok: true,
      json: async () => ({ choices: [{ message: { content: '{"ok":true}' } }] })
    };
  };

  try {
    const resultado = await completarJSON({
      system: 'sistema',
      user: 'usuario',
      model: 'modelo-teste',
      timeoutMs: 1000
    });

    assert.deepEqual(resultado, { ok: true });
    assert.equal(requisicao.url, 'https://api.groq.com/openai/v1/chat/completions');
    const corpo = JSON.parse(requisicao.options.body);
    assert.equal(corpo.model, 'modelo-teste');
    assert.equal(corpo.messages[0].content, 'sistema');
    assert.equal(corpo.messages[1].content, 'usuario');
    assert.equal(requisicao.options.headers.Authorization, 'Bearer chave-de-teste');
  } finally {
    global.fetch = fetchAnterior;
    if (anterior === undefined) delete process.env.GROQ_API_KEY;
    else process.env.GROQ_API_KEY = anterior;
  }
});

test('rejeita resposta que não seja JSON válido', async () => {
  const anterior = process.env.GROQ_API_KEY;
  const fetchAnterior = global.fetch;
  process.env.GROQ_API_KEY = 'chave-de-teste';
  global.fetch = async () => ({
    ok: true,
    json: async () => ({ choices: [{ message: { content: 'não é json' } }] })
  });

  try {
    await assert.rejects(
      completarJSON({ system: 'sistema', user: 'usuario' }),
      /JSON inválido/
    );
  } finally {
    global.fetch = fetchAnterior;
    if (anterior === undefined) delete process.env.GROQ_API_KEY;
    else process.env.GROQ_API_KEY = anterior;
  }
});
