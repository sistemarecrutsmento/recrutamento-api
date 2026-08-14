// Serviço central de IA do VagasIO.
// A chave e a chamada ao provedor ficam exclusivamente no backend.

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

function criarErroIA(mensagem, codigo, metadata = {}) {
  const erro = new Error(mensagem);
  erro.ia = true;
  erro.code = codigo;
  Object.assign(erro, metadata);
  return erro;
}

function classificarStatus(status) {
  if (status === 401 || status === 403) return 'IA_AUTH_ERROR';
  if (status === 404) return 'IA_MODEL_ERROR';
  if (status === 408) return 'IA_TIMEOUT';
  if (status === 409) return 'IA_CONFLICT';
  if (status === 429) return 'IA_RATE_LIMIT';
  if (status >= 500) return 'IA_PROVIDER_ERROR';
  if (status >= 400) return 'IA_REQUEST_ERROR';
  return 'IA_PROVIDER_ERROR';
}

function limitarMensagem(valor) {
  return String(valor || '').replace(/\s+/g, ' ').trim().slice(0, 500);
}

async function completarJSON({
  system,
  user,
  model = process.env.GROQ_MODEL || 'llama-3.1-8b-instant',
  temperature = 0,
  maxTokens = 4000,
  timeoutMs = Number(process.env.GROQ_TIMEOUT_MS || 30000)
}) {
  if (!process.env.GROQ_API_KEY) {
    throw criarErroIA('Chave da IA não configurada', 'IA_API_KEY_MISSING');
  }
  if (!model) throw criarErroIA('Modelo da IA não configurado', 'IA_MODEL_ERROR');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;
    try {
      response = await fetch(GROQ_URL, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${process.env.GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model,
          temperature,
          max_tokens: maxTokens,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: String(system || '') },
            { role: 'user', content: String(user || '') }
          ]
        })
      });
    } catch (e) {
      if (e?.name === 'AbortError') {
        throw criarErroIA('Tempo limite excedido na IA', 'IA_TIMEOUT');
      }
      throw criarErroIA('Falha de rede ao acessar a IA', 'IA_NETWORK_ERROR', { causa: e?.code || e?.name });
    }

    if (!response.ok) {
      const body = limitarMensagem(await response.text().catch(() => ''));
      throw criarErroIA(`Provedor de IA retornou HTTP ${response.status}`, classificarStatus(response.status), {
        statusCode: response.status,
        provedorMensagem: body
      });
    }

    let payload;
    try {
      payload = await response.json();
    } catch (e) {
      throw criarErroIA('Resposta do provedor não é JSON', 'IA_INVALID_RESPONSE');
    }

    const content = payload?.choices?.[0]?.message?.content;
    if (!content || typeof content !== 'string') {
      throw criarErroIA('Resposta do provedor não contém conteúdo', 'IA_INVALID_RESPONSE');
    }

    try {
      return JSON.parse(content.replace(/^```json\s*|\s*```$/g, '').trim());
    } catch (e) {
      throw criarErroIA('A IA retornou JSON inválido', 'IA_INVALID_JSON', { causa: e.message });
    }
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { completarJSON, GROQ_URL };
