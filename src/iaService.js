// Serviço central de IA do VagasIO.
// Mantém a integração atual com a Groq em um único ponto para que
// parser de currículo e futuras funcionalidades reutilizem a mesma infraestrutura.

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';

function criarErroIA(mensagem, metadata = {}) {
  const erro = new Error(mensagem);
  erro.ia = true;
  Object.assign(erro, metadata);
  return erro;
}

async function completarJSON({
  system,
  user,
  model = process.env.GROQ_MODEL || 'llama-3.1-8b-instant',
  temperature = 0,
  maxTokens = 4000,
  timeoutMs = Number(process.env.GROQ_TIMEOUT_MS || 30000)
}) {
  if (!process.env.GROQ_API_KEY) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(GROQ_URL, {
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

    if (!response.ok) {
      throw criarErroIA(`Groq ${response.status}`, {
        statusCode: response.status
      });
    }

    const payload = await response.json();
    const content = payload?.choices?.[0]?.message?.content;
    if (!content) return null;

    try {
      return JSON.parse(String(content).replace(/^```json\s*|\s*```$/g, '').trim());
    } catch (e) {
      throw criarErroIA('A IA retornou JSON inválido', {
        causa: e.message
      });
    }
  } catch (e) {
    if (e.name === 'AbortError') {
      throw criarErroIA('Tempo limite excedido na IA', { code: 'IA_TIMEOUT' });
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  completarJSON,
  GROQ_URL
};
