// Serviço central de IA do VagasIO.
// A chave e a chamada ao provedor ficam exclusivamente no backend.

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const LOCAL_MODEL = 'local-compat-v1';

const STOPWORDS = new Set('a o e de da do das dos em no na nos nas para por com sem que uma um ao aos as os ou se seu sua seus suas vaga candidato candidata experiência experiencias formação curso área nivel nível requisitos requisito obrigatório obrigatorio desejável desejavel geral compatibilidade'.split(' '));

function normalizarToken(valor) {
  return String(valor || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9+#.]/g, ' ').trim();
}

function palavras(valor) {
  return normalizarToken(valor).split(/\s+/).filter(t => t.length >= 3 && !STOPWORDS.has(t));
}

function corpusCandidato(candidato) {
  const fontes = [
    ['formacao', JSON.stringify(candidato?.formacao || [])],
    ['experiencia', JSON.stringify(candidato?.experiencias || [])],
    ['competencias', JSON.stringify(candidato?.competencias || [])],
    ['curriculo', candidato?.curriculo_texto],
    ['perfil', candidato?.perfil],
    ['resposta_candidatura', JSON.stringify(candidato?.respostas || [])]
  ];
  return { texto: normalizarToken(fontes.map(([, texto]) => texto || '').join(' ')), fontes };
}

function analisarLocal(entrada) {
  const vaga = entrada?.vaga || {};
  const candidato = entrada?.candidato || {};
  const requisitos = Array.isArray(entrada?.requisitos) ? entrada.requisitos : [];
  const { texto: corpus, fontes } = corpusCandidato(candidato);
  const resultado = requisitos.map((req, indice) => {
    const descricao = String(req?.descricao || '').trim() || `Requisito ${indice + 1}`;
    const termos = palavras(descricao);
    if (!termos.length) {
      const possuiDados = corpus.length > 20;
      return {
        id: req.id || `req-${String(indice + 1).padStart(3, '0')}`,
        descricao, tipo: req.tipo === 'desejavel' ? 'desejavel' : 'obrigatorio', categoria: req.categoria || 'outros', peso: Number(req.peso) > 0 ? Number(req.peso) : 1,
        status: possuiDados ? 'parcialmente_atendido' : 'nao_identificado', evidencias: possuiDados ? [{ fonte: 'dados_disponiveis', descricao: 'Há dados profissionais disponíveis para avaliação.' }] : [],
        justificativa: possuiDados ? 'Avaliação geral baseada nos dados disponíveis; não foram identificados termos específicos.' : 'Não há dados suficientes para identificar evidências.', confianca: 'baixa'
      };
    }
    const encontrados = termos.filter(t => corpus.includes(t));
    const proporcao = encontrados.length / termos.length;
    const status = proporcao >= 0.7 ? 'atendido' : proporcao > 0 ? 'parcialmente_atendido' : 'nao_identificado';
    let fonte = 'dados_disponiveis';
    for (const [nome, texto] of fontes) { if (encontrados.some(t => normalizarToken(texto).includes(t))) { fonte = nome; break; } }
    return {
      id: req.id || `req-${String(indice + 1).padStart(3, '0')}`,
      descricao, tipo: req.tipo === 'desejavel' ? 'desejavel' : 'obrigatorio', categoria: req.categoria || 'outros', peso: Number(req.peso) > 0 ? Number(req.peso) : 1,
      status, evidencias: encontrados.length ? [{ fonte, descricao: `Evidência encontrada para: ${encontrados.join(', ')}.` }] : [],
      justificativa: encontrados.length ? `${encontrados.length} de ${termos.length} termos relevantes encontrados nos dados informados.` : 'Não foi encontrada evidência nas informações disponíveis; isso não significa que a competência não exista.',
      confianca: encontrados.length ? 'media' : 'baixa'
    };
  });
  return { requisitos: resultado, pontos_atencao: resultado.filter(r => r.status !== 'atendido').map(r => ({ descricao: `Revisar evidências de: ${r.descricao}`, fonte: 'dados_disponiveis' })), resumo: `Análise local baseada em correspondência de evidências entre a vaga ${vaga.titulo ? `“${vaga.titulo}”` : ''} e os dados informados do candidato.`, avisos: ['Análise determinística local; a decisão permanece com a equipe.'] };
}

function extrairEntradaDoPrompt(user) {
  const texto = String(user || '');
  const inicio = texto.indexOf('DADOS_FORNECIDOS:');
  if (inicio < 0) throw criarErroIA('Dados da análise local ausentes', 'IA_INVALID_REQUEST');
  const bloco = texto.slice(inicio + 'DADOS_FORNECIDOS:'.length);
  const fim = bloco.indexOf('Retorne apenas');
  return JSON.parse((fim >= 0 ? bloco.slice(0, fim) : bloco).trim());
}

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
  if (String(process.env.TRIAGEM_IA_PROVIDER || '').toLowerCase() === 'local') {
    try { return analisarLocal(extrairEntradaDoPrompt(user)); }
    catch (e) { if (e.ia) throw e; throw criarErroIA('Falha no motor local de compatibilidade', 'IA_LOCAL_ERROR', { causa: e.message }); }
  }
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
