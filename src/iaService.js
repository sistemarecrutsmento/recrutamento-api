// Serviço central de IA do VagasIO.
// A chave e a chamada ao provedor ficam exclusivamente no backend.

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const LOCAL_MODEL = 'local-compat-v1';

const STOPWORDS = new Set('a o e de da do das dos em no na nos nas para por com sem que uma um ao aos as os ou se seu sua seus suas vaga candidato candidata experiência experiencias formação curso área nivel nível requisitos requisito obrigatório obrigatorio desejável desejavel geral compatibilidade mínimo minima minimo anos ano com base dados disponíveis disponível'.split(' '));
const ALIASES = [
  [/microsoft\s+excel|excel\s+micro(?:soft)?/g, 'excel'],
  [/microsoft\s+power\s*bi|power\s*bi/g, 'powerbi'],
  [/recursos\s+humanos|\brh\b/g, 'recursoshumanos'],
  [/gestao\s+de\s+equipes?|lideranca\s+de\s+equipes?/g, 'liderancaequipe'],
  [/indicadores|kpis?/g, 'indicadores']
];
const DIMENSION_WEIGHTS = {
  experiencia: 0.25, competencia_tecnica: 0.20, formacao: 0.15,
  senioridade: 0.10, obrigatorios: 0.20, desejaveis: 0.05, outros: 0.05
};

function normalizarToken(valor) {
  let s = String(valor || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  for (const [re, replacement] of ALIASES) s = s.replace(re, replacement);
  return s.replace(/[^a-z0-9+#.]/g, ' ').replace(/\s+/g, ' ').trim();
}
function palavras(valor) { return normalizarToken(valor).split(/\s+/).filter(t => t.length >= 3 && !STOPWORDS.has(t)); }
function mesesEntre(inicio, fim) {
  const parse = v => { const m = String(v || '').match(/^(\d{4})(?:-(\d{1,2}))?/); return m ? Number(m[1]) * 12 + Number(m[2] || 1) : null; };
  const a = parse(inicio); const b = parse(fim) ?? (new Date().getFullYear() * 12 + new Date().getMonth() + 1);
  return a && b >= a ? b - a + 1 : 0;
}
function normalizarNivel(v) {
  const s = normalizarToken(v);
  if (/estagio|aprendiz|trainee/.test(s)) return 1;
  if (/auxiliar|assistente/.test(s)) return 2;
  if (/junior|j?nior/.test(s)) return 3;
  if (/pleno/.test(s)) return 4;
  if (/senior|especialista/.test(s)) return 5;
  if (/lider|supervisor/.test(s)) return 6;
  if (/coordenador/.test(s)) return 7;
  if (/gerente|diretor/.test(s)) return 8;
  return 0;
}
function detectarCategoria(texto) {
  const s = normalizarToken(texto);
  if (/formacao|graduacao|superior|tecnico|bacharel|licenci|pos|mba/.test(s)) return 'formacao';
  if (/lider|equipe|gestao|supervis|coorden|gerenc/.test(s)) return 'lideranca';
  if (/senior|junior|pleno|especialista|nivel/.test(s)) return 'senioridade';
  if (/ano|mes|experiencia|atuacao|vivencia/.test(s)) return 'tempo_experiencia';
  if (/idioma|ingles|espanhol|portugues|frances/.test(s)) return 'idioma';
  if (/certific|certificacao/.test(s)) return 'certificacao';
  if (/cidade|estado|presencial|remoto|localizacao/.test(s)) return 'localizacao';
  if (/excel|powerbi|sql|javascript|python|java|software|ferramenta|tecnic/.test(s)) return 'competencia_tecnica';
  if (/responsabil|experiencia|atuacao|cargo|funcao/.test(s)) return 'experiencia';
  return 'outros';
}
function dividirRequisito(descricao) {
  const s = String(descricao || '').trim();
  const partes = s.split(/\s*(?:;|\.|\n|\s+e\s+|,|\s+tambem\s+)\s*/i).map(x => x.trim()).filter(x => x.length >= 3);
  return partes.length > 1 ? partes : [s];
}
function corpusCandidato(candidato) {
  const fontes = [];
  const add = (fonte, texto, extra = {}) => { if (texto) fontes.push({ fonte, texto: String(texto), ...extra }); };
  for (const f of candidato?.formacao || []) add('formacao', Object.values(f).join(' '), { item: f });
  for (const e of candidato?.experiencias || []) add('experiencia_profissional', Object.values(e).join(' '), { item: e, meses: mesesEntre(e.inicio, e.fim) });
  for (const c of candidato?.competencias || []) add('competencias', c);
  for (const i of candidato?.idiomas || []) add('idioma', i);
  add('perfil', candidato?.perfil); add('curriculo', candidato?.curriculo_texto);
  for (const r of candidato?.respostas || []) add('resposta_candidatura', `${r.pergunta} ${r.resposta}`);
  return { fontes, texto: normalizarToken(fontes.map(x => x.texto).join(' ')) };
}
function requisitosEstruturados(entrada) {
  const out = []; let n = 0;
  for (const original of (entrada?.requisitos || [])) {
    const partes = dividirRequisito(original.descricao);
    const pesoBase = Number(original.peso) > 0 ? Number(original.peso) / partes.length : 1;
    for (const descricao of partes) {
      const s = normalizarToken(descricao);
      const tipo = /diferencial|desejavel|preferencial|considerado um diferencial/.test(s) ? 'desejavel' : (original.tipo || 'obrigatorio');
      const min = Number((s.match(/(?:minimo|minima|pelo menos)\s*(?:de\s*)?(\d+)\s*anos?\b/) || [])[1] || 0);
      out.push({ id: `${original.id || 'req'}-${++n}`, descricao, categoria: detectarCategoria(descricao), tipo, peso: pesoBase, minimo_anos: min, interpretacao_confianca: partes.length > 1 ? 'media' : 'baixa' });
    }
  }
  return out;
}
function criticidadeRequisito(req) {
  const s = normalizarToken(req.descricao);
  if (/obrigator|indispensavel|legal|registro|licenca|cnh|habilitacao|diploma/.test(s)) return 'critico';
  if (req.tipo === 'obrigatorio' && (/minimo|minima|lider|supervis|coorden|gerenc|senior|avancado/.test(s))) return 'importante';
  return req.tipo === 'desejavel' ? 'padrao' : 'importante';
}
function sinaisConceituais(req, texto) {
  const s = normalizarToken(`${req.descricao} ${texto}`);
  const grupos = [
    [/liderancaequipe|lider|supervis|coorden|gestao|equipe|colaborador|distribuicao|desempenho/, 'lideranca'],
    [/indicadores|kpis?|relatorios|dashboards|metas|resultados/, 'indicadores'],
    [/operacoes|processos|rotinas|unidade|produtividade/, 'operacoes'],
    [/atendimento|cliente|relacionamento|vendas/, 'atendimento'],
    [/excel|powerbi|sql|javascript|python|java/, 'tecnologia']
  ];
  const pedido = grupos.filter(([re]) => re.test(normalizarToken(req.descricao))).map(([, n]) => n);
  const corpus = grupos.filter(([re]) => re.test(s)).map(([, n]) => n);
  return { pedido, corpus, transferiveis: pedido.filter(x => corpus.includes(x)) };
}
function mesesUnicos(experiencias) {
  const intervals = experiencias.map(e => {
    const parse = v => { const m = String(v || '').match(/^(\d{4})(?:-(\d{1,2}))?/); return m ? Number(m[1]) * 12 + Number(m[2] || 1) : null; };
    const a = parse(e.inicio); const b = parse(e.fim) ?? (new Date().getFullYear() * 12 + new Date().getMonth() + 1);
    return a && b >= a ? [a, b] : null;
  }).filter(Boolean).sort((x, y) => x[0] - y[0]);
  let total = 0, current = null;
  for (const i of intervals) { if (!current) current = i; else if (i[0] <= current[1] + 1) current[1] = Math.max(current[1], i[1]); else { total += current[1] - current[0] + 1; current = i; } }
  return total + (current ? current[1] - current[0] + 1 : 0);
}
function avaliarRequisito(req, fontes, corpus) {
  const termos = palavras(req.descricao).filter(t => !/^\d+$/.test(t));
  const sinais = sinaisConceituais(req, corpus);
  const encontradas = termos.filter(t => corpus.includes(t));
  const evidencias = fontes.filter(f => { const c = normalizarToken(f.texto); return encontradas.some(t => c.includes(t)) || sinais.transferiveis.length > 0 && f.fonte === 'experiencia_profissional' && sinaisConceituais(req, c).transferiveis.length > 0; });
  const experiencias = evidencias.filter(e => e.fonte === 'experiencia_profissional');
  const melhor = [...experiencias].sort((a, b) => (b.meses || 0) - (a.meses || 0))[0] || evidencias[0];
  const experienciaDireta = experiencias.some(e => termos.some(t => normalizarToken(`${e.item?.cargo || ''} ${e.item?.descricao || ''}`).includes(t)));
  const transferivel = !experienciaDireta && experiencias.length > 0 && sinais.transferiveis.length > 0;
  let forca = 0;
  if (encontradas.length || transferivel) forca = 1;
  if (evidencias.some(e => e.fonte === 'competencias')) forca = Math.max(forca, 2);
  if (evidencias.some(e => e.fonte === 'perfil')) forca = Math.max(forca, 2);
  if (experiencias.length) forca = Math.max(forca, transferivel ? 3 : 4);
  if (experiencias.some(e => e.item?.descricao && palavras(e.item.descricao).length >= 5)) forca = Math.max(forca, 4);
  if (experiencias.some(e => (e.meses || 0) >= 12 && /result|responsabil|lider|gestao|indicador|desenvolv|reduz|aument|dashboard/.test(normalizarToken(e.item?.descricao)))) forca = 5;
  const proporcao = termos.length ? Math.min(1, Math.max(0.35, encontradas.length / termos.length)) : (transferivel ? 0.7 : 1);
  let score = forca === 0 ? 0 : (20 + forca * 16) * proporcao;
  if (transferivel) score *= 0.82;
  if (req.minimo_anos > 0) {
    const meses = mesesUnicos(experiencias.map(e => e.item || {}));
    score = Math.min(score, Math.min(1, meses / (req.minimo_anos * 12)) * 100);
  }
  const nivelExigido = normalizarNivel(req.descricao); const nivelCandidato = Math.max(0, ...experiencias.map(e => normalizarNivel(e.item?.cargo)));
  if (nivelExigido && nivelCandidato) score *= Math.min(1, Math.max(0.5, nivelCandidato / nivelExigido));
  score = Math.max(0, Math.min(100, Math.round(score)));
  const status = forca === 0 ? 'nao_informado' : score >= 75 ? 'atendido' : score >= 35 ? 'parcialmente_atendido' : 'nao_atendido';
  const fonte = melhor?.fonte || 'dados_disponiveis';
  const evid = melhor ? [{ fonte, tipo: fonte, cargo: melhor.item?.cargo, empresa: melhor.item?.empresa, periodo: `${melhor.item?.inicio || '?'} a ${melhor.item?.fim || (melhor.item?.emprego_atual ? 'atual' : '?')}`, descricao: `Experiência ${experienciaDireta ? 'direta' : transferivel ? 'transferível' : 'relacionada'}${melhor.item?.cargo ? ` como ${melhor.item.cargo}` : ''}${melhor.item?.empresa ? ` na empresa ${melhor.item.empresa}` : ''}${melhor.item?.descricao ? `: ${String(melhor.item.descricao).slice(0, 300)}` : '.'}`, forca }] : [];
  const criticidade = criticidadeRequisito(req);
  return { score, status, criticidade, experiencia_tipo: experienciaDireta ? 'experiencia_direta' : transferivel ? 'experiencia_transferivel' : experiencias.length ? 'experiencia_relacionada' : undefined, evidencias: evid, justificativa: forca ? `Evidência ${experienciaDireta ? 'direta' : transferivel ? 'transferível' : 'declarada'} classificada em ${forca}/5.` : 'Dados insuficientes para avaliar este requisito.', confianca_score: Math.round(Math.min(100, forca * 18 + (req.interpretacao_confianca === 'media' ? 30 : 20) - (transferivel ? 12 : 0))), confianca: forca >= 4 ? 'alta' : forca >= 2 ? 'media' : 'baixa' };
}

function analisarLocal(entrada) {
  const { fontes, texto: corpus } = corpusCandidato(entrada?.candidato || {});
  const requisitosBrutos = requisitosEstruturados(entrada);
  const grupos = new Map();
  for (const req of requisitosBrutos) { const chave = `${req.tipo}:${req.categoria}`; grupos.set(chave, (grupos.get(chave) || 0) + 1); }
  const temObrigatorio = requisitosBrutos.some(r => r.tipo === 'obrigatorio');
  const baseTotal = requisitosBrutos.reduce((s, r) => s + (r.tipo === 'desejavel' ? 0.10 : (DIMENSION_WEIGHTS[r.categoria] || DIMENSION_WEIGHTS.outros)), 0) || 1;
  const requisitos = requisitosBrutos.map(req => ({ ...req, peso: ((req.tipo === 'desejavel' ? 0.10 : (DIMENSION_WEIGHTS[req.categoria] || DIMENSION_WEIGHTS.outros)) / baseTotal) / (grupos.get(`${req.tipo}:${req.categoria}`) || 1) * 100 }));
  const avaliados = requisitos.map(req => ({ ...req, ...avaliarRequisito(req, fontes, corpus) }));
  const pesoTotal = avaliados.reduce((s, r) => s + r.peso, 0) || 1;
  const pontos = avaliados.reduce((s, r) => s + r.peso * r.score, 0);
  const obrigatoriosNaoAtendidos = avaliados.filter(r => r.tipo === 'obrigatorio' && r.status === 'nao_atendido');
  const penalidade = obrigatoriosNaoAtendidos.reduce((s, r) => s + (r.criticidade === 'critico' ? 25 : r.criticidade === 'importante' ? 10 : 5), 0);
  const score = Math.max(0, Math.min(100, Math.round(pontos / pesoTotal - Math.min(50, penalidade))));
  const confianca = Math.round(avaliados.reduce((s, r) => s + r.confianca_score * r.peso, 0) / pesoTotal) || 0;
  const dimensoes = {}; for (const r of avaliados) { dimensoes[r.categoria] = (dimensoes[r.categoria] || { pontos: 0, peso: 0 }); dimensoes[r.categoria].pontos += r.score * r.peso; dimensoes[r.categoria].peso += r.peso; }
  for (const d of Object.values(dimensoes)) d.score = Math.round(d.pontos / d.peso);
  const experiencias = entrada?.candidato?.experiencias || [];
  const chaves = new Set(); const conflitos = [];
  for (const e of experiencias) { const k = `${normalizarToken(e.cargo)}|${normalizarToken(e.empresa)}`; if (chaves.has(k) && k !== '|') conflitos.push(`Experiência duplicada ou potencialmente conflitante: ${e.cargo || 'cargo'} — ${e.empresa || 'empresa'}.`); chaves.add(k); }
  return { requisitos: avaliados, dimensoes, conflitos, score_compatibilidade: score, confianca_score: confianca, pontos_atencao: avaliados.filter(r => r.status !== 'atendido').map(r => ({ descricao: `Revisar: ${r.descricao}`, fonte: 'dados_disponiveis' })), resumo: 'Índice de aderência estimada entre os requisitos da vaga e as evidências profissionais disponíveis. Não representa probabilidade de contratação.', avisos: ['Análise determinística local, explicável e de apoio à decisão humana.'], obrigatorios_nao_atendidos: obrigatoriosNaoAtendidos.length, penalidade_obrigatorios: Math.min(50, penalidade) };
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

module.exports = { completarJSON, GROQ_URL, analisarLocal, requisitosEstruturados };
