const pdfParse = require('pdf-parse');

const EMPTY = () => ({
  dados_pessoais: { nome: '', email: '', celular: '', cpf: '', data_nascimento: '', sexo: '' },
  endereco: { cep: '', estado: '', cidade: '', bairro: '', logradouro: '', numero: '', complemento: '' },
  perfil: { sobre_voce: '' }, formacao: [], experiencias: [], competencias: [], idiomas: [],
  _meta: { fonte: 'nenhuma', confianca: {} }
});

const clean = (v) => String(v ?? '').replace(/\u0000/g, '').replace(/[ \t]+/g, ' ').trim();
const norm = (v) => clean(v).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const nonempty = (v) => clean(v) !== '';
const uniq = (a) => [...new Set((a || []).map(clean).filter(Boolean))];

function normalizarTexto(texto) {
  const linhas = String(texto || '').replace(/\r\n?/g, '\n').replace(/[\u200B-\u200D\uFEFF]/g, '').split('\n').map(clean);
  // Preserva linhas úteis e remove linhas vazias repetidas; não concatena colunas artificialmente.
  const out = []; let vazias = 0;
  for (const l of linhas) { if (!l) { if (++vazias <= 1) out.push(''); } else { vazias = 0; out.push(l); } }
  return out.join('\n').trim();
}

function dataInterna(valor) {
  const s = norm(valor);
  if (!s) return '';
  if (/\b(atual|atualmente|presente|present|current)\b/.test(s)) return '';
  let m = s.match(/\b((?:19|20)\d{2})[-\/.](0?[1-9]|1[0-2])\b/);
  if (m) return `${m[1]}-${String(m[2]).padStart(2, '0')}`;
  m = s.match(/\b(0?[1-9]|1[0-2])[-\/.]((?:19|20)\d{2})\b/);
  if (m) return `${m[2]}-${String(m[1]).padStart(2, '0')}`;
  const meses = { jan: '01', fev: '02', mar: '03', abr: '04', mai: '05', jun: '06', jul: '07', ago: '08', set: '09', out: '10', nov: '11', dez: '12' };
  m = s.match(/\b(jan|fev|mar|abr|mai|jun|jul|ago|set|out|nov|dez)[a-z]*\.?\s+((?:19|20)\d{2})\b/);
  if (m) return `${m[2]}-${meses[m[1]]}`;
  m = s.match(/\b((?:19|20)\d{2})\b/);
  return m ? m[1] : '';
}

function normalizarDataNascimento(v) {
  const s = clean(v); const m = s.match(/(\d{1,2})[\/. -](\d{1,2})[\/. -](\d{4})/);
  return m ? `${m[3]}-${String(m[2]).padStart(2, '0')}-${String(m[1]).padStart(2, '0')}` : (/^\d{4}-\d{2}-\d{2}$/.test(s) ? s : '');
}

function extrairDeterministico(texto) {
  const r = EMPTY(); const linhas = texto.split('\n').map(clean).filter(Boolean); const flat = linhas.join(' ');
  r.dados_pessoais.email = (flat.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [''])[0].toLowerCase();
  const tel = flat.match(/(?:\+?55\s*)?(?:\(?\d{2}\)?\s*)?9?\d{4}[- ]?\d{4}\b/); r.dados_pessoais.celular = tel ? clean(tel[0]) : '';
  const cpf = flat.match(/\b\d{3}[. -]?\d{3}[. -]?\d{3}[- ]?\d{2}\b/); r.dados_pessoais.cpf = cpf ? cpf[0].replace(/\D/g, '') : '';
  const nasc = flat.match(/(?:nascimento|nascida|nascido|birth)[^\d]{0,20}(\d{1,2}[/. -]\d{1,2}[/. -]\d{4})/i); r.dados_pessoais.data_nascimento = nasc ? normalizarDataNascimento(nasc[1]) : '';
  r.dados_pessoais.nome = (linhas.slice(0, 8).find(l => /^[A-Za-zÀ-ÿ' -]{4,80}$/.test(l) && l.split(/\s+/).length >= 2 && !/@/.test(l) && !/curr[íi]culo|resume|objetivo|perfil/i.test(l)) || '');
  const cep = flat.match(/\b\d{5}-?\d{3}\b/); r.endereco.cep = cep ? cep[0].replace(/(\d{5})(\d{3})/, '$1-$2') : '';
  const ufLine = linhas.find(l => /\b[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{2,}\s*[,/-]\s*[A-Z]{2}\b/.test(l));
  const uf = ufLine && ufLine.match(/\b([A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{2,})\s*[,/-]\s*([A-Z]{2})\b/);
  if (uf) { r.endereco.cidade = clean(uf[1]); r.endereco.estado = uf[2]; }
  const addr = linhas.find(l => /\b(rua|r\.|avenida|av\.|travessa|tv\.|rodovia|estrada|alameda)\b/i.test(l)) || '';
  if (addr) { const street = addr.slice(addr.search(/\b(rua|r\.|avenida|av\.|travessa|tv\.|rodovia|estrada|alameda)\b/i)); const p = street.split(/\s*\|\s*|\s+-\s+/)[0].split(',').map(clean); r.endereco.logradouro = p[0] || ''; r.endereco.bairro = p[1] || ''; r.endereco.numero = (addr.match(/(?:n[ºo°]?|número)\s*(\d+)/i) || addr.match(/\b(\d{1,6})\b/) || ['',''])[1]; }
  const sec = (patterns, stop) => { const i = linhas.findIndex(l => patterns.test(norm(l))); if (i < 0) return []; const j = linhas.findIndex((l, n) => n > i && stop.test(norm(l))); return linhas.slice(i + 1, j < 0 ? linhas.length : j); };
  const perfilLinhas = sec(/^(perfil|resumo|objetivo|apresentacao)( profissional)?\b/, /^(principais|experi|forma|educa|compet|habil|idioma|curso)/);
  if (perfilLinhas.length) r.perfil.sobre_voce = perfilLinhas.join(' ');
  const compLinhas = sec(/^(competencias?|habilidades|skills|conhecimentos)( tecnicos?)?\b/, /^(idioma|forma|educa|experi|curso|certifica)/);
  r.competencias = uniq(compLinhas.flatMap(l => l.split(/[,;|•]/).map(clean)).filter(l => l && !/^(sistemas|gestao|certificacoes?):?$/i.test(l)));
  const degree = flat.match(/(?:bacharelado|licenciatura|tecnólogo|tecnologia|graduação|pós-graduação|mba|curso)\s+(?:em\s+)?(.+?)\s+-\s+(.+?)\s*\(([^)]+)\)/i);
  if (degree) { r.formacao = [{ nivel: norm(degree[0]).startsWith('bacharelado') ? 'superior' : '', curso: clean(degree[1]), instituicao: clean(degree[2]), situacao: /andamento|cursando/i.test(degree[3]) ? 'cursando' : /conclu/i.test(degree[3]) ? 'concluido' : clean(degree[3]), data_conclusao: '' }]; }
  const inicio = linhas.findIndex(l => /^(experi[êe]ncia|hist[óo]rico profissional|trajet[óo]ria|carreira|professional experience|work experience)\b/i.test(l));
  if (inicio >= 0) {
    const fim = linhas.findIndex((l, i) => i > inicio && /^(forma[çc][ãa]o|educa[çc][ãa]o|compet[êe]ncias?|habilidades?|idiomas?|cursos?)\b/i.test(l));
    const bloco = linhas.slice(inicio + 1, fim < 0 ? linhas.length : fim);
    const cab = bloco.map((l, i) => ({ l, i })).filter(x => /\|/.test(x.l) && /(?:19|20)\d{2}|atual|presente|jan|fev|mar|abr|mai|jun|jul|ago|set|out|nov|dez/i.test(x.l));
    r.experiencias = cab.map((x, n) => { const p = x.l.split('|').map(clean); const trecho = bloco.slice(x.i + 1, cab[n + 1]?.i ?? bloco.length); const ds = [...x.l.matchAll(/(?:jan|fev|mar|abr|mai|jun|jul|ago|set|out|nov|dez)\w*\.?\s+\d{4}|\b(?:19|20)\d{2}\b/gi)].map(m => dataInterna(m[0])); return { empresa: p[0] || '', cargo: p[1] || '', inicio: ds[0] || '', fim: ds[1] || '', emprego_atual: /atual|presente/i.test(x.l), descricao: trecho.join(' ').trim() }; }).filter(e => e.empresa || e.cargo);
  }
  return r;
}

function sanearIA(raw) {
  const r = EMPTY(); const x = raw && typeof raw === 'object' ? raw : {};
  const p = x.dados_pessoais || x; const a = x.endereco || x; const perfil = x.perfil || x;
  r.dados_pessoais = { nome: clean(p.nome), email: clean(p.email).toLowerCase(), celular: clean(p.celular), cpf: clean(p.cpf).replace(/\D/g, ''), data_nascimento: normalizarDataNascimento(p.data_nascimento), sexo: clean(p.sexo) };
  r.endereco = { cep: clean(a.cep), estado: clean(a.estado).toUpperCase(), cidade: clean(a.cidade), bairro: clean(a.bairro), logradouro: clean(a.logradouro), numero: clean(a.numero), complemento: clean(a.complemento) };
  r.perfil.sobre_voce = clean(perfil.sobre_voce);
  const forms = Array.isArray(x.formacao) ? x.formacao : (x.formacao ? [x.formacao] : []);
  const nivel = v => { const n = norm(v); if (/fundamental/.test(n)) return 'fundamental'; if (/medio/.test(n)) return 'medio'; if (/tecnico/.test(n)) return 'tecnico'; if (/pos|mba/.test(n)) return 'pos'; if (/mestrado/.test(n)) return 'mestrado'; if (/doutorado/.test(n)) return 'doutorado'; if (/superior|bacharel|licenc|tecnologo|graduacao/.test(n)) return 'superior'; return clean(v); };
  const situacao = v => { const n = norm(v); if (/andamento|cursando|estudando/.test(n)) return 'cursando'; if (/conclu|formad/.test(n)) return 'concluido'; if (/tranc/.test(n)) return 'trancado'; return clean(v); };
  r.formacao = forms.map(f => ({ nivel: nivel(f.nivel), curso: clean(f.curso), instituicao: clean(f.instituicao), situacao: situacao(f.situacao), data_conclusao: dataInterna(f.data_conclusao) })).filter(f => Object.values(f).some(Boolean));
  r.experiencias = (Array.isArray(x.experiencias) ? x.experiencias : []).map(e => ({ empresa: clean(e.empresa), cargo: clean(e.cargo), inicio: dataInterna(e.inicio), fim: dataInterna(e.fim), emprego_atual: Boolean(e.emprego_atual) || /atual|presente|current/i.test(clean(e.fim)), descricao: clean(e.descricao) })).filter(e => e.empresa || e.cargo || e.descricao);
  r.competencias = uniq(Array.isArray(x.competencias) ? x.competencias : []); r.idiomas = uniq(Array.isArray(x.idiomas) ? x.idiomas : []);
  return r;
}

function fundir(ia, det) {
  const r = EMPTY();
  for (const k of ['dados_pessoais', 'endereco']) for (const f of Object.keys(r[k])) r[k][f] = nonempty(ia[k][f]) ? ia[k][f] : det[k][f];
  r.perfil.sobre_voce = nonempty(ia.perfil.sobre_voce) ? ia.perfil.sobre_voce : det.perfil.sobre_voce;
  r.formacao = ia.formacao.length ? ia.formacao : det.formacao;
  const porEmpresa = new Map();
  for (const e of [...det.experiencias, ...ia.experiencias]) {
    const chave = `${norm(e.empresa)}|${norm(e.cargo)}|${e.inicio || ''}` || `cargo:${norm(e.cargo)}:${e.inicio}`;
    const anterior = porEmpresa.get(chave);
    if (!anterior) porEmpresa.set(chave, { ...e });
    else porEmpresa.set(chave, { ...anterior, ...Object.fromEntries(Object.entries(e).filter(([, v]) => nonempty(v) || typeof v === 'boolean')), descricao: nonempty(e.descricao) ? e.descricao : anterior.descricao });
  }
  r.experiencias = [...porEmpresa.values()];
  r.competencias = ia.competencias.length ? ia.competencias : det.competencias; r.idiomas = ia.idiomas.length ? ia.idiomas : det.idiomas;
  r._meta = { fonte: ia.experiencias.length || ia.formacao.length ? 'ia+deterministico' : 'deterministico', confianca: { email: nonempty(r.dados_pessoais.email) ? 'alta' : 'baixa', celular: nonempty(r.dados_pessoais.celular) ? 'alta' : 'baixa', experiencias: r.experiencias.length ? 'media' : 'baixa' } };
  return r;
}

function compatibilidadeVagasIO(r) {
  const f = r.formacao[0] || {}; return { ...r.dados_pessoais, ...r.endereco, formacao: f.nivel || '', instituicao: f.instituicao || '', curso: f.curso || '', situacao: f.situacao || '', data_conclusao: f.data_conclusao || '', sobre_voce: r.perfil.sobre_voce, experiencias: r.experiencias, competencias: r.competencias, idiomas: r.idiomas, estrutura: r };
}

async function interpretarComGroq(texto) {
  if (!process.env.GROQ_API_KEY) return null;
  const prompt = `Extraia este currículo para o JSON pedido. Não invente nada. Campos ausentes ficam vazios. Cada emprego é um item independente. sobre_voce contém somente resumo/perfil/objetivo; nunca experiências, formação ou competências. Use datas YYYY-MM ou YYYY; não invente mês. Retorne apenas JSON válido no schema: {"dados_pessoais":{"nome":"","email":"","celular":"","cpf":"","data_nascimento":"","sexo":""},"endereco":{"cep":"","estado":"","cidade":"","bairro":"","logradouro":"","numero":"","complemento":""},"perfil":{"sobre_voce":""},"formacao":[{"nivel":"","curso":"","instituicao":"","situacao":"","data_conclusao":""}],"experiencias":[{"empresa":"","cargo":"","inicio":"","fim":"","emprego_atual":false,"descricao":""}],"competencias":[],"idiomas":[]}\n\nCURRÍCULO:\n${texto.slice(0, 45000)}`;
  const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.GROQ_API_KEY}` }, body: JSON.stringify({ model: process.env.GROQ_MODEL || 'llama-3.1-8b-instant', temperature: 0, max_tokens: 4000, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: 'Você é um extrator de dados. Retorne somente JSON e nunca invente.' }, { role: 'user', content: prompt }] }) });
  if (!resp.ok) throw new Error(`Groq ${resp.status}`); const j = await resp.json(); const c = j?.choices?.[0]?.message?.content; return c ? JSON.parse(String(c).replace(/^```json\s*|\s*```$/g, '').trim()) : null;
}

function resumoDiagnostico(nome, valor) {
  const r = { etapa: nome, tipo: typeof valor };
  if (typeof valor === 'string') { r.caracteres = valor.length; r.linhas = valor ? valor.split('\n').length : 0; }
  if (valor && typeof valor === 'object') {
    r.chaves = Object.keys(valor).filter(k => !k.startsWith('_'));
    if (Array.isArray(valor.experiencias)) r.experiencias = valor.experiencias.length;
    if (Array.isArray(valor.formacao)) r.formacoes = valor.formacao.length;
    if (Array.isArray(valor.competencias)) r.competencias = valor.competencias.length;
    r.presenca = { nome: !!valor.dados_pessoais?.nome, email: !!valor.dados_pessoais?.email, resumo: !!valor.perfil?.sobre_voce, endereco: Object.values(valor.endereco || {}).some(Boolean) };
  }
  return r;
}

async function analisarCurriculo(buffer) {
  const parsed = await pdfParse(buffer); const bruto = String(parsed.text || ''); const texto = normalizarTexto(bruto);
  if (texto.replace(/\s/g, '').length < 80) { const err = new Error('Este PDF não contém texto legível. Tente um PDF exportado com texto ou preencha manualmente.'); err.code = 'PDF_SEM_TEXTO'; throw err; }
  const det = extrairDeterministico(texto); let iaBruta = null; let ia = null; let iaErro = '';
  try { iaBruta = await interpretarComGroq(texto); ia = sanearIA(iaBruta); } catch (e) { iaErro = e.message; console.warn('[CURRICULO IA FALLBACK]', e.message); ia = sanearIA(null); }
  const r = fundir(ia, det); const final = compatibilidadeVagasIO(r);
  const diagnostico = [resumoDiagnostico('A_texto_bruto', bruto), resumoDiagnostico('B_texto_normalizado', texto), resumoDiagnostico('C_parser_deterministico', det), resumoDiagnostico('D_ia_bruta', iaBruta || {}), resumoDiagnostico('E_ia_validada', ia), resumoDiagnostico('F_fusao', r), resumoDiagnostico('G_resposta_frontend', final), { etapa: 'ia_status', executada: !!iaBruta, erro: iaErro || null, caracteres_enviados_ia: Math.min(texto.length, 45000) }];
  return { dados: final, estrutura: r, texto_caracteres: texto.length, diagnostico };
}

module.exports = { analisarCurriculo, normalizarTexto, sanearIA };
