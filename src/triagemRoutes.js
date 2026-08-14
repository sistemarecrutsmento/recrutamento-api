const { analisarTriagem, PROMPT_VERSION, SCHEMA_VERSION } = require('./triagemService');
const { obterConfigTriagem, triagemDisponivel } = require('./triagemConfig');
const { construirEntradaTriagem, hashEntrada } = require('./triagemPrompt');

function modeloTriagem() {
  return String(process.env.TRIAGEM_IA_PROVIDER || '').toLowerCase() === 'local'
    ? 'local-compat-v2'
    : (process.env.GROQ_MODEL || 'llama-3.1-8b-instant');
}

function numeroId(valor) {
  const id = Number(valor);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function montarRequisitos(vaga, tags) {
  const requisitos = [];
  if (String(vaga.requisitos || '').trim()) {
    requisitos.push({
      id: 'req-texto-vaga',
      descricao: String(vaga.requisitos).trim(),
      tipo: 'obrigatorio',
      categoria: 'outros',
      peso: 70
    });
  }

  const tagsValidas = (tags || [])
    .map(tag => String(tag?.tag || '').trim())
    .filter(Boolean);
  const pesoPorTag = tagsValidas.length ? 30 / tagsValidas.length : 0;
  tagsValidas.forEach((nome, i) => {
    requisitos.push({
      id: `req-tag-${i + 1}`,
      descricao: nome,
      tipo: 'desejavel',
      categoria: 'competencias',
      peso: pesoPorTag
    });
  });
  // A vaga pode legitimamente have no texto de requisitos or tags (for example,
  // a quick vacancy created from the company panel). Still provide one
  // explicit, neutral criterion so the provider can return a bounded score
  // from the available title/description/candidate data. Never use this as an
  // automatic hiring decision; the result remains informational.
  if (!requisitos.length) {
    requisitos.push({
      id: 'req-compatibilidade-geral',
      descricao: 'Compatibilidade geral com a vaga com base nos dados disponíveis',
      tipo: 'obrigatorio',
      categoria: 'outros',
      peso: 100
    });
  }
  return requisitos;
}

function montarDadosTriagem(dado) {
  const requisitos = montarRequisitos(dado, dado.tags);
  const candidato = {
    formacao: [{ nivel: dado.formacao, curso: dado.curso, instituicao: dado.instituicao, situacao: dado.situacao, data_conclusao: dado.data_conclusao }],
    experiencias: dado.experiencias,
    competencias: Array.isArray(dado.competencias) ? dado.competencias : [],
    perfil: dado.sobre_voce,
    curriculo_texto: '',
    respostas: []
  };
  const vaga = {
    titulo: dado.titulo, area: dado.area, nivel: dado.nivel, descricao: dado.descricao,
    requisitos: dado.requisitos, cidade: dado.cidade, estado: dado.estado,
    tags: (dado.tags || []).map(t => t.tag)
  };
  const entrada = construirEntradaTriagem({ vaga, candidato, requisitos });
  return { vaga, candidato, requisitos, entrada, hash: hashEntrada(entrada) };
}

const COLUNAS_ANALISE = `
  id, candidatura_id, status, versao, analise_atual, score, nivel_compatibilidade,
  resultado_json, modelo, versao_prompt, versao_schema, criada_em,
  iniciada_em, finalizada_em, erro_codigo
`;

function cacheCompativel(analise, { candidaturaId, hash, modelo, versaoPrompt = PROMPT_VERSION, versaoSchema = SCHEMA_VERSION }) {
  return Boolean(analise
    && Number(analise.candidatura_id) === Number(candidaturaId)
    && analise.hash_entrada === hash
    && analise.modelo === modelo
    && analise.versao_prompt === versaoPrompt
    && analise.versao_schema === versaoSchema
    && analise.status === 'concluida'
    && analise.analise_atual === true);
}

async function buscarAnaliseCache(db, { candidaturaId, hash, modelo, empresaId, forUpdate = false }) {
  const lock = forUpdate ? ' FOR UPDATE' : '';
  const { rows } = await db.query(`
    SELECT ${COLUNAS_ANALISE}
    FROM candidatura_analises_ia
    WHERE candidatura_id = $1
      AND empresa_id = $2
      AND hash_entrada = $3
      AND modelo = $4
      AND versao_prompt = $5
      AND versao_schema = $6
      AND status = 'concluida'
      AND analise_atual = true
    ORDER BY criada_em DESC
    LIMIT 1${lock}
  `, [candidaturaId, empresaId, hash, modelo, PROMPT_VERSION, SCHEMA_VERSION]);
  return cacheCompativel(rows[0], { candidaturaId, hash, modelo }) ? rows[0] : null;
}

async function registrarNovaAnalise({ pool, req, candidaturaId, dado, dados, forcarReanalise, analisar = analisarTriagem }) {
  const modelo = modeloTriagem();
  if (!forcarReanalise) {
    const cache = await buscarAnaliseCache(pool, {
      candidaturaId,
      hash: dados.hash,
      modelo,
      empresaId: req.user.empresa_id
    });
    if (cache) return { analise: cache, reutilizada: true };
  }

  const iniciadaEm = new Date();
  const analise = await analisar({ vaga: dados.vaga, candidato: dados.candidato, requisitos: dados.requisitos });
  if (!analise.score || !Number.isFinite(analise.score.score)) {
    const erro = new Error('Score da análise inválido.');
    erro.code = 'TRIAGEM_SCORE_INVALIDO';
    throw erro;
  }
  const finalizadaEm = new Date();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serializa novas versões da mesma candidatura antes de alterar analise_atual.
    await client.query('SELECT id FROM candidaturas WHERE id = $1 FOR UPDATE', [candidaturaId]);

    if (!forcarReanalise) {
      const cache = await buscarAnaliseCache(client, {
        candidaturaId,
        hash: dados.hash,
        modelo,
        empresaId: req.user.empresa_id,
        forUpdate: true
      });
      if (cache) {
        await client.query('COMMIT');
        return { analise: cache, reutilizada: true };
      }
    }

    await client.query(
      'UPDATE candidatura_analises_ia SET analise_atual = false WHERE candidatura_id = $1 AND analise_atual = true',
      [candidaturaId]
    );
    const { rows: criada } = await client.query(`
      INSERT INTO candidatura_analises_ia
        (empresa_id, vaga_id, candidatura_id, candidato_id, status, versao,
         analise_atual, score, nivel_compatibilidade, resultado_json,
         snapshot_vaga_json, snapshot_candidato_json, hash_entrada, modelo,
         versao_prompt, versao_schema, solicitada_por_id, solicitada_por_tipo,
         iniciada_em, finalizada_em)
      SELECT $1, $2, $3, $4, 'concluida', COALESCE(MAX(versao), 0) + 1,
             true, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17
      FROM candidatura_analises_ia
      WHERE candidatura_id = $3
      RETURNING id, status, versao, score, nivel_compatibilidade, resultado_json,
                modelo, versao_prompt, versao_schema, criada_em, iniciada_em,
                finalizada_em
    `, [
      req.user.empresa_id, dado.vaga_id, candidaturaId, dado.candidato_id,
      analise.score.score, analise.score.nivel, analise.resultado,
      dados.vaga, dados.candidato, dados.hash, analise.modelo,
      analise.versao_prompt, analise.versao_schema, req.user.id, req.user.tipo,
      iniciadaEm, finalizadaEm
    ]);
    await client.query('COMMIT');
    return { analise: criada[0], reutilizada: false };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) { /* conexão será liberada */ }
    if (e.code === '23505') {
      e.code = 'TRIAGEM_CONCORRENCIA';
      e.statusCode = 409;
    }
    throw e;
  } finally {
    client.release();
  }
}

function registrarRotasTriagem({ app, pool, requireEmpresaViewer, requireRecrutadorOuAdmin, empresaVagaFilialScope, audit, analisar = analisarTriagem }) {
  // Prevent duplicate provider calls when list/detail requests race for the same candidature.
  // The durable cache remains the source of truth; this only coalesces in-flight work.
  const analisesEmAndamento = new Map();
  async function processarAnalise(req, res, forcarReanalise = false) {
    const candidaturaId = numeroId(req.params.id);
    if (!candidaturaId) return res.status(400).json({ erro: 'ID de candidatura inválido' });
    if (!triagemDisponivel()) return res.status(404).json({ erro: 'Recurso não encontrado' });

    const config = obterConfigTriagem();
    if (config.automatic || config.batch) {
      // Flags automáticas permanecem sem efeito nesta versão síncrona.
    }

    try {
      const { rows } = await pool.query(`
        SELECT c.id AS candidatura_id, c.vaga_id, c.candidato_id,
               v.empresa_id, v.titulo, v.area, v.nivel, v.descricao,
               v.requisitos, v.cidade, v.estado,
               cd.formacao, cd.instituicao, cd.curso, cd.situacao,
               cd.data_conclusao, cd.sobre_voce, cd.experiencia,
               cd.areas_interesse, cd.competencias,
               COALESCE((SELECT json_agg(e ORDER BY e.inicio DESC NULLS LAST, e.id DESC)
                 FROM experiencias e WHERE e.candidato_id = cd.id), '[]'::json) AS experiencias,
               COALESCE((SELECT json_agg(t ORDER BY t.tag)
                 FROM vaga_tags t WHERE t.vaga_id = v.id), '[]'::json) AS tags,
               EXISTS (
                 SELECT 1 FROM empresa_vaga_acesso eva
                 WHERE eva.vaga_id = c.vaga_id AND eva.empresa_id = $2
                   AND eva.revogado_em IS NULL
                   AND ${empresaVagaFilialScope(req, 'eva')}
               ) AS tem_acesso
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE c.id = $1
      `, [candidaturaId, req.user.empresa_id]);

      if (!rows.length || !rows[0].tem_acesso || Number(rows[0].empresa_id) !== Number(req.user.empresa_id)) {
        return res.status(404).json({ erro: 'Candidatura não encontrada' });
      }

      const dado = rows[0];
      const dados = montarDadosTriagem(dado);
      // Vagas antigas ou testes podem não ter requisitos/tags cadastrados.
      // Ainda assim, a análise deve funcionar com um critério neutro e explícito,
      // sem inventar requisitos específicos da vaga.
      if (!dados.requisitos.length) {
        dados.requisitos = [{
          id: 'req-compatibilidade-geral',
          descricao: 'Compatibilidade geral com a vaga com base nos dados disponíveis',
          tipo: 'obrigatorio',
          categoria: 'outros',
          peso: 100,
        }];
      }

      const chave = `${req.user.empresa_id}:${candidaturaId}:${forcarReanalise ? 'force' : 'normal'}`;
      let trabalho = analisesEmAndamento.get(chave);
      if (!trabalho) {
        trabalho = registrarNovaAnalise({ pool, req, candidaturaId, dado, dados, forcarReanalise, analisar });
        analisesEmAndamento.set(chave, trabalho);
        trabalho.finally(() => analisesEmAndamento.delete(chave)).catch(() => {});
      }
      const resultado = await trabalho;
      await audit(req, `empresa.candidatura.analise_ia_${forcarReanalise ? 'reanalisada' : 'created'}`, {
        resource_type: 'candidatura',
        resource_id: candidaturaId,
        metadata: { score: resultado.analise.score, reutilizada: resultado.reutilizada }
      });
      return res.status(resultado.reutilizada ? 200 : 201).json({ ok: true, analise: resultado.analise, reutilizada: resultado.reutilizada });
    } catch (e) {
      // Diagnóstico seguro: código/status e mensagem curta, nunca token, chave ou payload.
      console.error('[triagem criar]', JSON.stringify({
        code: e.code || 'TRIAGEM_UNKNOWN_ERROR',
        statusCode: e.statusCode || null,
        message: String(e.message || '').slice(0, 300),
        candidaturaId
      }));
      if (e.statusCode === 409) return res.status(409).json({ erro: 'Conflito ao criar a análise; tente novamente', erro_codigo: 'IA_CONFLICT' });
      if (e.code === 'TRIAGEM_SCORE_INVALIDO' || e.code === 'TRIAGEM_RESULTADO_INVALIDO' || e.code === 'IA_INVALID_JSON' || e.code === 'IA_INVALID_RESPONSE') {
        return res.status(422).json({ erro: 'A análise retornou dados inválidos', erro_codigo: e.code });
      }
      return res.status(503).json({ erro: 'A análise por IA está temporariamente indisponível. Tente novamente em instantes.', erro_codigo: e.code || 'IA_UNAVAILABLE' });
    }
  }

  app.get('/api/empresa/candidatura/:id/analise-ia', requireEmpresaViewer, async (req, res) => {
    if (!triagemDisponivel()) return res.status(404).json({ erro: 'Recurso não encontrado' });
    const candidaturaId = numeroId(req.params.id);
    if (!candidaturaId) return res.status(400).json({ erro: 'ID de candidatura inválido' });
    try {
      const { rows } = await pool.query(`
        SELECT a.id, a.status, a.versao, a.analise_atual, a.score,
               a.nivel_compatibilidade, a.resultado_json, a.modelo,
               a.versao_prompt, a.versao_schema, a.criada_em,
               a.iniciada_em, a.finalizada_em, a.erro_codigo
        FROM candidatura_analises_ia a
        JOIN candidaturas c ON c.id = a.candidatura_id
        JOIN empresa_vaga_acesso eva ON eva.vaga_id = c.vaga_id
        WHERE a.candidatura_id = $1
          AND a.empresa_id = $2
          AND eva.empresa_id = $2
          AND eva.revogado_em IS NULL
          AND ${empresaVagaFilialScope(req, 'eva')}
          AND a.analise_atual = true
        ORDER BY a.criada_em DESC
        LIMIT 1
      `, [candidaturaId, req.user.empresa_id]);
      if (!rows.length) return res.status(404).json({ erro: 'Análise não encontrada' });
      return res.json({ analise: rows[0] });
    } catch (e) {
      console.error('[triagem obter]', e.message);
      return res.status(500).json({ erro: 'Erro ao buscar análise' });
    }
  });

  app.post('/api/empresa/candidatura/:id/analise-ia', requireRecrutadorOuAdmin, (req, res) => processarAnalise(req, res, false));
  app.post('/api/empresa/candidatura/:id/analise-ia/reanalisar', requireRecrutadorOuAdmin, (req, res) => processarAnalise(req, res, true));
}

module.exports = {
  registrarRotasTriagem,
  cacheCompativel,
  montarRequisitos,
  montarDadosTriagem,
  buscarAnaliseCache
};
