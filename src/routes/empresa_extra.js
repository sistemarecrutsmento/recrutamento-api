// =========================================================================
// FASE 8 — Rotas /api/empresa/* complementares
// =========================================================================
// Estas rotas completam a paridade multi-tenant que existia apenas em
// /api/admin/* (versão admin SaaS). Todas usam `req.user.empresa_id` do JWT
// para isolar dados por empresa. Middleware:
//   requireEmpresaViewer        → admin_empresa, recrutador, viewer (GETs)
//   requireRecrutadorOuAdmin    → admin_empresa, recrutador (mutações)
//
// SQLs reutilizam dos handlers /api/admin/* correspondentes, com filtro de
// tenant adicionado quando aplicável. NÃO altera as rotas /api/admin/* SaaS.
// =========================================================================

const { requireEmpresaViewer, requireRecrutadorOuAdmin } = require('../auth');

function registrar(app, ctx) {
  const { pool } = ctx;
  console.log('[FASE 8] Registrando 21 rotas /api/empresa/* complementares...');

  // ===========================================================
  // GET /api/empresa/candidatos
  // Lista candidatos que se candidataram para vagas da empresa.
  // Adaptado de /api/admin/candidatos (L2613).
  // ===========================================================
  app.get('/api/empresa/candidatos', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { area } = req.query;
      const params = [req.user.id, empresa_id];
      const { rows } = await pool.query(`
        SELECT DISTINCT c.id, c.nome, c.email, c.cpf, c.celular, c.cidade, c.estado,
               c.areas_interesse, c.banco_talentos, c.criado_em, c.foto_url,
               ult.status AS ultimo_status, ult.id AS ultima_candidatura_id,
               ult.etapa_atual AS ultima_etapa,
               v.titulo AS ultima_vaga_titulo,
               (SELECT COUNT(*) FROM candidaturas cc WHERE cc.candidato_id = c.id) AS total_candidaturas
        FROM candidatos c
        JOIN candidaturas cand_filtro ON cand_filtro.candidato_id = c.id
        JOIN vagas v_filtro ON v_filtro.id = cand_filtro.vaga_id
        LEFT JOIN LATERAL (
          SELECT cu.id, cu.status, cu.etapa_atual, cu.vaga_id
          FROM candidaturas cu WHERE cu.candidato_id = c.id ORDER BY cu.criada_em DESC NULLS LAST LIMIT 1
        ) ult ON true
        LEFT JOIN vagas v ON v.id = ult.vaga_id
        WHERE v_filtro.criada_por = $1 OR v_filtro.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2)
        ${area ? `AND c.areas_interesse @> $3::jsonb` : ''}
        ORDER BY c.criado_em DESC
      `, area ? [...params, JSON.stringify([area])] : params);
      res.json({ candidatos: rows });
    } catch (e) {
      console.error('[EMPRESA LISTAR CANDIDATOS]', e);
      res.status(500).json({ erro: 'Erro ao listar candidatos' });
    }
  });

  // ===========================================================
  // GET /api/empresa/candidaturas
  // Lista candidaturas das vagas da empresa. Adaptado de /api/admin/candidaturas.
  // ===========================================================
  app.get('/api/empresa/candidaturas', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { etapa } = req.query;
      let where = `WHERE (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))`;
      const params = [req.user.id, empresa_id];
      if (etapa) {
        const etapas = etapa.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        if (etapas.length > 0) {
          where += ` AND c.etapa_atual = ANY($${params.length + 1}::int[])`;
          params.push(etapas);
        }
      }
      const { rows } = await pool.query(`
        SELECT c.*, v.titulo, v.empresa, cd.nome as candidato_nome, cd.email as candidato_email
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        ${where}
        ORDER BY c.criada_em DESC
      `, params);
      res.json({ candidaturas: rows });
    } catch (e) {
      console.error('[EMPRESA LISTAR CANDIDATURAS]', e);
      res.status(500).json({ erro: 'Erro ao listar candidaturas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/candidaturas-por-etapa
  // Kanban: contagem de candidaturas por etapa, filtrada por tenant.
  // ===========================================================
  app.get('/api/empresa/candidaturas-por-etapa', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT c.etapa_atual, COUNT(*)::int as total
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.status NOT IN ('reprovado')
          AND (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
        GROUP BY c.etapa_atual
        ORDER BY c.etapa_atual
      `, [req.user.id, empresa_id]);
      const etapasMap = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0 };
      rows.forEach(r => { etapasMap[r.etapa_atual] = r.total; });
      res.json({ etapas: etapasMap, lista: rows });
    } catch (e) {
      console.error('[EMPRESA CAND POR ETAPA]', e);
      res.status(500).json({ erro: 'Erro ao listar candidaturas por etapa' });
    }
  });

  // ===========================================================
  // GET /api/empresa/contratacoes
  // Lista contratações (candidaturas com status='contratado') da empresa.
  // ===========================================================
  app.get('/api/empresa/contratacoes', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT c.id, c.atualizada_em as contratada_em, c.etapa_atual,
               v.titulo as vaga_titulo, v.cidade, v.estado, v.salario_min, v.salario_max,
               cd.id as candidato_id, cd.nome as candidato_nome, cd.email as candidato_email,
               cd.celular as candidato_celular, cd.foto_url as candidato_foto
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE c.status = 'contratado'
          AND (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
        ORDER BY c.atualizada_em DESC
      `, [req.user.id, empresa_id]);
      res.json({ contratacoes: rows });
    } catch (e) {
      console.error('[EMPRESA CONTRATACOES]', e);
      res.status(500).json({ erro: 'Erro ao listar contratações' });
    }
  });

  // ===========================================================
  // GET /api/empresa/entrevistas
  // Lista entrevistas das vagas da empresa.
  // ===========================================================
  app.get('/api/empresa/entrevistas', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { periodo } = req.query;
      let whereExtra = '';
      const params = [req.user.id, empresa_id];
      if (periodo === 'proximas') whereExtra = ` AND e.data_hora >= NOW() AND e.status = 'agendada'`;
      else if (periodo === 'passadas') whereExtra = ` AND e.data_hora < NOW()`;
      const { rows } = await pool.query(`
        SELECT e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos,
               e.local, e.link_reuniao, e.observacoes, e.status,
               c.vaga_id, v.titulo as vaga_titulo,
               cd.id as candidato_id, cd.nome as candidato_nome, cd.foto_url, cd.email
        FROM entrevistas e
        JOIN candidaturas c ON c.id = e.candidatura_id
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
          ${whereExtra}
        ORDER BY e.data_hora ASC
      `, params);
      res.json({ entrevistas: rows });
    } catch (e) {
      console.error('[EMPRESA ENTREVISTAS]', e);
      res.status(500).json({ erro: 'Erro ao listar entrevistas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/conversas
  // Lista conversas ativas (candidaturas com mensagens) da empresa.
  // ===========================================================
  app.get('/api/empresa/conversas', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT c.id as candidatura_id, c.status, c.etapa_atual, c.atualizada_em,
               v.titulo as vaga_titulo,
               cd.id as candidato_id, cd.nome as candidato_nome, cd.foto_url,
               (SELECT COUNT(*) FROM mensagens_processo m
                WHERE m.candidatura_id = c.id AND m.autor_tipo = 'candidato'
                  AND m.criado_em > COALESCE(
                    (SELECT MAX(criado_em) FROM mensagens_processo
                     WHERE candidatura_id = c.id AND autor_tipo = 'admin'), '1970-01-01'
                  ))::int as nao_lidas_empresa,
               (SELECT MAX(criado_em) FROM mensagens_processo m WHERE m.candidatura_id = c.id) as ultima_msg
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE c.status NOT IN ('reprovado', 'rejeitado')
          AND (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
        ORDER BY c.atualizada_em DESC
      `, [req.user.id, empresa_id]);
      res.json({ conversas: rows });
    } catch (e) {
      console.error('[EMPRESA CONVERSAS]', e);
      res.status(500).json({ erro: 'Erro ao listar conversas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/dashboard
  // Dashboard tenant-isolado: KPIs das vagas DA EMPRESA.
  // ===========================================================
  app.get('/api/empresa/dashboard', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const tenantWhere = `(v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))`;
      const kpis = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM vagas v WHERE ${tenantWhere} AND v.status = 'publicada')::int as vagas_ativas,
          (SELECT COUNT(*) FROM vagas v WHERE ${tenantWhere} AND v.status = 'pausada')::int as vagas_pausadas,
          (SELECT COUNT(*) FROM vagas v WHERE ${tenantWhere} AND v.status = 'fechada')::int as vagas_fechadas,
          (SELECT COUNT(*) FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere} AND c.status NOT IN ('reprovado','contratado'))::int as processos_ativos,
          (SELECT COUNT(*) FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere} AND c.status = 'contratado')::int as contratacoes_total,
          (SELECT COUNT(*) FROM entrevistas e JOIN candidaturas c ON c.id = e.candidatura_id JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere} AND e.data_hora >= NOW() AND e.status = 'agendada')::int as entrevistas_agendadas,
          (SELECT COUNT(DISTINCT c.candidato_id) FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere})::int as candidatos_unicos
      `, [req.user.id, empresa_id]);
      const conv = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere} AND c.status = 'contratado')::int as contratados,
          (SELECT COUNT(*) FROM candidaturas c JOIN vagas v ON v.id = c.vaga_id WHERE ${tenantWhere} AND c.etapa_atual >= 3)::int as passaram_triagem
      `, [req.user.id, empresa_id]);
      const taxaConversao = conv.rows[0].passaram_triagem > 0
        ? +(conv.rows[0].contratados / conv.rows[0].passaram_triagem * 100).toFixed(1)
        : 0;
      const proximas = await pool.query(`
        SELECT e.id, e.candidatura_id, e.etapa, e.data_hora, e.duracao_minutos, e.local, e.link_reuniao, e.status,
               c.vaga_id, v.titulo as vaga_titulo,
               cd.id as candidato_id, cd.nome as candidato_nome, cd.foto_url
        FROM entrevistas e
        JOIN candidaturas c ON c.id = e.candidatura_id
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE ${tenantWhere}
          AND e.status = 'agendada'
          AND e.data_hora >= NOW()
          AND e.data_hora < NOW() + INTERVAL '7 days'
        ORDER BY e.data_hora ASC
        LIMIT 20
      `, [req.user.id, empresa_id]);
      res.json({
        kpis: kpis.rows[0],
        taxa_conversao: taxaConversao,
        proximas_entrevistas: proximas.rows,
        contratacoes: conv.rows[0],
      });
    } catch (e) {
      console.error('[EMPRESA DASHBOARD]', e);
      res.status(500).json({ erro: 'Erro ao carregar dashboard' });
    }
  });

  // ===========================================================
  // GET /api/empresa/vagas-com-candidaturas
  // Lista vagas da empresa com contagem de candidaturas.
  // ===========================================================
  app.get('/api/empresa/vagas-com-candidaturas', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT v.id, v.titulo, v.empresa, v.cidade, v.estado, v.status, v.criada_em,
               COUNT(c.id) FILTER (WHERE c.status NOT IN ('rejeitado','reprovado')) AS total_ativas,
               COUNT(c.id) AS total_geral,
               COUNT(c.id) FILTER (WHERE c.status = 'em_analise') AS em_analise,
               COUNT(c.id) FILTER (WHERE c.status = 'em_andamento') AS em_andamento,
               COUNT(c.id) FILTER (WHERE c.status = 'contratado') AS contratados
        FROM vagas v
        LEFT JOIN candidaturas c ON c.vaga_id = v.id
        WHERE v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2)
        GROUP BY v.id
        HAVING COUNT(c.id) > 0
        ORDER BY v.criada_em DESC
      `, [req.user.id, empresa_id]);
      res.json({ vagas: rows });
    } catch (e) {
      console.error('[EMPRESA VAGAS COM CANDIDATURAS]', e);
      res.status(500).json({ erro: 'Erro ao listar vagas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/vagas-abertas-antigas
  // Vagas abertas há mais de 30 dias.
  // ===========================================================
  app.get('/api/empresa/vagas-abertas-antigas', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT v.id, v.titulo, v.criada_em,
               NOW() - v.criada_em as idade,
               (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id)::int as total_candidaturas
        FROM vagas v
        WHERE (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
          AND v.status = 'publicada'
          AND v.criada_em < NOW() - INTERVAL '30 days'
        ORDER BY v.criada_em ASC
      `, [req.user.id, empresa_id]);
      res.json({ vagas: rows });
    } catch (e) {
      console.error('[EMPRESA VAGAS ANTIGAS]', e);
      res.status(500).json({ erro: 'Erro ao listar vagas antigas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/vagas-fechadas-sem-contratacao
  // ===========================================================
  app.get('/api/empresa/vagas-fechadas-sem-contratacao', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT v.id, v.titulo, v.criada_em,
               (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id)::int as total_candidaturas,
               (SELECT COUNT(*) FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'contratado')::int as contratacoes
        FROM vagas v
        WHERE (v.criada_por = $1 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $2))
          AND v.status = 'fechada'
          AND NOT EXISTS (SELECT 1 FROM candidaturas c WHERE c.vaga_id = v.id AND c.status = 'contratado')
        ORDER BY v.criada_em DESC NULLS LAST
      `, [req.user.id, empresa_id]);
      res.json({ vagas: rows });
    } catch (e) {
      console.error('[EMPRESA VAGAS FECHADAS S CONTRAT]', e);
      res.status(500).json({ erro: 'Erro ao listar vagas' });
    }
  });

  // ===========================================================
  // GET /api/empresa/equipe
  // Lista usuários da EMPRESA logada (escopo tenant).
  // ===========================================================
  app.get('/api/empresa/equipe', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { rows } = await pool.query(`
        SELECT u.id, u.nome, u.email, u.role, u.ativo, u.criado_em, u.cargo
        FROM empresa_usuarios u
        WHERE u.empresa_id = $1
        ORDER BY u.criado_em DESC
      `, [empresa_id]);
      res.json({ equipe: rows });
    } catch (e) {
      console.error('[EMPRESA EQUIPE]', e);
      res.status(500).json({ erro: 'Erro ao listar equipe' });
    }
  });

  // ===========================================================
  // POST /api/empresa/entrevista
  // ===========================================================
  app.post('/api/empresa/entrevista', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, observacoes } = req.body;
      if (!candidatura_id || !etapa || !data_hora) {
        return res.status(400).json({ erro: 'candidatura_id, etapa e data_hora são obrigatórios' });
      }
      const candCheck = await pool.query(`
        SELECT c.id FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [candidatura_id, req.user.id, empresa_id]);
      if (candCheck.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });

      const { rows } = await pool.query(`
        INSERT INTO entrevistas (candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, observacoes, status, criada_em)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'agendada', NOW())
        RETURNING id
      `, [candidatura_id, etapa, data_hora, duracao_minutos || 60, local, link_reuniao, observacoes]);
      res.json({ ok: true, id: rows[0].id });
    } catch (e) {
      console.error('[EMPRESA ENTREVISTA POST]', e);
      res.status(500).json({ erro: 'Erro ao agendar entrevista' });
    }
  });

  // ===========================================================
  // PUT /api/empresa/entrevista/:id
  // ===========================================================
  app.put('/api/empresa/entrevista/:id', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { data_hora, duracao_minutos, local, link_reuniao, observacoes, status } = req.body;
      const check = await pool.query(`
        SELECT e.id FROM entrevistas e
        JOIN candidaturas c ON c.id = e.candidatura_id
        JOIN vagas v ON v.id = c.vaga_id
        WHERE e.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Entrevista não pertence a esta empresa' });
      await pool.query(`
        UPDATE entrevistas
        SET data_hora = COALESCE($1, data_hora),
            duracao_minutos = COALESCE($2, duracao_minutos),
            local = COALESCE($3, local),
            link_reuniao = COALESCE($4, link_reuniao),
            observacoes = COALESCE($5, observacoes),
            status = COALESCE($6, status)
        WHERE id = $7
      `, [data_hora, duracao_minutos, local, link_reuniao, observacoes, status, id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[EMPRESA ENTREVISTA PUT]', e);
      res.status(500).json({ erro: 'Erro ao atualizar entrevista' });
    }
  });

  // ===========================================================
  // POST /api/empresa/entrevista/:id/cancelar
  // ===========================================================
  app.post('/api/empresa/entrevista/:id/cancelar', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { motivo } = req.body;
      const check = await pool.query(`
        SELECT e.id FROM entrevistas e
        JOIN candidaturas c ON c.id = e.candidatura_id
        JOIN vagas v ON v.id = c.vaga_id
        WHERE e.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Entrevista não pertence a esta empresa' });
      await pool.query(`UPDATE entrevistas SET status = 'cancelada', observacoes = COALESCE($1, observacoes) WHERE id = $2`, [motivo ? `[CANCELADA] ${motivo}` : null, id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[EMPRESA ENTREVISTA CANCEL]', e);
      res.status(500).json({ erro: 'Erro ao cancelar entrevista' });
    }
  });

  // ===========================================================
  // POST /api/empresa/documento/:id/revisar
  // ===========================================================
  app.post('/api/empresa/documento/:id/revisar', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { decisao, motivo } = req.body;
      if (!['aprovado', 'reprovado'].includes(decisao)) {
        return res.status(400).json({ erro: 'decisao deve ser "aprovado" ou "reprovado"' });
      }
      const check = await pool.query(`
        SELECT d.id FROM documentos_candidatura d
        JOIN candidaturas c ON c.id = d.candidatura_id
        JOIN vagas v ON v.id = c.vaga_id
        WHERE d.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Documento não pertence a esta empresa' });
      await pool.query(`
        UPDATE documentos_candidatura
        SET status = $1, motivo_reprovacao = $2, revisado_em = NOW(), revisado_por = $3
        WHERE id = $4
      `, [decisao, motivo || null, req.user.id, id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[EMPRESA DOC REVISAR]', e);
      res.status(500).json({ erro: 'Erro ao revisar documento' });
    }
  });

  // ===========================================================
  // POST /api/empresa/candidatura/:id/aprovar-documentos
  // ===========================================================
  app.post('/api/empresa/candidatura/:id/aprovar-documentos', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const check = await pool.query(`
        SELECT c.id FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });
      await pool.query(`
        UPDATE documentos_candidatura
        SET status = 'aprovado', revisado_em = NOW(), revisado_por = $1
        WHERE candidatura_id = $2 AND status = 'pendente'
      `, [req.user.id, id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[EMPRESA APROVAR DOCS]', e);
      res.status(500).json({ erro: 'Erro ao aprovar documentos' });
    }
  });

  // ===========================================================
  // POST /api/empresa/candidatura/:id/comentario
  // ===========================================================
  app.post('/api/empresa/candidatura/:id/comentario', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { texto } = req.body;
      if (!texto || texto.trim().length === 0) return res.status(400).json({ erro: 'texto obrigatório' });
      const check = await pool.query(`
        SELECT c.id, c.historico FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });
      const hist = check.rows[0].historico || [];
      hist.push({ tipo: 'comentario', por: `empresa:${req.user.email}`, quando: new Date().toISOString(), texto });
      await pool.query(`UPDATE candidaturas SET historico = $1::jsonb WHERE id = $2`, [JSON.stringify(hist), id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[EMPRESA COMENTARIO]', e);
      res.status(500).json({ erro: 'Erro ao adicionar comentário' });
    }
  });

  // ===========================================================
  // POST /api/empresa/candidatura/:id/status
  // ===========================================================
  app.post('/api/empresa/candidatura/:id/status', requireRecrutadorOuAdmin, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { acao, etapa, parecer } = req.body;
      const check = await pool.query(`
        SELECT c.*, v.etapas as vaga_etapas FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });
      const cand = check.rows[0];
      let novaEtapa = etapa !== undefined ? etapa : cand.etapa_atual;
      let novoStatus = cand.status;
      if (acao === 'avancar') {
        novaEtapa = cand.etapa_atual + 1;
        const totalEtapas = Array.isArray(cand.vaga_etapas) ? cand.vaga_etapas.length : 7;
        if (novaEtapa >= totalEtapas) novoStatus = 'contratado';
        else novoStatus = 'em_andamento';
      } else if (acao === 'reprovar') {
        novoStatus = 'reprovado';
      } else if (acao === 'reabrir') {
        novoStatus = 'em_andamento';
      }
      const hist = cand.historico || [];
      hist.push({ tipo: 'status', por: `empresa:${req.user.email}`, quando: new Date().toISOString(), acao, etapa: novaEtapa, status: novoStatus, parecer: parecer || null });
      await pool.query(`UPDATE candidaturas SET etapa_atual = $1, status = $2, historico = $3::jsonb, atualizada_em = NOW() WHERE id = $4`, [novaEtapa, novoStatus, JSON.stringify(hist), id]);
      res.json({ ok: true, etapa_atual: novaEtapa, status: novoStatus });
    } catch (e) {
      console.error('[EMPRESA STATUS]', e);
      res.status(500).json({ erro: 'Erro ao atualizar status' });
    }
  });

  // ===========================================================
  // GET /api/empresa/candidatura/:id/proposta
  // ===========================================================
  app.get('/api/empresa/candidatura/:id/proposta', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const check = await pool.query(`
        SELECT c.id FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });
      const { rows } = await pool.query(`
        SELECT id, candidatura_id, texto, arquivo_url, salario, beneficios, data_inicio,
               status, criada_em, enviada_em, aceita_em, recusada_em, motivo_recusa
        FROM propostas WHERE candidatura_id = $1 ORDER BY criada_em DESC LIMIT 1
      `, [id]);
      res.json({ proposta: rows[0] || null });
    } catch (e) {
      console.error('[EMPRESA PROPOSTA GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar proposta' });
    }
  });

  // ===========================================================
  // GET /api/empresa/candidatura/:id/documentos
  // ===========================================================
  app.get('/api/empresa/candidatura/:id/documentos', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const check = await pool.query(`
        SELECT c.id FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [id, req.user.id, empresa_id]);
      if (check.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });
      const { rows } = await pool.query(`
        SELECT id, candidatura_id, tipo, nome_arquivo, arquivo_url, status, motivo_reprovacao,
               enviado_em, revisado_em, revisado_por
        FROM documentos_candidatura WHERE candidatura_id = $1 ORDER BY tipo
      `, [id]);
      res.json({ documentos: rows });
    } catch (e) {
      console.error('[EMPRESA DOCS GET]', e);
      res.status(500).json({ erro: 'Erro ao listar documentos' });
    }
  });

  // ===========================================================
  // GET /api/empresa/candidatura/:id
  // ===========================================================
  app.get('/api/empresa/candidatura/:id', requireEmpresaViewer, async (req, res) => {
    try {
      const { empresa_id } = req.user;
      const { id } = req.params;
      const { rows } = await pool.query(`
        SELECT c.*, v.titulo as vaga_titulo, v.criada_por as vaga_criada_por, v.empresa as vaga_empresa,
               cd.nome as candidato_nome, cd.email as candidato_email, cd.cpf as candidato_cpf,
               cd.celular as candidato_celular, cd.foto_url as candidato_foto,
               cd.cidade as candidato_cidade, cd.estado as candidato_estado
        FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        JOIN candidatos cd ON cd.id = c.candidato_id
        WHERE c.id = $1
      `, [id]);
      if (rows.length === 0) return res.status(404).json({ erro: 'Candidatura não encontrada' });
      const cand = rows[0];
      const acessOk = cand.vaga_criada_por === req.user.id ||
        (await pool.query(`SELECT 1 FROM empresa_vaga_acesso WHERE vaga_id = $1 AND empresa_id = $2`, [cand.vaga_id, empresa_id])).rows.length > 0;
      if (!acessOk) return res.status(403).json({ erro: 'Sem acesso a esta candidatura' });
      delete cand.vaga_criada_por;
      res.json({ candidatura: cand });
    } catch (e) {
      console.error('[EMPRESA CANDIDATURA GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar candidatura' });
    }
  });
}

module.exports = { registrar };