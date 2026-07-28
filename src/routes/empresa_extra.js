// Last updated: 2026-07-28T17:48:21Z
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
      const { candidatura_id, etapa: etapaBody, data_hora, duracao_minutos, local, link_reuniao, observacoes, tipo } = req.body;
      const etapa = etapaBody != null ? Number(etapaBody) : 4; // default etapa 4 (Gestor/Empresa)
      if (!candidatura_id || !data_hora) {
        return res.status(400).json({ erro: 'candidatura_id e data_hora são obrigatórios' });
      }
      const candCheck = await pool.query(`
        SELECT c.id FROM candidaturas c
        JOIN vagas v ON v.id = c.vaga_id
        WHERE c.id = $1 AND (v.criada_por = $2 OR v.id IN (SELECT vaga_id FROM empresa_vaga_acesso WHERE empresa_id = $3))
      `, [candidatura_id, req.user.id, empresa_id]);
      if (candCheck.rows.length === 0) return res.status(403).json({ erro: 'Candidatura não pertence a esta empresa' });

      const { rows } = await pool.query(`
        INSERT INTO entrevistas (candidatura_id, etapa, data_hora, duracao_minutos, local, link_reuniao, observacoes, status, criado_em)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'agendada', NOW())
        RETURNING id
      `, [candidatura_id, etapa, data_hora, duracao_minutos || 60, local, link_reuniao, observacoes]);
      res.json({ ok: true, entrevista: { id: rows[0].id }, id: rows[0].id });
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
      const { decisao, motivo, status: statusBody, justificativa, acao } = req.body;
      // Normaliza: aceita 'decisao', 'status' ou 'acao' (retrocompat + novo padrão)
      let statusFinal = decisao || statusBody;
      if (acao === 'aprovar') statusFinal = 'aprovado';
      else if (acao === 'reprovar') statusFinal = 'reprovado';
      else if (acao === 'retornar') statusFinal = 'retornado';
      const motivoFinal = motivo || justificativa || null;
      if (!statusFinal || !['aprovado', 'reprovado', 'retornado', 'pendente'].includes(statusFinal)) {
        return res.status(400).json({ erro: 'status deve ser: aprovado, reprovado, retornado ou pendente' });
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
        SET status = $1, justificativa_admin = $2, revisado_em = NOW()
        WHERE id = $3
      `, [statusFinal, motivoFinal, id]);
      res.json({ ok: true, status: statusFinal, documento: { id: Number(id), status: statusFinal } });
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
        SELECT id, proposta_texto as texto, proposta_pdf_url as arquivo_url,
               proposta_enviada_em as enviada_em, proposta_aceita_em as aceita_em,
               proposta_recusada_em as recusada_em, proposta_motivo_recusa as motivo_recusa
        FROM candidaturas WHERE id = $1
      `, [id]);
      const row = rows[0];
      const proposta = row && row.enviada_em ? {
        candidatura_id: Number(id),
        texto: row.texto,
        arquivo_url: row.arquivo_url,
        enviada_em: row.enviada_em,
        aceita_em: row.aceita_em,
        recusada_em: row.recusada_em,
        motivo_recusa: row.motivo_recusa
      } : null;
      res.json({ proposta });
    } catch (e) {
      console.error('[EMPRESA PROPOSTA GET]', e);
      res.status(500).json({ erro: 'Erro ao buscar proposta' });
    }
  });
}

module.exports = { registrar };