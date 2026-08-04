const STAGES = [
  { nome: 'Inscrição' },
  { nome: 'Triagem' },
  { nome: 'Entrevista RH' },
  { nome: 'Entrevista Gestor' },
  { nome: 'Teste Prático' },
  { nome: 'Proposta' },
  { nome: 'Coleta Documentos' },
  { nome: 'Contratação' }
];

const DOCS = [
  ['texto', 'cpf', 'CPF'], ['texto', 'rg', 'RG'], ['texto', 'pis_pasep', 'Número do PIS/PASEP'],
  ['texto', 'titulo_eleitor', 'Título de Eleitor'], ['texto', 'reservista', 'Certificado de Reservista'],
  ['texto', 'conta_bancaria', 'Conta bancária'], ['arquivo', 'rg_foto', 'RG ou CNH'],
  ['arquivo', 'cpf_foto', 'CPF ou CNH'], ['arquivo', 'ctps', 'Carteira de Trabalho Digital'],
  ['arquivo', 'comprovante_residencia', 'Comprovante de residência'],
  ['arquivo', 'titulo_eleitor_foto', 'Título de Eleitor'], ['arquivo', 'certidao_nascimento', 'Certidão de nascimento ou casamento'],
  ['arquivo', 'reservista_foto', 'Certificado de Reservista'], ['arquivo', 'escolaridade', 'Comprovante de escolaridade'],
  ['arquivo', 'foto_3x4', 'Foto 3x4'], ['arquivo', 'aso', 'ASO']
];

const VAGAS = [
  ['[DEMO] Analista de Recursos Humanos', 'Recursos Humanos', 'Pleno', 'RH / Pessoas', 3200, 4500],
  ['[DEMO] Assistente Administrativo', 'Operações Modelo', 'Júnior', 'Administrativo', 1800, 2400],
  ['[DEMO] Consultor(a) de Vendas', 'Comercial Modelo', 'Pleno', 'Comercial / Vendas', 2200, 3800],
  ['[DEMO] Desenvolvedor(a) Front-end', 'Tecnologia Modelo', 'Pleno', 'Tecnologia', 5000, 7500],
  ['[DEMO] Coordenador(a) de Operações', 'Operações Modelo', 'Sênior', 'Operações / Gestão', 5500, 7800],
  ['[DEMO] Auxiliar Financeiro', 'Financeiro Modelo', 'Júnior', 'Financeiro', 1900, 2700]
];

const PEOPLE = [
  ['Ana Clara Ribeiro', 'ana.clara.demo@exemplo.invalid', '11990000001', 'São Paulo', 'SP', 0, 'em_analise'],
  ['Bruno Henrique Alves', 'bruno.henrique.demo@exemplo.invalid', '11990000002', 'Campinas', 'SP', 1, 'em_andamento'],
  ['Camila Souza Martins', 'camila.souza.demo@exemplo.invalid', '11990000003', 'Ribeirão Preto', 'SP', 2, 'em_andamento'],
  ['Diego Ferreira Lima', 'diego.ferreira.demo@exemplo.invalid', '11990000004', 'Belo Horizonte', 'MG', 3, 'em_andamento'],
  ['Eduarda Nascimento', 'eduarda.nascimento.demo@exemplo.invalid', '11990000005', 'Curitiba', 'PR', 4, 'em_andamento'],
  ['Felipe Augusto Costa', 'felipe.augusto.demo@exemplo.invalid', '11990000006', 'Salvador', 'BA', 5, 'em_andamento'],
  ['Gabriela Oliveira Santos', 'gabriela.oliveira.demo@exemplo.invalid', '11990000007', 'Recife', 'PE', 6, 'em_andamento'],
  ['Henrique Martins Rocha', 'henrique.martins.demo@exemplo.invalid', '11990000008', 'Rio de Janeiro', 'RJ', 7, 'contratado'],
  ['Isabela Mendes Castro', 'isabela.mendes.demo@exemplo.invalid', '11990000009', 'São Paulo', 'SP', 2, 'rejeitado'],
  ['João Pedro Silva', 'joao.pedro.demo@exemplo.invalid', '11990000010', 'Fortaleza', 'CE', 1, 'em_andamento'],
  ['Larissa Gomes Freitas', 'larissa.gomes.demo@exemplo.invalid', '11990000011', 'Goiânia', 'GO', 6, 'em_andamento'],
  ['Marcos Vinícius Teixeira', 'marcos.vinicius.demo@exemplo.invalid', '11990000012', 'Porto Alegre', 'RS', 7, 'contratado']
];

function isoDaysAgo(n) {
  return new Date(Date.now() - n * 86400000).toISOString();
}

function historyFor(stage, status, name, daysAgo) {
  const items = [];
  for (let i = 0; i <= stage; i++) {
    items.push({
      etapa: i,
      status: i === stage ? status : 'em_andamento',
      acao: i === 0 ? 'inscricao' : 'avancar',
      mensagem: i === 0 ? 'Candidatura recebida' : `Candidato avançou para ${STAGES[i]?.nome || 'próxima etapa'}`,
      data: isoDaysAgo(Math.max(1, daysAgo - (stage - i) * 2)),
      por: i === 0 ? 'Sistema' : 'Equipe de Recrutamento'
    });
  }
  if (status === 'rejeitado') items.push({ etapa: stage, status, acao: 'reprovar', mensagem: 'Candidato reprovado nesta etapa', data: isoDaysAgo(1), por: 'Equipe de Recrutamento' });
  if (status === 'contratado') items.push({ etapa: 7, status, acao: 'contratar', mensagem: 'Contratação concluída', data: isoDaysAgo(1), por: 'Equipe de Recrutamento' });
  return items;
}

async function seedDemoCompleto(pool, targetEmail) {
  const client = await pool.connect();
  const result = { targetEmail, empresaId: null, empresaNome: null, vagas: 0, candidatos: 0, candidaturas: 0, entrevistas: 0, documentos: 0, mensagens: 0, idempotente: false };
  try {
    await client.query('BEGIN');

    const target = await client.query(`
      SELECT id, nome, email, 'admin' AS tipo, NULL::integer AS empresa_id FROM admins WHERE lower(email)=lower($1)
      UNION ALL
      SELECT u.id, u.nome, u.email, 'empresa' AS tipo, u.empresa_id FROM empresa_usuarios u WHERE lower(u.email)=lower($1)
      LIMIT 1
    `, [targetEmail]);
    if (!target.rowCount) throw new Error(`Usuário alvo não encontrado: ${targetEmail}`);
    const user = target.rows[0];

    let empresa;
    if (user.empresa_id) {
      const q = await client.query('SELECT id, nome FROM empresas WHERE id=$1', [user.empresa_id]);
      if (!q.rowCount) throw new Error('A empresa vinculada ao usuário não foi encontrada');
      empresa = q.rows[0];
    } else {
      const q = await client.query(`SELECT id, nome FROM empresas WHERE slug='demo-vagasio-fabio17' LIMIT 1`);
      if (q.rowCount) empresa = q.rows[0];
      else {
        const ins = await client.query(`
          INSERT INTO empresas (nome, cnpj, email_principal, telefone, ativo, criado_por, plano, slug, cor_destaque)
          VALUES ('VagasIO — Empresa Modelo (Demonstração)', NULL, $1, '(11) 90000-0000', true, $2, 'profissional', 'demo-vagasio-fabio17', '#720F35')
          RETURNING id, nome
        `, [targetEmail, user.tipo === 'admin' ? user.id : null]);
        empresa = ins.rows[0];
      }
    }
    result.empresaId = empresa.id;
    result.empresaNome = empresa.nome;

    const vagaIds = [];
    for (const [titulo, nomeEmpresa, nivel, area, min, max] of VAGAS) {
      const existing = await client.query('SELECT id FROM vagas WHERE titulo=$1 AND empresa_id=$2 LIMIT 1', [titulo, empresa.id]);
      let id;
      if (existing.rowCount) { id = existing.rows[0].id; result.idempotente = true; }
      else {
        const ins = await client.query(`
          INSERT INTO vagas (titulo, empresa, empresa_id, cidade, estado, tipo_contrato, nivel, area, salario_min, salario_max, descricao, requisitos, beneficios, etapas, status, criada_por)
          VALUES ($1,$2,$3,'São Paulo','SP','CLT',$4,$5,$6,$7,$8,$9,$10,$11,'publicada',$12) RETURNING id
        `, [titulo, nomeEmpresa, empresa.id, nivel, area, min, max,
          `Esta é uma vaga fictícia criada para demonstrar o fluxo completo do VagasIO. A equipe acompanhará o candidato desde a inscrição até a contratação.`,
          'Boa comunicação, organização, experiência compatível com a função e disponibilidade para as etapas do processo.',
          'Vale-refeição, vale-transporte, plano de saúde e desenvolvimento profissional.', JSON.stringify(STAGES), user.tipo === 'admin' ? user.id : null]);
        id = ins.rows[0].id; result.vagas++;
      }
      vagaIds.push(id);
      await client.query(`INSERT INTO empresa_vaga_acesso (empresa_id, vaga_id, concedido_por, tipo) VALUES ($1,$2,$3,'propria') ON CONFLICT (empresa_id,vaga_id) DO UPDATE SET revogado_em=NULL`, [empresa.id, id, user.tipo === 'admin' ? user.id : null]);
    }

    const candidaturaIds = [];
    for (let i = 0; i < PEOPLE.length; i++) {
      const [nome, email, celular, cidade, estado, stage, status] = PEOPLE[i];
      const existingPerson = await client.query('SELECT id FROM candidatos WHERE email=$1 LIMIT 1', [email]);
      let candidatoId;
      if (existingPerson.rowCount) { candidatoId = existingPerson.rows[0].id; result.idempotente = true; }
      else {
        const ins = await client.query(`
          INSERT INTO candidatos (nome, email, celular, cidade, estado, formacao, instituicao, curso, situacao, primeiro_emprego, banco_talentos, recebe_comunicacoes, email_verificado, sobre_voce, experiencia, areas_interesse)
          VALUES ($1,$2,$3,$4,$5,'Ensino superior completo','Universidade Modelo','Administração e Gestão','Concluído',false,true,false,true,$6,$7,$8) RETURNING id
        `, [nome, email, celular, cidade, estado,
          'Profissional fictício criado para demonstração das funcionalidades do VagasIO.',
          'Experiência demonstrativa em atendimento, organização de processos e trabalho em equipe.', JSON.stringify(['Gestão de pessoas', 'Processos', 'Comunicação'])]);
        candidatoId = ins.rows[0].id; result.candidatos++;
        await client.query(`INSERT INTO experiencias (candidato_id,cargo,empresa,inicio,fim,emprego_atual,descricao) VALUES ($1,$2,$3,'2021-01-01','2024-12-31',false,$4)`, [candidatoId, 'Analista de Operações', 'Empresa Modelo', 'Experiência fictícia para apresentação do perfil.']);
      }
      const vagaId = vagaIds[i % vagaIds.length];
      const existsC = await client.query('SELECT id FROM candidaturas WHERE vaga_id=$1 AND candidato_id=$2 LIMIT 1', [vagaId, candidatoId]);
      let candidaturaId;
      const propostaEnviada = stage >= 5;
      const propostaAceita = stage >= 6;
      if (existsC.rowCount) { candidaturaId = existsC.rows[0].id; result.idempotente = true; }
      else {
        const days = 30 - i;
        const hist = historyFor(stage, status, nome, days);
        const ins = await client.query(`
          INSERT INTO candidaturas (vaga_id,candidato_id,status,etapa_atual,historico,observacoes_etapas,criada_em,atualizada_em,proposta_texto,proposta_enviada_em,proposta_aceita_em,proposta_recusada_em,proposta_motivo_recusa)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id
        `, [vagaId, candidatoId, status, stage, JSON.stringify(hist), JSON.stringify({ '1': 'Perfil em análise pela equipe.', '2': 'Entrevista registrada para demonstração.' }), isoDaysAgo(days), isoDaysAgo(Math.max(1, days - 2)),
          propostaEnviada ? 'Parabéns! Esta é uma proposta fictícia criada para demonstrar o fluxo de contratação do VagasIO.' : null,
          propostaEnviada ? isoDaysAgo(5) : null, propostaAceita ? isoDaysAgo(3) : null,
          status === 'rejeitado' ? isoDaysAgo(2) : null, status === 'rejeitado' ? 'Perfil fictício usado para demonstrar o encerramento de um processo.' : null]);
        candidaturaId = ins.rows[0].id; result.candidaturas++;
      }
      candidaturaIds.push(candidaturaId);

      if (stage >= 2 && stage <= 4) {
        const intExists = await client.query('SELECT id FROM entrevistas WHERE candidatura_id=$1 AND etapa=$2 LIMIT 1', [candidaturaId, stage]);
        if (!intExists.rowCount) {
          const statusInt = stage === 2 ? 'agendada' : (stage === 3 ? 'realizada' : 'cancelada');
          await client.query(`INSERT INTO entrevistas (candidatura_id,etapa,data_hora,duracao_minutos,local,link_reuniao,observacoes,status,criado_por) VALUES ($1,$2,$3,45,$4,$5,$6,$7,$8)`, [candidaturaId, stage, stage === 2 ? new Date(Date.now() + 2 * 86400000).toISOString() : isoDaysAgo(3), stage === 2 ? 'Google Meet (demonstração)' : 'Sala de reuniões — Empresa Modelo', 'https://meet.google.com/demo-vagasio', 'Registro fictício para demonstrar agenda, realização e cancelamento de entrevistas.', statusInt, user.tipo === 'admin' ? user.id : null]);
          result.entrevistas++;
        }
      }

      if (i === 2 || i === 6 || i === 7 || i === 11) {
        const docCount = i === 7 || i === 11 ? DOCS.length : 6;
        for (let d = 0; d < docCount; d++) {
          const [categoria, tipo, label] = DOCS[d];
          const docExists = await client.query('SELECT id FROM documentos_candidatura WHERE candidatura_id=$1 AND tipo=$2 LIMIT 1', [candidaturaId, tipo]);
          if (!docExists.rowCount) {
            const aprovado = i === 7 || i === 11 || d < 4;
            await client.query(`INSERT INTO documentos_candidatura (candidatura_id,tipo,categoria,valor_texto,arquivo_url,arquivo_nome,arquivo_tipo,arquivo_tamanho,status,justificativa_admin,enviado_em,revisado_em) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [candidaturaId, tipo, categoria, categoria === 'texto' ? `DEMO-${String(candidatoId).padStart(6,'0')}` : null, categoria === 'arquivo' ? 'https://example.invalid/arquivo-demo.pdf' : null, categoria === 'arquivo' ? `demo-${tipo}.pdf` : null, categoria === 'arquivo' ? 'application/pdf' : null, categoria === 'arquivo' ? 24576 : null, aprovado ? 'aprovado' : 'pendente', aprovado ? 'Documento fictício aprovado para demonstração.' : null, isoDaysAgo(4), aprovado ? isoDaysAgo(2) : null]);
            result.documentos++;
          }
        }
      }

      if (stage >= 2 && status !== 'rejeitado') {
        const msgExists = await client.query('SELECT id FROM mensagens_processo WHERE candidatura_id=$1 LIMIT 1', [candidaturaId]);
        if (!msgExists.rowCount) {
          await client.query(`INSERT INTO mensagens_processo (candidatura_id,autor_tipo,autor_nome,texto,contexto,criado_em) VALUES ($1,'admin','Equipe de Recrutamento',$2,'demonstração',$3)`, [candidaturaId, `Olá, ${nome.split(' ')[0]}! Esta mensagem fictícia demonstra a comunicação durante o processo seletivo.`, isoDaysAgo(2)]);
          result.mensagens++;
        }
      }
      if (stage >= 2 && status !== 'rejeitado') {
        const chatExists = await client.query('SELECT id FROM empresa_chat WHERE candidatura_id=$1 LIMIT 1', [candidaturaId]);
        if (!chatExists.rowCount) {
          await client.query(`INSERT INTO empresa_chat (candidatura_id,remetente_tipo,remetente_id,remetente_nome,mensagem,criado_em) VALUES ($1,'rh',$2,'Equipe de Recrutamento',$3,$4)`, [candidaturaId, user.tipo === 'admin' ? user.id : null, `Atualização fictícia: o processo de ${nome} está na etapa ${stage + 1}.`, isoDaysAgo(1)]);
          result.mensagens++;
        }
      }
    }

    await client.query('COMMIT');
    result.total = { vagas: vagaIds.length, candidaturas: candidaturaIds.length };
    return result;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { seedDemoCompleto };
