'use strict';
const { pool } = require('../db');
async function up(){const c=await pool.connect();try{const indexes=[
'CREATE INDEX IF NOT EXISTS idx_candidaturas_vaga_status ON candidaturas(vaga_id,status,atualizada_em DESC)',
'CREATE INDEX IF NOT EXISTS idx_candidaturas_candidato_status ON candidaturas(candidato_id,status,atualizada_em DESC)',
'CREATE INDEX IF NOT EXISTS idx_entrevistas_candidatura_data ON entrevistas(candidatura_id,data_hora DESC)',
'CREATE INDEX IF NOT EXISTS idx_vagas_publicadas_empresa ON vagas(empresa_id,criada_em DESC) WHERE LOWER(TRIM(status))=\'publicada\'',
'CREATE INDEX IF NOT EXISTS idx_empresas_ativo_slug ON empresas(slug) WHERE ativo=true'
];for(const sql of indexes)await c.query(sql);return {ok:true};}finally{c.release();}}
module.exports={up};
