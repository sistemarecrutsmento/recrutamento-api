'use strict';
const { pool } = require('../db');
async function up(){const c=await pool.connect();try{await c.query(`CREATE TABLE IF NOT EXISTS lgpd_retention_reviews (id BIGSERIAL PRIMARY KEY, empresa_id INTEGER NOT NULL REFERENCES empresas(id), decisao VARCHAR(20) NOT NULL, motivo TEXT NOT NULL, decidido_por INTEGER, decidido_em TIMESTAMP NOT NULL DEFAULT NOW())`);await c.query('CREATE INDEX IF NOT EXISTS idx_lgpd_reviews_empresa ON lgpd_retention_reviews(empresa_id, decidido_em DESC)');return {ok:true};}finally{c.release();}}
module.exports={up};
