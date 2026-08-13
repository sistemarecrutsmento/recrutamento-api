'use strict';
const { pool } = require('../db');
async function up(){const c=await pool.connect();try{await c.query(`CREATE TABLE IF NOT EXISTS suporte_tickets (id BIGSERIAL PRIMARY KEY, empresa_id INTEGER REFERENCES empresas(id), criado_por INTEGER, assunto VARCHAR(180) NOT NULL, descricao TEXT NOT NULL, prioridade VARCHAR(20) NOT NULL DEFAULT 'normal', status VARCHAR(20) NOT NULL DEFAULT 'aberto', criado_em TIMESTAMP NOT NULL DEFAULT NOW(), atualizado_em TIMESTAMP NOT NULL DEFAULT NOW(), fechado_em TIMESTAMP)`);await c.query(`CREATE INDEX IF NOT EXISTS idx_suporte_tickets_empresa ON suporte_tickets(empresa_id, status, criado_em DESC)`);return {ok:true};}finally{c.release();}}
module.exports={up};
