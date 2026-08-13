'use strict';
const { pool } = require('../db');
async function up(){const c=await pool.connect();try{await c.query("ALTER TABLE empresas ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT false");await c.query('ALTER TABLE empresas ADD COLUMN IF NOT EXISTS legal_hold_motivo TEXT');await c.query('ALTER TABLE empresas ADD COLUMN IF NOT EXISTS legal_hold_em TIMESTAMP');await c.query('ALTER TABLE empresas ADD COLUMN IF NOT EXISTS legal_hold_por INTEGER');return {ok:true};}finally{c.release();}}
module.exports={up};
