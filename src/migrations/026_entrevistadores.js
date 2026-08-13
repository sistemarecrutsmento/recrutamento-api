'use strict';
const { pool } = require('../db');
async function up() { const c=await pool.connect(); try { await c.query(`ALTER TABLE entrevistas ADD COLUMN IF NOT EXISTS entrevistadores JSONB NOT NULL DEFAULT '[]'::jsonb`); return {ok:true}; } finally { c.release(); } }
module.exports={up};
