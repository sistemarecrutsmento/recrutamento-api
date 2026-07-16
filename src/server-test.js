// SERVIDOR MÍNIMO PARA DIAGNOSTICAR
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { pool, init } = require('./db');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/saude', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    console.log('[LOGIN] body:', JSON.stringify(req.body));
    if (!email || !senha) return res.status(400).json({ erro: 'faltou' });

    const { rows } = await pool.query(
      'SELECT id, email, senha_hash FROM admins WHERE email = $1',
      [email.toLowerCase()]
    );
    console.log('[LOGIN] rows:', rows.length);
    if (rows.length === 0) return res.status(401).json({ erro: 'sem usuario' });

    console.log('[LOGIN] hash no banco:', rows[0].senha_hash?.substring(0, 15));
    console.log('[LOGIN] chamando bcrypt.compare...');
    const t0 = Date.now();
    const ok = await bcrypt.compare(senha, rows[0].senha_hash);
    console.log('[LOGIN] compare levou', (Date.now() - t0) + 'ms, resultado:', ok);

    if (!ok) return res.status(401).json({ erro: 'senha errada' });
    res.json({ ok: true, msg: 'logado' });
  } catch (e) {
    console.error('[LOGIN ERRO]', e);
    res.status(500).json({ erro: e.message });
  }
});

(async () => {
  // SEM init() - só subir o servidor
  console.log('Subindo sem init()');
  app.listen(process.env.PORT || 10000, () => console.log('UP'));
})();
