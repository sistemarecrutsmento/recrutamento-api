// SERVIDOR MÍNIMO PARA DIAGNOSTICAR
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/api/saude', (req, res) => res.json({ ok: true, ts: Date.now(), node: process.version }));
app.get('/api/env', (req, res) => res.json({
  hasDb: !!process.env.DATABASE_URL,
  dbStart: process.env.DATABASE_URL?.substring(0, 20),
  hasEmail: !!process.env.EMAIL_FROM,
  hasJwt: !!process.env.JWT_SECRET
}));

app.listen(process.env.PORT || 10000, () => console.log('UP na porta', process.env.PORT || 10000));
