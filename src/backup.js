// backup.js — Estratégia de backup: SQL INSERT statements → gzip → Cloudinary
// Uso: const { performBackup, getBackupMetadata } = require('./backup');
const { Pool } = require('pg');
const zlib = require('zlib');
const { cloudinary } = require('./cloudinary');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 3,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  statement_timeout: 60_000,
  query_timeout: 60_000
});

// Tabelas na ordem de dependência (pais antes de filhos)
const TABELAS = [
  'admins',
  'recrutadores',
  'empresas',
  'empresa_usuarios',
  'candidatos',
  'experiencias',
  'codigos_verificacao',
  'password_resets',
  'vagas',
  'candidaturas',
  'mensagens_processo',
  'chat_arquivos',
  'documentos_candidatura',
  'entrevistas',
  'empresa_chat',
  'empresa_vaga_acesso',
  'empresa_notificacoes'
];

const FOLDER = 'backups-vagas';
const PUBLIC_ID_PREFIX = 'backup-vagas';

/**
 * Gera INSERT statements para uma tabela inteira.
 * Lida com escaping de valores textuais e JSONB.
 */
async function dumpTable(client, tabela) {
  const { rows } = await client.query(`SELECT * FROM ${tabela} ORDER BY id`);
  if (rows.length === 0) return '';

  const colunas = Object.keys(rows[0]);
  const colList = colunas.map(c => `"${c}"`).join(', ');

  const linhas = rows.map(row => {
    const valores = colunas.map(col => {
      const val = row[col];
      if (val === null || val === undefined) return 'NULL';
      if (typeof val === 'number') return String(val);
      if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE';
      if (val instanceof Date) return `'${val.toISOString().replace("T", " ").replace("Z", "")}'`;
      // JSONB / objeto
      if (typeof val === 'object') {
        return `'${JSON.stringify(val).replace(/'/g, "''")}'::jsonb`;
      }
      // String
      return `'${String(val).replace(/'/g, "''")}'`;
    });
    return `INSERT INTO "${tabela}" (${colList}) VALUES (${valores.join(', ')});`;
  });

  return linhas.join('\n');
}

/**
 * Executa backup completo:
 * 1. Abre transação
 * 2. Lê todas as tabelas
 * 3. Gera SQL com BEGIN/COMMIT
 * 4. Comprime com gzip
 * 5. Envia para Cloudinary
 * 6. Retorna metadados
 */
async function performBackup() {
  const client = await pool.connect();
  try {
    console.log('[BACKUP] Iniciando backup completo...');
    const inicio = Date.now();

    const partes = ['BEGIN;'];
    const contagens = {};

    for (const tabela of TABELAS) {
      try {
        const sql = await dumpTable(client, tabela);
        if (sql) {
          partes.push(`-- ${tabela}`);
          partes.push(sql);
          // Contagem aproximada (linhas INSERT)
          const count = sql.split('\n').filter(l => l.startsWith('INSERT')).length;
          contagens[tabela] = count;
        } else {
          contagens[tabela] = 0;
        }
        console.log(`[BACKUP] ${tabela}: ${contagens[tabela]} linhas`);
      } catch (e) {
        console.error(`[BACKUP] Erro ao dumpar ${tabela}:`, e.message);
        throw e;
      }
    }

    partes.push('COMMIT;');
    const sqlText = partes.join('\n');
    const duracaoMs = Date.now() - inicio;

    console.log(`[BACKUP] SQL gerado: ${(sqlText.length / 1024 / 1024).toFixed(2)} MB, ${duracaoMs}ms`);

    // Comprime com gzip
    const buffer = zlib.gzipSync(Buffer.from(sqlText, 'utf-8'));
    const compressedMb = (buffer.length / 1024 / 1024).toFixed(2);
    console.log(`[BACKUP] Comprimido: ${compressedMb} MB`);

    // Envia para Cloudinary
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
    const publicId = `${PUBLIC_ID_PREFIX}-${timestamp}`;

    const uploadResult = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: FOLDER,
          public_id: publicId,
          resource_type: 'raw',
          overwrite: true
        },
        (err, result) => {
          if (err) return reject(err);
          resolve(result);
        }
      );
      stream.end(buffer);
    });

    const metadados = {
      ok: true,
      timestamp: new Date().toISOString(),
      duracaoMs,
      tamanhoSql: sqlText.length,
      tamanhoGzip: buffer.length,
      compressedMb: Number(compressedMb),
      tabelas: contagens,
      totalLinhas: Object.values(contagens).reduce((a, b) => a + b, 0),
      cloudinary: {
        url: uploadResult.secure_url,
        public_id: uploadResult.public_id,
        bytes: uploadResult.bytes
      }
    };

    console.log(`[BACKUP] Completo! URL: ${uploadResult.secure_url}`);
    return metadados;
  } finally {
    client.release();
  }
}

/**
 * Retorna o metadata do último backup do Cloudinary (sem baixar).
 */
async function getBackupMetadata() {
  try {
    const result = await cloudinary.search
      .expression(`folder:${FOLDER} AND public_id:${PUBLIC_ID_PREFIX}*`)
      .sort_by('created_at', 'desc')
      .max_results(1)
      .execute();

    if (result.resources.length === 0) {
      return { ok: true, ultimoBackup: null };
    }

    const r = result.resources[0];
    return {
      ok: true,
      ultimoBackup: {
        public_id: r.public_id,
        url: r.secure_url,
        tamanhoBytes: r.bytes,
        criadoEm: r.created_at,
        formato: r.format,
        tipo: r.resource_type
      }
    };
  } catch (e) {
    console.error('[BACKUP META ERROR]', e.message);
    return { ok: false, erro: e.message };
  }
}

module.exports = { performBackup, getBackupMetadata, TABELAS };