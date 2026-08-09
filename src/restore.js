// restore.js — Restauração de backup a partir do buffer gzipado gerado pelo backup.js
// Uso: const { restoreFromBuffer, restoreFromCloudinary } = require('./restore');
const { Pool } = require('pg');
const zlib = require('zlib');
const { cloudinary } = require('./cloudinary');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 3,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  statement_timeout: 120_000,
  query_timeout: 120_000
});

/**
 * Descomprime um buffer gzipado e retorna o texto SQL.
 */
function decompress(buffer) {
  return zlib.gunzipSync(buffer).toString('utf-8');
}

/**
 * Extrai statements SQL individuais do texto completo.
 * Lida com BEGIN, COMMIT, comentários e linhas INSERT.
 * Retorna array de strings SQL não-vazias.
 */
function parseStatements(sqlText) {
  // Remove comentários de linha (-- ...) preservando quebras de linha
  const semComentarios = sqlText.replace(/^--.*$/gm, '').trim();

  // Divide por ';' seguido de quebra de linha
  const statements = semComentarios
    .split(/;\s*\n/)
    .map(s => s.trim())
    .filter(s => s.length > 0);

  // Junta de volta os ';' que foram removidos pelo split
  return statements.map(s => {
    // Se o statement não termina com ';', adiciona
    if (s.endsWith(';')) return s;
    return s + ';';
  });
}

/**
 * Conta quantas linhas foram inseridas (INSERT ... VALUES) nos statements.
 */
function countInserted(statements) {
  let count = 0;
  for (const stmt of statements) {
    if (stmt.toUpperCase().startsWith('INSERT')) {
      // Cada VALUES pode ter múltiplas linhas, mas nossos backups
      // geram um INSERT por linha — então cada statement = 1 linha
      count++;
    }
  }
  return count;
}

/**
 * Extrai o nome da tabela de um INSERT.
 */
function extractTable(stmt) {
  const m = stmt.match(/INSERT\s+(?:INTO\s+)?"?(\w+)"?/i);
  return m ? m[1] : 'desconhecida';
}

/**
 * Restaura um backup a partir de um buffer gzipado.
 *
 * @param {Buffer} gzipBuffer - Buffer gzipado com o SQL
 * @param {Object} [options]
 * @param {boolean} [options.dryRun=false] - Se true, só parseia e conta (não executa)
 * @returns {Promise<Object>} Resultado da restauração
 */
async function restoreFromBuffer(gzipBuffer, options = {}) {
  const dryRun = options.dryRun || false;
  const inicio = Date.now();

  // 1. Descomprime
  console.log('[RESTORE] Descomprimindo buffer...');
  let sqlText;
  try {
    sqlText = decompress(gzipBuffer);
  } catch (e) {
    console.error('[RESTORE] Erro ao descomprimir:', e.message);
    return { ok: false, erro: `Erro ao descomprimir: ${e.message}` };
  }
  console.log(`[RESTORE] SQL: ${(sqlText.length / 1024 / 1024).toFixed(2)} MB`);

  // 2. Parseia statements
  const statements = parseStatements(sqlText);
  const totalInsert = countInserted(statements);
  console.log(`[RESTORE] ${statements.length} statements, ${totalInsert} INSERTs`);

  if (dryRun) {
    // Agrupa por tabela
    const porTabela = {};
    for (const stmt of statements) {
      if (stmt.toUpperCase().startsWith('INSERT')) {
        const t = extractTable(stmt);
        porTabela[t] = (porTabela[t] || 0) + 1;
      }
    }
    return {
      ok: true,
      dryRun: true,
      duracaoMs: Date.now() - inicio,
      tamanhoSql: sqlText.length,
      totalStatements: statements.length,
      totalInsert,
      porTabela
    };
  }

  // 3. Executa em transação
  const client = await pool.connect();
  try {
    console.log('[RESTORE] Iniciando transação...');
    await client.query('BEGIN');

    let insertOk = 0;
    let insertErro = 0;
    const erros = [];

    for (let i = 0; i < statements.length; i++) {
      const stmt = statements[i];
      try {
        if (stmt.toUpperCase() === 'BEGIN;' || stmt.toUpperCase() === 'COMMIT;') {
          // Pula BEGIN/COMMIT — a transação é gerenciada por nós
          continue;
        }
        await client.query(stmt);
        if (stmt.toUpperCase().startsWith('INSERT')) {
          insertOk++;
        }
      } catch (e) {
        if (stmt.toUpperCase().startsWith('INSERT')) {
          insertErro++;
          erros.push({ index: i, tabela: extractTable(stmt), erro: e.message });
        } else {
          // Erro em outro tipo de statement (não esperado)
          erros.push({ index: i, statement: stmt.substring(0, 80), erro: e.message });
        }
        if (erros.length > 10) {
          // Muitos erros — aborta
          throw new Error(`Muitos erros (${erros.length}). Último: ${e.message}`);
        }
      }
    }

    if (erros.length > 0) {
      // Se houver qualquer erro, rollback total
      await client.query('ROLLBACK');
      console.error(`[RESTORE] ROLLBACK — ${erros.length} erro(s) detectado(s)`);
      return {
        ok: false,
        erro: `Rollback executado. ${erros.length} erro(s) durante INSERTs`,
        erros: erros.slice(0, 10),
        insertOk,
        insertErro,
        duracaoMs: Date.now() - inicio
      };
    }

    await client.query('COMMIT');
    console.log(`[RESTORE] COMMIT — ${insertOk} INSERTs executados com sucesso`);
    return {
      ok: true,
      duracaoMs: Date.now() - inicio,
      insertOk,
      totalInsert,
      totalStatements: statements.length
    };
  } catch (e) {
    // Garante rollback em caso de exceção não tratada
    try { await client.query('ROLLBACK'); } catch (_) { /* ignora */ }
    console.error('[RESTORE] Erro fatal:', e.message);
    return { ok: false, erro: e.message, duracaoMs: Date.now() - inicio };
  } finally {
    client.release();
  }
}

/**
 * Baixa o último backup do Cloudinary e restaura.
 *
 * @param {Object} [options] - Opções passadas para restoreFromBuffer
 * @returns {Promise<Object>}
 */
async function restoreFromCloudinary(options = {}) {
  // Busca o último backup
  const result = await cloudinary.search
    .expression('folder:backups-vagas AND public_id:backup-vagas*')
    .sort_by('created_at', 'desc')
    .max_results(1)
    .execute();

  if (result.resources.length === 0) {
    return { ok: false, erro: 'Nenhum backup encontrado no Cloudinary' };
  }

  const r = result.resources[0];
  console.log(`[RESTORE] Último backup: ${r.public_id} (${r.created_at})`);

  // Backups são authenticated; o download usa URL assinada gerada no servidor.
  const downloadUrl = cloudinary.url(r.public_id, {
    resource_type: r.resource_type || 'raw',
    type: 'authenticated',
    sign_url: true,
    secure: true,
    format: 'gz'
  });
  const response = await fetch(downloadUrl);
  if (!response.ok) {
    return { ok: false, erro: `Erro ao baixar backup: ${response.status}` };
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  console.log(`[RESTORE] Backup baixado: ${(buffer.length / 1024 / 1024).toFixed(2)} MB`);

  return restoreFromBuffer(buffer, options);
}

module.exports = { restoreFromBuffer, restoreFromCloudinary, parseStatements, decompress };