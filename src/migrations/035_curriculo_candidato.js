// Fase PDF — currículo importado persistido por candidato (idempotente).
// O arquivo original fica protegido no backend; nunca é incluído nas respostas de perfil.
async function up(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS curriculos_candidato (
      candidato_id INTEGER PRIMARY KEY REFERENCES candidatos(id) ON DELETE CASCADE,
      arquivo_nome TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      tamanho_bytes INTEGER NOT NULL,
      base64_data TEXT NOT NULL,
      dados_importados JSONB,
      diagnostico JSONB,
      criado_em TIMESTAMP DEFAULT NOW(),
      atualizado_em TIMESTAMP DEFAULT NOW()
    )
  `);
  await client.query(`CREATE INDEX IF NOT EXISTS idx_curriculos_candidato_atualizado ON curriculos_candidato(atualizado_em)`);
}
module.exports = { up };
