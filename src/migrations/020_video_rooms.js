const { pool } = require('../db');

async function up() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS video_rooms (
      id BIGSERIAL PRIMARY KEY,
      room_id TEXT NOT NULL UNIQUE,
      candidatura_id INTEGER NOT NULL REFERENCES candidaturas(id) ON DELETE CASCADE,
      entrevista_id INTEGER NOT NULL REFERENCES entrevistas(id) ON DELETE CASCADE,
      empresa_id INTEGER REFERENCES empresas(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'active',
      expires_at TIMESTAMPTZ NOT NULL,
      ended_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(candidatura_id, entrevista_id)
    );
    CREATE INDEX IF NOT EXISTS idx_video_rooms_tenant ON video_rooms(empresa_id, candidatura_id);
    CREATE TABLE IF NOT EXISTS video_participant_tokens (
      id BIGSERIAL PRIMARY KEY,
      room_id TEXT NOT NULL REFERENCES video_rooms(room_id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      user_id TEXT NOT NULL,
      user_type TEXT NOT NULL,
      participant_role TEXT NOT NULL CHECK (participant_role IN ('candidate','recruiter')),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS idx_video_tokens_room ON video_participant_tokens(room_id, expires_at);
  `);
}
module.exports = { up };
