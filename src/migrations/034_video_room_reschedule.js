const { pool } = require('../db');

async function up() {
  await pool.query(`
    ALTER TABLE video_rooms DROP CONSTRAINT IF EXISTS video_rooms_candidatura_id_entrevista_id_key;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_video_rooms_active_interview
      ON video_rooms(entrevista_id) WHERE status='active';
  `);
}
module.exports = { up };
