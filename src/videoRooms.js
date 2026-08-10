'use strict';
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { pool } = require('./db');

// Development rollout uses the existing VagasIO authentication and records.
// Keep an explicit flag so the capability can be rolled back without code changes.
const enabled = () => process.env.VAGASIO_VIDEO_CALLS === '1';
const signalUrl = () => {
  const raw = String(process.env.VAGASIO_VIDEO_SIGNAL_URL || '').trim();
  if (/^https:\/\//i.test(raw)) return raw.replace(/^https:/i, 'wss:');
  return raw;
};
const normalizeTipo = (tipo) => {
  const t = String(tipo || '').toLowerCase().trim();
  if (['candidato','candidate'].includes(t)) return 'candidato';
  if (['empresa','empresa_admin','admin_empresa','recrutador','recruiter'].includes(t)) return t === 'recrutador' || t === 'recruiter' ? 'recrutador' : 'empresa';
  if (['admin','administrador'].includes(t)) return 'admin';
  return '';
};
const allow = (u) => ['candidato','empresa','recrutador','admin'].includes(normalizeTipo(u?.tipo));
function role(u) { return normalizeTipo(u?.tipo) === 'candidato' ? 'candidate' : (allow(u) ? 'recruiter' : null); }
function gate(req, res) {
  const enabledNow = enabled(), url = signalUrl(), tipo = normalizeTipo(req.user?.tipo);
  if (!enabledNow || !tipo || !/^wss:\/\//i.test(url)) {
    console.warn('[VIDEO GATE] bloqueado', JSON.stringify({ enabled: enabledNow, tipo: tipo || 'ausente', signalConfigured: /^wss:\/\//i.test(url) }));
    res.status(404).json({ erro:'Recurso não encontrado' }); return false;
  }
  return true;
}
function hash(v) { return crypto.createHash('sha256').update(v).digest('hex'); }
async function access(req, id) {
  const p = await pool.query(`SELECT ca.id candidatura_id, ca.candidato_id, ca.vaga_id, e.id entrevista_id,
      COALESCE(v.empresa_id, eu.empresa_id) empresa_id
    FROM entrevistas e JOIN candidaturas ca ON ca.id=e.candidatura_id
    JOIN vagas v ON v.id=ca.vaga_id
    LEFT JOIN empresa_usuarios eu ON eu.empresa_id=v.empresa_id AND eu.id=$2
    WHERE e.id=$1`, [id, req.user.id]);
  if (!p.rowCount) return null;
  const r=p.rows[0], isCand=req.user.tipo==='candidato' && Number(r.candidato_id)===Number(req.user.id);
  const isRecruiter=['empresa','recrutador'].includes(req.user.tipo) && Number(req.user.empresa_id)===Number(r.empresa_id);
  const isAdmin=req.user.tipo==='admin';
  return (isCand||isRecruiter||isAdmin) ? {...r, participant_role:isCand?'candidate':'recruiter'} : null;
}
async function getOrCreate(req, interviewId) {
  const a=await access(req, interviewId); if(!a) return null;
  const ttl=Math.min(Math.max(Number(process.env.VAGASIO_VIDEO_ROOM_TTL_SECONDS||7200),900),86400);
  const q=await pool.query(`INSERT INTO video_rooms(room_id,candidatura_id,entrevista_id,empresa_id,expires_at)
    VALUES($1,$2,$3,$4,NOW()+($5 * INTERVAL '1 second'))
    ON CONFLICT(candidatura_id,entrevista_id) DO UPDATE SET expires_at=GREATEST(video_rooms.expires_at,EXCLUDED.expires_at)
    RETURNING room_id,candidatura_id,entrevista_id,expires_at,status`, ['vio-'+crypto.randomUUID(),a.candidatura_id,a.entrevista_id,a.empresa_id,ttl]);
  return {...q.rows[0], participant_role:a.participant_role};
}
async function issue(req, room) {
  const q=await pool.query(`SELECT r.*, ca.candidato_id FROM video_rooms r JOIN candidaturas ca ON ca.id=r.candidatura_id WHERE r.room_id=$1`,[room]);
  if(!q.rowCount) return null;
  const r=q.rows[0], isCand=req.user.tipo==='candidato'&&Number(req.user.id)===Number(r.candidato_id), isRec=['empresa','recrutador'].includes(req.user.tipo)&&Number(req.user.empresa_id)===Number(r.empresa_id), isAdmin=req.user.tipo==='admin';
  if((!isCand&&!isRec&&!isAdmin)||r.status!=='active'||new Date(r.expires_at)<=new Date()) return null;
  const participant_role=isCand?'candidate':'recruiter';
  // Never fall back to the general API secret: this key is shared only with preview signaling.
  const secret=process.env.VAGASIO_VIDEO_JWT_SECRET || process.env.VAGASIO_VIDEO_PREVIEW_JWT_SECRET;
  if(!secret) throw new Error('VAGASIO_VIDEO_JWT_SECRET missing');
  const now=Math.floor(Date.now()/1000), exp=Math.min(Math.floor(new Date(r.expires_at).getTime()/1000),now+300);
  const claims={iss:'vagasio-preview',aud:'vagasio-video',sub:String(req.user.id),user_id:String(req.user.id),room:String(r.room_id),candidature_id:String(r.candidatura_id),interview_id:String(r.entrevista_id),role:participant_role,jti:crypto.randomUUID(),iat:now};
  const token=jwt.sign(claims,secret,{algorithm:'HS256',expiresIn:Math.max(30,exp-now)});
  await pool.query(`INSERT INTO video_participant_tokens(room_id,token_hash,user_id,user_type,participant_role,expires_at) VALUES($1,$2,$3,$4,$5,to_timestamp($6))`,[r.room_id,hash(token),String(req.user.id),req.user.tipo,participant_role,exp]);
  return {token,expiresAt:new Date(exp*1000).toISOString(),roomId:r.room_id,role:participant_role,userId:String(req.user.id),signalUrl:signalUrl(),candidatureId:String(r.candidatura_id),interviewId:String(r.entrevista_id)};
}
module.exports={gate,role,allow,access,getOrCreate,issue,pool,signalUrl};
