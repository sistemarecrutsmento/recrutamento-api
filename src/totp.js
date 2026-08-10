/**
 * TOTP (Time-based One-Time Password) — RFC 6238
 * Implementação pura com Node.js crypto (sem dependências externas).
 *
 * Usado para 2FA de empresa. Compatível com Google Authenticator, Authy, etc.
 */
const crypto = require('crypto');

// ─── Base32 decode manual (Node.js não tem Buffer.from(..., 'base32')) ─────

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  // Normaliza: maiúsculo, remove padding
  const str = input.toUpperCase().replace(/=+$/, '');
  let bits = 0, value = 0;
  const output = [];
  for (const char of str) {
    const idx = B32_ALPHABET.indexOf(char);
    if (idx === -1) continue; // ignora chars inválidos
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(output);
}

// ─── HOTP Base (RFC 4226) ─────────────────────────────────────────────────

function hotp(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) <<  8) |
     (hmac[offset + 3] & 0xff)
  ) % 1_000_000;
  return String(code).padStart(6, '0');
}

// ─── TOTP (RFC 6238) ──────────────────────────────────────────────────────

const TOTP_STEP = 30; // segundos por janela
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // janelas antes/depois aceitas (tolerância de clock)

/**
 * Gera um código TOTP para o instante atual.
 */
function totpGenerate(secret) {
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP);
  return hotp(secret, counter);
}

/**
 * Verifica um código TOTP com janela de tolerância.
 * @returns {boolean}
 */
function totpVerify(secret, token) {
  if (!token || typeof token !== 'string' || !/^\d{6}$/.test(token)) return false;
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP);
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    if (hotp(secret, counter + delta) === token) return true;
  }
  return false;
}

// ─── Gerador de segredo base32 ────────────────────────────────────────────

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function generateTotpSecret(length = 20) {
  // 20 bytes → 160 bits → 32 chars base32
  const bytes = crypto.randomBytes(length);
  let result = '';
  let bits = 0, acc = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_CHARS[(acc >> bits) & 0x1f];
    }
  }
  if (bits > 0) result += BASE32_CHARS[(acc << (5 - bits)) & 0x1f];
  return result;
}

/**
 * Gera a URL para QR Code (otpauth://).
 * @param {string} secret - segredo base32
 * @param {string} email  - email do usuário
 * @param {string} issuer - nome da plataforma
 */
function totpOtpauthUrl(secret, email, issuer = 'VagasIO') {
  const enc = encodeURIComponent;
  return `otpauth://totp/${enc(issuer)}:${enc(email)}?secret=${secret}&issuer=${enc(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP}`;
}

// ─── Códigos de backup (uso único) ───────────────────────────────────────

const BACKUP_CODE_COUNT = 8;

/**
 * Gera códigos de backup. Retorna { plainCodes, hashedCodes }.
 * plainCodes são exibidos ao usuário UMA VEZ; hashedCodes ficam no DB.
 */
async function generateBackupCodes() {
  const bcrypt = require('bcryptjs');
  const plainCodes = Array.from({ length: BACKUP_CODE_COUNT }, () =>
    crypto.randomBytes(5).toString('hex').toUpperCase().replace(/(.{4})/g, '$1-').slice(0, 9)
  );
  const hashedCodes = await Promise.all(plainCodes.map(c => bcrypt.hash(c, 10)));
  return { plainCodes, hashedCodes };
}

/**
 * Verifica e consome um código de backup (remove o código usado).
 * @param {string[]} hashedCodes - array de hashes armazenado no DB
 * @param {string}   input       - código informado pelo usuário
 * @returns {Promise<{valido: boolean, updatedCodes: string[]}>}
 */
async function verifyBackupCode(hashedCodes, input) {
  const bcrypt = require('bcryptjs');
  const clean = (input || '').toUpperCase().replace(/[^A-F0-9]/g, '');
  if (!clean || clean.length < 8) return { valido: false, updatedCodes: hashedCodes };
  for (let i = 0; i < hashedCodes.length; i++) {
    const match = await bcrypt.compare(input.toUpperCase(), hashedCodes[i]);
    if (match) {
      const updatedCodes = hashedCodes.filter((_, idx) => idx !== i);
      return { valido: true, updatedCodes };
    }
  }
  return { valido: false, updatedCodes: hashedCodes };
}

module.exports = {
  totpGenerate,
  totpVerify,
  generateTotpSecret,
  totpOtpauthUrl,
  generateBackupCodes,
  verifyBackupCode,
};
