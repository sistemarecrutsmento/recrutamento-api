const MIME_ALIASES = Object.freeze({
  'image/jpg': 'image/jpeg'
});

function normalizeMime(mime) {
  return MIME_ALIASES[mime] || mime;
}

function decodeBase64(value) {
  if (typeof value !== 'string' || !value.trim()) {
    return { ok: false, erro: 'Conteúdo vazio' };
  }
  const raw = value.replace(/^data:[^;,]+;base64,/, '').replace(/\s/g, '');
  if (!raw || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 === 1) {
    return { ok: false, erro: 'Base64 inválido' };
  }
  const buffer = Buffer.from(raw, 'base64');
  if (!buffer.length) return { ok: false, erro: 'Arquivo vazio' };
  return { ok: true, buffer };
}

function startsWithBytes(buffer, bytes) {
  if (buffer.length < bytes.length) return false;
  return bytes.every((value, index) => buffer[index] === value);
}

function isZip(buffer) {
  return startsWithBytes(buffer, [0x50, 0x4b, 0x03, 0x04])
    || startsWithBytes(buffer, [0x50, 0x4b, 0x05, 0x06])
    || startsWithBytes(buffer, [0x50, 0x4b, 0x07, 0x08]);
}

function isOle(buffer) {
  return startsWithBytes(buffer, [
    0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
  ]);
}

function isText(buffer) {
  if (buffer.includes(0)) return false;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(text);
  } catch (_) {
    return false;
  }
}

function matchesMime(buffer, mime) {
  switch (normalizeMime(mime)) {
    case 'application/pdf':
      return startsWithBytes(buffer, [0x25, 0x50, 0x44, 0x46, 0x2d]); // %PDF-
    case 'image/png':
      return startsWithBytes(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case 'image/jpeg':
      return startsWithBytes(buffer, [0xff, 0xd8, 0xff]);
    case 'image/gif':
      return buffer.length >= 6 && (buffer.subarray(0, 6).toString() === 'GIF87a' || buffer.subarray(0, 6).toString() === 'GIF89a');
    case 'image/webp':
      return buffer.length >= 12 && buffer.subarray(0, 4).toString() === 'RIFF' && buffer.subarray(8, 12).toString() === 'WEBP';
    case 'application/msword':
    case 'application/vnd.ms-excel':
      return isOle(buffer);
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
      return isZip(buffer);
    case 'text/plain':
    case 'text/csv':
      return isText(buffer);
    default:
      return false;
  }
}

const EXTENSIONS_BY_MIME = Object.freeze({
  'application/pdf': ['.pdf'],
  'image/jpeg': ['.jpg', '.jpeg'],
  'image/png': ['.png'],
  'image/gif': ['.gif'],
  'image/webp': ['.webp'],
  'application/msword': ['.doc'],
  'application/vnd.ms-excel': ['.xls'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
  'text/plain': ['.txt', '.text'],
  'text/csv': ['.csv']
});

function extensionMatchesMime(filename, mime) {
  if (filename === undefined || filename === null || filename === '') return true;
  if (typeof filename !== 'string') return false;
  const normalizedName = filename.trim().toLowerCase();
  const lastDot = normalizedName.lastIndexOf('.');
  if (lastDot <= 0 || lastDot === normalizedName.length - 1) return false;
  const extension = normalizedName.slice(lastDot);
  const allowed = EXTENSIONS_BY_MIME[normalizeMime(mime)] || [];
  return allowed.includes(extension);
}

function validateBase64File(value, mime, maxBytes, filename) {
  const normalizedMime = normalizeMime(mime);
  const decoded = decodeBase64(value);
  if (!decoded.ok) return decoded;
  if (decoded.buffer.length > maxBytes) {
    return { ok: false, erro: `Arquivo maior que o limite de ${Math.floor(maxBytes / (1024 * 1024))} MB` };
  }
  if (!matchesMime(decoded.buffer, normalizedMime)) {
    return { ok: false, erro: 'Conteúdo incompatível com o tipo de arquivo informado' };
  }
  if (!extensionMatchesMime(filename, normalizedMime)) {
    return { ok: false, erro: 'Extensão incompatível com o tipo de arquivo informado' };
  }
  return { ok: true, buffer: decoded.buffer, mime: normalizedMime };
}

module.exports = { decodeBase64, validateBase64File, matchesMime, normalizeMime, extensionMatchesMime };
