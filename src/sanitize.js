// Helpers de sanitização — defesa em profundidade contra XSS armazenado.
// O front já escapa via escapeHtml(), mas o backend também sanitiza antes de gravar
// para que QUALQUER consumidor (admin, app mobile, futuro frontend) receba texto seguro.

/**
 * Sanitiza texto de usuário para armazenamento.
 * Remove tags HTML/scripts completos e event handlers, mantendo texto legível.
 * Não é uma sanitização HTML completa (use DOMPurify no front para isso),
 * mas elimina os vetores XSS mais comuns.
 */
function sanitizeText(text) {
  if (typeof text !== 'string') return text;
  // Remove tags HTML completas (incluindo <script>, <img>, etc.)
  let s = text.replace(/<\/?[a-z][\s\S]*?(?=>|$)/gi, '');
  // Remove event handlers tipo onclick=, onerror=, onload= (por redundância)
  s = s.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  // Remove javascript: em URLs (defesa contra protocolos perigosos)
  s = s.replace(/javascript\s*:/gi, '');
  // Remove data: URIs perigosos (mantém imagens seguras se houver)
  // Permitir só data:image/(png|jpg|jpeg|gif|webp)
  s = s.replace(/data\s*:\s*(?!image\/(png|jpg|jpeg|gif|webp);)[^"'\s)]+/gi, '');
  return s;
}

/**
 * Sanitiza nome de arquivo enviado em upload.
 * Remove path traversal (../, ..\), caracteres nulos, e limita a ASCII seguro.
 */
function sanitizeFilename(name) {
  if (typeof name !== 'string') return 'arquivo';
  // Pega só o nome base (sem path)
  let s = name.replace(/^.*[\\\/]/, '');
  // Remove caracteres nulos
  s = s.replace(/\x00/g, '');
  // Remove CRLF (impede header injection)
  s = s.replace(/[\r\n]/g, '');
  // Remove aspas (impede header injection em Content-Disposition)
  s = s.replace(/["'`]/g, '');
  // Limita tamanho
  if (s.length > 200) s = s.slice(-200);
  // Se ficou vazio
  if (!s || !s.trim()) return 'arquivo';
  return s;
}

/**
 * Escapa para uso seguro em Content-Disposition: filename="...".
 * RFC 6266: usa filename* com encoding pra Unicode, ou escapa aspas pra ASCII.
 */
function escapeContentDispositionFilename(name) {
  if (typeof name !== 'string') return 'arquivo';
  // Se tem só ASCII printable (sem aspas, sem CR/LF), pode usar filename direto
  if (/^[\x20-\x7E]*$/.test(name) && !name.includes('"')) {
    return name;
  }
  // Caso contrário, força ASCII fallback
  const asciiSafe = name
    .replace(/[^\x20-\x7E]/g, '_')
    .replace(/["\\]/g, '_');
  return asciiSafe || 'arquivo';
}

module.exports = {
  sanitizeText,
  sanitizeFilename,
  escapeContentDispositionFilename
};