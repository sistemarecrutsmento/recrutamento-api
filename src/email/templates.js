// =============================================================================
// templates.js — Template HTML base responsivo para todos os e-mails Vagas.io
// =============================================================================
// Sem JS no e-mail. Layout table-based para máxima compatibilidade.
// =============================================================================

const BASE_URL = process.env.FRONTEND_URL || 'https://sistemarecrutsmento.github.io/vagas';

const VINHO   = '#7B1F1F';
const DOURADO = '#C8973A';

/** Escapa HTML para uso seguro em templates */
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * wrap({ titulo, conteudo, cta_link, cta_texto, rodape }) → string HTML
 * Layout responsivo, compatível com Gmail/Outlook/mobile.
 */
function wrap({ titulo, conteudo, cta_link, cta_texto, rodape }) {
  const ano = new Date().getFullYear();

  const ctaBloco = cta_link && cta_texto
    ? `<div style="text-align:center;margin:28px 0 16px">
         <a href="${cta_link}"
            style="display:inline-block;background:${VINHO};color:#ffffff;
                   padding:14px 32px;border-radius:6px;text-decoration:none;
                   font-weight:700;font-size:15px;font-family:'Inter',Arial,sans-serif;
                   letter-spacing:0.3px;">
           ${cta_texto}
         </a>
       </div>`
    : '';

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
  <title>${esc(titulo)}</title>
</head>
<body style="margin:0;padding:0;background:#F0F0F0;font-family:'Inter',Arial,Helvetica,sans-serif;">

<!-- Wrapper -->
<table width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background:#F0F0F0;padding:24px 0;">
  <tr>
    <td align="center">

      <!-- Card -->
      <table width="600" cellpadding="0" cellspacing="0" border="0"
             style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:${VINHO};border-radius:10px 10px 0 0;
                     padding:24px 32px;text-align:center;">
            <div style="font-size:13px;color:rgba(255,255,255,0.7);
                        letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;">
              Vagas.io
            </div>
            <div style="font-size:22px;font-weight:800;color:#ffffff;line-height:1.3;">
              ${esc(titulo)}
            </div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="background:#ffffff;padding:32px 32px 24px;
                     border-left:1px solid #E5E5E5;border-right:1px solid #E5E5E5;">
            ${conteudo}
            ${ctaBloco}
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#F7F7F7;border-radius:0 0 10px 10px;
                     border:1px solid #E5E5E5;border-top:0;
                     padding:16px 32px;text-align:center;">
            <div style="font-size:12px;color:#999;line-height:1.6;">
              ${rodape
                ? `<span style="color:#666;">${rodape}</span><br/>`
                : ''}
              Se precisar de ajuda, responda este e-mail.<br/>
              <a href="${BASE_URL}" style="color:${VINHO};text-decoration:none;">
                vagasio.com.br
              </a>
              &nbsp;·&nbsp;
              <a href="${BASE_URL}/candidato/email-preferencias.html"
                 style="color:#999;text-decoration:none;">
                Preferências de e-mail
              </a>
            </div>
            <div style="margin-top:12px;font-size:11px;color:#bbb;">
              © ${ano} Vagas.io — Todos os direitos reservados.
            </div>
          </td>
        </tr>

      </table>
      <!-- /Card -->

    </td>
  </tr>
</table>
</body>
</html>`;
}

/** Parágrafo padrão */
function p(html) {
  return `<p style="margin:0 0 14px;font-size:15px;color:#1A1A1A;line-height:1.6;">${html}</p>`;
}

/** Box de destaque (fundo cinza claro) */
function box(html) {
  return `<div style="background:#F5F5F5;border-radius:8px;padding:16px 20px;
           margin:16px 0;font-size:14px;color:#1A1A1A;line-height:1.7;">
           ${html}
         </div>`;
}

/** Badge colorido */
function badge(texto, cor) {
  return `<span style="display:inline-block;background:${cor || VINHO};color:#fff;
           border-radius:4px;padding:3px 10px;font-size:12px;font-weight:700;">
           ${esc(texto)}</span>`;
}

/** Bloco de aviso (amarelo) */
function aviso(html) {
  return `<div style="background:#FFF8E1;border-left:4px solid ${DOURADO};
           padding:12px 16px;border-radius:6px;margin:16px 0;
           font-size:13px;color:#5D4037;line-height:1.5;">${html}</div>`;
}

module.exports = { wrap, esc, p, box, badge, aviso, BASE_URL, VINHO, DOURADO };
