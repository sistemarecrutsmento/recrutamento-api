# Login social do candidato — configuração externa

A ativação atual está focada no Google. O Apple permanece preparado no backend para uma etapa futura, mas não aparece no Portal do Candidato.

O fluxo já está implementado com OAuth/OIDC, PKCE, `state` de uso único, validação de `nonce`, validação de identidade e troca por sessão JWT/refresh existente.

## Google

Cadastrar um cliente OAuth Web no Google Cloud Console com:

- Origem autorizada: `https://vagasio.com.br`
- Redirect URI: `https://recrutamento-api-novo.onrender.com/api/auth/social/google/callback`

Variáveis no Render:

- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`
- opcional: `GOOGLE_OAUTH_REDIRECT_URI` se a URL padrão for diferente

## Apple

Criar um Service ID no Apple Developer, habilitar Sign in with Apple e cadastrar:

- Return URL: `https://recrutamento-api-novo.onrender.com/api/auth/social/apple/callback`
- Domínio associado: `vagasio.com.br`

Variáveis no Render:

- `APPLE_CLIENT_ID` — Service ID
- `APPLE_TEAM_ID`
- `APPLE_KEY_ID`
- `APPLE_PRIVATE_KEY` — conteúdo completo da chave `.p8`; pode usar `\\n` para quebras de linha
- opcional: `APPLE_OAUTH_REDIRECT_URI`

Comuns:

- `CANDIDATE_FRONTEND_URL=https://vagasio.com.br/candidato/`
- `API_PUBLIC_URL=https://recrutamento-api-novo.onrender.com`

Sem essas variáveis, os botões permanecem visíveis, mas respondem com feedback claro de que o provedor ainda não foi configurado; nenhuma credencial falsa ou fluxo paralelo é criado.
