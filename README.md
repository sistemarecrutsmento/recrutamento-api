# VagasIO — Backend API

Sistema de recrutamento B2B SaaS multi-tenant. Conecta empresas a candidatos com fluxo completo de seleção.

## Stack

- **Runtime:** Node.js 18.20.4
- **Framework:** Express 4.x
- **Banco:** PostgreSQL (Render Managed)
- **Auth:** JWT + Refresh Tokens + 2FA (admin) + OTP e-mail (candidato) + TOTP (empresa)
- **E-mail:** Resend API
- **Upload:** Cloudinary
- **Video/Meet:** Google Calendar API

## Arquitetura

```
/api/candidato/*    candidato autenticado
/api/empresa/*      empresa (admin, recrutador, viewer)
/api/saas/*         SaaS admin global
/api/admin/*        admin legado + operações gerais
/api/public/*       portal público (sem auth)
/api/analytics/*    eventos analytics
/api/notificacoes/* notificações in-app
/api/auth/*         login empresa + refresh tokens
/api/saude          health check + DB status
/api/ci/*           CI bypass (apenas NODE_ENV != production)
```

## Fases implementadas

| Fase | Descrição |
|------|-----------|
| 1 | Multi-tenant, isolamento por empresa |
| 2 | RBAC (admin_empresa, recrutador, viewer) |
| 3 | Vagas + candidaturas básicas |
| 4 | RBAC refinado + testes E2E |
| 5 | Portal público (slug, vagas públicas) |
| 6 | Fluxo de candidatura com timeline |
| 7 | Notificações in-app |
| 8 | Multi-tenant completo |
| 9 | Planos + onboarding |
| 10 | Auth avançado (refresh, sessões, 2FA) |
| 11 | Busca + tags + favoritos + match |
| 12 | Chat em processo |
| 13 | E-mail transacional (Resend) |
| 14 | Analytics + auditoria + PWA |
| 15 | CI/CD + documentação + qualidade |

## Instalação local

```bash
git clone https://github.com/sistemarecrutsmento/recrutamento-api
cd recrutamento-api
npm ci
cp .env.example .env
# Preencher .env com valores reais
npm start
```

## Variáveis de ambiente

Ver `.env.example` para lista completa.

Obrigatórias:
- `DATABASE_URL` — PostgreSQL connection string
- `JWT_SECRET` — chave aleatória 64+ chars
- `RESEND_API_KEY` — envio de e-mails
- `NODE_ENV` — `development` ou `production`

## Testes

```bash
# A partir do workspace raiz (não do repo)
python3 _scripts/test_fase8.py
python3 _scripts/test_fase9.py
python3 _scripts/test_fase10.py
python3 _scripts/test_fase11.py
python3 _scripts/test_fase13.py
python3 _scripts/test_fase14.py
python3 _scripts/test_migrations.py
bash   _scripts/test_fase15.sh

# Detector de rotas duplicadas
python3 _scripts/check_routes.py
```

Para testes com admin token sem 2FA (CI):
```bash
export CI_ADMIN_SECRET=<segredo>
python3 _scripts/test_fase14.py
```

## Deploy

Ver `docs/deploy.md`.

## Documentação

| Arquivo | Descrição |
|---------|-----------|
| `docs/api.md` | Referência de endpoints (202 rotas) |
| `docs/rbac.md` | Matriz de permissões por papel |
| `docs/deploy.md` | Guia de deploy (Render + GitHub Pages) |
| `docs/database.md` | Entidades e relacionamentos |

## CI/CD

GitHub Actions em `.github/workflows/ci.yml`.

Jobs:
- `syntax` — sintaxe JS + rotas duplicadas + npm audit
- `tests` — E2E Fases 8-15 (usa `CI_ADMIN_SECRET` para eliminar skips de 2FA)
- `smoke` — health check de produção (apenas push em `main`)

Secret necessário no GitHub: `CI_ADMIN_SECRET`

## Estrutura

```
src/
  server.js           app principal (202 rotas)
  auth.js             middlewares de autenticação
  token.js            JWT + refresh tokens
  db.js               pool PostgreSQL + 11 migrations
  audit.js            logs imutáveis
  twoFactor.js        2FA por e-mail
  totp.js             TOTP (app autenticador)
  analyticsService.js eventos analytics
  email.js            e-mail SMTP
  email/
    emailService.js   Resend + templates
    templates.js      HTML templates
  migrations/
    001 a 011         migrations idempotentes
```
