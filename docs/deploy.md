# Deploy — Vagas.io

Gerado na Fase 15. Documenta o fluxo atual de deploy backend (Render) e frontend (GitHub Pages).

---

## Stack

| Componente | Tecnologia | Hospedagem |
|---|---|---|
| Backend (API) | Node.js 18.20.4 + Express | Render (Web Service) |
| Banco de Dados | PostgreSQL (Render Managed) | Render |
| Frontend Candidato | HTML/JS/CSS | GitHub Pages |
| Frontend Empresa | HTML/JS/CSS | GitHub Pages |
| Frontend SaaS Admin | HTML/JS/CSS | GitHub Pages |

---

## Backend — Render

### Serviço

- **Nome:** `recrutamento-api-novo`
- **ID:** `srv-d9iilsv41pts73bb08d0`
- **URL:** `https://recrutamento-api-novo.onrender.com`
- **Tipo:** Web Service
- **Plano:** Free (spin-down após inatividade)
- **Repositório:** `https://github.com/sistemarecrutsmento/recrutamento-api`
- **Branch:** `main`
- **Auto-deploy:** sim (a cada push na main)

### Build & Start

```
Build Command:  npm install --no-audit --no-fund
Start Command:  node src/server.js
Node Version:   18.20.4 (via .nvmrc e package.json engines)
Root Dir:       / (raiz do repositório)
```

### Migrations

As migrations são executadas automaticamente no boot do servidor (`db.js → init()`).  
São idempotentes — cada migration usa `IF NOT EXISTS` e `ensureColumn`.

```
001_multi_tenant_fase1.js
002_normalizar_rbac.js
003_portal_publico_fase5.js
004_candidatura_historico_fase6.js
005_notificacoes_fase7.js
006_planos_onboarding_fase9.js
007_auth_fase10.js
008_busca_tags_favoritos_fase11.js
009_chat_fase12.js
010_email_fase13.js
011_analytics_pwa_fase14.js
```

Cada migration está protegida por `try/catch` individual — uma falha não derruba as outras.

### Health Check

```
GET /api/saude
→ 200 { "ok": true, "sistema": "...", "hora": "...", "db": "ok" }
→ 503 { "ok": false, ..., "db": "unavailable" }
```

### Variáveis de Ambiente

Ver `.env.example` na raiz do repositório.  
Variáveis obrigatórias para produção:

| Variável | Obrigatória | Descrição |
|---|:---:|---|
| `DATABASE_URL` | ✓ | Connection string PostgreSQL |
| `JWT_SECRET` | ✓ | Chave de assinatura JWT (>= 32 chars aleatórios) |
| `NODE_ENV` | ✓ | `production` em produção |
| `PORT` | ✓ | Porta HTTP (Render injeta automaticamente) |
| `RESEND_API_KEY` | ✓ | API key do Resend.com para envio de e-mails |
| `EMAIL_REMETENTE` | ✓ | Nome + e-mail do remetente (`Nome <email@dominio.com>`) |
| `SISTEMA_NOME` | ✓ | Nome exibido nos e-mails e health check |
| `CORS_ORIGIN` | ✓ | Origens permitidas (ex: `https://sistemarecrutsmento.github.io`) |
| `ADMIN_SENHA` | ✓ | Senha inicial do admin SaaS (usada apenas na criação) |
| `CLOUDINARY_URL` | — | Upload de fotos/documentos |
| `GCP_SERVICE_ACCOUNT_JSON` | — | Google Meet integration |
| `MEET_ADMIN_EMAIL` | — | E-mail admin para criar eventos Google Meet |
| `CRON_SECRET` | — | Secret para endpoint `/api/cron/digest` |
| `CI_ADMIN_SECRET` | ⚠️ | **Apenas CI/teste** — nunca em produção |
| `DEBUG_API` | ⚠️ | `1` ativa rotas `/_debug/*` — nunca em produção |

> ⚠️ `CI_ADMIN_SECRET` é bloqueado em `NODE_ENV=production` no código.

---

## Deploy Manual (scripts locais)

Os scripts abaixo são usados pelo Zapia para deploy programático. **Não rodam em CI.**

### Backend

```bash
# Empurrar arquivo(s) para o repositório backend + trigger Render
python3 _scripts/git_push_api.py "mensagem do commit" recrutamento-api/src/server.js
python3 _scripts/git_push_api.py "mensagem" --yes arquivo1.js arquivo2.js
```

O script:
1. Lê o arquivo local
2. Compara com o que está no GitHub (pula se idêntico)
3. Faz PUT via GitHub API
4. Render detecta o push e inicia novo deploy automaticamente

### Frontend

```bash
# Empurrar arquivo(s) para o repositório frontend (GitHub Pages)
python3 _scripts/git_push.py "mensagem do commit" vagas/candidato/index.html
python3 _scripts/git_push.py "mensagem" --yes vagas/empresa/dashboard.html
```

> **Atenção:** `git_push.py` aponta para `sistemarecrutsmento/vagas`.  
> `git_push_api.py` aponta para `sistemarecrutsmento/recrutamento-api`.  
> Não trocar — eles têm o repo hard-coded.

---

## Frontend — GitHub Pages

### Repositório

- **Repo:** `https://github.com/sistemarecrutsmento/vagas`
- **URL Base:** `https://sistemarecrutsmento.github.io/vagas`
- **Branch:** `main`

### Estrutura de Diretórios

```
vagas/
├── candidato/           → Portal do candidato (PWA)
│   ├── index.html
│   ├── manifest.json
│   ├── sw.js
│   └── ...
├── empresa/             → Portal da empresa
│   ├── index.html
│   ├── dashboard.html
│   └── ...
├── saas/                → Admin SaaS global
│   └── index.html
└── (raiz)               → Redirecionamentos legados
```

### Observações

- GitHub Pages pode demorar 1–2 min para propagar após push.
- Para forçar reload do cache, bumpar o parâmetro `?v=N` nos imports de JS/CSS.
- O service worker do candidato (`sw.js`) tem cache próprio — ao atualizar, bumpar `CACHE_VERSION`.

---

## Cron Job — Digest Diário

O digest de e-mails é disparado via Zapia Cron:

- **Schedule:** `0 10 * * *` (10:00 BRT, todo dia)
- **Endpoint:** `POST /api/cron/digest`
- **Autenticação:** `Authorization: Bearer <CRON_SECRET>`

---

## CI/CD — GitHub Actions

O workflow `.github/workflows/ci.yml` no repositório `recrutamento-api` executa:

1. Checkout
2. Node 18.20.4
3. `npm ci`
4. Sintaxe check (`node --check`)
5. Testes de regressão (Fases 4–14)
6. Migration test (banco limpo → migrations → idempotência)
7. Route audit

Secrets necessários no repositório GitHub:

| Secret | Uso |
|---|---|
| `API_URL` | URL da API de teste (ex: `https://recrutamento-api-novo.onrender.com`) |
| `CI_ADMIN_SECRET` | Para obter admin token sem 2FA nos testes |

---

## Smoke Test Pós-Deploy

```bash
# Health check
curl https://recrutamento-api-novo.onrender.com/api/saude

# Portal público
curl https://sistemarecrutsmento.github.io/vagas/candidato/

# Vagas públicas
curl https://recrutamento-api-novo.onrender.com/api/vagas
```
