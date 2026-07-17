# Recrutamento e Seleção — Backend

API em Node.js + Express + PostgreSQL.

## Variáveis de ambiente (.env)

- `PORT` — porta (Render define automático)
- `DATABASE_URL` — string de conexão do Postgres (Render fornece)
- `JWT_SECRET` — chave aleatória longa
- `EMAIL_FROM` — e-mail remetente
- `EMAIL_APP_PASSWORD` — senha de app do Gmail
- `SISTEMA_NOME` — nome exibido nos e-mails
- `CORS_ORIGIN` — origens permitidas (separadas por vírgula)
- `ADMIN_SENHA` — senha inicial do admin (criado no primeiro start)

## Endpoints principais

### Candidato
- `POST /api/candidato/iniciar` — { email } → envia código
- `POST /api/candidato/verificar` — { email, codigo } → devolve token
- `POST /api/candidato/cadastrar` — salva perfil completo
- `GET /api/candidato/perfil` — pega perfil
- `GET /api/candidato/candidaturas` — lista candidaturas
- `POST /api/candidato/candidatar/:vagaId` — se candidata

### Vagas (público)
- `GET /api/vagas` — lista (filtros: cidade, area, tipo, nivel, busca)
- `GET /api/vagas/:id` — detalhe

### Admin/Recrutador
- `POST /api/admin/login` — { email, senha }
- `GET /api/admin/dashboard` — KPIs + processos + ranking
- `POST /api/admin/vagas` — cria vaga
- `GET /api/admin/vagas` — lista vagas
- `GET /api/admin/candidatos` — lista candidatos
- `GET /api/admin/candidaturas` — lista candidaturas
- `GET /api/admin/candidatura/:id` — detalhe
- `POST /api/admin/candidatura/:id/status` — atualiza status
- `POST /api/admin/recrutadores` — cria recrutador
- `GET /api/admin/recrutadores` — lista recrutadores

### Util
- `GET /api/saude` — health check
- `GET /api/cep/:cep` — busca CEP (ViaCEP)
 
---
Updated: Fri Jul 17 03:37:39 UTC 2026
