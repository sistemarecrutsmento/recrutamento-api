# Banco de Dados — Vagas.io

Gerado na Fase 15. Documenta as principais entidades, relacionamentos e constraints.

---

## Visão Geral

PostgreSQL gerenciado pelo Render. Migrations aplicadas automaticamente no boot via `src/db.js → init()`.

---

## Entidades Principais

### `empresas`
Tenant central da plataforma (isolamento multi-tenant).

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `nome` | TEXT | Nome da empresa |
| `cnpj` | TEXT UNIQUE | CNPJ formatado |
| `slug` | TEXT UNIQUE | URL amigável (portal público) |
| `plano_id` | INT FK→planos | Plano contratado |
| `onboarding_step` | INT | Passo do onboarding (0–3) |
| `ativo` | BOOLEAN | Empresa ativa na plataforma |
| `criado_em` | TIMESTAMPTZ | Data de criação |

**Tenant ownership:** todas as tabelas operacionais têm `empresa_id FK → empresas.id`.

---

### `empresa_usuarios`
Usuários da empresa (admin, recrutador, viewer).

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `empresa_id` | INT FK→empresas | Tenant |
| `email` | TEXT UNIQUE | E-mail de login |
| `senha_hash` | TEXT | bcrypt |
| `role` | TEXT | `admin`, `recrutador`, `viewer` |
| `nome` | TEXT | Nome exibido |
| `ativo` | BOOLEAN | Usuário ativo |
| `totp_secret` | TEXT | Segredo 2FA (TOTP) — sensível |
| `totp_ativo` | BOOLEAN | 2FA ativo |

**Dado sensível:** `senha_hash`, `totp_secret` — nunca expor em responses.

---

### `admin_users`
Administradores globais da plataforma SaaS.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `email` | TEXT UNIQUE | E-mail de login |
| `senha_hash` | TEXT | bcrypt |
| `nome` | TEXT | Nome |
| `role` | TEXT | `admin` |
| `is_saas` | BOOLEAN | Admin global da plataforma |

---

### `candidatos`
Usuários candidatos.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `email` | TEXT UNIQUE | E-mail (login via OTP) |
| `nome` | TEXT | Nome completo |
| `cpf` | TEXT | CPF — sensível |
| `telefone` | TEXT | Telefone |
| `cidade`, `estado` | TEXT | Localização |
| `onboarding_step` | INT | Passo do onboarding (0–3) |
| `criado_em` | TIMESTAMPTZ | Data de criação |

**Dado sensível:** `cpf` — LGPD: dados pessoais sensíveis.

---

### `vagas`
Vagas de emprego publicadas pelas empresas.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `empresa_id` | INT FK→empresas | Tenant |
| `titulo` | TEXT | Título da vaga |
| `descricao` | TEXT | Descrição completa |
| `etapas` | JSONB | Array de `{nome: string}` — etapas do processo |
| `status` | TEXT | `rascunho`, `aberta`, `fechada`, `arquivada` |
| `cidade`, `estado` | TEXT | Localização |
| `area`, `tipo`, `nivel` | TEXT | Classificação |
| `salario_min/max` | NUMERIC | Faixa salarial |
| `publicado_em` | TIMESTAMPTZ | Data de publicação |
| `criado_em` | TIMESTAMPTZ | Data de criação |

---

### `candidaturas`
Vínculo candidato ↔ vaga, com estado do processo seletivo.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `candidato_id` | INT FK→candidatos | Candidato |
| `vaga_id` | INT FK→vagas | Vaga |
| `empresa_id` | INT FK→empresas | Tenant (desnormalizado para queries) |
| `status` | TEXT | `pendente`, `em_andamento`, `aprovado`, `rejeitado`, `contratado`, `desistiu` |
| `etapa_atual` | INT | Índice 0-based na array `vagas.etapas` |
| `historico` | JSONB | Array de eventos do processo |
| `observacoes_etapas` | JSONB | Comentários internos por etapa |
| `proposta_*` | vários | Campos da etapa de proposta |
| `criado_em` | TIMESTAMPTZ | Data de candidatura |

**Constraint:** UNIQUE(`candidato_id`, `vaga_id`) — um candidato não pode se candidatar duas vezes.

---

### `entrevistas`
Entrevistas agendadas para candidaturas.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `candidatura_id` | INT FK→candidaturas | Candidatura |
| `empresa_id` | INT FK→empresas | Tenant |
| `data_hora` | TIMESTAMPTZ | Data e hora |
| `tipo` | TEXT | `online`, `presencial`, `telefone` |
| `status` | TEXT | `agendada`, `realizada`, `cancelada`, `no_show` |
| `link_reuniao` | TEXT | Link Google Meet ou outro |
| `local` | TEXT | Local (presencial) |
| `duracao_minutos` | INT | Duração prevista |
| `observacoes` | TEXT | Notas internas |

---

### `notificacoes`
Feed de notificações para empresas e candidatos.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `user_type` | TEXT | `candidato`, `empresa` |
| `user_id` | INT | ID do destinatário |
| `empresa_id` | INT FK→empresas | Tenant |
| `tipo` | TEXT | Tipo de evento |
| `titulo`, `mensagem` | TEXT | Conteúdo |
| `lida` | BOOLEAN | Lida/não lida |
| `link` | TEXT | Deep link para a ação |
| `criado_em` | TIMESTAMPTZ | Data |

---

### `mensagens_processo` / chat
Mensagens do chat interno do processo seletivo.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `candidatura_id` | INT FK→candidaturas | Contexto |
| `empresa_id` | INT FK→empresas | Tenant |
| `remetente_tipo` | TEXT | `candidato`, `empresa` |
| `remetente_id` | INT | ID do remetente |
| `conteudo` | TEXT | Texto da mensagem |
| `tipo` | TEXT | `texto`, `arquivo` |
| `lida` | BOOLEAN | Lida pelo destinatário |
| `criado_em` | TIMESTAMPTZ | Data |

---

### `refresh_tokens`
Tokens de refresh para rotação segura de sessão.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `token_hash` | TEXT | Hash SHA-256 do token opaco |
| `user_type` | TEXT | `candidato`, `empresa`, `admin` |
| `user_id` | INT | ID do usuário |
| `expires_at` | TIMESTAMPTZ | Expiração (7 dias) |
| `revogado` | BOOLEAN | Revogado/inválido |
| `ip` | TEXT | IP de criação |

**Segurança:** o token bruto nunca é armazenado, apenas o hash.  
**Rotação:** uso de um refresh token o revoga e emite um novo.

---

### `audit_logs`
Log imutável de eventos de segurança e operacionais.

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `evento` | TEXT | Tipo de evento (ex: `login.2fa_verified`) |
| `user_type` | TEXT | Tipo de ator |
| `user_id` | INT | ID do ator |
| `empresa_id` | INT | Tenant (quando aplicável) |
| `ip` | TEXT | IP da requisição |
| `user_agent` | TEXT | User-Agent |
| `result` | TEXT | `success`, `blocked`, `error` |
| `resource_type`, `resource_id` | TEXT/INT | Recurso afetado |
| `metadata` | JSONB | Contexto adicional (< 2048 bytes) |
| `criado_em` | TIMESTAMPTZ | Data (imutável) |

**Imutabilidade:** sem UPDATE ou DELETE — HTTP 405 nas rotas de auditoria.

---

### `analytics_eventos`
Eventos de analytics do produto (Fase 14).

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `evento` | TEXT | Tipo (whitelist de 21 eventos) |
| `user_type` | TEXT | `candidato`, `empresa`, `anonimo` |
| `user_id` | INT | ID do usuário autenticado |
| `empresa_id` | INT FK→empresas | Tenant |
| `vaga_id` | INT FK→vagas | Vaga relacionada |
| `candidatura_id` | INT FK→candidaturas | Candidatura relacionada |
| `sessao_id` | TEXT | ID de sessão (UUID) |
| `anonimo_id` | TEXT | ID anônimo (fingerprint) |
| `metadata` | JSONB | Contexto (< 2048 bytes) |
| `criado_em` | TIMESTAMPTZ | Data |

---

### `email_outbox` / `email_preferencias`
Controle de envio de e-mails e preferências do usuário.

**`email_preferencias`:**
- `user_type`, `user_id`: usuário
- `digest_ativo`: recebe digest diário
- `notif_*`: preferências por tipo de notificação

---

### `vaga_tags`
Tags livres associadas a vagas.

| Campo | Tipo | Descrição |
|---|---|---|
| `vaga_id` | INT FK→vagas | Vaga |
| `empresa_id` | INT FK→empresas | Tenant |
| `tag` | TEXT | Tag (lowercase, normalizada) |

**PK composta:** (`vaga_id`, `tag`)

---

### `candidato_favoritos`
Vagas salvas como favorito pelo candidato.

| Campo | Tipo | Descrição |
|---|---|---|
| `candidato_id` | INT FK→candidatos | Candidato |
| `vaga_id` | INT FK→vagas | Vaga |
| `criado_em` | TIMESTAMPTZ | Data |

**PK composta:** (`candidato_id`, `vaga_id`)

---

### `planos`
Planos comerciais da plataforma (Fase 9).

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | SERIAL PK | Identificador |
| `nome` | TEXT | Ex: `gratuito`, `essencial` |
| `preco_mensal` | NUMERIC | Preço em R$ |
| `max_vagas` | INT | Limite de vagas |
| `max_usuarios` | INT | Limite de usuários |

---

## Diagrama de Relacionamentos (simplificado)

```
empresas ──┬── empresa_usuarios
           ├── vagas ─── vaga_tags
           ├── candidaturas ─── entrevistas
           │                ─── mensagens_processo
           │                ─── notificacoes (empresa)
           └── analytics_eventos

candidatos ─── candidaturas
           ─── candidato_favoritos
           ─── notificacoes (candidato)

admin_users ─── audit_logs
            ─── refresh_tokens (admin)

planos ──── empresas
```

---

## Notas de Segurança / LGPD

| Dado | Classificação | Proteção |
|---|---|---|
| `senha_hash` | Sensível | bcrypt, nunca exposto |
| `totp_secret` | Sensível | Colunas não retornadas em SELECT padrão |
| `cpf` | Pessoal sensível (LGPD) | Nunca indexado em texto plano |
| `token_hash` | Segurança | Apenas hash SHA-256 armazenado |
| `audit_logs` | Imutável | Sem DELETE/UPDATE permitidos via API |
| `metadata` em analytics | Limitado | Máx 2048 bytes |
