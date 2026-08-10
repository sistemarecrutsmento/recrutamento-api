# RBAC — Controle de Acesso por Papel

Gerado automaticamente na Fase 15. Reflete o comportamento real do código (`auth.js`, `server.js`).

---

## Papéis

| Papel | Código (`tipo`) | Descrição |
|---|---|---|
| **SaaS Admin** | `admin` + `is_saas=true` | Administrador global da plataforma VagasIO |
| **Admin Empresa** | `empresa` + `role='admin'` | Dono ou admin da empresa cliente |
| **Recrutador** | `empresa` + `role='recrutador'` | Recrutador da empresa cliente |
| **Viewer** | `empresa` + `role='viewer'` | Acesso leitura às áreas da empresa |
| **Candidato** | `candidato` | Usuário candidato |
| **Público** | *(sem token)* | Acesso não autenticado |

---

## Middlewares de Autenticação

| Middleware | Permite |
|---|---|
| `authAdmin` | `tipo = 'admin'` ou `tipo = 'recrutador'` |
| `authAdminOnly` | `tipo = 'admin'` apenas |
| `authEmpresa` | `tipo = 'empresa'` |
| `authCandidato` | `tipo = 'candidato'` |
| `requireAdminEmpresa` | `tipo = 'empresa'` + `role = 'admin'` |
| `requireRecrutadorOuAdmin` | `tipo = 'empresa'` + `role IN ('admin','recrutador')` |
| `requireEmpresaViewer` | `tipo = 'empresa'` (qualquer role) |
| `authCandidatoOrEmpresaOrAdmin` | candidato, empresa, admin ou recrutador |

---

## Matriz de Permissões

### Vagas

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Listar vagas públicas | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Ver detalhe vaga pública | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Listar vagas da empresa | ✓ | ✓ | ✓ | ✓ | — | — |
| Criar vaga | ✓ | ✓ | ✓ | — | — | — |
| Editar vaga | ✓ | ✓ | ✓ | — | — | — |
| Publicar/fechar vaga | ✓ | ✓ | ✓ | — | — | — |
| Deletar vaga | ✓ | ✓ | — | — | — | — |
| Tags de vaga | ✓ | ✓ | ✓ | ✓ | — | ✓ (leitura) |

### Candidaturas

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Candidatar-se | — | — | — | — | ✓ | — |
| Ver próprias candidaturas | — | — | — | — | ✓ | — |
| Listar candidaturas da empresa | ✓ | ✓ | ✓ | ✓ | — | — |
| Avançar/reprovar candidatura | ✓ | ✓ | ✓ | — | — | — |
| Histórico de candidatura | ✓ | ✓ | ✓ | ✓ | ✓ (própria) | — |
| Aprovar documentos | ✓ | ✓ | ✓ | — | — | — |
| Desistir de candidatura | — | — | — | — | ✓ | — |

### Entrevistas

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Agendar entrevista | ✓ | ✓ | ✓ | — | — | — |
| Cancelar entrevista | ✓ | ✓ | ✓ | — | — | — |
| Atualizar entrevista | ✓ | ✓ | ✓ | — | — | — |
| Ver entrevistas agendadas | ✓ | ✓ | ✓ | ✓ | ✓ (próprias) | — |

### Propostas

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Enviar proposta | ✓ | ✓ | ✓ | — | — | — |
| Ver proposta | ✓ | ✓ | ✓ | ✓ | ✓ (própria) | — |
| Aceitar proposta | — | — | — | — | ✓ | — |
| Recusar proposta | — | — | — | — | ✓ | — |

### Chat

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Enviar mensagem | ✓ | ✓ | ✓ | — | ✓ | — |
| Ler mensagens | ✓ | ✓ | ✓ | ✓ | ✓ (próprias) | — |
| Encerrar conversa | ✓ | ✓ | ✓ | — | ✓ (própria) | — |
| Templates de chat | ✓ | ✓ | ✓ | — | — | — |

### Equipe / Usuários da Empresa

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Listar equipe | ✓ | ✓ | ✓ | ✓ | — | — |
| Criar usuário | ✓ | ✓ | — | — | — | — |
| Editar usuário | ✓ | ✓ | — | — | — | — |
| Remover usuário | ✓ | ✓ | — | — | — | — |
| Resetar senha | ✓ | ✓ | — | — | — | — |

### Analytics

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Registrar evento | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ (anônimo) |
| Analytics da empresa | ✓ | ✓ | ✓ | ✓ | — | — |
| Analytics global (SaaS) | ✓ | — | — | — | — | — |

### Auditoria

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Ver audit logs | ✓ | — | — | — | — | — |
| Auditoria SaaS | ✓ | — | — | — | — | — |

### Empresas (SaaS)

| Recurso | SaaS Admin | Admin Empresa | Recrutador | Viewer | Candidato | Público |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Listar empresas | ✓ | — | — | — | — | — |
| Criar empresa | ✓ | — | — | — | — | ✓ (cadastro) |
| Editar empresa | ✓ | — | — | — | — | — |
| Ver própria empresa | — | ✓ | ✓ | ✓ | — | — |
| Editar própria empresa | — | ✓ | — | — | — | — |

---

## Isolamento Multi-Tenant

Todas as rotas `/api/empresa/*` e `/api/candidato/*` aplicam isolamento por `empresa_id` derivado do JWT.  
Nenhuma consulta de empresa pode acessar dados de outra empresa.  
O `empresa_id` nunca vem do body — sempre do token.

---

## 2FA

- Admin SaaS: 2FA obrigatório por e-mail no login
- Empresa: 2FA opcional (TOTP via app autenticador)
- Candidato: sem 2FA (OTP por e-mail para login)
