# API Reference — VagasIO

Gerado Fase 15. Total: 202 endpoints.

---

## Autenticação

```
Authorization: Bearer <token>
```

| Tipo | Como obter |
|---|---|
| Candidato | `POST /api/candidato/verificar` (OTP) |
| Empresa | `POST /api/auth/login-empresa` |
| Admin/SaaS | `POST /api/admin/login` → `POST /api/admin/2fa/verificar` |

---

## auth (15 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/auth/esqueci-senha` | public |
| `POST` | `/api/auth/login-empresa` | public |
| `POST` | `/api/auth/login-empresa-v2` | public |
| `POST` | `/api/auth/login-recrutador` | public |
| `POST` | `/api/auth/logout` | public |
| `POST` | `/api/auth/redefinir-senha` | public |
| `POST` | `/api/auth/refresh` | public |
| `GET` | `/api/auth/sessoes` | public |
| `DELETE` | `/api/auth/sessoes/:id` | public |
| `POST` | `/api/auth/sessoes/encerrar-outras` | public |
| `POST` | `/api/auth/sessoes/encerrar-todas` | public |
| `POST` | `/api/auth/trocar-senha-empresa` | empresa-viewer+ |
| `POST` | `/api/auth/trocar-senha-recrutador` | admin |
| `GET` | `/api/auth/validar-token` | public |
| `POST` | `/api/ci/admin-token` | public |

## candidato (31 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/candidato/aceitar-proposta/:candidaturaId` | candidato |
| `POST` | `/api/candidato/cadastrar` | candidato |
| `POST` | `/api/candidato/cadastro` | public |
| `POST` | `/api/candidato/candidatar/:vagaId` | candidato |
| `GET` | `/api/candidato/candidatura/:id/proposta` | candidato |
| `GET` | `/api/candidato/candidaturas` | candidato |
| `GET` | `/api/candidato/candidaturas/:id` | candidato |
| `GET` | `/api/candidato/candidaturas/:id/historico` | candidato |
| `GET` | `/api/candidato/chat` | candidato |
| `GET` | `/api/candidato/chat/:cid` | candidato |
| `PATCH` | `/api/candidato/chat/:cid/encerrar` | candidato |
| `PATCH` | `/api/candidato/chat/:cid/lidas` | candidato |
| `POST` | `/api/candidato/chat/:cid/mensagens` | candidato |
| `GET` | `/api/candidato/conversas` | candidato |
| `GET` | `/api/candidato/dashboard/kpis` | candidato |
| `GET` | `/api/candidato/entrevistas` | candidato |
| `GET` | `/api/candidato/favoritos` | candidato |
| `POST` | `/api/candidato/favoritos/:vaga_id` | candidato |
| `DELETE` | `/api/candidato/favoritos/:vaga_id` | candidato |
| `PUT` | `/api/candidato/foto` | candidato |
| `DELETE` | `/api/candidato/foto` | candidato |
| `POST` | `/api/candidato/iniciar` | public |
| `POST` | `/api/candidato/login` | public |
| `GET` | `/api/candidato/onboarding` | candidato |
| `POST` | `/api/candidato/onboarding/step` | candidato |
| `GET` | `/api/candidato/perfil` | candidato |
| `PUT` | `/api/candidato/perfil` | candidato |
| `POST` | `/api/candidato/recusar-proposta/:candidaturaId` | candidato |
| `POST` | `/api/candidato/trocar-senha` | candidato |
| `GET` | `/api/candidato/vagas/:id/match` | candidato |
| `POST` | `/api/candidato/verificar` | public |

## empresa (50 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/empresa/2fa/confirmar` | empresa-viewer+ |
| `POST` | `/api/empresa/2fa/desativar` | empresa-viewer+ |
| `POST` | `/api/empresa/2fa/iniciar` | empresa-viewer+ |
| `GET` | `/api/empresa/2fa/status` | empresa-viewer+ |
| `POST` | `/api/empresa/2fa/verificar` | public |
| `GET` | `/api/empresa/agenda` | empresa-viewer+ |
| `GET` | `/api/empresa/analytics` | empresa-viewer+ |
| `POST` | `/api/empresa/cadastro` | public |
| `GET` | `/api/empresa/candidatos` | empresa-viewer+ |
| `GET` | `/api/empresa/candidatura/:id` | empresa-viewer+ |
| `POST` | `/api/empresa/candidatura/:id/acao` | empresa-recrutador+ |
| `GET` | `/api/empresa/candidatura/:id/chat` | empresa-viewer+ |
| `POST` | `/api/empresa/candidatura/:id/chat` | empresa-recrutador+ |
| `GET` | `/api/empresa/candidatura/:id/documentos` | empresa-viewer+ |
| `PATCH` | `/api/empresa/candidaturas/:id/etapa` | empresa-recrutador+ |
| `GET` | `/api/empresa/candidaturas/:id/historico` | empresa-viewer+ |
| `GET` | `/api/empresa/chat` | empresa-viewer+ |
| `GET` | `/api/empresa/chat-rh-lista` | empresa-viewer+ |
| `GET` | `/api/empresa/chat/:cid` | empresa-viewer+ |
| `PATCH` | `/api/empresa/chat/:cid/encerrar` | empresa-recrutador+ |
| `PATCH` | `/api/empresa/chat/:cid/lidas` | empresa-viewer+ |
| `POST` | `/api/empresa/chat/:cid/mensagens` | empresa-recrutador+ |
| `GET` | `/api/empresa/chat/templates` | empresa-viewer+ |
| `POST` | `/api/empresa/chat/templates` | empresa-recrutador+ |
| `DELETE` | `/api/empresa/chat/templates/:tid` | empresa-recrutador+ |
| `GET` | `/api/empresa/dashboard` | empresa-viewer+ |
| `GET` | `/api/empresa/dashboard/kpis` | empresa-viewer+ |
| `POST` | `/api/empresa/esqueci-senha` | public |
| `GET` | `/api/empresa/minha-empresa` | empresa-viewer+ |
| `PUT` | `/api/empresa/minha-empresa` | empresa-recrutador+ |
| `POST` | `/api/empresa/onboarding/step` | empresa-recrutador+ |
| `POST` | `/api/empresa/trocar-senha` | empresa-viewer+ |
| `GET` | `/api/empresa/usuarios` | empresa-viewer+ |
| `POST` | `/api/empresa/usuarios` | empresa-admin |
| `PUT` | `/api/empresa/usuarios/:id` | empresa-admin |
| `DELETE` | `/api/empresa/usuarios/:id` | empresa-admin |
| `POST` | `/api/empresa/usuarios/:id/reset-senha` | empresa-admin |
| `POST` | `/api/empresa/vagas` | empresa-recrutador+ |
| `GET` | `/api/empresa/vagas` | empresa-viewer+ |
| `GET` | `/api/empresa/vagas-com-candidaturas` | empresa-viewer+ |
| `GET` | `/api/empresa/vagas-todas` | empresa-viewer+ |
| `PUT` | `/api/empresa/vagas/:id` | empresa-recrutador+ |
| `GET` | `/api/empresa/vagas/:id/matches` | empresa-viewer+ |
| `PATCH` | `/api/empresa/vagas/:id/status` | empresa-recrutador+ |
| `GET` | `/api/empresa/vagas/:id/tags` | empresa-viewer+ |
| `POST` | `/api/empresa/vagas/:id/tags` | empresa-recrutador+ |
| `PUT` | `/api/empresa/vagas/:id/tags` | empresa-recrutador+ |
| `DELETE` | `/api/empresa/vagas/:id/tags/:tag` | empresa-recrutador+ |
| `GET` | `/api/empresa/vagas/:vaga_id` | empresa-viewer+ |
| `GET` | `/api/empresa/vagas/:vaga_id/candidatos` | empresa-viewer+ |

## admin (55 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/admin/2fa/reenviar` | public |
| `POST` | `/api/admin/2fa/verificar` | public |
| `GET` | `/api/admin/_diag-schema-fase1` | admin |
| `GET` | `/api/admin/audit-logs` | admin |
| `POST` | `/api/admin/backup` | admin-only |
| `GET` | `/api/admin/candidato/:id` | admin |
| `POST` | `/api/admin/candidato/:id/deletar` | admin |
| `GET` | `/api/admin/candidatos` | admin |
| `GET` | `/api/admin/candidatura/:id` | admin |
| `POST` | `/api/admin/candidatura/:id/aprovar-documentos` | admin |
| `GET` | `/api/admin/candidatura/:id/chat-empresa` | admin |
| `POST` | `/api/admin/candidatura/:id/chat-empresa` | admin |
| `POST` | `/api/admin/candidatura/:id/comentario` | admin |
| `GET` | `/api/admin/candidatura/:id/documentos` | admin |
| `POST` | `/api/admin/candidatura/:id/enviar-proposta` | admin |
| `GET` | `/api/admin/candidatura/:id/proposta` | admin |
| `POST` | `/api/admin/candidatura/:id/status` | admin |
| `GET` | `/api/admin/candidaturas` | admin |
| `GET` | `/api/admin/candidaturas-por-etapa` | admin |
| `GET` | `/api/admin/chat-empresa-lista` | admin |
| `GET` | `/api/admin/contratacoes` | admin |
| `GET` | `/api/admin/conversas` | admin |
| `GET` | `/api/admin/dashboard` | admin |
| `POST` | `/api/admin/documento/:id/revisar` | admin |
| `PUT` | `/api/admin/empresa-usuarios/:id` | admin-only |
| `DELETE` | `/api/admin/empresa-usuarios/:id` | admin-only |
| `POST` | `/api/admin/empresa-vaga` | admin-only |
| `DELETE` | `/api/admin/empresa-vaga` | admin-only |
| `GET` | `/api/admin/empresa-vaga/:empresa_id` | admin |
| `GET` | `/api/admin/empresas` | admin |
| `POST` | `/api/admin/empresas` | admin-only |
| `PUT` | `/api/admin/empresas/:id` | admin-only |
| `DELETE` | `/api/admin/empresas/:id` | admin-only |
| `POST` | `/api/admin/empresas/:id/usuarios` | admin-only |
| `POST` | `/api/admin/entrevista` | admin |
| `PUT` | `/api/admin/entrevista/:id` | admin |
| `POST` | `/api/admin/entrevista/:id/cancelar` | admin |
| `GET` | `/api/admin/entrevistas` | admin |
| `GET` | `/api/admin/equipe` | admin |
| `POST` | `/api/admin/login` | public |
| `POST` | `/api/admin/recrutadores` | admin |
| `GET` | `/api/admin/recrutadores` | admin |
| `PUT` | `/api/admin/recrutadores/:id` | admin-only |
| `DELETE` | `/api/admin/recrutadores/:id` | admin-only |
| `POST` | `/api/admin/restore-test` | admin-only |
| `POST` | `/api/admin/seed-vagas-demo` | admin |
| `POST` | `/api/admin/vagas` | admin |
| `GET` | `/api/admin/vagas` | admin |
| `GET` | `/api/admin/vagas-abertas-antigas` | admin |
| `GET` | `/api/admin/vagas-com-candidaturas` | admin |
| `GET` | `/api/admin/vagas-fechadas-sem-contratacao` | admin |
| `PUT` | `/api/admin/vagas/:id` | admin |
| `DELETE` | `/api/admin/vagas/:id` | admin |
| `GET` | `/api/admin/vagas/:id` | admin |
| `GET` | `/api/admin/vagas/:id/candidaturas` | admin |

## saas (6 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/saas/analytics` | admin |
| `GET` | `/api/saas/auditoria` | admin |
| `POST` | `/api/saas/email/digest` | admin |
| `POST` | `/api/saas/email/test` | admin |
| `GET` | `/api/saas/empresas` | admin |
| `PUT` | `/api/saas/empresas/:id` | admin |

## vagas (2 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/vagas` | public |
| `GET` | `/api/vagas/:id` | public |

## public (5 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/public/empresa/:slug` | public |
| `GET` | `/api/public/empresa/:slug/vagas` | public |
| `GET` | `/api/public/empresa/:slug/vagas/:id` | public |
| `GET` | `/api/public/vagas/:id/tags` | public |
| `GET` | `/api/public/vagas/por-tag/:tag` | public |

## analytics (1 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/analytics/eventos` | public |

## notificacoes (4 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/notificacoes` | public |
| `PATCH` | `/api/notificacoes/:id/lida` | public |
| `PATCH` | `/api/notificacoes/marcar-todas-lidas` | public |
| `GET` | `/api/notificacoes/nao-lidas` | public |

## util (21 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/_build` | public |
| `GET` | `/api/_debug-email-notificacao` | debug |
| `GET` | `/api/_debug-email-teste` | debug |
| `GET` | `/api/_debug-processo` | debug |
| `GET` | `/api/_debug/admin-info` | debug |
| `GET` | `/api/_debug/bcrypt` | debug |
| `GET` | `/api/_debug/config` | debug |
| `GET` | `/api/_debug/dashboard` | debug |
| `GET` | `/api/_debug/fase6` | public |
| `DELETE` | `/api/_debug/limpar-squatter` | debug |
| `POST` | `/api/_debug/meet-criar-teste` | admin |
| `DELETE` | `/api/_debug/meet-deletar/:eventId` | admin |
| `GET` | `/api/_debug/meet-listar-teste` | debug |
| `GET` | `/api/_debug/meet-teste` | debug |
| `POST` | `/api/_debug/migrar` | admin |
| `POST` | `/api/_debug/reset-admin` | admin |
| `GET` | `/api/_debug/ultimo-codigo/:email` | admin |
| `POST` | `/api/_debug/vaga-etapas` | admin |
| `GET` | `/api/_debug/versao` | debug |
| `GET` | `/api/cep/:cep` | public |
| `GET` | `/api/saude` | public |

## candidatura (3 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/candidatura/:id/desistir` | candidato |
| `POST` | `/api/candidatura/:id/documentos` | candidato |
| `GET` | `/api/candidatura/:id/documentos` | candidato |

## chat (5 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/chat/:candidatura_id/mensagens` | candidato |
| `POST` | `/api/chat/:candidatura_id/mensagens` | candidato |
| `POST` | `/api/chat/:candidatura_id/upload` | candidato |
| `GET` | `/api/chat/arquivo/:id` | candidato |
| `GET` | `/api/chat/mensagem/:id/arquivos` | candidato |

## cron (1 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `POST` | `/api/cron/digest` | public |

## email (2 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/email/preferencias` | public |
| `PATCH` | `/api/email/preferencias` | public |

## planos (1 endpoints)

| Método | Rota | Auth |
|---|---|---|
| `GET` | `/api/planos` | public |

