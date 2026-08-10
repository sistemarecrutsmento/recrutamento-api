# Procedimento de Restauração Manual — VagasIO

> **Atenção:** Executar APENAS em caso de desastre (corrupção de dados, deleção acidental, etc).
> A restauração SOBRESCREVE os dados atuais. Faça um backup ANTES de restaurar.

---

## 1. Localizar o último backup no Cloudinary

O backup é armazenado na pasta `backups-vagas` do Cloudinary como arquivo `.gz`.

Acesse: https://console.cloudinary.com → Media Library → `backups-vagas`

Ou use a API via curl:

```bash
# Substitua pela sua Cloud name, API Key e Secret
curl -s "https://api.cloudinary.com/v1_1/SEU_CLOUD_NAME/resources/raw/backups-vagas" \
  -H "Authorization: Basic $(echo -n 'API_KEY:API_SECRET' | base64)" | jq '.resources[0]'
```

Procure o arquivo com nome `backup-vagas-YYYY-MM-DDTHH-mm-ss.gz`.

---

## 2. Baixar o arquivo do Cloudinary

```bash
# Exemplo: pegar a URL do último backup via API de busca
curl -s "https://api.cloudinary.com/v1_1/SEU_CLOUD_NAME/resources/raw/backups-vagas?max_results=1" \
  -H "Authorization: Basic $(echo -n 'API_KEY:API_SECRET' | base64)" | jq -r '.resources[0].secure_url'

# Fazer o download
curl -L -o backup-vagas.sql.gz "URL_DO_ARQUIVO"
```

---

## 3. Descomprimir

```bash
gunzip -k backup-vagas.sql.gz
# Resultado: backup-vagas.sql
```

Verifique o arquivo:

```bash
head -5 backup-vagas.sql
# Deve começar com "BEGIN;" e conter INSERTs

wc -l backup-vagas.sql
# Mostra total de linhas
```

---

## 4. Restaurar via psql

```bash
# Comando básico
psql "postgresql://usuario:senha@host:5432/recrutamento" < backup-vagas.sql
```

> ✅ **Comando seguro:** Roda dentro de uma transação (`BEGIN; ... COMMIT;`).
> Se algo falhar, o PostgreSQL faz rollback automático e o banco NÃO é alterado.

### Opções úteis do psql

```bash
# Com timeout por query (evita pendurar)
PGOPTIONS='--statement-timeout=120s' psql "URL" < backup-vagas.sql

# Se o banco estiver em produção, pare o servidor antes:
# 1. No Render: Stop do serviço
# 2. Execute o restore
# 3. Start do serviço
```

---

## 5. Verificar a restauração

### Contagem de tabelas

```sql
SELECT table_name, pg_size_pretty(pg_total_relation_size(table_name)) as tamanho
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
```

### Contagem de linhas por tabela-chave

```bash
psql "URL" -c "
SELECT 'admins' as tabela, count(*) as linhas FROM admins
UNION ALL
SELECT 'recrutadores', count(*) FROM recrutadores
UNION ALL
SELECT 'empresas', count(*) FROM empresas
UNION ALL
SELECT 'candidatos', count(*) FROM candidatos
UNION ALL
SELECT 'vagas', count(*) FROM vagas
UNION ALL
SELECT 'candidaturas', count(*) FROM candidaturas
UNION ALL
SELECT 'documentos_candidatura', count(*) FROM documentos_candidatura
UNION ALL
SELECT 'entrevistas', count(*) FROM entrevistas
ORDER BY tabela;
"
```

### Comparação antes/depois

Se você salvou as contagens antes do desastre:

```bash
# Antes (se disponível):
echo "{\"candidatos\": 142, \"vagas\": 12, ...}" > contagens_antes.json

# Depois do restore:
psql "URL" -c "SELECT 'candidatos' as t, count(*) as c FROM candidatos" > contagens_depois.txt
```

Compare manualmente os totais.

---

## 6. Validar integridade dos dados

### Verificar integridade referencial

```bash
psql "URL" -c "
-- Candidaturas órfãs (sem candidato)
SELECT COUNT(*) as candidaturas_sem_candidato FROM candidaturas c
LEFT JOIN candidatos ca ON ca.id = c.candidato_id WHERE ca.id IS NULL;

-- Documentos órfãos (sem candidatura)
SELECT COUNT(*) as docs_sem_candidatura FROM documentos_candidatura dc
LEFT JOIN candidaturas c ON c.id = dc.candidatura_id WHERE c.id IS NULL;

-- Entrevistas órfãs (sem candidatura)
SELECT COUNT(*) as entrevistas_sem_candidatura FROM entrevistas e
LEFT JOIN candidaturas c ON c.id = e.candidatura_id WHERE c.id IS NULL;
"
```

Todas devem retornar 0.

### Verificar dados sensíveis

```bash
# Admin existe
psql "URL" -c "SELECT id, nome, email, role FROM admins WHERE email = 'fabio08dejesusjunior@gmail.com';"

# Empresa principal
psql "URL" -c "SELECT id, nome, email_principal FROM empresas;"
```

---

## 7. Restauração programática (via restore.js)

Se o módulo `restore.js` estiver disponível no servidor, é possível restaurar via código:

```javascript
const { restoreFromCloudinary } = require('./src/restore');

// Dry run primeiro (só conta, não executa):
const dry = await restoreFromCloudinary({ dryRun: true });
console.log('Dry run:', dry);

// Se estiver tudo ok, executa:
const result = await restoreFromCloudinary();
console.log('Restore:', result);
```

> ⚠️ **Nunca chamar `restoreFromCloudinary()` sem dryRun primeiro em produção.**

---

## 8. Pós-restauração

1. **Reiniciar** o servidor Node.js (Render faz deploy/restart)
2. **Testar login** do admin
3. **Testar** listagem de vagas, candidaturas, documentos
4. **Notificar** usuários sobre a janela de indisponibilidade
5. **Gerar novo backup** imediatamente (`performBackup()`)

---

## Endpoint de consulta segura

`POST /api/admin/restore-test` (authAdminOnly) — retorna metadados do último backup.

```bash
curl -X POST https://recrutamento-api.onrender.com/api/admin/restore-test \
  -H "Authorization: Bearer SEU_TOKEN"
```

Resposta esperada:

```json
{
  "ok": true,
  "ultimoBackup": {
    "public_id": "backup-vagas-2026-07-27T00-00-00",
    "url": "https://res.cloudinary.com/...",
    "tamanhoBytes": 123456,
    "criadoEm": "2026-07-27T00:00:00Z",
    "formato": "gz",
    "tipo": "raw"
  }
}
```

---

## Checklist de emergência

- [ ] Backup atual baixado e salvo em local seguro
- [ ] Servidor parado (Render: Stop service)
- [ ] `psql "URL" < backup.sql` executado
- [ ] Contagens verificadas (tabelas-chave)
- [ ] Integridade referencial OK (0 órfãos)
- [ ] Login admin funcional
- [ ] Servidor restartado
- [ ] Teste de funcionalidade crítica
- [ ] Novo backup gerado