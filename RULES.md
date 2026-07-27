# RULES.md - Your Rules

Add your own conventions, lessons, and rules as you figure out what works with your human.

Think of this as your personal notebook for how to work better:
- Corrections your human has made
- Patterns you've noticed
- Workflows that work well
- Things to avoid

## Lições aprendidas

### 🐛 Bug ReferenceError: variável usada ANTES de declarada (19/07/2026)

**Errei feio na edição do `histHtml.map` em `analisar.html`:** peguei o trecho do `statusLabel` que referenciava `etapaNum` (a 1ª versão usava `etapaNum` no novo bloco), mas a `const etapaNum` só é declarada mais pra baixo. Resultado: a página admin inteira travou em "Carregando..." com `ReferenceError: etapaNum is not defined` no console.

**Sintoma**: spinner infinito, mesmo com servidor respondendo rápido.

**Lição**:
- Em `array.map(h => { ... })`, declarar **TODAS as constantes usadas no body ANTES de qualquer lógica que dependa delas**.
- Padrão seguro: `data`, `etapaNum`, `etapaNome`, `statusLabel` etc. sempre no TOPO do map, antes dos if's.
- Antes de commitar, abrir DevTools (F12 → Console) e recarregar a página — erro de sintaxe aparece na hora.

### 🚨 REGRA DE OURO: Como subir arquivos pro GitHub Pages (vagas)

**SEMPRE use `_scripts/git_push.py`. NUNCA escreva script de commit avulso.**

```bash
# ✅ CERTO — usa o script blindado
python3 _scripts/git_push.py "mensagem" vagas/index.html vagas/app-v2.js

# Com confirmação automática (pra scripts não-interativos)
python3 _scripts/git_push.py "mensagem" --yes vagas/index.html
```

**O que o script faz (e os outros NÃO faziam):**
1. **Lê SEMPRE do local** (`vagas/...`), nunca do GitHub
2. **Compara com o GitHub** antes de subir — se tá igual, pula com mensagem
3. **Mostra diff** das mudanças antes de confirmar
4. **Pede confirmação** (a menos que use `--yes`)
5. Token fica em `~/.config/zapia/github_token` (não precisa passar na linha)

**⚠️ ATENÇÃO — REPO HARD-CODED (jul/2026):** o `_scripts/git_push.py` tem `REPO = "sistemarecrutsmento/vagas"` **hard-coded** — ele SÓ serve pro frontend. Se você tentar subir `recrutamento-api/...` com ele, ele vai mandar pro repo `vagas` (frontend) e o GitHub Pages **ignora** (faz parte do diretório, mas o Render nunca lê lá). **Use o `_scripts/git_push_api.py` para o backend** (espelho com `REPO = "sistemarecrutsmento/recrutamento-api"`).

```bash
# ✅ CERTO — backend
python3 _scripts/git_push_api.py "msg" recrutamento-api/src/server.js
python3 _scripts/git_push_api.py "msg" --yes recrutamento-api/src/server.js
```

**🚫 O que NUNCA fazer:**
- ❌ Escrever `commit_*.py` ou `deploy_*.py` avulso pra subir arquivo
- ❌ Copiar script antigo e mudar mensagem (esquecer o que mudou)
- ❌ Puxar conteúdo do GitHub e fazer replace (foi o bug que aconteceu — script "subiu" mas subiu conteúdo idêntico)

**🐛 Bug que aconteceu (18/07/2026, noite):**
- Escrevi `commit_logout.py` que fazia `get_remote()` + `content.replace()` + `PUT`
- Resultado: o `?v=..._5` ficou no `index.html` mas o `app-v2.js` ficou IDÊNTICO ao que já tava (logout com confirm nunca subiu de verdade)
- Usuário reclamou que "as atualizações não subiram"
- **Causa raiz**: o script puxava o base64 DO GITHUB, fazia um replace, e dava PUT — o conteúdo real era o do GitHub, não o local

**Solução definitiva**: o `_scripts/git_push.py` SEMPRE lê do local, normaliza quebras de linha, compara bytes, e só sobe se for diferente.

### 🐛 Lição: Sair do drawer sumindo — `padding-bottom: 80px` no `.drawer-body`

**Bug (jul/2026)**: o Sair tava no rodapé do drawer mas **não aparecia** em `index/painel/vaga/documentos/inscricao`. Só aparecia na `perfil.html`.

**Causa raiz**: as 5 páginas usavam:
```css
.drawer-body { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: 12px 0 80px; }
```
O `padding-bottom: 80px` empurrava o conteúdo do body pra baixo, e como o `.drawer` tinha `height: 100vh` + `overflow: hidden`, o **footer (com Sair) saía da tela**.

A `perfil.html` (que funcionava) usava:
```css
.drawer-links { flex: 1 1 auto; min-height: 0; padding: 16px 0; overflow-y: auto; }
```

**Fix** aplicado em todas as 5 páginas:
- `.drawer-body` → `padding: 16px 0` (sem o 80px)
- `.drawer` → `aside.drawer { bottom: 0; width: 320px; }` (mais largo, sem height fixo)
- `.drawer-logout` → `border-radius: 8px` (igual perfil)

**Lição**: ao comparar uma página "que funciona" com as que "não funcionam", comparar o CSS de cada bloco, não só o markup. O `padding-bottom` num container flex pode esconder o footer sem cortar nada visualmente.

**Sobre o ☰ (jul/2026)**: o `<button id="btn-menu-logo">` é injetado pelo JS em `header.insertBefore(btn, firstChild)` com `position: absolute; right: 16px`. Ele **deve** ficar no canto direito. NUNCA mover pra dentro do `header-actions` (vai esconder o "Completar cadastro" / "Entrar").

### Sobre prompts de "continuar tarefa" (idle timeout)
- O Zapia mostra "Tarefa complexa — Está demorando mais do que o esperado, você quer continuar?" quando a conversa fica parada muitos minutos.
- **Causa mais comum**: rodei deploy + waits de propagação (30-60s cada) + muitos testes de screenshot pra "confirmar visualmente".
- **Como evitar**:
  1. **NÃO fazer screenshot de confirmação quando o snapshot de texto/refs já mostra que funcionou** (a tool já validou).
  2. **Agrupar testes em batch**: 1 validação visual cobre várias mudanças (não 3-4).
  3. **Deploys**: agrupar TODAS as mudanças em 1-2 commits, não ficar deployando a cada ajuste pequeno.
  4. Se o trabalho é longo de verdade, **mostrar progresso em 1 mensagem curta** e seguir, sem screenshot.
- **Regra de ouro**: o usuário disse "vou verificar e volto" = ele confirma. Não preciso de screenshot final pra cada coisa.

### Quando o usuário pedir "vamos começar do zero"
1. **BACKUP PRIMEIRO** — sempre baixe tudo antes de deletar
2. Salve o backup num subdiretorio nomeado (`backup_git/`, etc)
3. Delete do GitHub via API (esvaziar arquivos funciona mesmo sem permissão de admin)
4. **NÃO invente URLs** — se você não tem a URL grounded (via tool), peça pro usuário
5. Crie um INVENTARIO.json com tudo que foi removido
6. Avise o que precisa ser feito manualmente (ex: deletar serviços no Render que precisam de senha)

### 🚨 REGRA: NÃO inventar URLs, telefones ou e-mails

**Errei feio (22/07/2026)** — citei `https://vagasio.com.br/candidato/index.html` numa resposta SEM TER essa URL grounded em tool result. O domínio `vagasio.com.br/admin/` está grounded (veio do "Lookup Handles" do summary anterior), mas eu inventei os subpaths.

**Sintoma**: sistema de "hallucination guard" bloqueou a mensagem antes de enviar.

**Regra de ouro**:
- URLs: só citar se vier de `web_fetch`/`web_search`/`browser` ou se o usuário escreveu explicitamente
- Pra subpaths (tipo `/candidato/entrevistas.html`), **não chutar** — dizer "acessar a página de candidato logado" em vez de URL completa
- Se o usuário pedir um link específico, **perguntar** ou **usar a tool** pra confirmar
- E-mails: mesmo critério (só citar os que já estão em `USER.md` ou em tool result)
- Telefones: idem

**O que dizer quando não sei a URL exata**:
- ✅ "Acessa o painel admin (o que você usa hoje)"
- ✅ "Vai na página de candidato logado"
- ❌ "https://site.com/admin/index.html" (se não confirmei)

### Projeto Vagas — REGRAS DE OURO (FABIO pediu em 18/07/2026)

**UM ÚNICO FRONTEND + UM ÚNICO BACKEND. Não criar cópias.**

#### Pastas locais (workspace)
- `vagas/` → espelho do repo `sistemarecrutsmento/vagas` (frontend no ar via GitHub Pages)
  - `vagas/index.html`, `vagas/app-v2.js`, `vagas/inscricao.html`, etc. = candidato
  - `vagas/admin/index.html`, `vagas/admin/app.js`, etc. = admin
- `recrutamento-api/` → espelho do repo `sistemarecrutsmento/recrutamento-api` (backend no Render)

**PROIBIDO** criar pastas tipo `recrutamento-front`, `recrutamento-backend`, `recrutamento-v2`, `recrutamento-novo`, `recrutamento-selecao`, etc. SEMPRE trabalhar nas pastas `vagas/` e `recrutamento-api/`.

#### Repositórios no GitHub
- **Frontend (oficial)**: `sistemarecrutsmento/vagas` → https://sistemarecrutsmento.github.io/vagas/
- **Backend (oficial)**: `sistemarecrutsmento/recrutamento-api` → https://recrutamento-api.onrender.com/
- `recrutamento-selecao` → **RENOMEADO** para `recrutamento-selecao-DESCONTINUADO` (marca d'água, usuário pode deletar manualmente depois)

#### Como confirmar o repo oficial de qualquer projeto
1. Se o user mencionar URL: abrir e ver o source.
2. Listar `https://api.github.com/user/repos` e filtrar por nome.
3. Conferir qual tem deploy ativo (GitHub Pages / Render / Vercel).
4. Se houver dúvida entre 2 repos parecidos, **perguntar ao user** antes de editar.

#### Lições do problema que aconteceu (18/07/2026)
- Eu tinha 2 cópias do mesmo projeto (`recrutamento-selecao/` antigo + `vagas/` oficial) e editava a errada.
- Resultado: o user via o site "antigo" sem as atualizações que eu tinha feito.
- **Lição**: antes de mexer em qualquer arquivo, conferir se o arquivo que vou abrir bate com o que está no site oficial.
- **O que eu fiz pra resolver**:
  1. Confirmei qual repo está no ar (via `curl` no GitHub Pages + comparando arquivos).
  2. Renomeei o repo abandonado pra `recrutamento-selecao-DESCONTINUADO` (não tenho permissão de admin pra deletar).
  3. Apaguei as pastas locais antigas (`recrutamento-front/`, `recrutamento-selecao/`, `recrutamento-backend/`).
  4. Consolidei tudo em `vagas/` (espelho do repo oficial) e `recrutamento-api/` (backend).
  5. Salvei esta regra no RULES.md.

## 📋 Sistema de Notificações no Admin (jul/2026, PENDENTE)

**Ideia aprovada por Fabio (18/07/2026)**: feed global de eventos + contadores com links inteligentes.

**Regras de Fabio**:
- Cada contador deve ser um **link inteligente** que leva direto pra página certa filtrada
- Cada item do feed também: link pro `analisar.html?id=X` ou `candidaturas.html?vaga=X`
- Tabela `notificacoes` (espelha o `historico` da candidatura, mas desnormalizada pra query simples)
- INSERTs nos 5 pontos do `server.js` que fazem `historico.push`: linhas 1245, 1389, 1473, 1540, 1603
- Rota nova: `GET /api/admin/notificacoes` retorna feed + 4 KPIs

**Status**: PAUSADO até Fabio voltar. Ver `memory/2026-07-18.md` seção "Tarde/noite" pra contexto completo.

---

## 📋 Sistema de 7 Etapas + Proposta (jul/2026)

**Vaga padrão tem 7 etapas**:
1. Inscrição | 2. Triagem | 3. RH | 4. Gestor | 5. Proposta | 6. Coleta Documentos | 7. Contratação

**`etapa_atual` no DB é 0-indexed** (0=Inscrição, 4=Proposta, 5=Coleta, 6=Contratação) — significa "índice no array `etapas[]` da vaga da PRÓXIMA etapa a fazer". Inscrição já tá feita, próxima é a `etapa_atual`. Incremento: `etapa_atual + 1` ao avançar. **NÃO é 1-indexed** (errei essa doc por meses; consertei em 22/07/2026 quando achei o bug do INSERT que gravava 1).

- Candidato se inscreve: `etapa_atual = 0` (na Inscrição)
- Admin clica "Avançar" na Triagem: `etapa_atual = 1` (foi pra Triagem, próxima é RH)
- Frontend (admin/inscricao/painel): exibe `etapa_atual + 1` como label 1-indexed ("1/8 — Inscrição", "2/8 — Triagem", etc)

**Fluxo da Etapa 5 (Proposta)**:
- Admin clica "📨 Enviar Proposta" (aparece quando candidato tá na etapa 4 ou 5)
- Modal com texto da proposta + upload opcional de PDF
- Backend: `POST /api/admin/candidatura/:id/enviar-proposta` → salva + envia e-mail + bloqueia avanço até enviar
- Candidato vê o bloco no `inscricao.html` com **✅ Aceitar** / **❌ Recusar**
- Aceitar → `etapa_atual = 6` + `proposta_aceita_em = NOW()`
- Recusar → `status = 'rejeitado'` + `proposta_recusada_em` + `proposta_motivo_recusa`

**Trava Etapa 6 (Coleta)**: ao avançar, exige 16 docs obrigatórios todos enviados E aprovados.

**Arquivos críticos**:
- `recrutamento-api/src/server.js` linhas 1319-1510 (rotas proposta)
- `recrutamento-api/src/db.js` (colunas proposta_*)
- `vagas/inscricao.html` (emProposta=true → mostra bloco)
- `vagas/admin/analisar.html` (modal de proposta)

### 🚨 REGRA: Quando o Render retorna 404 em rotas que existem no código

**Sintoma**: rotas que estão no `server.js` retornam 404, mesmo depois de deploy forçado com clearCache. Outras rotas do mesmo arquivo funcionam.

**Diagnóstico**:
1. Pegar a env var `RENDER_GIT_COMMIT` em runtime (via rota `/api/_debug-email-teste` que lista env vars) — confirma se o commit certo tá rodando.
2. Se o commit TÁ rodando mas rotas não funcionam = **cache do `node_modules` corrompido no volume persistente**.

**Solução**: criar um NOVO serviço do zero no Render. Não dá pra limpar via clearCache.

**Aplicação real (25/07/2026)**: tinha 2 serviços antigos, ambos com código cacheado parcialmente. Criei `recrutamento-api-novo` (srv-d9iilsv41pts73bb08d0) do zero, com as 11 env vars, e funcionou de primeira.

### 💡 SaaS Multi-Tenant (IDEIA PAUSADA — Fabio pediu pra guardar)
**Volta no assunto?** Perguntar antes de retomar. Ver `memory/2026-07-25.md` seção "IDEIA PAUSADA".
- Caminho escolhido: A (multi-tenant mesmo banco)
- 80% já tá pronto (tabelas + páginas + rotas de empresa)
- 3 perguntas TRAVADAS: aprovação / publicação / cobrança

### ⚠️ Rotas debug temporárias (criar/remover quando precisar)
Quando criar debug routes (`/api/_debug-*`) pro Fabio, listar aqui pra remover depois:
- `/api/_debug-email-notificacao`
- `/api/_debug-email-teste`
- `/api/_debug-recrutadores`
- ~~`/api/_debug-empresas-usuarios`~~ (REMOVIDA 26/07/2026 — listava usuários empresa pra teste de login)
- ~~`/api/_debug-forcar-etapa`~~ (REMOVIDA 26/07/2026 — forçava etapa_atual pra testar regex de permissão)

### 🚨 REGRA: Env vars do Render com JSON quebrado por newlines

**Problema**: o Render converte `\\n` (escapado) em `\n` (newline real) ao salvar env vars via API. Isso quebra JSON que tem `private_key` de Service Account do Google.

**Sintoma**: 
```
"Unexpected token \n in JSON at position 168"
ou
"Invalid control character at: line 1 column 169 (char 168)"
```

**Solução**: NO APP que lê a env var, adicionar fix que detecta newlines reais no `private_key` (entre `-----BEGIN PRIVATE KEY-----` e `-----END PRIVATE KEY-----`) e re-escape pra `\\n` antes de fazer `JSON.parse`:

```javascript
let jsonStr = process.env.GCP_SERVICE_ACCOUNT_JSON;
try {
  credentials = JSON.parse(jsonStr);
} catch (e1) {
  const beginMarker = '-----BEGIN PRIVATE KEY-----';
  const endMarker = '-----END PRIVATE KEY-----';
  const beginIdx = jsonStr.indexOf(beginMarker);
  const endIdx = jsonStr.indexOf(endMarker);
  if (beginIdx > -1 && endIdx > -1) {
    const endOfEnd = endIdx + endMarker.length;
    const privateKeyBlock = jsonStr.substring(beginIdx, endOfEnd);
    const fixedBlock = privateKeyBlock.replace(/\n/g, '\\n');
    jsonStr = jsonStr.substring(0, beginIdx) + fixedBlock + jsonStr.substring(endOfEnd);
    credentials = JSON.parse(jsonStr);
  } else {
    throw e1;
  }
}
```

**Aplicação real (25/07/2026)**: foi EXATAMENTE isso que travou a integração com Google Meet no Render.

### 🐛 Lição: SyntaxError em `app.js` SILENCIA o login inteiro (26/07/2026)

**Sintoma**: Login parou de funcionar "do nada". Clicar em "Entrar" não faz NADA. Botão não muda. Nada acontece.

**Causa raiz**: Quando o `app.js` tem um `SyntaxError` (no meu caso, `const elAprov` declarado DUAS vezes no mesmo escopo de `carregarDashboardV2`), o navegador **REJEITA TODO O ARQUIVO** — nenhuma função é definida, incluindo `fazerLogin`. Por isso `onclick="fazerLogin()"` falha silenciosamente com `ReferenceError: fazerLogin is not defined`.

**O que eu tinha feito**: nas últimas horas (26/07), ao adicionar/remover blocos nos KPIs secundários (taxa_aprovacao_30d), copiei/colei código sem renomear a variável local `elAprov`. Resultado: linha 1178 e linha 1360 do `app.js` declararam `const elAprov` no mesmo escopo da função.

**Como detectar antes de subir**:
1. SEMPRE validar sintaxe do `app.js` antes de commitar:
   ```bash
   # Validar via Python (sem precisar de node):
   python3 -c "
   src = open('vagas/admin/app.js').read()
   lines = src.split('\n')
   escopo_stack = [{}]
   import re
   for i, line in enumerate(lines, 1):
       new_stack = [dict(s) for s in escopo_stack]
       for m in re.finditer(r'\b(const|let)\s+(\w+)\s*=', line):
           escopo_atual = new_stack[-1]
           if m.group(2) in escopo_atual:
               print(f'Linha {i}: DUPLICADO {m.group(2)} (linha {escopo_atual[m.group(2)]})')
           else:
               escopo_atual[m.group(2)] = i
       # processar { e } (simplificado)
       in_string = None
       for c in line:
           if in_string:
               if c == in_string: in_string = None
               continue
           if c in '\"\\'\`': in_string = c; continue
           if c == '{': new_stack.append({})
           elif c == '}': new_stack.pop() if len(new_stack) > 1 else None
       escopo_stack = new_stack
   "
   ```
2. Criar página de teste que carrega o `app.js` num ambiente isolado:
   ```html
   <script>window.addEventListener('error', e => { document.title = 'ERRO: ' + e.message });</script>
   <script src="../admin/app.js?v=test"></script>
   ```
3. Olhar `document.title` no navegador — se virou "ERRO: Uncaught SyntaxError...", o app.js está quebrado.

**Como diagnosticar no navegador do usuário**:
- Pedir pro usuário abrir F12 → Console e procurar por mensagens em VERMELHO com "SyntaxError" ou "Uncaught".
- O erro tipicamente aponta pra linha problemática.

**Lição**: cada vez que eu mexo num arquivo JS grande (100KB+), RODA essa validação antes de subir. Não confiar em "parece OK".

### 🎯 REGRA: Alterar APENAS o que foi pedido (Fabio, 26/07/2026)

**Pedido do Fabio**: "alterar apenas o que foi pedido e não perder nada do restante dos arquivos ou códigos para não perder funções importantes que fazem diferença"

**Aplicar SEMPRE**:
1. Fazer mudança cirúrgica — só no ponto exato que ele pediu
2. **Diff antes de subir** — se mostrar mais coisa que o pedido, PARAR e revisar
3. **Não apagar código** sem confirmar antes
4. **Não "limpar"** código que parece desnecessário (pode ter função crítica)
5. **Em arquivos grandes** (app.js, app-v2.js): SEMPRE validar sintaxe + escanear duplicações antes de subir
