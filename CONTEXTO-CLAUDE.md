# Evolve Financeiro — Contexto Completo para Claude

> **Para usar em outra conta do Claude (ex: Antigravity Conta 2).**
> Leia este arquivo inteiro antes de tocar em qualquer código.
> Workflow: edite os arquivos → `git add . && git commit -m "msg" && git push` → Railway sobe em ~2 min. Pronto.

---

## O que é

Ferramenta web de controle financeiro da agência **Evolve Ads** (Hudson + Diego).
Será revendida para outros clientes — precisa de qualidade de produto.

---

## Localização dos arquivos

```
/Users/Hudson/Documents/squads/evolve-financeiro/
├── app.py                  ← Backend Flask (~960 linhas)
├── static/index.html       ← Frontend SPA completo (~3000 linhas)
├── evolve.db               ← Banco LOCAL (só testes — dados reais estão no Railway)
├── requirements.txt
├── Procfile                ← web: gunicorn app:app
└── CONTEXTO-CLAUDE.md      ← este arquivo
```

---

## Como rodar localmente

```bash
cd /Users/Hudson/Documents/squads/evolve-financeiro
source venv/bin/activate
python app.py
# Acesse: http://localhost:5050
```

---

## Deploy — como funciona

**Tudo automático via Railway. Você nunca precisa acessar o painel do Railway.**

```bash
# Após qualquer edição:
git add app.py static/index.html   # ou git add .
git commit -m "descrição do que mudou"
git push
# Railway detecta o push e faz deploy em ~2 minutos
# URL de produção: https://evolve-financeiro.up.railway.app
```

O remote já está configurado com credenciais embutidas no Mac do Hudson.
Para verificar: `git remote -v` dentro da pasta do projeto.

Se o token expirar ou precisar configurar em outra máquina:
1. Hudson acessa https://github.com/settings/tokens e cria/regenera um PAT com escopo `repo`
2. Rodar: `git remote set-url origin https://gestaoevolveads:TOKEN@github.com/gestaoevolveads/evolve-financeiro.git`

---

## Variáveis de ambiente no Railway

```
DATA_DIR=/data
SECRET_KEY=<valor secreto configurado no Railway>
MISE_PYTHON_GITHUB_ATTESTATIONS=false   ← obrigatório para build funcionar
```

---

## Usuários e senhas (produção atual)

| Usuário | Senha | Perfil |
|---|---|---|
| `hudson` | `evolve2026` | Sócio — acesso total + botão Restaurar |
| `diego` | `evolve2026` | Sócio — acesso total + botão Restaurar |
| `financeiro` | `evolve2026` | Carla — sem botão Restaurar |

---

## Stack

- **Backend**: Flask (Python) + SQLite
- **Frontend**: SPA em HTML/CSS/JS puro — arquivo único `static/index.html`
- **Auth**: JWT no header `Authorization: Bearer <token>`, expira em 7 dias
- **Banco**: SQLite com volume persistente no Railway em `/data/evolve.db`

---

## Banco de dados — tabelas

```sql
users           -- id, username, password_hash, name
months          -- id, year, month, regime, mei_das, prolabore_socio, notes
revenues        -- id, month_id, client_name, amount, received_date, category,
                --   is_new_client, sort_order, recurring_id, status
costs           -- id, month_id, name, amount, payment_date, category,
                --   sort_order, recurring_id, status
goals           -- id, name, target_value, metric, year, month, active
audit_log       -- id, ts, username, action, detail
categories      -- id, type(revenue/cost), slug, label, color, sort_order, active
settings        -- key, value  (ex: saldo_inicial)
receivables     -- id, description, client_name, amount, due_date, received_date, status, category, notes
payables        -- id, description, amount, due_date, paid_date, status, category, notes
recurring_items -- id, type, description, client_name, amount, category,
                --   start_year, start_month, end_year, end_month, active
```

Regras de migração (NUNCA quebrar):
- Sempre `ALTER TABLE ... ADD COLUMN` dentro de `try/except`
- Sempre `CREATE TABLE IF NOT EXISTS`
- **NUNCA** DROP, TRUNCATE ou DELETE em dados de produção

---

## Funcionalidades implementadas

### Navegação (topbar)
```
Dashboard | Jan'26…Dez'26 | Jan'27 | 📊 Fluxo | 💳 Contas | 🔭 Projeção | 🔍 Busca | 📋 Histórico
Botões: ⚙ Categorias | 🔁 Recorrentes | 💾 Backup | ↩ Restaurar (só sócios)
```

### Features
1. **Dashboard** — métricas anuais, metas com progresso, gráfico receita×despesa, distribuição por categoria, tabela resumo
2. **Meses** — receitas e despesas com edição inline, debounce 700ms, cópia do mês anterior
3. **Fluxo de Caixa** — gráfico histórico + projeção, saldo inicial configurável
4. **Contas** — A Receber e A Pagar agrupadas por mês, badges de status, alertas de vencimento
5. **Projeção** — horizonte 1M/2M/3M/6M/12M/Ano2026, gráfico, Projetado×Realizado por mês
6. **Recorrentes** — modal para gerenciar, gera lançamentos projetados automaticamente, botão 🔁 em cada linha
7. **Categorias** — CRUD com cor e slug, dinâmicas
8. **Metas** — modal 🎯, barra de progresso no dashboard
9. **Bônus** — cálculo trimestral (resultado > 0 AND caixa > 3×avg_custo → 50% resultado ÷ 2)
10. **Relatório PDF** — por mês e anual
11. **Backup/Restaurar** — JSON completo (Restaurar só aparece para hudson/diego)
12. **Busca** — pesquisa global em receitas e despesas
13. **Histórico** — audit log de todas as ações
14. **Polling** — sync automático a cada 30s

### Sistema de Recorrentes
- `recurring_items`: cadastra uma receita/despesa recorrente com intervalo de datas
- Botão 🔁 em cada linha converte item existente em recorrente ("Tornar recorrente")
- Modal "Gerenciar Recorrentes" permite criar novos diretamente, editar datas, encerrar
- Items projetados aparecem com visual diferenciado + botão ✓ Confirmar
- DELETE de recorrente remove só os lançamentos **futuros** com `status='projetado'`
- Campo `status`: `'realizado'` (confirmado/legado) ou `'projetado'` (gerado automaticamente)

---

## Lógica de negócio crítica

```python
# calcMonth() retorna dois grupos:
# - Realizado: status='realizado' OR status IS NULL (legado)
# - Projetado: todos os items (realizado + projetado)
# Campos: rev, cos, bal, margin, revProj, cosProj, balProj

# Projeção usa APENAS dados cadastrados — sem médias ou estimativas

# Em JS, usar ?? (nullish coalescing) para valores que podem ser 0:
# CERTO:   const h = S.projecaoHorizon ?? 0
# ERRADO:  const h = S.projecaoHorizon || 0   ← trata 0 como falsy
```

---

## Auditoria de segurança — resultados (2026-08-06)

A auditoria foi feita. Abaixo os achados **CRÍTICOS** a corrigir antes de revender:

### C-1: SECRET_KEY com fallback hardcoded [app.py linha 6]
```python
# PROBLEMA ATUAL:
SECRET = os.environ.get('SECRET_KEY', 'evolve-financeiro-2026-#@!')
# FIX:
SECRET = os.environ.get('SECRET_KEY')
if not SECRET:
    raise RuntimeError("SECRET_KEY environment variable is required")
```

### C-2: Senhas default hardcoded + reset automático [app.py linhas 171–181]
O código reseta senhas para `evolve2026` se o marker `pw_migration_v1` não estiver no audit_log.
Além disso, grava a senha em texto claro no audit_log.
**Fix**: remover o bloco `else` de reset automático inteiramente. Seed inicial OK mas sem reset.

### C-3: `/api/restore` sem RBAC no backend [app.py linha 875]
A restrição "só sócios podem restaurar" existe **apenas no JS frontend**.
Qualquer usuário com token válido pode chamar o endpoint via curl e apagar todos os dados.
**Fix**: adicionar coluna `role` em `users` e verificar no backend com decorator `@require_role('admin')`.

### A-1: Sem rate limiting no login [app.py linha 202]
**Fix**: `pip install flask-limiter` + `@limiter.limit("10 per minute")` no endpoint de login.

### A-2: XSS via `cat.label` em innerHTML [index.html ~linha 2872]
```javascript
// PROBLEMA:
sel.innerHTML = S.revCats.map(c => `<option value="${c.slug}">${c.label}</option>`).join('');
// FIX:
sel.innerHTML = S.revCats.map(c => `<option value="${esc(c.slug)}">${esc(c.label)}</option>`).join('');
```

### A-3: Sem security headers [app.py — ausência total]
**Fix**: adicionar `@app.after_request` com X-Frame-Options, CSP, X-Content-Type-Options, etc.

### A-4: xlsx-latest sem versão pinada [index.html linha 8]
```html
<!-- PROBLEMA: -->
<script src="https://cdn.sheetjs.com/xlsx-latest/package/dist/xlsx.full.min.js"></script>
<!-- FIX: usar versão específica OU baixar e servir localmente -->
<script src="https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js"></script>
```

### Confirmados como OK (não precisam de fix)
- SQL Injection: **não encontrado** — 100% das queries usam parâmetros `?`
- CSRF: **não vulnerável** — JWT no header, nunca em cookie
- SQLite WAL mode: recomendado adicionar `PRAGMA journal_mode = WAL` para robustez

---

## Pendências (por prioridade)

### 🔴 Antes de revender
- [ ] Aplicar fixes de segurança C-1, C-2, C-3, A-1, A-2, A-3, A-4 (detalhes acima)
- [ ] Adicionar coluna `role` em `users` + RBAC no backend

### 🟡 Melhorias importantes
- [ ] Backup automático diário (cron no Railway ou antes de cada deploy)
- [ ] SQLite WAL mode: `PRAGMA journal_mode = WAL` na função `db()`
- [ ] Senha mínima 12 caracteres (atualmente 6)

### 🟢 Desejável para V2
- [ ] Migrar para PostgreSQL (Railway oferece — mais robusto para produção)
- [ ] Multi-tenant: hoje é one-DB-per-instance; para múltiplos clientes, instâncias separadas no Railway

---

## O que NÃO fazer

- Não usar `flask-cors` — está no requirements.txt mas não é necessário; pode remover
- Não adicionar estimativas/médias na projeção — usar APENAS dados cadastrados (decisão do Hudson)
- Não usar `||` para checar valores que podem ser zero — usar `??`
- Não fazer git commit de `evolve.db` — está no .gitignore, banco local é só para testes
