# Evolve Financeiro 2026 — Contexto Completo para Claude

## O que é esse projeto

Ferramenta web de controle financeiro mensal da **Evolve** (agência de marketing digital dos sócios Hudson e Diego). Stack: **Flask + SQLite + HTML/CSS/JS puro** (sem framework frontend). Roda em `http://localhost:5050` localmente e vai ser deployado no Railway.

## Estrutura de arquivos

```
evolve-financeiro/
├── app.py                    # Backend Flask completo
├── evolve.db                 # Banco SQLite (NÃO versionar)
├── requirements.txt          # flask, bcrypt, PyJWT, gunicorn
├── Procfile                  # Para Railway: gunicorn
├── nixpacks.toml             # Config Railway/Nixpacks
├── runtime.txt               # python-3.11.9
├── .gitignore                # exclui venv/, *.db, etc.
├── Iniciar Financeiro.command # Script local macOS para rodar
└── static/
    └── index.html            # Frontend completo (SPA, ~1800 linhas)
```

## Como rodar localmente

```bash
cd evolve-financeiro
source venv/bin/activate      # ou: python3 -m venv venv && pip install -r requirements.txt
python app.py
# Acesse: http://localhost:5050
```

Se porta ocupada: `lsof -ti:5050 | xargs kill -9`

## Usuários e senhas

| Usuário | Senha | Perfil |
|---|---|---|
| `hudson` | `evolveads2026` | Sócio — acesso total |
| `diego` | `evolveads2026` | Sócio — acesso total |
| `financeiro` | `evolve2026` | Funcionária — sem restore |

Sócios (hudson/diego) veem botão extra "↩ Restaurar" no topbar.

## Banco de dados — tabelas

```sql
users          -- id, username, password_hash, name
months         -- id, year, month, regime, mei_das, prolabore_socio, notes
revenues       -- id, month_id, client_name, amount, received_date, category, is_new_client, sort_order
costs          -- id, month_id, name, amount, payment_date, category, sort_order
goals          -- id, name, target_value, metric, year, month, active
audit_log      -- id, ts, username, action, detail
```

## Configuração de ambiente (Railway)

Variáveis de ambiente necessárias:
- `DATA_DIR=/data` — onde o SQLite fica no volume persistente
- `SECRET_KEY=string-aleatória-segura`

O `DB_PATH` em `app.py` usa `os.environ.get('DATA_DIR', ...)` então funciona local e em produção.

## Funcionalidades implementadas

### Backend (app.py)
- `POST /api/auth/login` — login com JWT (7 dias)
- `GET  /api/auth/me` — usuário logado
- `POST /api/auth/change-password` — troca senha
- `GET  /api/months` — todos os meses com receitas e custos
- `GET  /api/months/<id>` — mês específico
- `PUT  /api/months/<id>` — atualiza regime, DAS, pró-labore, notas
- `POST /api/months/<id>/revenues` — adiciona receita
- `PUT  /api/revenues/<id>` — edita receita
- `DELETE /api/revenues/<id>` — exclui receita
- `POST /api/months/<id>/costs` — adiciona despesa
- `PUT  /api/costs/<id>` — edita despesa
- `DELETE /api/costs/<id>` — exclui despesa
- `POST /api/months/<id>/copy-previous` — copia receitas ou despesas do mês anterior
- `POST /api/months/<id>/import` — import bulk de linhas
- `GET  /api/search?q=` — busca em receitas e despesas
- `GET  /api/goals` — lista metas
- `POST /api/goals` — cria meta
- `PUT  /api/goals/<id>` — edita meta
- `DELETE /api/goals/<id>` — desativa meta
- `GET  /api/audit?limit=200` — histórico de alterações
- `GET  /api/backup` — download JSON completo (backup)
- `POST /api/restore` — restaura backup JSON
- `GET  /api/export` — export para Painel v4

### Frontend (static/index.html)
- **Login** com JWT, tema dark/light (persiste em localStorage)
- **Nav** com mês a mês (Jan/26 a Jan/27) + Busca + Histórico
- **Dashboard** — métricas anuais, metas com progresso, gráfico receita×despesas×saldo, distribuição por categoria, tabela resumo mensal
- **Aba de cada mês** — tabela de receitas (inline edit), tabela de despesas (inline edit), métricas do mês, distribuição por categoria
- **Copiar do mês anterior** — receitas ou despesas
- **Import** — duas abas: CSV paste e upload .xlsx/.csv (usa SheetJS CDN)
- **Categorias de receita**: servico, consultoria, recorrente, pontual, outros
- **Categorias de despesa**: pro-labore, pessoal, imposto, ferramentas, marketing, operacional, outros
- **Novo cliente** — botão ★/☆ Novo em cada receita, mostra métrica "Entrada clientes" no mês
- **Ticket médio** — calculado por mês e média anual
- **Metas** — modal 🎯, métrica (receita_mensal, receita_anual, margem, clientes, saldo), barra de progresso no dashboard
- **Bônus** — modal 💰, calcula por trimestre (Q1-Q4): trimestre lucrativo + caixa > 3 meses de reserva → 50% do resultado ÷ 2 sócios
- **Relatório PDF/PNG** — botão 📄 por mês e anual, abre nova janela formatada para impressão/PDF
- **Export → Painel v4** — download JSON
- **Busca** — aba de pesquisa global por nome de cliente/despesa
- **Histórico** — aba 📋 com log de todas as ações por data/hora/usuário
- **Backup** — botão 💾 no topbar baixa JSON completo
- **Restaurar** — botão ↩ (só hudson/diego) restaura a partir de JSON
- **Polling** — sync automático a cada 30s com badge de status
- **Salvo debounce** — edições inline salvam automaticamente 700ms após parar de digitar

## Cálculos financeiros

```python
# DAS Simples Nacional (progressivo por faixa de receita anual)
def dasEf(annual): ...

# Por mês:
rev = soma das receitas
cos = soma das despesas
bal = rev - cos
margin = bal/rev * 100
clients = qtd de receitas com valor > 0
avgTicket = rev / clients
newClients = qtd com is_new_client=1

# Bônus por trimestre:
# Condição 1: resultado do trimestre > 0
# Condição 2: caixa acumulado > média mensal de custos × 3
# Distribuição: resultado × 50% / 2 sócios
```

## Deploy Railway — passo a passo

1. `git init && git add . && git commit -m "initial"`
2. Cria repo **privado** no GitHub
3. Railway → New Project → Deploy from GitHub
4. Settings → Volumes → Add Volume → mount `/data`
5. Variables: `DATA_DIR=/data` e `SECRET_KEY=valor-secreto`
6. URL gerada é a URL definitiva (passar para Diego e Carla)

## Pendências / melhorias possíveis

- [ ] Migrar banco para PostgreSQL se Railway volume der problema
- [ ] Agendar backup automático diário (cron no Railway)
- [ ] Conectar com Painel v4 via import automático do JSON
- [ ] Adicionar gráfico de pizza por categoria (Chart.js)
- [ ] Notificação por email/Slack em eventos importantes
- [ ] 2027 — adicionar mais meses conforme necessário

## Contexto de negócio

- Regime atual: **MEI** (dois sócios, um CNPJ MEI cada)
- DAS MEI padrão: R$ 86,90/sócio/mês
- Pró-labore padrão: R$ 1.400/sócio/mês
- Bônus: trimestral se critérios atendidos
- Funcionária de financeiro: Carla (acesso à ferramenta mas não a dados estratégicos do Painel v4)
- O **Painel v4** é uma ferramenta separada de projeções — mantida separada por segurança e foco
