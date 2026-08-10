from flask import Flask, request, jsonify, send_from_directory
import sqlite3, bcrypt, jwt, datetime, os, secrets, time, re
from functools import wraps
from collections import defaultdict

app = Flask(__name__, static_folder='static')

_DATA    = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(_DATA, 'evolve.db')

# SECRET_KEY é obrigatório em produção (Railway define DATA_DIR).
# Em dev local, gera um segredo aleatório e persiste em .dev_secret (gitignored).
SECRET = os.environ.get('SECRET_KEY')
if not SECRET:
    if os.environ.get('DATA_DIR'):
        raise RuntimeError('SECRET_KEY environment variable is required')
    _dev = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dev_secret')
    if os.path.exists(_dev):
        SECRET = open(_dev).read().strip()
    else:
        SECRET = secrets.token_urlsafe(48)
        with open(_dev, 'w') as f: f.write(SECRET)
        os.chmod(_dev, 0o600)

ADMIN_USERS = ('hudson', 'diego')

MONTHS_PT   = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez']
MONTHS_FULL = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro']

def audit(username, action, detail=''):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with db() as c:
        c.execute('INSERT INTO audit_log (ts,username,action,detail) VALUES (?,?,?,?)', (ts, username, action, detail))
        c.commit()

# ── DB ────────────────────────────────────────────────────────────────────────

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('PRAGMA journal_mode = WAL')
    c.execute('PRAGMA busy_timeout = 5000')
    return c

# ── Security headers ──────────────────────────────────────────────────────────

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.sheetjs.com; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

@app.after_request
def security_headers(resp):
    resp.headers['Content-Security-Policy']   = CSP
    resp.headers['X-Content-Type-Options']    = 'nosniff'
    resp.headers['X-Frame-Options']           = 'DENY'
    resp.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']        = 'geolocation=(), microphone=(), camera=()'
    if request.is_secure:
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return resp

def init_db():
    with db() as c:
        c.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name          TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS months (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                year                INTEGER NOT NULL,
                month               INTEGER NOT NULL,
                regime              TEXT    DEFAULT 'MEI',
                mei_das             REAL    DEFAULT 86.90,
                prolabore_socio     REAL    DEFAULT 1400.00,
                notes               TEXT    DEFAULT '',
                UNIQUE(year, month)
            );
            CREATE TABLE IF NOT EXISTS revenues (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                month_id       INTEGER NOT NULL,
                client_name    TEXT    DEFAULT '',
                amount         REAL    DEFAULT 0,
                received_date  TEXT    DEFAULT '',
                category       TEXT    DEFAULT 'servico',
                is_new_client  INTEGER DEFAULT 0,
                sort_order     INTEGER DEFAULT 0,
                FOREIGN KEY(month_id) REFERENCES months(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS costs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                month_id      INTEGER NOT NULL,
                name          TEXT    DEFAULT '',
                amount        REAL    DEFAULT 0,
                payment_date  TEXT    DEFAULT '',
                category      TEXT    DEFAULT 'operacional',
                sort_order    INTEGER DEFAULT 0,
                FOREIGN KEY(month_id) REFERENCES months(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS goals (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT NOT NULL,
                target_value  REAL NOT NULL,
                metric        TEXT DEFAULT 'receita_mensal',
                year          INTEGER DEFAULT 2026,
                month         INTEGER DEFAULT 0,
                active        INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                username   TEXT NOT NULL,
                action     TEXT NOT NULL,
                detail     TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS categories (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                type       TEXT    NOT NULL,
                slug       TEXT    NOT NULL,
                label      TEXT    NOT NULL,
                color      TEXT    DEFAULT '#6b7fa3',
                sort_order INTEGER DEFAULT 0,
                active     INTEGER DEFAULT 1,
                UNIQUE(type, slug)
            );
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS receivables (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                description   TEXT    DEFAULT '',
                client_name   TEXT    DEFAULT '',
                amount        REAL    DEFAULT 0,
                due_date      TEXT    DEFAULT '',
                received_date TEXT    DEFAULT '',
                status        TEXT    DEFAULT 'pendente',
                category      TEXT    DEFAULT 'servico',
                notes         TEXT    DEFAULT '',
                created_at    TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS payables (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT    DEFAULT '',
                amount      REAL    DEFAULT 0,
                due_date    TEXT    DEFAULT '',
                paid_date   TEXT    DEFAULT '',
                status      TEXT    DEFAULT 'pendente',
                category    TEXT    DEFAULT 'operacional',
                notes       TEXT    DEFAULT '',
                created_at  TEXT    DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS recurring_items (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT    NOT NULL,
                description TEXT    NOT NULL,
                client_name TEXT    DEFAULT '',
                amount      REAL    DEFAULT 0,
                category    TEXT    DEFAULT 'servico',
                start_year  INTEGER NOT NULL,
                start_month INTEGER NOT NULL,
                end_year    INTEGER,
                end_month   INTEGER,
                active      INTEGER DEFAULT 1,
                created_at  TEXT    DEFAULT (datetime('now'))
            );
        ''')

        # Migrations for existing DBs
        for sql in [
            "ALTER TABLE revenues ADD COLUMN category TEXT DEFAULT 'servico'",
            "ALTER TABLE revenues ADD COLUMN is_new_client INTEGER DEFAULT 0",
            "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT '')",
            "ALTER TABLE revenues ADD COLUMN recurring_id INTEGER",
            "ALTER TABLE revenues ADD COLUMN status TEXT DEFAULT 'realizado'",
            "ALTER TABLE costs ADD COLUMN recurring_id INTEGER",
            "ALTER TABLE costs ADD COLUMN status TEXT DEFAULT 'realizado'",
            "ALTER TABLE recurring_items ADD COLUMN day_of_month INTEGER",
            "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
            # Regra que so vale na projecao: comissao de venda depende de fechar
            # negocio, entao nao deve aparecer lancada na aba do mes como se
            # fosse compromisso certo — so entra na projecao e no simulador.
            "ALTER TABLE cost_rules ADD COLUMN so_projecao INTEGER DEFAULT 0",
            # Regra que vale so para ALGUNS clientes: guarda quem tem hoje e se
            # cliente novo passa a ter. Sem isso, "R$ 100 por conta" so existia
            # na forma tudo-ou-nada.
            "ALTER TABLE cost_rules ADD COLUMN clientes TEXT DEFAULT ''",
            "ALTER TABLE cost_rules ADD COLUMN cobre_novos INTEGER DEFAULT 1",
            # Competencia em que a regra passa a valer. Sem isso, um custo novo
            # valia retroativamente em todo mes projetado.
            "ALTER TABLE cost_rules ADD COLUMN inicio_ano INTEGER",
            "ALTER TABLE cost_rules ADD COLUMN inicio_mes INTEGER",
            "ALTER TABLE cost_rules ADD COLUMN fim_ano INTEGER",
            "ALTER TABLE cost_rules ADD COLUMN fim_mes INTEGER",
            # De onde veio a recorrencia. Chave estavel para reimportar sem
            # duplicar: o Evolve Flow manda o id do cliente dele.
            "ALTER TABLE recurring_items ADD COLUMN origem TEXT DEFAULT ''",
            "ALTER TABLE recurring_items ADD COLUMN origem_chave TEXT DEFAULT ''",
            # Relatórios da Carla: anotação por lançamento e marcação de item não recorrente
            "ALTER TABLE revenues ADD COLUMN note TEXT DEFAULT ''",
            "ALTER TABLE costs    ADD COLUMN note TEXT DEFAULT ''",
            "ALTER TABLE revenues ADD COLUMN nonrecurring INTEGER DEFAULT 0",
            "ALTER TABLE costs    ADD COLUMN nonrecurring INTEGER DEFAULT 0",
            "ALTER TABLE revenues ADD COLUMN overridden INTEGER DEFAULT 0",
            "ALTER TABLE costs    ADD COLUMN overridden INTEGER DEFAULT 0",
            "ALTER TABLE recurring_items ADD COLUMN frequency TEXT DEFAULT 'monthly'",
            "ALTER TABLE recurring_items ADD COLUMN month_of_year INTEGER",
            # Blocos de texto dos relatórios (resumo, conclusão, observações).
            # key no formato 'mensal:2026-07:resumo' ou 'semanal:2026-08-03:obs'
            "CREATE TABLE IF NOT EXISTS report_texts (key TEXT PRIMARY KEY, value TEXT DEFAULT '', updated_at TEXT DEFAULT (datetime('now')))",
            # Regras de custo em degrau: fixo, por cliente ou % do 1o pagamento,
            # cada uma valendo dentro de uma faixa de numero de clientes.
            """CREATE TABLE IF NOT EXISTS cost_rules (
                 id           INTEGER PRIMARY KEY AUTOINCREMENT,
                 nome         TEXT NOT NULL,
                 tipo         TEXT NOT NULL DEFAULT 'fixo',
                 valor        REAL DEFAULT 0,
                 min_clientes INTEGER DEFAULT 0,
                 max_clientes INTEGER,
                 categoria    TEXT DEFAULT 'operacional',
                 ativo        INTEGER DEFAULT 1,
                 created_at   TEXT DEFAULT (datetime('now')))""",
        ]:
            try: c.execute(sql)
            except Exception: pass

        # Seed categories on first run
        if c.execute('SELECT COUNT(*) FROM categories').fetchone()[0] == 0:
            for tp, slug, label, color, order in [
                ('revenue','servico','Serviço','#6D5CE7',1),
                ('revenue','consultoria','Consultoria','#A06AF6',2),
                ('revenue','recorrente','Recorrente','#7E52A0',3),
                ('revenue','pontual','Pontual','#C4B0F8',4),
                ('revenue','outros','Outros','#9A96B8',5),
                ('cost','pro-labore','Pró-labore','#5B4BD1',1),
                ('cost','pessoal','Pessoal','#8B7BFF',2),
                ('cost','imposto','Imposto','#29274C',3),
                ('cost','ferramentas','Ferramentas','#A06AF6',4),
                ('cost','marketing','Marketing','#C4B0F8',5),
                ('cost','operacional','Operacional','#7E52A0',6),
                ('cost','outros','Outros','#9A96B8',7),
            ]:
                c.execute('INSERT OR IGNORE INTO categories (type,slug,label,color,sort_order) VALUES (?,?,?,?,?)',
                    (tp, slug, label, color, order))
        c.execute("INSERT OR IGNORE INTO settings (key,value) VALUES ('saldo_inicial','0')")

        # Seed inicial: só cria usuários se o banco estiver vazio.
        # NUNCA resetar senha de usuário existente — troca é feita via /api/auth/change-password.
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            seed_pw = os.environ.get('SEED_PASSWORD') or secrets.token_urlsafe(12)
            for uname, name in [('hudson','Hudson'),('diego','Diego'),('financeiro','Financeiro')]:
                h = bcrypt.hashpw(seed_pw.encode(), bcrypt.gensalt()).decode()
                role = 'admin' if uname in ADMIN_USERS else 'user'
                c.execute('INSERT INTO users (username,password_hash,name,role) VALUES (?,?,?,?)', (uname,h,name,role))
            print(f'[init] Usuários criados. Senha inicial: {seed_pw}  <- troque no primeiro acesso', flush=True)

        # Atribui role=admin aos sócios uma única vez (bancos já existentes)
        done = c.execute("SELECT value FROM settings WHERE key='role_migration_v1'").fetchone()
        if not done:
            c.executemany('UPDATE users SET role=? WHERE username=?',
                [('admin', u) for u in ADMIN_USERS])
            c.execute("UPDATE users SET role='user' WHERE role IS NULL OR role=''")
            c.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('role_migration_v1','1')")

        # Paleta Evolve nas categorias (uma única vez).
        # Só troca quem ainda está com a cor padrão ANTIGA — cor customizada é preservada.
        if not c.execute("SELECT value FROM settings WHERE key='cat_palette_evolve_v1'").fetchone():
            for tp, slug, old, new in [
                ('revenue','servico',    '#00e5a0','#6D5CE7'),
                ('revenue','consultoria','#4f9eff','#A06AF6'),
                ('revenue','recorrente', '#a78bfa','#7E52A0'),
                ('revenue','pontual',    '#f5a623','#C4B0F8'),
                ('revenue','outros',     '#6b7fa3','#9A96B8'),
                ('cost','pro-labore',    '#a78bfa','#5B4BD1'),
                ('cost','pessoal',       '#4f9eff','#8B7BFF'),
                ('cost','imposto',       '#ff5757','#29274C'),
                ('cost','ferramentas',   '#f5a623','#A06AF6'),
                ('cost','marketing',     '#2dd4bf','#C4B0F8'),
                ('cost','operacional',   '#6b7fa3','#7E52A0'),
                ('cost','outros',        '#6b7fa3','#9A96B8'),
            ]:
                c.execute('UPDATE categories SET color=? WHERE type=? AND slug=? AND lower(color)=lower(?)',
                          (new, tp, slug, old))
            c.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('cat_palette_evolve_v1','1')")

        for year, month in [(2026,m) for m in range(1,13)] + [(2027,1)]:
            c.execute('INSERT OR IGNORE INTO months (year,month) VALUES (?,?)', (year,month))
        c.commit()

init_db()

# ── Auth ──────────────────────────────────────────────────────────────────────

def auth(f):
    @wraps(f)
    def wrap(*a, **kw):
        token = request.headers.get('Authorization','').replace('Bearer ','')
        if not token: return jsonify({'error':'Token necessário'}), 401
        try: request.user = jwt.decode(token, SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError: return jsonify({'error':'Sessão expirada'}), 401
        except Exception: return jsonify({'error':'Token inválido'}), 401
        return f(*a, **kw)
    return wrap

def user_role(user_id):
    """Lê o role do banco — nunca confia no que veio no token."""
    with db() as c:
        r = c.execute('SELECT role FROM users WHERE id=?', (user_id,)).fetchone()
    return (r['role'] if r and r['role'] else 'user')

def require_role(role):
    def deco(f):
        @wraps(f)
        @auth
        def wrap(*a, **kw):
            if user_role(request.user.get('user_id')) != role:
                audit(request.user.get('username','?'), 'acesso_negado', f'{request.path} exige role={role}')
                return jsonify({'error':'Permissão negada'}), 403
            return f(*a, **kw)
        return wrap
    return deco

# ── Rate limit (in-process, sem dependência externa) ──────────────────────────

_hits = defaultdict(list)

def rate_limit(key, limit, window):
    """True se a requisição é permitida. Janela deslizante por chave."""
    now = time.time()
    bucket = [t for t in _hits[key] if now - t < window]
    if len(_hits) > 5000: _hits.clear()   # guarda contra crescimento indefinido
    if len(bucket) >= limit:
        _hits[key] = bucket
        return False
    bucket.append(now)
    _hits[key] = bucket
    return True

def client_ip():
    fwd = request.headers.get('X-Forwarded-For','')
    return fwd.split(',')[0].strip() if fwd else (request.remote_addr or '?')

@app.post('/api/auth/login')
def login():
    d = request.get_json() or {}
    uname = d.get('username','').strip().lower()
    pw    = d.get('password','')
    if not rate_limit(f'login:{client_ip()}', 10, 60) or not rate_limit(f'login:u:{uname}', 10, 60):
        audit(uname or '?', 'rate_limit', f'IP {client_ip()} — excesso de tentativas de login')
        return jsonify({'error':'Muitas tentativas. Aguarde 1 minuto.'}), 429
    with db() as c:
        user = c.execute('SELECT * FROM users WHERE username=?',(uname,)).fetchone()
    if not user or not bcrypt.checkpw(pw.encode(), user['password_hash'].encode()):
        return jsonify({'error':'Usuário ou senha incorretos'}), 401
    role = user['role'] if user['role'] else 'user'
    token = jwt.encode({
        'user_id':user['id'], 'username':user['username'], 'name':user['name'], 'role':role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, SECRET, algorithm='HS256')
    audit(user['username'], 'login', 'Acesso ao sistema')
    return jsonify({'token':token, 'name':user['name'], 'username':user['username'], 'role':role})

@app.get('/api/auth/me')
@auth
def me():
    return jsonify({**request.user, 'role': user_role(request.user.get('user_id'))})

@app.post('/api/auth/change-password')
@auth
def change_pw():
    d = request.get_json() or {}
    if len(d.get('new','')) < 12:
        return jsonify({'error':'Senha deve ter pelo menos 12 caracteres'}), 400
    with db() as c:
        user = c.execute('SELECT * FROM users WHERE id=?',(request.user['user_id'],)).fetchone()
        if not bcrypt.checkpw(d.get('current','').encode(), user['password_hash'].encode()):
            return jsonify({'error':'Senha atual incorreta'}), 401
        h = bcrypt.hashpw(d['new'].encode(), bcrypt.gensalt()).decode()
        c.execute('UPDATE users SET password_hash=? WHERE id=?',(h, user['id']))
        c.commit()
    return jsonify({'success':True})

# ── Months ────────────────────────────────────────────────────────────────────

def month_full(c, mid):
    m = c.execute('SELECT * FROM months WHERE id=?',(mid,)).fetchone()
    if not m: return None
    d = dict(m)
    d['revenues'] = [dict(r) for r in c.execute('SELECT * FROM revenues WHERE month_id=? ORDER BY sort_order,id',(mid,)).fetchall()]
    d['costs']    = [dict(x) for x in c.execute('SELECT * FROM costs    WHERE month_id=? ORDER BY sort_order,id',(mid,)).fetchall()]
    return d

@app.get('/api/months')
@auth
def get_months():
    with db() as c:
        months = c.execute('SELECT * FROM months ORDER BY year,month').fetchall()
        return jsonify([month_full(c, m['id']) for m in months])

@app.get('/api/months/<int:mid>')
@auth
def get_month(mid):
    with db() as c:
        d = month_full(c, mid)
    if not d: return jsonify({'error':'Não encontrado'}), 404
    return jsonify(d)

@app.put('/api/months/<int:mid>')
@auth
def update_month(mid):
    d = request.get_json() or {}
    with db() as c:
        c.execute('UPDATE months SET regime=?,mei_das=?,prolabore_socio=?,notes=? WHERE id=?',
            (d.get('regime','MEI'), d.get('mei_das',86.90), d.get('prolabore_socio',1400.0), d.get('notes',''), mid))
        c.commit()
    return jsonify({'success':True})

# ── Revenues ──────────────────────────────────────────────────────────────────

@app.post('/api/months/<int:mid>/revenues')
@auth
def add_revenue(mid):
    d = request.get_json() or {}
    with db() as c:
        month = c.execute('SELECT year,month FROM months WHERE id=?',(mid,)).fetchone()
        cur = c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order,status) VALUES (?,?,?,?,?,?,?,?)',
            (mid, d.get('client_name',''), d.get('amount',0), d.get('received_date',''),
             d.get('category','servico'), d.get('is_new_client',0), d.get('sort_order',999),
             'projetado' if d.get('status')=='projetado' else 'realizado'))
        c.commit()
        row = c.execute('SELECT * FROM revenues WHERE id=?',(cur.lastrowid,)).fetchone()
    mref = f"{MONTHS_PT[month['month']-1]}/{month['year']}" if month else str(mid)
    audit(request.user['username'], 'receita_adicionada', f"{mref} — {d.get('client_name','')}")
    return jsonify(dict(row))

def partial_update(table, allowed, payload, row_id):
    """Atualiza SÓ os campos presentes no payload.

    Update fixo apagaria campos novos (note, nonrecurring) toda vez que uma
    tela antiga salvasse sem envia-los.
    """
    sets, vals = [], []
    for col, cast in allowed.items():
        if col in payload:
            sets.append(f'{col}=?')
            vals.append(cast(payload[col]))
    if not sets:
        return False
    vals.append(row_id)
    with db() as c:
        c.execute(f'UPDATE {table} SET {",".join(sets)} WHERE id=?', vals)
        c.commit()
    return True

def _s(v):    return '' if v is None else str(v)
def _f(v):
    try: return float(v or 0)
    except (TypeError, ValueError): return 0.0
def _b(v):    return 1 if v else 0

# status entra na whitelist com validacao propria: um payload torto gravaria
# qualquer string e quebraria os filtros de realizado/projetado espalhados pela
# aplicacao inteira.
def _st(v):
    return 'projetado' if _s(v) == 'projetado' else 'realizado'

REVENUE_COLS = {'client_name':_s,'amount':_f,'received_date':_s,'category':_s,
                'is_new_client':_b,'note':_s,'nonrecurring':_b,'overridden':_b,'status':_st}
COST_COLS    = {'name':_s,'amount':_f,'payment_date':_s,'category':_s,
                'note':_s,'nonrecurring':_b,'overridden':_b,'status':_st}

@app.put('/api/revenues/<int:rid>')
@auth
def update_revenue(rid):
    d = request.get_json() or {}
    if 'amount' in d:
        with db() as c:
            cur = c.execute('SELECT amount, recurring_id FROM revenues WHERE id=?', (rid,)).fetchone()
        if cur and cur['recurring_id'] and abs(_f(cur['amount']) - _f(d['amount'])) > 0.001:
            d['overridden'] = 1
    if not partial_update('revenues', REVENUE_COLS, d, rid):
        return jsonify({'error':'Nada para atualizar'}), 400
    audit(request.user['username'], 'receita_editada', f"ID {rid} — {d.get('client_name','')} R${_f(d.get('amount')):.2f}")
    return jsonify({'success':True})

@app.delete('/api/revenues/<int:rid>')
@auth
def delete_revenue(rid):
    with db() as c:
        row = c.execute('SELECT r.client_name, r.amount, m.year, m.month FROM revenues r JOIN months m ON r.month_id=m.id WHERE r.id=?',(rid,)).fetchone()
        c.execute('DELETE FROM revenues WHERE id=?',(rid,))
        c.commit()
    detail = f"{MONTHS_PT[row['month']-1]}/{row['year']} — {row['client_name']} R${row['amount']:.2f}" if row else str(rid)
    audit(request.user['username'], 'receita_excluída', detail)
    return jsonify({'success':True})

# ── Costs ─────────────────────────────────────────────────────────────────────

@app.post('/api/months/<int:mid>/costs')
@auth
def add_cost(mid):
    d = request.get_json() or {}
    with db() as c:
        month = c.execute('SELECT year,month FROM months WHERE id=?',(mid,)).fetchone()
        cur = c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order,status) VALUES (?,?,?,?,?,?,?)',
            (mid, d.get('name',''), d.get('amount',0), d.get('payment_date',''),
             d.get('category','operacional'), d.get('sort_order',999),
             'projetado' if d.get('status')=='projetado' else 'realizado'))
        c.commit()
        row = c.execute('SELECT * FROM costs WHERE id=?',(cur.lastrowid,)).fetchone()
    mref = f"{MONTHS_PT[month['month']-1]}/{month['year']}" if month else str(mid)
    audit(request.user['username'], 'despesa_adicionada', f"{mref} — {d.get('name','')}")
    return jsonify(dict(row))

@app.put('/api/costs/<int:cid>')
@auth
def update_cost(cid):
    d = request.get_json() or {}
    if 'amount' in d:
        with db() as c:
            cur = c.execute('SELECT amount, recurring_id FROM costs WHERE id=?', (cid,)).fetchone()
        if cur and cur['recurring_id'] and abs(_f(cur['amount']) - _f(d['amount'])) > 0.001:
            d['overridden'] = 1
    if not partial_update('costs', COST_COLS, d, cid):
        return jsonify({'error':'Nada para atualizar'}), 400
    audit(request.user['username'], 'despesa_editada', f"ID {cid} — {d.get('name','')} R${_f(d.get('amount')):.2f}")
    return jsonify({'success':True})

@app.delete('/api/costs/<int:cid>')
@auth
def delete_cost(cid):
    with db() as c:
        row = c.execute('SELECT c.name, c.amount, m.year, m.month FROM costs c JOIN months m ON c.month_id=m.id WHERE c.id=?',(cid,)).fetchone()
        c.execute('DELETE FROM costs WHERE id=?',(cid,))
        c.commit()
    detail = f"{MONTHS_PT[row['month']-1]}/{row['year']} — {row['name']} R${row['amount']:.2f}" if row else str(cid)
    audit(request.user['username'], 'despesa_excluída', detail)
    return jsonify({'success':True})

# ── Copy previous ──────────────────────────────────────────────────────────────

@app.post('/api/months/<int:mid>/copy-previous')
@auth
def copy_previous(mid):
    d       = request.get_json() or {}
    mode    = d.get('mode','replace')
    kind    = d.get('kind','revenues')  # revenues or costs
    with db() as c:
        cur = c.execute('SELECT * FROM months WHERE id=?',(mid,)).fetchone()
        if not cur: return jsonify({'error':'Mês não encontrado'}),404
        y,m = cur['year'], cur['month']
        prev_y, prev_m = (y-1,12) if m==1 else (y, m-1)
        prev = c.execute('SELECT * FROM months WHERE year=? AND month=?',(prev_y,prev_m)).fetchone()
        if not prev: return jsonify({'error':'Mês anterior sem dados'}),404

        if kind == 'revenues':
            prevs = c.execute("SELECT * FROM revenues WHERE month_id=? AND (status IS NULL OR status='realizado') ORDER BY sort_order,id",(prev['id'],)).fetchall()
            if mode=='replace': c.execute('DELETE FROM revenues WHERE month_id=?',(mid,))
            for r in prevs:
                c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order) VALUES (?,?,?,?,?,?,?)',
                    (mid, r['client_name'], r['amount'], '', r['category'], 0, r['sort_order']))
            c.commit()
            rows = [dict(r) for r in c.execute('SELECT * FROM revenues WHERE month_id=? ORDER BY sort_order,id',(mid,)).fetchall()]
        else:
            prevs = c.execute("SELECT * FROM costs WHERE month_id=? AND (status IS NULL OR status='realizado') ORDER BY sort_order,id",(prev['id'],)).fetchall()
            if mode=='replace': c.execute('DELETE FROM costs WHERE month_id=?',(mid,))
            for r in prevs:
                c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order) VALUES (?,?,?,?,?,?)',
                    (mid, r['name'], r['amount'], '', r['category'], r['sort_order']))
            c.commit()
            rows = [dict(r) for r in c.execute('SELECT * FROM costs WHERE month_id=? ORDER BY sort_order,id',(mid,)).fetchall()]

    mref = f"{MONTHS_PT[m-1]}/{y}"
    audit(request.user['username'], f'cópia_de_{kind}', f"{mref} — modo {mode}")
    return jsonify(rows)

# ── Bulk import ────────────────────────────────────────────────────────────────

@app.post('/api/months/<int:mid>/import')
@auth
def import_data(mid):
    d    = request.get_json() or {}
    kind = d.get('kind','revenues')
    rows = d.get('rows', [])
    with db() as c:
        if kind == 'revenues':
            for row in rows:
                c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order) VALUES (?,?,?,?,?,?,?)',
                    (mid, row.get('client_name',''), float(row.get('amount',0) or 0),
                     row.get('received_date',''), row.get('category','servico'),
                     1 if row.get('is_new_client') else 0, 999))
        else:
            for row in rows:
                c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order) VALUES (?,?,?,?,?,?)',
                    (mid, row.get('name',''), float(row.get('amount',0) or 0),
                     row.get('payment_date',''), row.get('category','operacional'), 999))
        c.commit()
    with db() as c:
        month = c.execute('SELECT year,month FROM months WHERE id=?',(mid,)).fetchone()
    mref = f"{MONTHS_PT[month['month']-1]}/{month['year']}" if month else str(mid)
    audit(request.user['username'], f'import_{kind}', f"{mref} — {len(rows)} linhas")
    return jsonify({'success':True, 'imported':len(rows)})

# ── Search ─────────────────────────────────────────────────────────────────────

@app.get('/api/search')
@auth
def search():
    q = request.args.get('q','').strip()
    if len(q) < 2: return jsonify({'revenues':[],'costs':[]})
    like = f'%{q}%'
    with db() as c:
        revs  = c.execute('SELECT r.*,m.year,m.month FROM revenues r JOIN months m ON r.month_id=m.id WHERE r.client_name LIKE ? ORDER BY m.year,m.month',(like,)).fetchall()
        costs = c.execute('SELECT c.*,m.year,m.month FROM costs c JOIN months m ON c.month_id=m.id WHERE c.name LIKE ? ORDER BY m.year,m.month',(like,)).fetchall()
    return jsonify({'revenues':[dict(r) for r in revs], 'costs':[dict(c) for c in costs]})

# ── Goals ─────────────────────────────────────────────────────────────────────

@app.get('/api/goals')
@auth
def get_goals():
    with db() as c:
        goals = c.execute('SELECT * FROM goals WHERE active=1 ORDER BY id').fetchall()
    return jsonify([dict(g) for g in goals])

@app.post('/api/goals')
@auth
def create_goal():
    d = request.get_json() or {}
    with db() as c:
        cur = c.execute('INSERT INTO goals (name,target_value,metric,year,month) VALUES (?,?,?,?,?)',
            (d['name'], float(d['target_value']), d.get('metric','receita_mensal'), d.get('year',2026), d.get('month',0)))
        c.commit()
        g = c.execute('SELECT * FROM goals WHERE id=?',(cur.lastrowid,)).fetchone()
    return jsonify(dict(g))

@app.put('/api/goals/<int:gid>')
@auth
def update_goal(gid):
    d = request.get_json() or {}
    with db() as c:
        c.execute('UPDATE goals SET name=?,target_value=?,metric=?,month=? WHERE id=?',
            (d['name'], float(d['target_value']), d.get('metric','receita_mensal'), d.get('month',0), gid))
        c.commit()
    return jsonify({'success':True})

@app.delete('/api/goals/<int:gid>')
@auth
def delete_goal(gid):
    with db() as c:
        c.execute('UPDATE goals SET active=0 WHERE id=?',(gid,))
        c.commit()
    return jsonify({'success':True})

# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get('/api/audit')
@auth
def get_audit():
    limit = min(int(request.args.get('limit', 100)), 500)
    with db() as c:
        rows = c.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?',(limit,)).fetchall()
    return jsonify([dict(r) for r in rows])

# ── Categories ────────────────────────────────────────────────────────────────

@app.get('/api/categories')
@auth
def get_categories():
    with db() as c:
        rows = c.execute('SELECT * FROM categories WHERE active=1 ORDER BY type,sort_order,id').fetchall()
    return jsonify({
        'revenue': [dict(r) for r in rows if r['type']=='revenue'],
        'cost':    [dict(r) for r in rows if r['type']=='cost'],
    })

@app.post('/api/categories')
@auth
def create_category():
    d     = request.get_json() or {}
    tp    = d.get('type','revenue')
    slug  = d.get('slug','').strip().lower().replace(' ','-')
    label = d.get('label','').strip()
    color = d.get('color','#6b7fa3')
    if not slug or not label:
        return jsonify({'error':'Slug e label são obrigatórios'}), 400
    with db() as c:
        try:
            cur = c.execute('INSERT INTO categories (type,slug,label,color,sort_order) VALUES (?,?,?,?,?)',
                (tp, slug, label, color, 99))
            c.commit()
            row = c.execute('SELECT * FROM categories WHERE id=?', (cur.lastrowid,)).fetchone()
        except Exception:
            return jsonify({'error': f'Categoria com slug "{slug}" já existe'}), 400
    return jsonify(dict(row))

@app.put('/api/categories/<int:cid>')
@auth
def update_category(cid):
    d = request.get_json() or {}
    with db() as c:
        c.execute('UPDATE categories SET label=?,color=? WHERE id=?',
            (d.get('label',''), d.get('color','#6b7fa3'), cid))
        c.commit()
    return jsonify({'success': True})

@app.delete('/api/categories/<int:cid>')
@auth
def delete_category(cid):
    with db() as c:
        c.execute('UPDATE categories SET active=0 WHERE id=?', (cid,))
        c.commit()
    return jsonify({'success': True})

# ── Settings ───────────────────────────────────────────────────────────────────

@app.get('/api/settings')
@auth
def get_settings():
    with db() as c:
        rows = c.execute('SELECT * FROM settings').fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.put('/api/settings')
@auth
def update_settings():
    d = request.get_json() or {}
    with db() as c:
        for key, value in d.items():
            c.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', (key, str(value)))
        c.commit()
    return jsonify({'success': True})

# ── Receivables (Contas a Receber) ─────────────────────────────────────────────

@app.get('/api/receivables')
@auth
def get_receivables():
    status = request.args.get('status', '')
    with db() as c:
        if status:
            rows = c.execute('SELECT * FROM receivables WHERE status=? ORDER BY due_date,id', (status,)).fetchall()
        else:
            rows = c.execute('SELECT * FROM receivables ORDER BY due_date,id').fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/receivables')
@auth
def create_receivable():
    d = request.get_json() or {}
    with db() as c:
        cur = c.execute(
            'INSERT INTO receivables (description,client_name,amount,due_date,category,notes) VALUES (?,?,?,?,?,?)',
            (d.get('description',''), d.get('client_name',''), float(d.get('amount',0)),
             d.get('due_date',''), d.get('category','servico'), d.get('notes','')))
        c.commit()
        row = c.execute('SELECT * FROM receivables WHERE id=?', (cur.lastrowid,)).fetchone()
    audit(request.user['username'], 'conta_receber_adicionada', d.get('description',''))
    return jsonify(dict(row))

@app.put('/api/receivables/<int:rid>')
@auth
def update_receivable(rid):
    d = request.get_json() or {}
    with db() as c:
        c.execute(
            'UPDATE receivables SET description=?,client_name=?,amount=?,due_date=?,received_date=?,status=?,category=?,notes=? WHERE id=?',
            (d.get('description',''), d.get('client_name',''), float(d.get('amount',0)),
             d.get('due_date',''), d.get('received_date',''), d.get('status','pendente'),
             d.get('category','servico'), d.get('notes',''), rid))
        c.commit()
    audit(request.user['username'], 'conta_receber_editada', f"ID {rid} — {d.get('description','')}")
    return jsonify({'success': True})

@app.delete('/api/receivables/<int:rid>')
@auth
def delete_receivable(rid):
    with db() as c:
        c.execute('DELETE FROM receivables WHERE id=?', (rid,))
        c.commit()
    audit(request.user['username'], 'conta_receber_excluída', f"ID {rid}")
    return jsonify({'success': True})

# ── Payables (Contas a Pagar) ──────────────────────────────────────────────────

@app.get('/api/payables')
@auth
def get_payables():
    status = request.args.get('status', '')
    with db() as c:
        if status:
            rows = c.execute('SELECT * FROM payables WHERE status=? ORDER BY due_date,id', (status,)).fetchall()
        else:
            rows = c.execute('SELECT * FROM payables ORDER BY due_date,id').fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/payables')
@auth
def create_payable():
    d = request.get_json() or {}
    with db() as c:
        cur = c.execute(
            'INSERT INTO payables (description,amount,due_date,category,notes) VALUES (?,?,?,?,?)',
            (d.get('description',''), float(d.get('amount',0)), d.get('due_date',''),
             d.get('category','operacional'), d.get('notes','')))
        c.commit()
        row = c.execute('SELECT * FROM payables WHERE id=?', (cur.lastrowid,)).fetchone()
    audit(request.user['username'], 'conta_pagar_adicionada', d.get('description',''))
    return jsonify(dict(row))

@app.put('/api/payables/<int:pid>')
@auth
def update_payable(pid):
    d = request.get_json() or {}
    with db() as c:
        c.execute(
            'UPDATE payables SET description=?,amount=?,due_date=?,paid_date=?,status=?,category=?,notes=? WHERE id=?',
            (d.get('description',''), float(d.get('amount',0)), d.get('due_date',''),
             d.get('paid_date',''), d.get('status','pendente'),
             d.get('category','operacional'), d.get('notes',''), pid))
        c.commit()
    audit(request.user['username'], 'conta_pagar_editada', f"ID {pid} — {d.get('description','')}")
    return jsonify({'success': True})

@app.delete('/api/payables/<int:pid>')
@auth
def delete_payable(pid):
    with db() as c:
        c.execute('DELETE FROM payables WHERE id=?', (pid,))
        c.commit()
    audit(request.user['username'], 'conta_pagar_excluída', f"ID {pid}")
    return jsonify({'success': True})

# ── Recurring Items ────────────────────────────────────────────────────────────

def _gen_recurring_rows(c, item):
    """Generate projected revenue/cost rows for a recurring_item across matching months."""
    months = c.execute('SELECT * FROM months ORDER BY year,month').fetchall()
    sy, sm = item['start_year'], item['start_month']
    ey, em = item['end_year'], item['end_month']
    # aceita dict ou sqlite3.Row: Row nao tem .get() e todos os chamadores
    # precisariam lembrar de converter, o que ja falhou uma vez
    def _campo(k, padrao=None):
        try:    v = item[k]
        except (IndexError, KeyError, TypeError): return padrao
        return padrao if v is None else v
    freq = _campo('frequency', 'monthly') or 'monthly'
    moy  = _campo('month_of_year')   # só para frequência anual
    for m in months:
        y, mo = m['year'], m['month']
        after_start = (y > sy) or (y == sy and mo >= sm)
        if ey and em:
            before_end = (y < ey) or (y == ey and mo <= em)
        else:
            before_end = True
        if not after_start or not before_end:
            continue
        # Frequência anual: só gera no mês específico de cada ano
        if freq == 'annual' and moy and mo != moy:
            continue
        iid = item['id']
        if item['type'] == 'revenue':
            ex = c.execute('SELECT id FROM revenues WHERE month_id=? AND recurring_id=?', (m['id'], iid)).fetchone()
            if not ex:
                c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order,recurring_id,status) VALUES (?,?,?,?,?,?,?,?,?)',
                    (m['id'], item['client_name'] or item['description'], item['amount'], '', item['category'], 0, 999, iid, 'projetado'))
        else:
            ex = c.execute('SELECT id FROM costs WHERE month_id=? AND recurring_id=?', (m['id'], iid)).fetchone()
            if not ex:
                c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order,recurring_id,status) VALUES (?,?,?,?,?,?,?,?)',
                    (m['id'], item['description'], item['amount'], '', item['category'], 999, iid, 'projetado'))

@app.get('/api/recurring')
@auth
def get_recurring():
    with db() as c:
        rows = c.execute('SELECT * FROM recurring_items WHERE active=1 ORDER BY type,id').fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/recurring')
@auth
def create_recurring():
    d = request.get_json() or {}
    tp   = d.get('type', 'revenue')
    desc = d.get('description', '').strip()
    if not desc:
        return jsonify({'error': 'Descrição obrigatória'}), 400
    freq = d.get('frequency','monthly')
    if freq not in ('monthly','annual'): freq = 'monthly'
    moy  = int(d['month_of_year']) if d.get('month_of_year') else None
    if freq != 'annual': moy = None
    if moy is not None and not (1 <= moy <= 12): moy = None
    # anual sem mes definido nao teria onde gerar: cai no mes de inicio
    if freq == 'annual' and not moy: moy = int(d.get('start_month', 1))
    with db() as c:
        cur = c.execute(
            'INSERT INTO recurring_items (type,description,client_name,amount,category,start_year,start_month,end_year,end_month,day_of_month,frequency,month_of_year) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
            (tp, desc, d.get('client_name',''), float(d.get('amount',0)),
             d.get('category','servico' if tp=='revenue' else 'operacional'),
             int(d.get('start_year',2026)), int(d.get('start_month',1)),
             d.get('end_year') or None, d.get('end_month') or None,
             int(d['day_of_month']) if d.get('day_of_month') else None,
             freq, moy))
        c.commit()
        item = dict(c.execute('SELECT * FROM recurring_items WHERE id=?',(cur.lastrowid,)).fetchone())
        _gen_recurring_rows(c, item)
        c.commit()
        tabela = 'revenues' if tp == 'revenue' else 'costs'
        item['linhas_geradas'] = c.execute(
            f'SELECT COUNT(*) FROM {tabela} WHERE recurring_id=?', (item['id'],)).fetchone()[0]
    audit(request.user['username'], 'recorrente_criado', desc)
    return jsonify(item)

@app.put('/api/recurring/<int:rid>')
@auth
def update_recurring(rid):
    d = request.get_json() or {}
    with db() as c:
        item = c.execute('SELECT * FROM recurring_items WHERE id=?',(rid,)).fetchone()
        if not item: return jsonify({'error':'Não encontrado'}),404
        new_ey   = d.get('end_year') or None
        new_em   = d.get('end_month') or None
        new_amt  = float(d.get('amount', item['amount']))
        new_desc = d.get('description', item['description'])
        new_client = d.get('client_name', item['client_name'])
        new_cat  = d.get('category', item['category'])
        new_dom  = int(d['day_of_month']) if d.get('day_of_month') else None
        # sqlite3.Row nao tem .get() — indexar por nome e o acesso correto, e a
        # coluna pode nao existir em base antiga, por isso o try
        try:    _freq_atual = item['frequency'] or 'monthly'
        except (IndexError, KeyError): _freq_atual = 'monthly'
        try:    _moy_atual = item['month_of_year']
        except (IndexError, KeyError): _moy_atual = None
        new_freq = d.get('frequency', _freq_atual)
        if new_freq not in ('monthly','annual'): new_freq = 'monthly'
        new_moy  = int(d['month_of_year']) if d.get('month_of_year') else _moy_atual
        if new_freq != 'annual': new_moy = None
        if new_moy is not None and not (1 <= new_moy <= 12): new_moy = None
        # Uma anual so existe no mes-alvo, entao a vigencia tem de comecar nele.
        # Sem isto, trocar mensal->anual mantinha o inicio no mes antigo e o item
        # desaparecia de todos os meses sem dizer por que.
        new_sy = int(d.get('start_year',  item['start_year']))
        new_sm = int(d.get('start_month', item['start_month']))
        if new_freq == 'annual' and new_moy:
            if new_moy < new_sm:
                new_sy += 1      # a proxima ocorrencia e no ano seguinte
            new_sm = new_moy
        c.execute('UPDATE recurring_items SET description=?,client_name=?,amount=?,category=?,start_year=?,start_month=?,end_year=?,end_month=?,day_of_month=?,frequency=?,month_of_year=? WHERE id=?',
            (new_desc, new_client, new_amt, new_cat,

             new_sy, new_sm,
             new_ey, new_em, new_dom, new_freq, new_moy, rid))
        tp = item['type']
        if tp == 'revenue':
            c.execute("UPDATE revenues SET amount=?,category=?,client_name=? WHERE recurring_id=? AND status='projetado'",
                (new_amt, new_cat, new_client or new_desc, rid))
            if new_ey and new_em:
                for m in c.execute("SELECT id FROM months WHERE year>? OR (year=? AND month>?)",(new_ey,new_ey,new_em)).fetchall():
                    c.execute("DELETE FROM revenues WHERE month_id=? AND recurring_id=? AND status='projetado'",(m['id'],rid))
            # Frequência anual: remove projetados dos meses que não são o mês-alvo
            if new_freq == 'annual' and new_moy:
                for m in c.execute("SELECT id FROM months WHERE month!=?",(new_moy,)).fetchall():
                    c.execute("DELETE FROM revenues WHERE month_id=? AND recurring_id=? AND status='projetado'",(m['id'],rid))
        else:
            c.execute("UPDATE costs SET amount=?,category=?,name=? WHERE recurring_id=? AND status='projetado'",
                (new_amt, new_cat, new_desc, rid))
            if new_ey and new_em:
                for m in c.execute("SELECT id FROM months WHERE year>? OR (year=? AND month>?)",(new_ey,new_ey,new_em)).fetchall():
                    c.execute("DELETE FROM costs WHERE month_id=? AND recurring_id=? AND status='projetado'",(m['id'],rid))
            if new_freq == 'annual' and new_moy:
                for m in c.execute("SELECT id FROM months WHERE month!=?",(new_moy,)).fetchall():
                    c.execute("DELETE FROM costs WHERE month_id=? AND recurring_id=? AND status='projetado'",(m['id'],rid))
        # Generate new projected rows if end date extended or removed
        updated = dict(c.execute('SELECT * FROM recurring_items WHERE id=?',(rid,)).fetchone())
        _gen_recurring_rows(c, updated)
        tabela = 'revenues' if updated['type']=='revenue' else 'costs'
        updated['linhas_geradas'] = c.execute(
            f'SELECT COUNT(*) FROM {tabela} WHERE recurring_id=?', (rid,)).fetchone()[0]
        c.commit()
    audit(request.user['username'], 'recorrente_editado', f"ID {rid} — {new_desc}")
    return jsonify(updated)

@app.delete('/api/recurring/<int:rid>')
@auth
def delete_recurring(rid):
    with db() as c:
        item = c.execute('SELECT * FROM recurring_items WHERE id=?',(rid,)).fetchone()
        if not item: return jsonify({'error':'Não encontrado'}),404
        if item['type'] == 'revenue':
            c.execute("DELETE FROM revenues WHERE recurring_id=? AND status='projetado'",(rid,))
        else:
            c.execute("DELETE FROM costs WHERE recurring_id=? AND status='projetado'",(rid,))
        c.execute('UPDATE recurring_items SET active=0 WHERE id=?',(rid,))
        c.commit()
    audit(request.user['username'], 'recorrente_excluído', f"ID {rid} — {item['description']}")
    return jsonify({'success':True})

@app.post('/api/revenues/<int:rid>/make-recurring')
@auth
def make_revenue_recurring(rid):
    d = request.get_json() or {}
    with db() as c:
        rev = c.execute('SELECT r.*,m.year,m.month FROM revenues r JOIN months m ON r.month_id=m.id WHERE r.id=?',(rid,)).fetchone()
        if not rev: return jsonify({'error':'Não encontrado'}),404
        sy, sm = rev['year'], rev['month']
        sm += 1
        if sm > 12: sy += 1; sm = 1
        cur = c.execute(
            'INSERT INTO recurring_items (type,description,client_name,amount,category,start_year,start_month,end_year,end_month) VALUES (?,?,?,?,?,?,?,?,?)',
            ('revenue', rev['client_name'] or 'Receita', rev['client_name'], rev['amount'],
             rev['category'], sy, sm, d.get('end_year') or None, d.get('end_month') or None))
        c.commit()
        item = dict(c.execute('SELECT * FROM recurring_items WHERE id=?',(cur.lastrowid,)).fetchone())
        c.execute('UPDATE revenues SET recurring_id=? WHERE id=?',(item['id'],rid))
        _gen_recurring_rows(c, item)
        c.commit()
    audit(request.user['username'], 'receita_tornou_recorrente', f"ID {rid}")
    return jsonify(item)

@app.post('/api/costs/<int:cid>/make-recurring')
@auth
def make_cost_recurring(cid):
    d = request.get_json() or {}
    with db() as c:
        cost = c.execute('SELECT c.*,m.year,m.month FROM costs c JOIN months m ON c.month_id=m.id WHERE c.id=?',(cid,)).fetchone()
        if not cost: return jsonify({'error':'Não encontrado'}),404
        sy, sm = cost['year'], cost['month']
        sm += 1
        if sm > 12: sy += 1; sm = 1
        cur = c.execute(
            'INSERT INTO recurring_items (type,description,client_name,amount,category,start_year,start_month,end_year,end_month) VALUES (?,?,?,?,?,?,?,?,?)',
            ('cost', cost['name'] or 'Despesa', '', cost['amount'], cost['category'], sy, sm,
             d.get('end_year') or None, d.get('end_month') or None))
        c.commit()
        item = dict(c.execute('SELECT * FROM recurring_items WHERE id=?',(cur.lastrowid,)).fetchone())
        c.execute('UPDATE costs SET recurring_id=? WHERE id=?',(item['id'],cid))
        _gen_recurring_rows(c, item)
        c.commit()
    audit(request.user['username'], 'despesa_tornou_recorrente', f"ID {cid}")
    return jsonify(item)

@app.post('/api/revenues/<int:rid>/confirm')
@auth
def confirm_revenue(rid):
    d = request.get_json() or {}
    date = d.get('received_date', datetime.date.today().isoformat())
    with db() as c:
        c.execute("UPDATE revenues SET status='realizado',received_date=? WHERE id=?",(date,rid))
        c.commit()
        rev = c.execute('SELECT r.*,m.year,m.month FROM revenues r JOIN months m ON r.month_id=m.id WHERE r.id=?',(rid,)).fetchone()
    mref = f"{MONTHS_PT[rev['month']-1]}/{rev['year']}" if rev else str(rid)
    audit(request.user['username'], 'receita_confirmada', f"ID {rid} — {mref} — {rev['client_name'] if rev else ''}")
    return jsonify({'success':True})

@app.post('/api/costs/<int:cid>/confirm')
@auth
def confirm_cost(cid):
    d = request.get_json() or {}
    date = d.get('paid_date', datetime.date.today().isoformat())
    with db() as c:
        c.execute("UPDATE costs SET status='realizado',payment_date=? WHERE id=?",(date,cid))
        c.commit()
        cost = c.execute('SELECT c.*,m.year,m.month FROM costs c JOIN months m ON c.month_id=m.id WHERE c.id=?',(cid,)).fetchone()
    mref = f"{MONTHS_PT[cost['month']-1]}/{cost['year']}" if cost else str(cid)
    audit(request.user['username'], 'despesa_confirmada', f"ID {cid} — {mref} — {cost['name'] if cost else ''}")
    return jsonify({'success':True})

# ── Export (para Painel v4) ────────────────────────────────────────────────────

@app.get('/api/export')
@auth
def export_data():
    with db() as c:
        months = c.execute('SELECT * FROM months ORDER BY year,month').fetchall()
        data   = [month_full(c, m['id']) for m in months]
    return jsonify(data)

# ── Regras de custo ───────────────────────────────────────────────────────────
# Custo em degrau: dado o numero de clientes, o valor e determinado. Nao e
# estimativa, e politica ja acordada — por isso vale na projecao oficial.

RULE_COLS = {'nome':_s,'tipo':_s,'valor':_f,'min_clientes':lambda v:int(v or 0),
             'max_clientes':lambda v:(None if v in ('', None) else int(v)),
             'categoria':_s,'ativo':_b,'so_projecao':_b,'clientes':_s,'cobre_novos':_b,
             'inicio_ano':lambda v:(None if v in ('',None) else int(v)),'inicio_mes':lambda v:(None if v in ('',None) else int(v)),'fim_ano':lambda v:(None if v in ('',None) else int(v)),'fim_mes':lambda v:(None if v in ('',None) else int(v))}
TIPOS_REGRA = ('fixo','por_cliente','pct_primeiro','por_cliente_sel')

# ══════════════════════════════════════════════════════════════════════════
# IMPORTAÇÃO DE CLIENTE VINDO DO EVOLVE FLOW
# O cliente entra como RECORRÊNCIA de receita — o caminho que ja existe. A
# partir dai _gen_recurring_rows espalha as linhas projetadas por todos os
# meses, e MRR, Fluxo e Projecao passam a enxergar sozinhos. Nenhuma formula
# de churn ou de projecao e tocada.
# ══════════════════════════════════════════════════════════════════════════

def _comp(txt):
    """'2026-09' -> (2026, 9). Devolve (None, None) se vazio ou invalido."""
    try:
        y, m = str(txt or '').split('-')[:2]
        y, m = int(y), int(m)
        if 1 <= m <= 12 and 2000 <= y <= 2100:
            return y, m
    except Exception:
        pass
    return None, None


def _valida_flow(d):
    """Devolve (dados_limpos, erros). Erro em qualquer campo obrigatorio
    impede a gravacao inteira — nunca grava pela metade."""
    erros = []
    if not isinstance(d, dict):
        return None, ['O arquivo não é um JSON de objeto.']
    if d.get('tipo') != 'evolve_flow_cliente_financeiro':
        erros.append('Não é um arquivo de cliente do Evolve Flow '
                     '(campo "tipo" ausente ou diferente do esperado).')
        return None, erros

    empresa = _s(d.get('empresa')).strip()
    if not empresa:
        erros.append('Falta o nome da empresa.')

    try:
        valor = float(str(d.get('valorContrato') or '').replace('.', '').replace(',', '.')
                      if ',' in str(d.get('valorContrato') or '') else (d.get('valorContrato') or 0))
    except (TypeError, ValueError):
        valor = 0.0
    if valor <= 0:
        erros.append('Valor do contrato ausente ou inválido.')

    iy, im = _comp(d.get('inicioContrato'))
    if not iy:
        erros.append('Falta o início do contrato (competência AAAA-MM).')
    fy, fm = _comp(d.get('fimContrato'))
    if d.get('fimContrato') and not fy:
        erros.append('Fim do contrato em formato inválido (esperado AAAA-MM).')
    if iy and fy and (fy * 12 + fm) < (iy * 12 + im):
        erros.append('O fim do contrato vem antes do início.')

    tipo = _s(d.get('tipoCobranca')) or 'recorrente'
    if tipo not in ('recorrente', 'pontual'):
        erros.append('Tipo de cobrança inválido (use "recorrente" ou "pontual").')

    # Cobranca pontual e um mes so: o fim e o proprio mes de inicio.
    if tipo == 'pontual' and iy:
        fy, fm = iy, im

    dia = None
    try:
        v = int(d.get('diaVencimento') or d.get('vencimento') or 0)
        if 1 <= v <= 31:
            dia = v
    except (TypeError, ValueError):
        dia = None

    chave = (_s(d.get('clienteId')).strip()
             or re.sub(r'\D', '', _s(d.get('cnpj')))
             or _s(d.get('emailFinanceiro')).strip().lower()
             or empresa.strip().lower())
    if not chave:
        erros.append('Sem identificador do cliente (id do Flow, CNPJ, e-mail ou nome).')

    if erros:
        return None, erros
    return {
        'empresa': empresa, 'valor': valor, 'iy': iy, 'im': im, 'fy': fy, 'fm': fm,
        'tipo': tipo, 'dia': dia, 'chave': chave,
        'categoria': _s(d.get('categoriaSugerida')) or 'servico',
        'descricao': _s(d.get('descricaoSugerida')) or ('Mensalidade ' + empresa),
    }, []


@app.post('/api/import/flow-cliente')
@auth
def import_flow_cliente():
    dados, erros = _valida_flow(request.get_json(silent=True))
    if erros:
        return jsonify({'error': 'Importação recusada', 'motivos': erros}), 400

    with db() as c:
        existente = c.execute(
            "SELECT * FROM recurring_items WHERE origem='flow' AND origem_chave=? AND active=1",
            (dados['chave'],)).fetchone()

        if existente:
            c.execute('UPDATE recurring_items SET description=?,client_name=?,amount=?,category=?,'
                      'start_year=?,start_month=?,end_year=?,end_month=?,day_of_month=? WHERE id=?',
                      (dados['descricao'], dados['empresa'], dados['valor'], dados['categoria'],
                       dados['iy'], dados['im'], dados['fy'], dados['fm'], dados['dia'],
                       existente['id']))
            rid = existente['id']
            # o valor pode ter mudado: alinha as linhas ainda projetadas
            c.execute("UPDATE revenues SET amount=?,category=?,client_name=? "
                      "WHERE recurring_id=? AND status='projetado'",
                      (dados['valor'], dados['categoria'], dados['empresa'], rid))
            # e remove as que cairam fora da vigencia nova
            if dados['fy']:
                for m in c.execute('SELECT id FROM months WHERE year>? OR (year=? AND month>?)',
                                   (dados['fy'], dados['fy'], dados['fm'])).fetchall():
                    c.execute("DELETE FROM revenues WHERE month_id=? AND recurring_id=? "
                              "AND status='projetado'", (m['id'], rid))
            for m in c.execute('SELECT id FROM months WHERE year<? OR (year=? AND month<?)',
                               (dados['iy'], dados['iy'], dados['im'])).fetchall():
                c.execute("DELETE FROM revenues WHERE month_id=? AND recurring_id=? "
                          "AND status='projetado'", (m['id'], rid))
            acao = 'atualizado'
        else:
            cur = c.execute(
                'INSERT INTO recurring_items (type,description,client_name,amount,category,'
                'start_year,start_month,end_year,end_month,day_of_month,origem,origem_chave) '
                "VALUES ('revenue',?,?,?,?,?,?,?,?,?,'flow',?)",
                (dados['descricao'], dados['empresa'], dados['valor'], dados['categoria'],
                 dados['iy'], dados['im'], dados['fy'], dados['fm'], dados['dia'], dados['chave']))
            rid = cur.lastrowid
            acao = 'criado'

        c.commit()
        item = dict(c.execute('SELECT * FROM recurring_items WHERE id=?', (rid,)).fetchone())
        _gen_recurring_rows(c, item)
        c.commit()

    audit(request.user['username'], 'cliente_importado_flow',
          f"{dados['empresa']} — R$ {dados['valor']:.2f} — {acao}")
    return jsonify({'acao': acao, 'recurring_id': rid, 'cliente': dados['empresa'],
                    'valor': dados['valor'], 'inicio': f"{dados['im']:02d}/{dados['iy']}",
                    'fim': (f"{dados['fm']:02d}/{dados['fy']}" if dados['fy'] else None),
                    'tipo': dados['tipo']})


@app.get('/api/cost-rules')
@auth
def list_cost_rules():
    with db() as c:
        rows = c.execute('SELECT * FROM cost_rules WHERE ativo=1 ORDER BY nome, min_clientes').fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/cost-rules')
@auth
def create_cost_rule():
    d = request.get_json() or {}
    nome = _s(d.get('nome')).strip()
    if not nome: return jsonify({'error':'Informe o nome da regra'}), 400
    tipo = _s(d.get('tipo')) or 'fixo'
    if tipo not in TIPOS_REGRA: return jsonify({'error':'Tipo inválido'}), 400
    mx = d.get('max_clientes')
    mx = None if mx in ('', None) else int(mx)
    mn = int(d.get('min_clientes') or 0)
    if mx is not None and mx < mn:
        return jsonify({'error':'A faixa termina antes de começar'}), 400
    with db() as c:
        _oi = lambda k: (None if d.get(k) in ('',None) else int(d[k]))
        cur = c.execute('INSERT INTO cost_rules (nome,tipo,valor,min_clientes,max_clientes,categoria,'
                        'so_projecao,clientes,cobre_novos,inicio_ano,inicio_mes,fim_ano,fim_mes) '
                        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        (nome, tipo, _f(d.get('valor')), mn, mx,
                         _s(d.get('categoria')) or 'operacional', _b(d.get('so_projecao')),
                         _s(d.get('clientes')), 1 if d.get('cobre_novos') in (None,'',1,'1',True) else 0,
                         _oi('inicio_ano'), _oi('inicio_mes'), _oi('fim_ano'), _oi('fim_mes')))
        c.commit()
        row = c.execute('SELECT * FROM cost_rules WHERE id=?', (cur.lastrowid,)).fetchone()
    audit(request.user['username'], 'regra_criada', f"{nome} — {tipo} {_f(d.get('valor')):.2f}")
    return jsonify(dict(row))

@app.put('/api/cost-rules/<int:rid>')
@auth
def update_cost_rule(rid):
    d = request.get_json() or {}
    if d.get('tipo') and d['tipo'] not in TIPOS_REGRA:
        return jsonify({'error':'Tipo inválido'}), 400
    if not partial_update('cost_rules', RULE_COLS, d, rid):
        return jsonify({'error':'Nada para atualizar'}), 400
    audit(request.user['username'], 'regra_editada', f"ID {rid}")
    return jsonify({'success':True})

@app.delete('/api/cost-rules/<int:rid>')
@auth
def delete_cost_rule(rid):
    with db() as c:
        row = c.execute('SELECT nome FROM cost_rules WHERE id=?', (rid,)).fetchone()
        c.execute('UPDATE cost_rules SET ativo=0 WHERE id=?', (rid,))
        c.commit()
    audit(request.user['username'], 'regra_removida', row['nome'] if row else str(rid))
    return jsonify({'success':True})

# ── Textos dos relatórios ─────────────────────────────────────────────────────
# Blocos de redação da Carla (resumo executivo, conclusão, observações).
# key: 'mensal:2026-07:resumo' | 'semanal:2026-08-03:obs' | 'mensal:2026-07:cat:pro-labore'

@app.get('/api/report-texts')
@auth
def get_report_texts():
    prefix = request.args.get('prefix','')
    with db() as c:
        rows = c.execute('SELECT key,value FROM report_texts WHERE key LIKE ?', (prefix+'%',)).fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.put('/api/report-texts')
@auth
def put_report_texts():
    d = request.get_json() or {}
    if not isinstance(d, dict) or not d:
        return jsonify({'error':'Payload inválido'}), 400
    if len(d) > 200:
        return jsonify({'error':'Muitos campos de uma vez'}), 400
    with db() as c:
        for k, v in d.items():
            if not isinstance(k, str) or len(k) > 200:
                continue
            c.execute("INSERT INTO report_texts (key,value,updated_at) VALUES (?,?,datetime('now')) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')",
                      (k, '' if v is None else str(v)[:20000]))
        c.commit()
    return jsonify({'success':True})

# ── Backup / Restore ──────────────────────────────────────────────────────────

@app.get('/api/backup')
@auth
def backup():
    import json as _json
    with db() as c:
        months  = c.execute('SELECT * FROM months ORDER BY year,month').fetchall()
        data    = [month_full(c, m['id']) for m in months]
        goals   = [dict(g) for g in c.execute('SELECT * FROM goals WHERE active=1').fetchall()]
        audit   = [dict(r) for r in c.execute('SELECT * FROM audit_log ORDER BY id').fetchall()]
    with db() as c2:
        cats      = [dict(r) for r in c2.execute('SELECT * FROM categories WHERE active=1').fetchall()]
        recvs     = [dict(r) for r in c2.execute('SELECT * FROM receivables').fetchall()]
        pays      = [dict(r) for r in c2.execute('SELECT * FROM payables').fetchall()]
        setts     = {r['key']: r['value'] for r in c2.execute('SELECT * FROM settings').fetchall()}
        recurring = [dict(r) for r in c2.execute('SELECT * FROM recurring_items WHERE active=1').fetchall()]
    payload = {
        'version': 1,
        'created_at': datetime.datetime.now().isoformat(),
        'months': data,
        'goals':  goals,
        'audit':  audit,
        'categories':  cats,
        'receivables': recvs,
        'payables':    pays,
        'settings':    setts,
        'recurring':   recurring,
    }
    from flask import Response
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    return Response(
        _json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="evolve_backup_{ts}.json"'}
    )

@app.post('/api/restore')
@require_role('admin')
def restore():
    payload = request.get_json() or {}
    if payload.get('version') != 1:
        return jsonify({'error': 'Formato de backup inválido'}), 400
    with db() as c:
        # Restore months + revenues + costs
        for m in payload.get('months', []):
            c.execute('''INSERT OR IGNORE INTO months (year,month,regime,mei_das,prolabore_socio,notes)
                         VALUES (?,?,?,?,?,?)''',
                (m['year'], m['month'], m.get('regime','MEI'),
                 m.get('mei_das',86.90), m.get('prolabore_socio',1400), m.get('notes','')))
            row = c.execute('SELECT id FROM months WHERE year=? AND month=?',(m['year'],m['month'])).fetchone()
            mid = row['id']
            c.execute('UPDATE months SET regime=?,mei_das=?,prolabore_socio=?,notes=? WHERE id=?',
                (m.get('regime','MEI'), m.get('mei_das',86.90), m.get('prolabore_socio',1400), m.get('notes',''), mid))
            c.execute('DELETE FROM revenues WHERE month_id=?',(mid,))
            c.execute('DELETE FROM costs    WHERE month_id=?',(mid,))
            for r in m.get('revenues',[]):
                c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order) VALUES (?,?,?,?,?,?,?)',
                    (mid,r.get('client_name',''),r.get('amount',0),r.get('received_date',''),
                     r.get('category','servico'),r.get('is_new_client',0),r.get('sort_order',999)))
            for r in m.get('costs',[]):
                c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order) VALUES (?,?,?,?,?,?)',
                    (mid,r.get('name',''),r.get('amount',0),r.get('payment_date',''),
                     r.get('category','operacional'),r.get('sort_order',999)))
        # Goals
        for g in payload.get('goals', []):
            c.execute('INSERT OR IGNORE INTO goals (name,target_value,metric,year,month) VALUES (?,?,?,?,?)',
                (g['name'],g['target_value'],g.get('metric','receita_mensal'),g.get('year',2026),g.get('month',0)))
        # Categories (optional — skip if not in backup)
        for cat in payload.get('categories', []):
            c.execute('INSERT OR IGNORE INTO categories (type,slug,label,color,sort_order) VALUES (?,?,?,?,?)',
                (cat['type'],cat['slug'],cat['label'],cat.get('color','#6b7fa3'),cat.get('sort_order',99)))
        # Receivables
        c.execute('DELETE FROM receivables')
        for r in payload.get('receivables', []):
            c.execute('INSERT INTO receivables (description,client_name,amount,due_date,received_date,status,category,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (r.get('description',''),r.get('client_name',''),r.get('amount',0),r.get('due_date',''),
                 r.get('received_date',''),r.get('status','pendente'),r.get('category','servico'),
                 r.get('notes',''),r.get('created_at','')))
        # Payables
        c.execute('DELETE FROM payables')
        for p in payload.get('payables', []):
            c.execute('INSERT INTO payables (description,amount,due_date,paid_date,status,category,notes,created_at) VALUES (?,?,?,?,?,?,?,?)',
                (p.get('description',''),p.get('amount',0),p.get('due_date',''),p.get('paid_date',''),
                 p.get('status','pendente'),p.get('category','operacional'),p.get('notes',''),p.get('created_at','')))
        # Settings
        for key, value in payload.get('settings', {}).items():
            c.execute('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)', (key, str(value)))
        # Recurring items
        for r in payload.get('recurring', []):
            c.execute('INSERT OR IGNORE INTO recurring_items (id,type,description,client_name,amount,category,start_year,start_month,end_year,end_month,active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (r.get('id'), r.get('type','revenue'), r.get('description',''), r.get('client_name',''),
                 r.get('amount',0), r.get('category','servico'),
                 r.get('start_year',2026), r.get('start_month',1),
                 r.get('end_year'), r.get('end_month'), r.get('active',1), r.get('created_at','')))
        c.commit()
    audit(request.user['username'], 'restore', 'Backup restaurado')
    return jsonify({'success': True})

# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get('/')
def index():
    return send_from_directory('static','index.html')

# ── Start ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('\n' + '='*52)
    print('  EVOLVE FINANCEIRO 2026')
    print('='*52)
    print('  Usuários:  hudson     / evolve2026')
    print('             diego      / evolve2026')
    print('             financeiro / evolve2026')
    print('  Acesse:    http://localhost:5050')
    print('='*52 + '\n')
    app.run(host='0.0.0.0', port=5050, debug=False)
