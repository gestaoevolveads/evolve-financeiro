from flask import Flask, request, jsonify, send_from_directory
import sqlite3, bcrypt, jwt, datetime, os
from functools import wraps

app = Flask(__name__, static_folder='static')
SECRET   = os.environ.get('SECRET_KEY', 'evolve-financeiro-2026-#@!')
_DATA    = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(_DATA, 'evolve.db')

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
    return c

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
        ''')

        # Migrations for existing DBs
        for sql in [
            "ALTER TABLE revenues ADD COLUMN category TEXT DEFAULT 'servico'",
            "ALTER TABLE revenues ADD COLUMN is_new_client INTEGER DEFAULT 0",
            "CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT DEFAULT '')",
        ]:
            try: c.execute(sql)
            except Exception: pass

        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
            for uname, pw, name in [('hudson','evolve2026','Hudson'),('diego','evolve2026','Diego'),('financeiro','evolve2026','Financeiro')]:
                h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                c.execute('INSERT INTO users (username,password_hash,name) VALUES (?,?,?)', (uname,h,name))
        else:
            # Reset passwords to default (one-time migration)
            marker = c.execute("SELECT detail FROM audit_log WHERE action='pw_migration_v1' LIMIT 1").fetchone()
            if not marker:
                for uname, pw in [('hudson','evolve2026'),('diego','evolve2026'),('financeiro','evolve2026')]:
                    h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
                    c.execute('UPDATE users SET password_hash=? WHERE username=?', (h, uname))
                c.execute("INSERT INTO audit_log (ts,username,action,detail) VALUES (datetime('now'),'system','pw_migration_v1','senhas resetadas para evolve2026')")

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

@app.post('/api/auth/login')
def login():
    d = request.get_json() or {}
    uname = d.get('username','').strip().lower()
    pw    = d.get('password','')
    with db() as c:
        user = c.execute('SELECT * FROM users WHERE username=?',(uname,)).fetchone()
    if not user or not bcrypt.checkpw(pw.encode(), user['password_hash'].encode()):
        return jsonify({'error':'Usuário ou senha incorretos'}), 401
    token = jwt.encode({
        'user_id':user['id'], 'username':user['username'], 'name':user['name'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, SECRET, algorithm='HS256')
    audit(user['username'], 'login', 'Acesso ao sistema')
    return jsonify({'token':token, 'name':user['name'], 'username':user['username']})

@app.get('/api/auth/me')
@auth
def me():
    return jsonify(request.user)

@app.post('/api/auth/change-password')
@auth
def change_pw():
    d = request.get_json() or {}
    if len(d.get('new','')) < 6:
        return jsonify({'error':'Senha deve ter pelo menos 6 caracteres'}), 400
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
        cur = c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order) VALUES (?,?,?,?,?,?,?)',
            (mid, d.get('client_name',''), d.get('amount',0), d.get('received_date',''),
             d.get('category','servico'), d.get('is_new_client',0), d.get('sort_order',999)))
        c.commit()
        row = c.execute('SELECT * FROM revenues WHERE id=?',(cur.lastrowid,)).fetchone()
    mref = f"{MONTHS_PT[month['month']-1]}/{month['year']}" if month else str(mid)
    audit(request.user['username'], 'receita_adicionada', f"{mref} — {d.get('client_name','')}")
    return jsonify(dict(row))

@app.put('/api/revenues/<int:rid>')
@auth
def update_revenue(rid):
    d = request.get_json() or {}
    with db() as c:
        c.execute('UPDATE revenues SET client_name=?,amount=?,received_date=?,category=?,is_new_client=? WHERE id=?',
            (d.get('client_name',''), d.get('amount',0), d.get('received_date',''),
             d.get('category','servico'), 1 if d.get('is_new_client') else 0, rid))
        c.commit()
    audit(request.user['username'], 'receita_editada', f"ID {rid} — {d.get('client_name','')} R${d.get('amount',0):.2f}")
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
        cur = c.execute('INSERT INTO costs (month_id,name,amount,payment_date,category,sort_order) VALUES (?,?,?,?,?,?)',
            (mid, d.get('name',''), d.get('amount',0), d.get('payment_date',''),
             d.get('category','operacional'), d.get('sort_order',999)))
        c.commit()
        row = c.execute('SELECT * FROM costs WHERE id=?',(cur.lastrowid,)).fetchone()
    mref = f"{MONTHS_PT[month['month']-1]}/{month['year']}" if month else str(mid)
    audit(request.user['username'], 'despesa_adicionada', f"{mref} — {d.get('name','')}")
    return jsonify(dict(row))

@app.put('/api/costs/<int:cid>')
@auth
def update_cost(cid):
    d = request.get_json() or {}
    with db() as c:
        c.execute('UPDATE costs SET name=?,amount=?,payment_date=?,category=? WHERE id=?',
            (d.get('name',''), d.get('amount',0), d.get('payment_date',''),
             d.get('category','operacional'), cid))
        c.commit()
    audit(request.user['username'], 'despesa_editada', f"ID {cid} — {d.get('name','')} R${d.get('amount',0):.2f}")
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
            prevs = c.execute('SELECT * FROM revenues WHERE month_id=? ORDER BY sort_order,id',(prev['id'],)).fetchall()
            if mode=='replace': c.execute('DELETE FROM revenues WHERE month_id=?',(mid,))
            for r in prevs:
                c.execute('INSERT INTO revenues (month_id,client_name,amount,received_date,category,is_new_client,sort_order) VALUES (?,?,?,?,?,?,?)',
                    (mid, r['client_name'], r['amount'], '', r['category'], 0, r['sort_order']))
            c.commit()
            rows = [dict(r) for r in c.execute('SELECT * FROM revenues WHERE month_id=? ORDER BY sort_order,id',(mid,)).fetchall()]
        else:
            prevs = c.execute('SELECT * FROM costs WHERE month_id=? ORDER BY sort_order,id',(prev['id'],)).fetchall()
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

# ── Export (para Painel v4) ────────────────────────────────────────────────────

@app.get('/api/export')
@auth
def export_data():
    with db() as c:
        months = c.execute('SELECT * FROM months ORDER BY year,month').fetchall()
        data   = [month_full(c, m['id']) for m in months]
    return jsonify(data)

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
    payload = {
        'version': 1,
        'created_at': datetime.datetime.now().isoformat(),
        'months': data,
        'goals':  goals,
        'audit':  audit,
    }
    from flask import Response
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    return Response(
        _json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="evolve_backup_{ts}.json"'}
    )

@app.post('/api/restore')
@auth
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
