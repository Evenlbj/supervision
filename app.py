from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3, hashlib, os, json, time, threading, socket, subprocess, datetime

app = Flask(__name__)
app.secret_key = 'ns2025'
DB  = os.path.join(os.path.dirname(__file__), 'netsuper.db')
JOBS = {}
PWD  = hashlib.sha256('Loucaclara27062015+'.encode()).hexdigest()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    c = db()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
        CREATE TABLE IF NOT EXISTS hosts(id INTEGER PRIMARY KEY, hostname TEXT, ip TEXT UNIQUE, status TEXT DEFAULT "unknown", ports TEXT DEFAULT "[]");
        CREATE TABLE IF NOT EXISTS cves(id INTEGER PRIMARY KEY, cve_id TEXT, score REAL, severity TEXT, desc TEXT);
    ''')
    c.execute('INSERT OR IGNORE INTO users(username,password) VALUES(?,?)', ('admin', PWD))
    c.execute('UPDATE users SET password=? WHERE username=?', (PWD, 'admin'))
    if not c.execute('SELECT COUNT(*) FROM cves').fetchone()[0]:
        for r in [('CVE-2024-9999',9.9,'CRITICAL','OpenSSH RCE'),
                  ('CVE-2017-0144',9.8,'CRITICAL','EternalBlue SMB'),
                  ('CVE-2022-0543',10.0,'CRITICAL','Redis RCE'),
                  ('CVE-2024-5678',8.1,'HIGH','MariaDB SQLi')]:
            c.execute('INSERT INTO cves(cve_id,score,severity,desc) VALUES(?,?,?,?)', r)
    c.commit()
    c.close()

app.jinja_env.filters['j'] = lambda s: json.loads(s) if s else []

def auth(f):
    from functools import wraps
    @wraps(f)
    def w(*a, **k):
        return f(*a, **k) if 'user' in session else redirect('/')
    return w

# ── Pages ──
@app.route('/', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = hashlib.sha256(request.form.get('password', '').encode()).hexdigest()
        c = db()
        user = c.execute('SELECT * FROM users WHERE username=?', (u,)).fetchone()
        c.close()
        if user and user['password'] == p:
            session['user'] = u
            return redirect('/dashboard')
        err = 'Identifiants incorrects'
    return render_template('login.html', err=err)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
@auth
def dashboard():
    c    = db()
    up   = c.execute("SELECT COUNT(*) FROM hosts WHERE status='up'").fetchone()[0]
    tot  = c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    cves = c.execute("SELECT * FROM cves ORDER BY score DESC").fetchall()
    c.close()
    return render_template('dashboard.html', up=up, tot=tot, cves=cves, username=session['user'])

@app.route('/hosts')
@auth
def hosts():
    c  = db()
    hs = c.execute("SELECT * FROM hosts ORDER BY status").fetchall()
    c.close()
    return render_template('host.html', hosts=hs, username=session['user'])

@app.route('/scan')
@auth
def scan():
    return render_template('scan.html', username=session['user'])

# ── APIs scan ──
@app.route('/api/scan/start', methods=['POST'])
@auth
def api_scan_start():
    target = request.get_json().get('target', '192.168.1.0/24')
    jid    = f"j{int(time.time())}"
    JOBS[jid] = {'status': 'running', 'progress': 0, 'log': [], 'hosts': []}
    threading.Thread(target=do_scan, args=(jid, target), daemon=True).start()
    return jsonify({'job_id': jid})

@app.route('/api/scan/status/<jid>')
@auth
def api_scan_status(jid):
    return jsonify(JOBS.get(jid, {'status': 'not_found'}))

@app.route('/api/scan/save', methods=['POST'])
@auth
def api_scan_save():
    d = request.get_json()
    c = db()
    c.execute('INSERT OR REPLACE INTO hosts(hostname,ip,status,ports) VALUES(?,?,?,?)',
              (d['hostname'], d['ip'], 'up', json.dumps(d.get('ports', []))))
    c.commit()
    c.close()
    return jsonify({'ok': True})

def do_scan(jid, target):
    import ipaddress
    job = JOBS[jid]
    try:    ips = [str(h) for h in ipaddress.ip_network(target, strict=False).hosts()][:20]
    except: ips = [target]
    job['log'].append(f'Scan {target} — {len(ips)} adresses')
    alive = []
    for i, ip in enumerate(ips):
        job['progress'] = int(i / len(ips) * 60)
        try:
            r = subprocess.run(['ping','-c','1','-W','1',ip], capture_output=True, timeout=2)
            if r.returncode == 0:
                alive.append(ip)
                job['log'].append(f'✓ {ip}')
        except: pass
    job['log'].append(f'{len(alive)} hôte(s) actif(s)')
    c = db()
    for i, ip in enumerate(alive):
        job['progress'] = 60 + int(i / max(len(alive), 1) * 40)
        ports = []
        for p in [22, 80, 443, 3306, 3389]:
            try:
                s = socket.socket()
                s.settimeout(0.4)
                if s.connect_ex((ip, p)) == 0:
                    ports.append(p)
                s.close()
            except: pass
        try:    hn = socket.gethostbyaddr(ip)[0]
        except: hn = 'host-' + ip.replace('.', '-')
        c.execute('INSERT OR REPLACE INTO hosts(hostname,ip,status,ports) VALUES(?,?,?,?)',
                  (hn, ip, 'up', json.dumps(ports)))
        job['hosts'].append({'ip': ip, 'hostname': hn, 'ports': ports})
        job['log'].append(f'  {ip} — ports: {ports}')
    c.commit()
    c.close()
    job['status']   = 'done'
    job['progress'] = 100

if __name__ == '__main__':
    init()
    app.run(debug=True, host='0.0.0.0', port=5000)
