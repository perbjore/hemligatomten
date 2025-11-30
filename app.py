import os
import json
import random
import smtplib
import ssl
from email.message import EmailMessage
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, g
from io import StringIO

APP_DB = os.path.join(os.path.dirname(__file__), 'secretsanta.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(APP_DB)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE,
        household TEXT,
        excludes TEXT,
        hidden INTEGER DEFAULT 0
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS assignments (
        giver_id INTEGER UNIQUE,
        receiver_id INTEGER
    )
    ''')
    db.commit()
    # Ensure 'hidden' column exists for older DBs
    cur.execute("PRAGMA table_info(participants)")
    cols = [r[1] for r in cur.fetchall()]
    if 'hidden' not in cols:
        cur.execute('ALTER TABLE participants ADD COLUMN hidden INTEGER DEFAULT 0')
        db.commit()

def query_participants():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT * FROM participants ORDER BY name')
    return cur.fetchall()

def clear_assignments():
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM assignments')
    db.commit()

def save_assignments(mapping):
    db = get_db()
    cur = db.cursor()
    cur.execute('DELETE FROM assignments')
    for giver, receiver in mapping.items():
        cur.execute('INSERT INTO assignments(giver_id, receiver_id) VALUES (?, ?)', (giver, receiver))
    db.commit()

def load_assignments():
    # default: return all assignments (including info for both sides)
    db = get_db()
    cur = db.cursor()
    cur.execute('''
        SELECT a.giver_id, a.receiver_id, p1.name AS giver_name, p1.email AS giver_email, p1.hidden AS giver_hidden, p2.name AS receiver_name, p2.email AS receiver_email
        FROM assignments a
        JOIN participants p1 ON a.giver_id = p1.id
        JOIN participants p2 ON a.receiver_id = p2.id
    ''')
    return cur.fetchall()

def load_assignments_visible(hide_hidden=True):
    db = get_db()
    cur = db.cursor()
    query = '''
        SELECT a.giver_id, a.receiver_id, p1.name AS giver_name, p1.email AS giver_email, p1.hidden AS giver_hidden, p2.name AS receiver_name, p2.email AS receiver_email
        FROM assignments a
        JOIN participants p1 ON a.giver_id = p1.id
        JOIN participants p2 ON a.receiver_id = p2.id
    '''
    cur.execute(query)
    rows = cur.fetchall()
    if hide_hidden:
        return [r for r in rows if r['giver_hidden'] == 0]
    return rows

def make_mapping(participants):
    # participants: list of dicts with keys id, name, email, household, excludes(list)
    ids = [p['id'] for p in participants]
    receivers = ids.copy()

    def valid_mapping(giver_id, receiver_id, pmap):
        if giver_id == receiver_id:
            return False
        giver = pmap[giver_id]
        receiver = pmap[receiver_id]
        if giver.get('household') and receiver.get('household') and giver['household'] == receiver['household']:
            return False
        if receiver.get('email') in (giver.get('excludes') or []):
            return False
        return True

    pmap = {p['id']: p for p in participants}

    attempts = 0
    max_attempts = 10000
    while attempts < max_attempts:
        attempts += 1
        random.shuffle(receivers)
        good = True
        mapping = {}
        for giver, receiver in zip(ids, receivers):
            if not valid_mapping(giver, receiver, pmap):
                good = False
                break
            mapping[giver] = receiver
        if good:
            return mapping

    return None


def complete_partial_mapping(participants, fixed_mapping):
    """
    Given participants (list of dicts) and a partial fixed_mapping {giver:receiver},
    try to assign receivers to the remaining givers such that all constraints hold
    and receiver uniqueness is preserved. Returns a full mapping or None on failure.
    """
    pmap = {p['id']: p for p in participants}
    all_ids = [p['id'] for p in participants]
    fixed_receivers = set(fixed_mapping.values())
    unassigned_givers = [pid for pid in all_ids if pid not in fixed_mapping]
    available_receivers = [rid for rid in all_ids if rid not in fixed_receivers]

    if len(unassigned_givers) != len(available_receivers):
        return None

    def valid(giver_id, receiver_id):
        if giver_id == receiver_id:
            return False
        giver = pmap[giver_id]
        receiver = pmap[receiver_id]
        if giver.get('household') and receiver.get('household') and giver['household'] == receiver['household']:
            return False
        if receiver.get('email') in (giver.get('excludes') or []):
            return False
        return True

    # build candidate lists
    candidates = {}
    for g in unassigned_givers:
        cand = [r for r in available_receivers if valid(g, r)]
        if not cand:
            # no possible receiver for this giver
            return None
        candidates[g] = cand

    # order givers by fewest candidates (heuristic)
    ordered = sorted(unassigned_givers, key=lambda x: len(candidates[x]))

    used = set()
    assignment = {}

    def backtrack(idx):
        if idx >= len(ordered):
            return True
        g = ordered[idx]
        for r in candidates[g]:
            if r in used:
                continue
            used.add(r)
            assignment[g] = r
            if backtrack(idx+1):
                return True
            used.remove(r)
            assignment.pop(g, None)
        return False

    ok = backtrack(0)
    if not ok:
        return None
    # merge fixed and assignment
    full = dict(fixed_mapping)
    full.update(assignment)
    return full

def get_participants_for_algo():
    rows = query_participants()
    participants = []
    for r in rows:
        excludes = []
        if r['excludes']:
            try:
                excludes = json.loads(r['excludes'])
            except Exception:
                excludes = [e.strip().lower() for e in r['excludes'].split(',') if e.strip()]
        participants.append({'id': r['id'], 'name': r['name'], 'email': r['email'], 'household': r['household'], 'excludes': excludes})
    return participants

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-change')
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, '_database', None)
        if db is not None:
            db.close()
    # Initialize the database now inside the app context
    with app.app_context():
        init_db()

    def admin_required(f):
        from functools import wraps
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not session.get('admin'):
                return redirect(url_for('admin_login', next=request.path))
            return f(*args, **kwargs)
        return wrapped

    @app.route('/')
    def index():
        # Provide list of unclaimed participants (created by admin without email)
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id, name, household FROM participants WHERE email IS NULL OR email = '' ORDER BY name")
        unclaimed = cur.fetchall()
        return render_template('index.html', unclaimed=unclaimed)

    @app.route('/register', methods=['POST'])
    def register():
        # Public registration is claim-only: user must select a pre-created participant slot
        email = request.form.get('email', '').strip().lower()
        claim_id = request.form.get('claim_id', '').strip()
        if not claim_id:
            flash('Registrering sker endast via förskapade platser. Vänligen välj ditt namn från listan.', 'error')
            return redirect(url_for('index'))
        if not email:
            flash('E-post krävs för att göra anspråk på en plats.', 'error')
            return redirect(url_for('index'))

        db = get_db()
        cur = db.cursor()
        try:
            cid = int(claim_id)
        except Exception:
            flash('Ogiltigt val.', 'error')
            return redirect(url_for('index'))

        cur.execute('SELECT * FROM participants WHERE id=?', (cid,))
        existing = cur.fetchone()
        if not existing:
            flash('Vald deltagare hittades inte.', 'error')
            return redirect(url_for('index'))
        if existing['email'] and existing['email'].strip() != '':
            flash('Den här platsen är redan tagen.', 'error')
            return redirect(url_for('index'))

        # ensure email not already used
        cur.execute('SELECT id FROM participants WHERE lower(email)=?', (email.lower(),))
        if cur.fetchone():
            flash('Denna e-post används redan av en annan deltagare.', 'error')
            return redirect(url_for('index'))

        # update only the email for the claimed participant
        cur.execute('UPDATE participants SET email=? WHERE id=?', (email, existing['id']))
        db.commit()
        # if assignments already exist, send the claimant their assignment
        sent = False
        try:
            sent = send_assignment_email_for_giver(existing['id'])
        except Exception:
            sent = False
        if sent:
            flash('Din e-post har lagts till och vi har skickat din tilldelning via e-post. Tack!', 'success')
        else:
            flash('Din e-post har lagts till för den valda deltagaren. Tack!', 'success')
        return redirect(url_for('index'))

    @app.route('/admin/login', methods=['GET', 'POST'])
    def admin_login():
        if request.method == 'POST':
            pw = request.form.get('password', '')
            admin_pw = os.environ.get('ADMIN_PASSWORD', 'changeme')
            if pw == admin_pw:
                session['admin'] = True
                flash('Inloggad som administratör', 'success')
                return redirect(url_for('admin_dashboard'))
            flash('Fel lösenord', 'error')
        return render_template('admin_login.html')

    @app.route('/admin/logout')
    def admin_logout():
        session.pop('admin', None)
        flash('Utloggad', 'info')
        return redirect(url_for('index'))

    @app.route('/admin')
    @admin_required
    def admin_dashboard():
        participants = query_participants()
        # For admin view: include assignments but mask any rows where the giver is marked hidden
        raw = load_assignments_visible(hide_hidden=False)
        assignments = []
        for r in raw:
            row = dict(r)
            if row.get('giver_hidden') == 1:
                row['receiver_name'] = '<Hidden>'
                row['receiver_email'] = '<Hidden>'
            # remove internal flag before rendering
            row.pop('giver_hidden', None)
            assignments.append(row)
        return render_template('admin_dashboard.html', participants=participants, assignments=assignments)

    @app.route('/admin/add_participant', methods=['POST'])
    @admin_required
    def admin_add_participant():
        name = request.form.get('name', '').strip()
        household = request.form.get('household', '').strip()
        email = request.form.get('email', '').strip().lower()
        #Check email validity
        if email:
            if '@' not in email or '.' not in email.split('@')[-1]:
                flash('Ogiltig e-postadress.', 'error')
                return redirect(url_for('admin_dashboard'))
        # check for email uniqueness
        if email:
            db = get_db()
            cur = db.cursor()
            cur.execute('SELECT id FROM participants WHERE lower(email)=?', (email.lower(),))
            if cur.fetchone():
                flash('Denna e-post används redan av en annan deltagare.', 'error')
                return redirect(url_for('admin_dashboard'))
        # no excludes input anymore; store empty list
        hidden = 1 if request.form.get('hidden') else 0
        if not name:
            flash('Namn krävs för att lägga till en deltagare', 'error')
            return redirect(url_for('admin_dashboard'))
        excludes = []
        db = get_db()
        cur = db.cursor()
        try:
                # insert NULL for email so multiple unclaimed slots don't violate UNIQUE constraint
            cur.execute('INSERT INTO participants(name, email, household, excludes, hidden) VALUES (?, ?, ?, ?, ?)', (name, email, household, json.dumps(excludes), hidden))
            db.commit()
            if email:
                flash('Deltagaren har lagts till med e-post.', 'success')
            else:
                flash('Deltagaren har lagts till (utan e-post). Familjemedlem kan göra anspråk genom att registrera sig med samma namn.', 'success')
        except sqlite3.IntegrityError:
            flash('Misslyckades med att lägga till deltagaren (möjlig dubblett).', 'error')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/draw', methods=['POST'])
    @admin_required
    def admin_draw():
        participants = get_participants_for_algo()
        if len(participants) < 2:
            flash('Minst två deltagare krävs för lottning.', 'error')
            return redirect(url_for('admin_dashboard'))
        mapping = make_mapping(participants)
        if mapping is None:
            flash('Kunde inte skapa en giltig tilldelning efter många försök. Försök justera undantag eller hushåll.', 'error')
            return redirect(url_for('admin_dashboard'))
        save_assignments(mapping)
        # After saving assignments, attempt to send notification emails if SMTP configured
        sent = 0
        failed = 0
        def send_assignment_email_row(row):
            # row: dict with giver_name, giver_email, receiver_name, receiver_email
            if not row.get('giver_email'):
                return False
            subject = 'Hemliga Tomten — din mottagare'
            body = f"God Jul {row.get('giver_name')},\n\nDragningen är klar du får ge en present till: {row.get('receiver_name')}\nE-post: {row.get('receiver_email')}\n\nLycka till!\nÖnskar Hemliga Tomten"
            return send_email(row.get('giver_email'), subject, body)

        # load rows (including givers' emails)
        rows = load_assignments_visible(hide_hidden=False)
        for r in rows:
            ro = dict(r)
            ok = send_assignment_email_row(ro)
            if ok:
                sent += 1
            else:
                failed += 1
        flash(f'Tilldelningar skapade och sparade. E-post skickade: {sent}, misslyckade: {failed}', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/assignments.csv')
    @admin_required
    def admin_assignments_csv():
        # Export assignments but mask any rows where the giver is marked hidden
        raw = load_assignments_visible(hide_hidden=False)
        rows = []
        for r in raw:
            row = dict(r)
            if row.get('giver_hidden') == 1:
                row['receiver_name'] = '<Hidden>'
                row['receiver_email'] = '<Hidden>'
            row.pop('giver_hidden', None)
            rows.append(row)
        si = StringIO()
        si.write('giver_name,giver_id,receiver_name,receiver_email,receiver_id\n')
        for r in rows:
            si.write(f"{r['giver_name']},{r['giver_id']},{r['receiver_name']},{r['receiver_email']},{r['receiver_id']}\n")
        si.seek(0)
        return send_file(StringIO(si.read()), mimetype='text/csv', as_attachment=True, download_name='assignments.csv')

    # --- Email helpers ---
    def get_smtp_settings():
        host = os.environ.get('SMTP_HOST')
        if not host:
            return None
        return {
            'host': host,
            'port': int(os.environ.get('SMTP_PORT', '587')),
            'user': os.environ.get('SMTP_USER'),
            'password': os.environ.get('SMTP_PASSWORD'),
            'use_tls': os.environ.get('SMTP_USE_TLS', '1') not in ('0', 'false', 'False'),
            'from_addr': os.environ.get('FROM_EMAIL') or os.environ.get('SMTP_USER')
        }

    def send_email(to_addr, subject, body):
        cfg = get_smtp_settings()
        if not cfg:
            return False
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = cfg.get('from_addr')
        msg['To'] = to_addr
        msg.set_content(body)
        try:
            if cfg.get('use_tls'):
                with smtplib.SMTP(cfg['host'], cfg['port']) as server:
                    server.ehlo()
                    server.starttls(context=ssl.create_default_context())
                    if cfg.get('user') and cfg.get('password'):
                        server.login(cfg['user'], cfg['password'])
                    server.send_message(msg)
            else:
                with smtplib.SMTP_SSL(cfg['host'], cfg['port']) as server:
                    if cfg.get('user') and cfg.get('password'):
                        server.login(cfg['user'], cfg['password'])
                    server.send_message(msg)
            return True
        except Exception:
            return False

    def send_assignment_email_for_giver(giver_id):
        db = get_db()
        cur = db.cursor()
        cur.execute('''
            SELECT p1.id AS giver_id, p1.name AS giver_name, p1.email AS giver_email, p2.name AS receiver_name, p2.email AS receiver_email
            FROM assignments a
            JOIN participants p1 ON a.giver_id = p1.id
            JOIN participants p2 ON a.receiver_id = p2.id
            WHERE p1.id = ?
        ''', (giver_id,))
        r = cur.fetchone()
        if not r:
            return False
        if not r['giver_email']:
            return False
        subject = 'Hemliga Tomten — din mottagare'
        body = f"Hej {r['giver_name']},\n\nDu har dragits till: {r['receiver_name']}\nE-post: {r['receiver_email']}\n\nLycka till!\nHemliga Tomten"
        return send_email(r['giver_email'], subject, body)

    @app.route('/admin/set_email', methods=['POST'])
    @admin_required
    def admin_set_email():
        pid = request.form.get('participant_id')
        email = request.form.get('email', '').strip().lower()
        if not pid or not email:
            flash('E-post och deltagar-id krävs.', 'error')
            return redirect(url_for('admin_dashboard'))
        try:
            pid_i = int(pid)
        except Exception:
            flash('Ogiltigt deltagar-id.', 'error')
            return redirect(url_for('admin_dashboard'))

        db = get_db()
        cur = db.cursor()
        # ensure email not used by another participant
        cur.execute('SELECT id FROM participants WHERE lower(email)=? AND id<>?', (email.lower(), pid_i))
        if cur.fetchone():
            flash('Denna e-post används redan av en annan deltagare.', 'error')
            return redirect(url_for('admin_dashboard'))

        cur.execute('UPDATE participants SET email=? WHERE id=?', (email, pid_i))
        db.commit()

        # if this participant has an assignment as a giver, try send email
        sent = False
        try:
            sent = send_assignment_email_for_giver(pid_i)
        except Exception:
            sent = False

        if sent:
            flash('E-post sparad och tilldelning skickad till deltagaren.', 'success')
        else:
            flash('E-post sparad. (Ingen e-post skickad eller SMTP inte konfigurerat.)', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/delete_participant', methods=['POST'])
    @admin_required
    def admin_delete_participant():
        pid = request.form.get('participant_id')
        if not pid:
            flash('Deltagar-id saknas.', 'error')
            return redirect(url_for('admin_dashboard'))
        try:
            pid_i = int(pid)
        except Exception:
            flash('Ogiltigt deltagar-id.', 'error')
            return redirect(url_for('admin_dashboard'))
        db = get_db()
        cur = db.cursor()
        # Find givers who will lose their receiver because this participant is being removed
        cur.execute('SELECT p1.id AS giver_id, p1.name AS giver_name FROM assignments a JOIN participants p1 ON a.giver_id = p1.id WHERE a.receiver_id = ?', (pid_i,))
        affected_rows = cur.fetchall()
        affected_names = [r['giver_name'] for r in affected_rows]

        # Remove any assignments that referenced this participant (as giver or receiver)
        cur.execute('DELETE FROM assignments WHERE giver_id=? OR receiver_id=?', (pid_i, pid_i))
        # Remove the participant row
        cur.execute('DELETE FROM participants WHERE id=?', (pid_i,))
        db.commit()

        if affected_names:
            names_str = ', '.join(affected_names)
            flash(f'Deltagaren raderad. Följande givare förlorade sina tilldelningar: {names_str}. Kör lottning för att skapa nya tilldelningar.', 'warning')
        else:
            flash('Deltagaren raderad. Ingen annans tilldelning påverkades.', 'success')
        return redirect(url_for('admin_dashboard'))

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=8050, debug=True)
