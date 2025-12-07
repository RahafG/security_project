"""
Simple Flask web application demonstrating five vulnerabilities and their fixes.
- Vulnerable endpoints are suffixed with _vuln
- Fixed endpoints are the default ones

Features implemented:
- User registration & login (vulnerable: SQL injection + MD5 password)
- Fixed: parameterized queries + bcrypt
- Comments that demonstrate XSS (vulnerable) and fixed with Bleach
- Role-based access control (RBAC): vulnerable admin page and fixed decorator
- Encryption of a sensitive field (phone) using Fernet
- HTTPS (instructions below) and secure cookie settings via Flask config

Run instructions (see README below in this file): install dependencies, initialize DB, run app.
"""

from flask import Flask, g, render_template_string, request, redirect, url_for, session, abort, flash
import sqlite3
import hashlib
from bcrypt import gensalt, hashpw, checkpw
from cryptography.fernet import Fernet
import os
from functools import wraps
import bleach
from flask_talisman import Talisman

# Configuration
DATABASE = 'app.db'
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change')
FERNET_KEY = os.environ.get('FERNET_KEY')  # set in env for production
if not FERNET_KEY:
    # For demo only: generate a key. In production, persist this securely.
    FERNET_KEY = Fernet.generate_key().decode()
fernet = Fernet(FERNET_KEY.encode())

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=True,    # cookies only over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # mitigate XSS reading cookies
    SESSION_COOKIE_SAMESITE='Lax'
)

# Use Talisman to set strong security headers and force HTTPS in production
Talisman(app, content_security_policy=None)

# Database helpers

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.executescript('''
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS comments;
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        phone_encrypted TEXT
    );
    CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        text TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    db.commit()
    print('Initialized database')

# Vulnerable registration (SQL injection + MD5 password)
@app.route('/register_vuln', methods=['GET', 'POST'])
def register_vuln():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone = request.form.get('phone', '')
        # INSECURE: MD5 for password hashing
        pwd_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        cur = db.cursor()
        # INSECURE: string formatting vulnerable to SQL injection
        try:
            sql = f"INSERT INTO users (username, password, phone_encrypted) VALUES ('{username}', '{pwd_hash}', '{phone}')"
            cur.execute(sql)
            db.commit()
            return 'Registered (vulnerable)'
        except Exception as e:
            return f'Error: {e}'
    return '''
    <h2>Vulnerable Register</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      Phone: <input name="phone"><br>
      <input type="submit">
    </form>
    '''

# Fixed registration (parameterized + bcrypt + encrypt phone)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone = request.form.get('phone', '')
        # Secure: bcrypt for password hashing
        salt = gensalt()
        pwd_hash = hashpw(password.encode(), salt)
        # Encrypt phone using Fernet
        phone_encrypted = fernet.encrypt(phone.encode()).decode() if phone else None
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute('INSERT INTO users (username, password, phone_encrypted) VALUES (?, ?, ?)',
                        (username, pwd_hash.decode(), phone_encrypted))
            db.commit()
            return 'Registered (fixed)'
        except Exception as e:
            return f'Error: {e}'
    return '''
    <h2>Secure Register</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      Phone: <input name="phone"><br>
      <input type="submit">
    </form>
    '''

# Vulnerable login (SQL injection) 
@app.route('/login_vuln', methods=['GET', 'POST'])
def login_vuln():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pwd_hash = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        cur = db.cursor()
        # INSECURE: vulnerable to SQL injection
        sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{pwd_hash}'"
        cur.execute(sql)
        row = cur.fetchone()
        if row:
            session['user_id'] = row['id']
            session['username'] = row['username']
            session['role'] = row['role']
            return redirect(url_for('dashboard'))
        return 'Login failed (vulnerable)'
    return '''
    <h2>Vulnerable Login</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit">
    </form>
    '''

# Fixed login (parameterized + bcrypt check)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cur = db.cursor()
        cur.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if row and checkpw(password.encode(), row['password'].encode()):
            session['user_id'] = row['id']
            session['username'] = row['username']
            session['role'] = row['role']
            return redirect(url_for('dashboard'))
        return 'Login failed (fixed)'
    return '''
    <h2>Secure Login</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit">
    </form>
    '''

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT phone_encrypted FROM users WHERE id = ?', (session['user_id'],))
    row = cur.fetchone()
    phone = None
    if row and row['phone_encrypted']:
        try:
            phone = fernet.decrypt(row['phone_encrypted'].encode()).decode()
        except Exception:
            phone = '[cannot decrypt]'
    return render_template_string('''
    <h2>Dashboard</h2>
    <p>Username: {{username}}</p>
    <p>Role: {{role}}</p>
    <p>Phone: {{phone}}</p>
    <p><a href="/logout">Logout</a></p>
    ''', username=session.get('username'), role=session.get('role'), phone=phone)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Comments (XSS demo)
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        text = request.form['text']
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO comments (user_id, text) VALUES (?, ?)', (session['user_id'], text))
        db.commit()
        return redirect(url_for('view_comments_vuln'))
    return '''
    <h2>Post Comment</h2>
    <form method="post">
      <textarea name="text"></textarea><br>
      <input type="submit">
    </form>
    '''

# Vulnerable: renders unsanitized user input
@app.route('/comments_vuln')
def view_comments_vuln():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT c.text, u.username FROM comments c JOIN users u ON c.user_id = u.id ORDER BY c.id DESC')
    rows = cur.fetchall()
    html = '<h2>Comments (vulnerable to XSS)</h2>'
    for r in rows:
        # UNSAFE: directly inserting user-supplied HTML
        html += f"<p><strong>{r['username']}</strong>: {r['text']}</p>"
    return html

# Fixed: sanitize output using Bleach (or rely on Jinja autoescape)
@app.route('/comments')
def view_comments():
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT c.text, u.username FROM comments c JOIN users u ON c.user_id = u.id ORDER BY c.id DESC')
    rows = cur.fetchall()
    html = '<h2>Comments (sanitized)</h2>'
    for r in rows:
        safe_text = bleach.clean(r['text'])
        html += f"<p><strong>{r['username']}</strong>: {safe_text}</p>"
    return html

# Access control (RBAC)
# Vulnerable admin page with no checks
@app.route('/admin_vuln')
def admin_vuln():
   return '<h2>Admin Panel (vulnerable) - anyone can see this!</h2>'


# Role decorator for access control
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'role' not in session:
                return redirect(url_for('login'))
            if session.get('role') != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/admin')
@role_required('admin')
def admin():
    return '<h2>Admin Panel (secured)</h2>'

# simple index
@app.route('/')
def index():
    return '''
    <h1>Security Demo App</h1>
    <ul>
      <li><a href="/register_vuln">Register (vulnerable)</a></li>
      <li><a href="/register">Register (fixed)</a></li>
      <li><a href="/login_vuln">Login (vulnerable)</a></li>
      <li><a href="/login">Login (fixed)</a></li>
      <li><a href="/dashboard">Dashboard</a></li>
      <li><a href="/comment">Post Comment</a></li>
      <li><a href="/comments_vuln">View Comments (vuln)</a></li>
      <li><a href="/comments">View Comments (fixed)</a></li>
      <li><a href="/admin_vuln">Admin (vuln)</a></li>
      <li><a href="/admin">Admin (fixed)</a></li>
    </ul>
    '''

#Helper to create an initial admin user for testing (bcrypt + encrypted phone)
def create_demo_admin():
    db = get_db()
    cur = db.cursor()
    admin_user = 'admin'
    pwd = 'adminpass'
    salt = gensalt()
    pwd_hash = hashpw(pwd.encode(), salt)
    phone_encrypted = fernet.encrypt(b'123-456-7890').decode()
    try:
        cur.execute('INSERT INTO users (username, password, role, phone_encrypted) VALUES (?, ?, ?, ?)',
                    (admin_user, pwd_hash.decode(), 'admin', phone_encrypted))
        db.commit()
        print('Demo admin created: username=admin password=adminpass')
    except Exception:
        pass

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--init-db', action='store_true')
    parser.add_argument('--create-admin', action='store_true')
    parser.add_argument('--cert', nargs=2, metavar=('cert.pem', 'key.pem'),
                        help='Provide cert and key to run HTTPS locally')
    args = parser.parse_args()

    
    # Initialize the database
    
    if args.init_db:
        with app.app_context():
            init_db()
        print("Database initialized successfully.")
        exit()

    
    # Create admin user (requires DB + app context)
    
    if args.create_admin:
        with app.app_context():
            init_db()
            create_demo_admin()
        print("Admin user created.")
        exit()

    
    # Run app with HTTPS or HTTP
    
    if args.cert:
        cert, key = args.cert
        app.run(host='0.0.0.0', port=8443, ssl_context=(cert, key), debug=True)
    else:
        app.run(host='0.0.0.0', port=5000, debug=True)




