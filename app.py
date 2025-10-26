import ssl
from flask import Flask, request, session, redirect, url_for, render_template, Response
from markupsafe import escape
import hashlib
import os
import socket
import urllib.parse
from db import get_db, close_db, init_db, generate_csrf_token, validate_and_consume_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', '********************')

with app.app_context():
    init_db(force=False)

@app.teardown_appcontext
def teardown(exception):
    close_db()

VULN_FETCH_MAX_BYTES = 128 * 1024  

def fetch_any_url(url, timeout=8):
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname
    port = parsed.port
    if not host:
        netloc = (parsed.netloc or "").strip()
        if netloc:
            if ":" in netloc:
                try:
                    host_part, port_s = netloc.split(":", 1)
                    host = host_part
                    port = int(port_s)
                except Exception:
                    host = netloc
            else:
                host = netloc

    if not host:
        raise ValueError("No host found in URL")

    # Default ports
    if not port:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80

    # Build selector: path + ?query (fragment ignored)
    selector = parsed.path or ""
    if parsed.query:
        selector += "?" + parsed.query
    selector = urllib.parse.unquote(selector)
    if scheme not in ("http", "https"):
        selector = selector.lstrip('/')

    # Create raw socket connection
    sock = socket.create_connection((host, port), timeout=timeout)

    # Wrap in TLS for HTTPS
    if scheme == "https":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)

    # Send data:
    if scheme in ("http", "https"):
        host_header = host
        if parsed.port:
            host_header = f"{host}:{parsed.port}"
        else:
            if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
                host_header = f"{host}:{port}"

        # ensure selector begins with '/' for HTTP GET
        path = selector if selector.startswith('/') else ('/' + selector if selector else '/')
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Finder/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(req.encode('utf-8', errors='ignore'))
    else:
        sock.sendall(selector.encode('utf-8', errors='ignore'))
    sock.settimeout(4.0)
    chunks = []
    total = 0
    try:
        while total < VULN_FETCH_MAX_BYTES:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
    except socket.timeout:
        # graceful stop on timeout
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    raw = b"".join(chunks)
    desc = f"{scheme.upper() or 'RAW'} -> {host}:{port} ({len(raw)} bytes)"
    return raw, desc



@app.route('/fetch', methods=['GET', 'POST'])
def fetch_page():
    if session.get('username') != 'admin':
        return render_template(
            'error.html',
            title="Unauthorized",
            message="You must be logged in as admin to use the fetcher.",
            retry_url="/login"
        ), 403

    if request.method == 'GET':
        return render_template('login_success.html', username='admin')

    url = (request.form.get('url') or "").strip()
    if not url:
        return render_template('login_success.html', username='admin', fetch_error="No URL provided")

    try:
        raw, desc = fetch_any_url(url)
        html_preview = raw.decode(errors='replace')
        # Show directly, don't redirect
        return render_template(
            'login_success.html',
            username='admin',
            fetch_desc=desc,
            fetched_content=html_preview
        )
    except Exception as e:
        return render_template(
            'login_success.html',
            username='admin',
            fetch_error=str(e)
        )
@app.route('/')
def index():
    token = generate_csrf_token()
    return render_template('index.html', csrf_token=token)

@app.route('/search', methods=['POST'])
def search():
    form_token = request.form.get('csrf_token', '')
    new_token = validate_and_consume_csrf(form_token)
    if not new_token:
        fresh = generate_csrf_token()
        return render_template('error.html', title="CSRF Failure",
                               message="CSRF token missing, invalid or already used.",
                               retry_url="/", csrf_token=fresh), 403
    q = request.form.get('q', '')
    db = get_db()
    cur = db.cursor()
    sql = f"SELECT id, title, content FROM posts WHERE title LIKE '%{q}%';"
    try:
        cur.execute(sql)
        rows = cur.fetchall()
    except Exception as e:
        err_msg = escape(str(e))
        fresh = generate_csrf_token()
        return render_template('error.html', title="Database error",
                               message=err_msg, retry_url="/", csrf_token=fresh), 500
    results = [{'id': r[0], 'title': r[1], 'content': r[2]} for r in rows]
    return render_template('search_results.html', query=q, results=results, csrf_token=new_token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        token = generate_csrf_token()
        return render_template('login.html', csrf_token=token)
    form_token = request.form.get('csrf_token', '')
    new_token = validate_and_consume_csrf(form_token)
    if not new_token:
        fresh = generate_csrf_token()
        return render_template('error.html', title="CSRF Failure",
                               message="CSRF token missing, invalid or already used.",
                               retry_url="/login", csrf_token=fresh), 403
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    password_hash = hashlib.md5(password.encode()).hexdigest()
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
        user = cur.fetchone()
    except Exception as e:
        fresh = generate_csrf_token()
        return render_template('error.html', title="Database error",
                               message=escape(str(e)), retry_url="/login", csrf_token=fresh), 500
    if user:
        session['username'] = username
        return render_template('login_success.html', username=username)
    else:
        return render_template('login.html', error='Invalid credentials', csrf_token=new_token), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/internal', methods=['GET'])
def internal_flag():
    provided = request.headers.get('API-token')
    if not provided or provided != '345345645676fgdfg3443g':
        return render_template('error.html', title="Forbidden",
                               message="Missing or invalid API token.", retry_url="/"), 403
    if request.remote_addr != '127.0.0.1':
        return render_template('error.html', title="Forbidden",
                               message="Requests to /internal are allowed from 127.0.0.1 only.", retry_url="/"), 403
    return Response("CTF{******************}", mimetype='text/plain')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
