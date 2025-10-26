import sqlite3
from flask import g
import os
import hashlib
import secrets
import time

DATABASE = os.environ.get('CTF_DB_PATH', 'ctf_lab.db')
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def close_db():
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
        g._database = None

def init_db(force=False):
    """Initialize DB and seed users/posts"""
    if force and os.path.exists(DATABASE):
        os.remove(DATABASE)

    db = get_db()
    cur = db.cursor()

    # Users table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')

    # Posts table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')

    # CSRF tokens table with timestamp
    cur.execute('''
    CREATE TABLE IF NOT EXISTS csrf_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE NOT NULL,
        created_at INTEGER NOT NULL
    )
    ''')

    db.commit()

    # Seed users
    users = [
        ('admin', hashlib.md5('*********'.encode()).hexdigest())
    ]
    for username, pw_hash in users:
        cur.execute('SELECT id FROM users WHERE username=?', (username,))
        if not cur.fetchone():
            cur.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))

    # Seed posts
    cur.execute('SELECT id FROM posts LIMIT 1')
    if not cur.fetchone():
        posts = [
            ("Welcome to CTF Lab", "This is a test post for search functionality."),
            ("SQL Injection Challenge", "Can you extract admin credentials?"),
            ("CSRF Protection", "Remember, this form requires a valid CSRF token."),
            ("Tips", "Always sanitize inputs to prevent SQL injection."),
            ("Flag Hint", "Maybe some queries reveal more than you expect..."),
        ]
        cur.executemany('INSERT INTO posts (title, content) VALUES (?, ?)', posts)

    db.commit()

CSRF_TOKEN_TTL = 5 * 60  # 10 minutes in seconds

def _cleanup_old_tokens():
    """Delete tokens older than TTL."""
    db = get_db()
    cur = db.cursor()
    cutoff = int(time.time()) - CSRF_TOKEN_TTL
    cur.execute('DELETE FROM csrf_tokens WHERE created_at < ?', (cutoff,))
    db.commit()

def generate_csrf_token():
    db = get_db()
    cur = db.cursor()

    # Cleanup old tokens first
    _cleanup_old_tokens()

    token = secrets.token_hex(16)
    created_at = int(time.time())
    cur.execute('INSERT INTO csrf_tokens (token, created_at) VALUES (?, ?)', (token, created_at))
    db.commit()
    return token

def validate_and_consume_csrf(token):
    if not token:
        return None

    db = get_db()
    cur = db.cursor()

    # Cleanup old tokens
    _cleanup_old_tokens()

    cur.execute('SELECT id FROM csrf_tokens WHERE token=?', (token,))
    row = cur.fetchone()
    if not row:
        return None  # invalid

    # Token valid — remove it
    cur.execute('DELETE FROM csrf_tokens WHERE id=?', (row[0],))
    db.commit()

    # Generate new token to replace it
    new_token = generate_csrf_token()
    return new_token
