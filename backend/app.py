#!/usr/bin/env python3
"""Nexus V3 - Unified messaging with attachments, projects, and groups."""

import os
import sys
import uuid
import sqlite3
import hashlib
import hmac
import json
import time
import base64
import smtplib
import threading
import datetime
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# --------------- Config ---------------
PORT = 5678
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nexus.db')
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
SECRET_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret')
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100MB
MAX_BODY_SIZE = 1024 * 1024  # 1MB for JSON bodies
BASE_URL = os.environ.get('NEXUS_BASE_URL', 'https://upwave-research.com/nexus')

SMTP_HOST = os.environ.get('NEXUS_SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('NEXUS_SMTP_PORT', '587'))
SMTP_USER = os.environ.get('NEXUS_SMTP_USER', '')
SMTP_PASS = os.environ.get('NEXUS_SMTP_PASS', '')
SMTP_FROM = os.environ.get('NEXUS_SMTP_FROM', '')

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_secret():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r') as f:
            return f.read().strip()
    secret = uuid.uuid4().hex
    with open(SECRET_FILE, 'w') as f:
        f.write(secret)
    os.chmod(SECRET_FILE, 0o600)
    return secret


SECRET_KEY = get_secret()

# Login rate limiting: {username: [fail_count, locked_until_timestamp]}
LOGIN_FAILS = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECS = 3 * 3600  # 3 hours

# --------------- Database ---------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _col_exists(conn, table, col):
    cols = [r['name'] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    return col in cols


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploader TEXT NOT NULL,
            size INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS groups_ (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS user_groups (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, group_id)
        );
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            creator TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Migrate columns
    if not _col_exists(conn, 'users', 'email'):
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    if not _col_exists(conn, 'users', 'api_token'):
        conn.execute("ALTER TABLE users ADD COLUMN api_token TEXT DEFAULT ''")
    if not _col_exists(conn, 'messages', 'group_id'):
        conn.execute("ALTER TABLE messages ADD COLUMN group_id INTEGER DEFAULT NULL")
    if not _col_exists(conn, 'messages', 'project_id'):
        conn.execute("ALTER TABLE messages ADD COLUMN project_id INTEGER DEFAULT NULL")
    if not _col_exists(conn, 'files', 'group_id'):
        conn.execute("ALTER TABLE files ADD COLUMN group_id INTEGER DEFAULT NULL")
    if not _col_exists(conn, 'files', 'message_id'):
        conn.execute("ALTER TABLE files ADD COLUMN message_id INTEGER DEFAULT NULL")
    if not _col_exists(conn, 'messages', 'is_announcement'):
        conn.execute("ALTER TABLE messages ADD COLUMN is_announcement INTEGER DEFAULT 0")
    if not _col_exists(conn, 'projects', 'work_dir'):
        conn.execute("ALTER TABLE projects ADD COLUMN work_dir TEXT DEFAULT ''")
    if not _col_exists(conn, 'messages', 'synced'):
        conn.execute("ALTER TABLE messages ADD COLUMN synced INTEGER DEFAULT 0")
    if not _col_exists(conn, 'users', 'last_seen_bulletin_id'):
        conn.execute("ALTER TABLE users ADD COLUMN last_seen_bulletin_id INTEGER DEFAULT 0")
    if not _col_exists(conn, 'projects', 'archived'):
        conn.execute("ALTER TABLE projects ADD COLUMN archived INTEGER DEFAULT 0")
    if not _col_exists(conn, 'messages', 'resolved'):
        conn.execute("ALTER TABLE messages ADD COLUMN resolved INTEGER DEFAULT 0")
        # Retroactively mark all existing non-announcement posts as resolved
        conn.execute("UPDATE messages SET resolved=1 WHERE is_announcement=0")
    if not _col_exists(conn, 'messages', 'scheduled_at'):
        conn.execute("ALTER TABLE messages ADD COLUMN scheduled_at TEXT DEFAULT NULL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS project_members (
            project_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (project_id, user_id)
        )
    """)
    conn.commit()
    conn.close()


# --------------- Auth helpers ---------------

def hash_password(password):
    salt = uuid.uuid4().hex
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def check_password(stored, password):
    salt, h = stored.split('$')
    return hmac.compare_digest(h, hashlib.sha256((salt + password).encode()).hexdigest())


def make_session_token(username, is_admin):
    payload = json.dumps({"u": username, "a": int(is_admin), "t": int(time.time())})
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_session_token(token):
    try:
        payload_b64, sig = token.rsplit('.', 1)
        expected = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        return {"username": data["u"], "is_admin": bool(data["a"])}
    except Exception:
        return None


# --------------- Email ---------------

def send_bulletin_notification(author, content, attached_filenames):
    if not SMTP_HOST:
        return
    def _send():
        try:
            conn = get_db()
            rows = conn.execute(
                "SELECT email FROM users WHERE email!='' AND email IS NOT NULL AND username!=?",
                (author,)
            ).fetchall()
            conn.close()
            recipients = [r['email'] for r in rows]
            if not recipients:
                return
            detail = content[:200] if content else ''
            if attached_filenames:
                detail += '\n\nAttachments:\n' + '\n'.join('- ' + fn for fn in attached_filenames)
            subject = f"[Nexus] Bulletin from {author}"
            body = f"{author} posted a bulletin:\n\n{detail}\n\n---\n{BASE_URL}/index.html"
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = SMTP_FROM
            msg['To'] = ', '.join(recipients)
            s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, recipients, msg.as_string())
            s.quit()
        except Exception as e:
            sys.stderr.write(f"[email] bulletin notification failed: {e}\n")
    threading.Thread(target=_send, daemon=True).start()


def _utc_now_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_scheduled_at(raw):
    """Validate and normalize an ISO 8601 UTC timestamp. Returns normalized string or None on invalid."""
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip().replace('Z', '+00:00')
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def scheduled_poller():
    """Background loop: fire scheduled posts whose time has arrived."""
    while True:
        try:
            now = _utc_now_iso()
            conn = get_db()
            rows = conn.execute(
                "SELECT id, author, content, group_id, project_id, is_announcement, scheduled_at "
                "FROM messages WHERE scheduled_at IS NOT NULL AND scheduled_at <= ?",
                (now,)
            ).fetchall()
            # Actual firing time (UTC, SQLite timestamp format)
            fire_ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            fired_ids = []
            for r in rows:
                # Rewrite created_at to the actual firing time so recipients see the
                # true delivery moment, not when the admin drafted it.
                conn.execute(
                    "UPDATE messages SET scheduled_at=NULL, created_at=? WHERE id=?",
                    (fire_ts, r['id'])
                )
                fired_ids.append(dict(r))
            conn.commit()
            # Gather attachment names for each fired row
            for info in fired_ids:
                atts = conn.execute("SELECT filename FROM files WHERE message_id=?", (info['id'],)).fetchall()
                info['attached_filenames'] = [a['filename'] for a in atts]
            conn.close()
            # Fire emails outside DB transaction
            for info in fired_ids:
                detail = (info['content'] or '')[:200]
                if info['attached_filenames']:
                    detail += '\n\nAttachments:\n' + '\n'.join('- ' + fn for fn in info['attached_filenames'])
                if info['is_announcement']:
                    send_bulletin_notification(info['author'], info['content'] or '', info['attached_filenames'])
                elif info['group_id']:
                    send_notification(info['group_id'], info['author'], detail, project_id=info['project_id'])
        except Exception as e:
            sys.stderr.write(f"[scheduled_poller] {e}\n")
        time.sleep(300)


def send_notification(group_id, author, detail, project_id=None):
    if not SMTP_HOST:
        return
    def _send():
        try:
            conn = get_db()
            group = conn.execute("SELECT name FROM groups_ WHERE id=?", (group_id,)).fetchone()
            if not group:
                conn.close()
                return
            group_name = group['name']
            pm_count = 0
            if project_id:
                pm_count = conn.execute(
                    "SELECT COUNT(*) c FROM project_members WHERE project_id=?",
                    (project_id,)
                ).fetchone()['c']
            if pm_count > 0:
                rows = conn.execute("""
                    SELECT u.email FROM users u
                    JOIN project_members pm ON u.id = pm.user_id
                    WHERE pm.project_id=? AND u.username!=? AND u.email!='' AND u.email IS NOT NULL
                """, (project_id, author)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT u.email FROM users u
                    JOIN user_groups ug ON u.id = ug.user_id
                    WHERE ug.group_id=? AND u.username!=? AND u.email!='' AND u.email IS NOT NULL
                """, (group_id, author)).fetchall()
            conn.close()
            recipients = [r['email'] for r in rows]
            if not recipients:
                return
            subject = f"[Nexus] {author} posted in {group_name}"
            body = f"{author} posted in group '{group_name}':\n\n{detail}\n\n---\n{BASE_URL}/index.html"
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = SMTP_FROM
            msg['To'] = ', '.join(recipients)
            s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, recipients, msg.as_string())
            s.quit()
        except Exception as e:
            sys.stderr.write(f"[email] notification failed: {e}\n")
    threading.Thread(target=_send, daemon=True).start()


# --------------- Multipart parser (multi-file) ---------------

def parse_multipart(body, boundary):
    fields = {}
    files = {}  # name -> list of {filename, data}
    parts = body.split(b'--' + boundary.encode())
    for part in parts:
        if part in (b'', b'--\r\n', b'--'):
            continue
        part = part.strip(b'\r\n')
        if b'\r\n\r\n' not in part:
            continue
        header_data, content = part.split(b'\r\n\r\n', 1)
        if content.endswith(b'\r\n'):
            content = content[:-2]
        headers = header_data.decode('utf-8', errors='replace')
        name = None
        filename = None
        for line in headers.split('\r\n'):
            if 'Content-Disposition' in line:
                for item in line.split(';'):
                    item = item.strip()
                    if item.startswith('name='):
                        name = item.split('=', 1)[1].strip('"')
                    if item.startswith('filename='):
                        filename = item.split('=', 1)[1].strip('"')
        if name:
            if filename is not None:
                files.setdefault(name, []).append({"filename": filename, "data": content})
            else:
                fields[name] = content.decode('utf-8', errors='replace')
    return fields, files


def _parse_boundary(content_type):
    for part in content_type.split(';'):
        part = part.strip()
        if part.startswith('boundary='):
            return part.split('=', 1)[1].strip('"')
    return None


# --------------- Helpers ---------------

def get_user_group_ids(conn, username):
    user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return []
    rows = conn.execute("SELECT group_id FROM user_groups WHERE user_id=?", (user['id'],)).fetchall()
    return [r['group_id'] for r in rows]


def get_user_id(conn, username):
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    return row['id'] if row else None


def user_in_project(conn, project_id, user_id):
    """True if user is in project's participant list, OR list is empty (=broadcast)."""
    if user_id is None:
        return False
    has_members = conn.execute("SELECT 1 FROM project_members WHERE project_id=? LIMIT 1",
                               (project_id,)).fetchone()
    if not has_members:
        return True
    row = conn.execute("SELECT 1 FROM project_members WHERE project_id=? AND user_id=?",
                       (project_id, user_id)).fetchone()
    return row is not None


# SQL fragment for filtering messages/projects to those the user can access.
# Use as: f"AND {PARTICIPANT_WHERE}" with bind user_id once.
_PARTICIPANT_WHERE_MSG = (
    "(m.project_id IS NULL"
    " OR NOT EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=m.project_id)"
    " OR EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=m.project_id AND pm.user_id=?))"
)
_PARTICIPANT_WHERE_PROJ = (
    "(NOT EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=p.id)"
    " OR EXISTS(SELECT 1 FROM project_members pm WHERE pm.project_id=p.id AND pm.user_id=?))"
)


def get_user_groups_info(conn, user_id):
    rows = conn.execute("""
        SELECT g.id, g.name FROM groups_ g
        JOIN user_groups ug ON g.id = ug.group_id
        WHERE ug.user_id=?
    """, (user_id,)).fetchall()
    return [dict(r) for r in rows]


def _content_disposition(disposition, filename):
    """Build Content-Disposition header value safe for non-ASCII filenames."""
    try:
        filename.encode('ascii')
        return f'{disposition}; filename="{filename}"'
    except UnicodeEncodeError:
        from urllib.parse import quote
        encoded = quote(filename, safe='')
        return f"{disposition}; filename=\"download\"; filename*=UTF-8''{encoded}"


def _save_attachment(f, uploader, group_id, message_id, conn):
    """Save a single attachment file to disk and DB. Returns filename."""
    stored_name = f"{uuid.uuid4().hex}_{f['filename']}"
    filepath = os.path.join(UPLOAD_DIR, stored_name)
    with open(filepath, 'wb') as out:
        out.write(f['data'])
    conn.execute(
        "INSERT INTO files (filename, stored_name, uploader, size, group_id, message_id) VALUES (?,?,?,?,?,?)",
        (f['filename'], stored_name, uploader, len(f['data']), group_id, message_id))
    return f['filename']


def _delete_message_cascade(conn, msg_id):
    """Delete a message and its attached files from disk and DB."""
    attached = conn.execute("SELECT stored_name FROM files WHERE message_id=?", (msg_id,)).fetchall()
    for f in attached:
        filepath = os.path.join(UPLOAD_DIR, f['stored_name'])
        if os.path.exists(filepath):
            os.remove(filepath)
    conn.execute("DELETE FROM files WHERE message_id=?", (msg_id,))
    conn.execute("DELETE FROM messages WHERE id=?", (msg_id,))


# --------------- Request Handler ---------------

class NexusHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, msg):
        self._send_json({"error": msg}, status)

    def _get_session(self):
        cookie = self.headers.get('Cookie', '')
        for c in cookie.split(';'):
            c = c.strip()
            if c.startswith('nexus_session='):
                session = verify_session_token(c.split('=', 1)[1])
                if session:
                    return session
        # Bearer token from Authorization header or X-Auth-Token header
        token = None
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:].strip()
        if not token:
            token = self.headers.get('X-Auth-Token', '').strip()
        if token:
            conn = get_db()
            row = conn.execute("SELECT username, is_admin FROM users WHERE api_token=? AND api_token!=''", (token,)).fetchone()
            conn.close()
            if row:
                return {"username": row['username'], "is_admin": bool(row['is_admin'])}
        return None

    def _read_body(self, max_size=MAX_BODY_SIZE):
        length = int(self.headers.get('Content-Length', 0))
        if length > max_size:
            return None
        return self.rfile.read(length)

    def _read_json(self):
        body = self._read_body()
        if body is None:
            return None
        try:
            return json.loads(body)
        except Exception:
            return None

    def _query_params(self):
        return parse_qs(urlparse(self.path).query)

    def _route(self, method):
        path = urlparse(self.path).path.rstrip('/')
        if path.startswith('/api'):
            path = path[4:]

        routes = {
            ('GET', '/health'): self.handle_health,
            ('POST', '/login'): self.handle_login,
            ('POST', '/logout'): self.handle_logout,
            ('GET', '/me'): self.handle_me,
            ('PUT', '/me'): self.handle_update_me,
            ('GET', '/users'): self.handle_list_users,
            ('POST', '/users'): self.handle_create_user,
            ('GET', '/messages'): self.handle_list_messages,
            ('POST', '/messages'): self.handle_create_message,
            ('GET', '/files'): self.handle_list_files,
            ('POST', '/files'): self.handle_upload_file,
            ('GET', '/groups'): self.handle_list_groups,
            ('POST', '/groups'): self.handle_create_group,
            ('GET', '/projects'): self.handle_list_projects,
            ('POST', '/projects'): self.handle_create_project,
            ('GET', '/announcements'): self.handle_list_announcements,
            ('POST', '/announcements'): self.handle_create_announcement,
            ('POST', '/announcements/seen'): self.handle_mark_bulletins_seen,
            ('GET', '/sync/pending'): self.handle_sync_pending,
            ('POST', '/sync/ack'): self.handle_sync_ack,
            ('GET', '/token'): self.handle_get_token,
            ('POST', '/token/generate'): self.handle_generate_token,
        }

        handler = routes.get((method, path))
        if handler:
            return handler()

        # Dynamic routes
        if method == 'DELETE' and path.startswith('/users/'):
            return self.handle_delete_user(path.split('/')[-1])
        if method == 'PUT' and path.startswith('/users/'):
            return self.handle_update_user(path.split('/')[-1])
        if method == 'GET' and path.startswith('/messages/'):
            return self.handle_get_message(path.split('/')[-1])
        if method == 'PUT' and path.startswith('/messages/'):
            return self.handle_update_message(path.split('/')[-1])
        if method == 'DELETE' and path.startswith('/messages/'):
            return self.handle_delete_message(path.split('/')[-1])
        if method == 'DELETE' and path.startswith('/announcements/'):
            return self.handle_delete_announcement(path.split('/')[-1])
        if method == 'GET' and '/files/' in path and path.endswith('/download'):
            return self.handle_download_file(path.split('/')[-2])
        if method == 'GET' and '/files/' in path and path.endswith('/preview'):
            return self.handle_preview_file(path.split('/')[-2])
        if method == 'DELETE' and path.startswith('/files/'):
            return self.handle_delete_file(path.split('/')[-1])
        if method == 'DELETE' and path.startswith('/groups/') and '/members' not in path:
            return self.handle_delete_group(path.split('/')[-1])
        # Project members (must be checked before generic /projects/<id>)
        parts = path.split('/')
        if len(parts) == 4 and parts[1] == 'projects' and parts[3] == 'members':
            pid = parts[2]
            if method == 'GET':
                return self.handle_list_project_members(pid)
            if method == 'PUT':
                return self.handle_set_project_members(pid)
        if method == 'PUT' and path.startswith('/projects/'):
            return self.handle_update_project(path.split('/')[-1])
        if method == 'DELETE' and path.startswith('/projects/'):
            return self.handle_delete_project(path.split('/')[-1])
        # Group members
        if len(parts) >= 4 and parts[1] == 'groups' and parts[3] == 'members':
            gid = parts[2]
            if method == 'GET' and len(parts) == 4:
                return self.handle_list_group_members(gid)
            if method == 'POST' and len(parts) == 4:
                return self.handle_add_group_member(gid)
            if method == 'DELETE' and len(parts) == 5:
                return self.handle_remove_group_member(gid, parts[4])

        self._send_error(404, "not found")

    def do_GET(self):
        self._route('GET')

    def do_POST(self):
        self._route('POST')

    def do_DELETE(self):
        self._route('DELETE')

    def do_PUT(self):
        self._route('PUT')

    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    # --------------- Health ---------------

    def handle_health(self):
        self._send_json({"status": "ok", "version": 3, "smtp": bool(SMTP_HOST)})

    # --------------- Auth ---------------

    def handle_login(self):
        data = self._read_json()
        if not data or 'username' not in data or 'password' not in data:
            return self._send_error(400, "username and password required")
        username = data['username']
        # Check lockout
        if username in LOGIN_FAILS:
            fails, locked_until = LOGIN_FAILS[username]
            if fails >= LOGIN_MAX_ATTEMPTS and time.time() < locked_until:
                remaining = int((locked_until - time.time()) / 60)
                return self._send_error(429, f"account locked, try again in {remaining} minutes")
            if time.time() >= locked_until:
                del LOGIN_FAILS[username]
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not check_password(row['password_hash'], data['password']):
            conn.close()
            # Record failure
            if username not in LOGIN_FAILS:
                LOGIN_FAILS[username] = [0, 0]
            LOGIN_FAILS[username][0] += 1
            if LOGIN_FAILS[username][0] >= LOGIN_MAX_ATTEMPTS:
                LOGIN_FAILS[username][1] = time.time() + LOGIN_LOCKOUT_SECS
            remaining_attempts = LOGIN_MAX_ATTEMPTS - LOGIN_FAILS[username][0]
            if remaining_attempts > 0:
                return self._send_error(403, f"invalid credentials ({remaining_attempts} attempts left)")
            return self._send_error(429, "account locked for 3 hours")
        # Success: clear failures
        if username in LOGIN_FAILS:
            del LOGIN_FAILS[username]
        groups = get_user_groups_info(conn, row['id'])
        conn.close()
        token = make_session_token(row['username'], row['is_admin'])
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie', f'nexus_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000')
        body = json.dumps({"ok": True, "username": row['username'], "is_admin": bool(row['is_admin']), "groups": groups}).encode()
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def handle_logout(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie', 'nexus_session=; Path=/; HttpOnly; Max-Age=0')
        body = json.dumps({"ok": True}).encode()
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def handle_me(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        user = conn.execute("SELECT id, email, last_seen_bulletin_id FROM users WHERE username=?", (session['username'],)).fetchone()
        groups = get_user_groups_info(conn, user['id']) if user else []
        last_seen = user['last_seen_bulletin_id'] if user else 0
        unread = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE is_announcement=1 AND id>? "
            "AND (scheduled_at IS NULL OR author=?)",
            (last_seen, session['username'])
        ).fetchone()[0]
        conn.close()
        self._send_json({
            "username": session['username'],
            "is_admin": session['is_admin'],
            "email": user['email'] if user else '',
            "groups": groups,
            "unread_bulletins": unread
        })

    def handle_update_me(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        data = self._read_json()
        if not data:
            return self._send_error(400, "no data")
        conn = get_db()
        if 'email' in data:
            conn.execute("UPDATE users SET email=? WHERE username=?", (data['email'], session['username']))
        if 'password' in data and data['password']:
            conn.execute("UPDATE users SET password_hash=? WHERE username=?",
                         (hash_password(data['password']), session['username']))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Token ---------------

    def handle_get_token(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        row = conn.execute("SELECT api_token FROM users WHERE username=?", (session['username'],)).fetchone()
        conn.close()
        self._send_json({"token": row['api_token'] if row else ''})

    def handle_generate_token(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        token = uuid.uuid4().hex
        conn = get_db()
        conn.execute("UPDATE users SET api_token=? WHERE username=?", (token, session['username']))
        conn.commit()
        conn.close()
        self._send_json({"token": token})

    # --------------- Users (admin) ---------------

    def handle_list_users(self):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        limit, _, offset, use_pagination = self._paginate_params()
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        rows = conn.execute("SELECT id, username, is_admin, email, created_at FROM users ORDER BY id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        result = []
        for r in rows:
            u = dict(r)
            u['groups'] = get_user_groups_info(conn, r['id'])
            result.append(u)
        conn.close()
        self._send_paginated(result, offset + len(result) < total, use_pagination, total)

    def handle_create_user(self):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data or 'username' not in data or 'password' not in data:
            return self._send_error(400, "username and password required")
        conn = get_db()
        try:
            cur = conn.execute("INSERT INTO users (username, password_hash, is_admin, email) VALUES (?,?,?,?)",
                         (data['username'], hash_password(data['password']),
                          int(data.get('is_admin', False)), data.get('email', '')))
            user_id = cur.lastrowid
            for gid in data.get('groups', []):
                conn.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)", (user_id, gid))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_error(409, "username already exists")
        conn.close()
        self._send_json({"ok": True}, 201)

    def handle_update_user(self, user_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data:
            return self._send_error(400, "no data")
        conn = get_db()
        if 'email' in data:
            conn.execute("UPDATE users SET email=? WHERE id=?", (data['email'], user_id))
        if 'groups' in data:
            conn.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
            for gid in data['groups']:
                conn.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)", (user_id, gid))
            # Drop project memberships for projects no longer in user's groups
            conn.execute("""
                DELETE FROM project_members
                WHERE user_id=? AND project_id IN (
                    SELECT p.id FROM projects p
                    WHERE p.group_id NOT IN (SELECT group_id FROM user_groups WHERE user_id=?)
                )
            """, (user_id, user_id))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_delete_user(self, user_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        conn.execute("DELETE FROM user_groups WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM project_members WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Groups ---------------

    def handle_list_groups(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        limit, _, offset, use_pagination = self._paginate_params()
        conn = get_db()
        if session['is_admin']:
            total = conn.execute("SELECT COUNT(*) FROM groups_").fetchone()[0]
            rows = conn.execute("SELECT * FROM groups_ ORDER BY id LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        else:
            total = conn.execute("""
                SELECT COUNT(*) FROM groups_ g
                JOIN user_groups ug ON g.id = ug.group_id
                JOIN users u ON u.id = ug.user_id WHERE u.username=?
            """, (session['username'],)).fetchone()[0]
            rows = conn.execute("""
                SELECT g.* FROM groups_ g
                JOIN user_groups ug ON g.id = ug.group_id
                JOIN users u ON u.id = ug.user_id
                WHERE u.username=? ORDER BY g.id LIMIT ? OFFSET ?
            """, (session['username'], limit, offset)).fetchall()
        result = []
        for r in rows:
            g = dict(r)
            members = conn.execute("""
                SELECT u.username FROM users u
                JOIN user_groups ug ON u.id = ug.user_id WHERE ug.group_id=?
            """, (r['id'],)).fetchall()
            g['members'] = [m['username'] for m in members]
            result.append(g)
        conn.close()
        self._send_paginated(result, offset + len(result) < total, use_pagination, total)

    def handle_create_group(self):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data or not data.get('name', '').strip():
            return self._send_error(400, "name required")
        conn = get_db()
        try:
            conn.execute("INSERT INTO groups_ (name) VALUES (?)", (data['name'].strip(),))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_error(409, "group name already exists")
        conn.close()
        self._send_json({"ok": True}, 201)

    def handle_delete_group(self, group_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        conn.execute("DELETE FROM user_groups WHERE group_id=?", (group_id,))
        # Delete all projects in this group (cascade)
        projects = conn.execute("SELECT id FROM projects WHERE group_id=?", (group_id,)).fetchall()
        for p in projects:
            msgs = conn.execute("SELECT id FROM messages WHERE project_id=?", (p['id'],)).fetchall()
            for m in msgs:
                _delete_message_cascade(conn, m['id'])
            conn.execute("DELETE FROM project_members WHERE project_id=?", (p['id'],))
            conn.execute("DELETE FROM projects WHERE id=?", (p['id'],))
        conn.execute("DELETE FROM groups_ WHERE id=?", (group_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_list_group_members(self, group_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        # Non-admin users can only see members of their own groups
        if not session['is_admin']:
            user_groups = get_user_group_ids(conn, session['username'])
            if int(group_id) not in user_groups:
                conn.close()
                return self._send_error(403, "not in this group")
        rows = conn.execute("""
            SELECT u.id, u.username, u.email FROM users u
            JOIN user_groups ug ON u.id = ug.user_id WHERE ug.group_id=?
        """, (group_id,)).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def handle_add_group_member(self, group_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data or 'username' not in data:
            return self._send_error(400, "username required")
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE username=?", (data['username'],)).fetchone()
        if not user:
            conn.close()
            return self._send_error(404, "user not found")
        conn.execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)", (user['id'], group_id))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_remove_group_member(self, group_id, username):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if user:
            conn.execute("DELETE FROM user_groups WHERE user_id=? AND group_id=?", (user['id'], group_id))
            conn.execute("""
                DELETE FROM project_members
                WHERE user_id=? AND project_id IN (SELECT id FROM projects WHERE group_id=?)
            """, (user['id'], group_id))
            conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Projects ---------------

    def handle_list_projects(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        params = self._query_params()
        if 'group_id' not in params:
            return self._send_error(400, "group_id required")
        gid = int(params['group_id'][0])
        conn = get_db()
        user_groups = get_user_group_ids(conn, session['username'])
        if gid not in user_groups and not session['is_admin']:
            conn.close()
            return self._send_error(403, "not in this group")
        show_archived = params.get('show_archived', ['0'])[0] == '1'
        arch_clause = "" if show_archived else " AND p.archived=0"
        order_clause = " ORDER BY p.archived, p.created_at DESC" if show_archived else " ORDER BY p.created_at DESC"
        if session['is_admin']:
            rows = conn.execute(
                f"SELECT p.* FROM projects p WHERE p.group_id=?{arch_clause}{order_clause} LIMIT 200",
                (gid,)
            ).fetchall()
        else:
            uid = get_user_id(conn, session['username'])
            rows = conn.execute(
                f"SELECT p.* FROM projects p WHERE p.group_id=?{arch_clause} "
                f"AND {_PARTICIPANT_WHERE_PROJ}{order_clause} LIMIT 200",
                (gid, uid)
            ).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def handle_create_project(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        data = self._read_json()
        if not data or not data.get('name', '').strip() or 'group_id' not in data:
            return self._send_error(400, "name and group_id required")
        gid = int(data['group_id'])
        conn = get_db()
        user_groups = get_user_group_ids(conn, session['username'])
        if gid not in user_groups and not session['is_admin']:
            conn.close()
            return self._send_error(403, "not in this group")
        cur = conn.execute("INSERT INTO projects (name, group_id, creator) VALUES (?,?,?)",
                     (data['name'].strip(), gid, session['username']))
        conn.commit()
        pid = cur.lastrowid
        conn.close()
        self._send_json({"ok": True, "id": pid}, 201)

    def handle_delete_project(self, project_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        proj = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not proj:
            conn.close()
            return self._send_error(404, "project not found")
        if proj['creator'] != session['username'] and not session['is_admin']:
            conn.close()
            return self._send_error(403, "only creator or admin can delete")
        # Cascade delete all messages + attachments in this project
        msgs = conn.execute("SELECT id FROM messages WHERE project_id=?", (project_id,)).fetchall()
        for m in msgs:
            _delete_message_cascade(conn, m['id'])
        conn.execute("DELETE FROM project_members WHERE project_id=?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_update_project(self, project_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data:
            return self._send_error(400, "no data")
        conn = get_db()
        if 'work_dir' in data:
            wd = data['work_dir'].strip().replace('/', '').replace('\\', '').replace('..', '')
            conn.execute("UPDATE projects SET work_dir=? WHERE id=?", (wd, project_id))
        if 'archived' in data:
            conn.execute("UPDATE projects SET archived=? WHERE id=?", (int(bool(data['archived'])), project_id))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_list_project_members(self, project_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        proj = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not proj:
            conn.close()
            return self._send_error(404, "project not found")
        # All group members (eligible), with in_project flag
        rows = conn.execute("""
            SELECT u.id, u.username, u.email,
                   EXISTS(SELECT 1 FROM project_members pm
                          WHERE pm.project_id=? AND pm.user_id=u.id) AS in_project
            FROM users u
            JOIN user_groups ug ON u.id = ug.user_id
            WHERE ug.group_id=?
            ORDER BY u.username
        """, (project_id, proj['group_id'])).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def handle_set_project_members(self, project_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        data = self._read_json()
        if not data or 'user_ids' not in data or not isinstance(data['user_ids'], list):
            return self._send_error(400, "user_ids (list) required")
        try:
            new_ids = set(int(x) for x in data['user_ids'])
        except (ValueError, TypeError):
            return self._send_error(400, "invalid user_ids")
        conn = get_db()
        proj = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if not proj:
            conn.close()
            return self._send_error(404, "project not found")
        if not session['is_admin'] and proj['creator'] != session['username']:
            conn.close()
            return self._send_error(403, "only creator or admin")
        if new_ids:
            placeholders = ','.join('?' * len(new_ids))
            valid = conn.execute(
                f"SELECT user_id FROM user_groups WHERE group_id=? AND user_id IN ({placeholders})",
                [proj['group_id']] + list(new_ids)
            ).fetchall()
            valid_ids = {r['user_id'] for r in valid}
            if valid_ids != new_ids:
                conn.close()
                return self._send_error(400, "some users are not in this group")
        conn.execute("DELETE FROM project_members WHERE project_id=?", (project_id,))
        for uid in new_ids:
            conn.execute("INSERT INTO project_members (project_id, user_id) VALUES (?,?)",
                         (project_id, uid))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Sync API (for local polling script) ---------------

    def handle_sync_pending(self):
        """Return messages with synced=0 that belong to projects with work_dir set."""
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        rows = conn.execute("""
            SELECT m.id, m.author, m.content, m.created_at, m.project_id, m.group_id,
                   p.name AS project_name, p.work_dir
            FROM messages m
            JOIN projects p ON m.project_id = p.id
            WHERE m.synced=0 AND m.is_announcement=0 AND p.work_dir!='' AND p.work_dir IS NOT NULL AND p.archived=0
            ORDER BY m.id
        """).fetchall()
        result = []
        for r in rows:
            m = dict(r)
            attachments = conn.execute("SELECT id, filename, stored_name FROM files WHERE message_id=?", (m['id'],)).fetchall()
            m['attachments'] = [dict(a) for a in attachments]
            result.append(m)
        conn.close()
        self._send_json(result)

    def handle_sync_ack(self):
        """Mark messages as synced."""
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data or 'ids' not in data:
            return self._send_error(400, "ids required")
        try:
            ids = [int(x) for x in data['ids']]
        except (ValueError, TypeError):
            return self._send_error(400, "invalid ids")
        conn = get_db()
        for mid in ids:
            conn.execute("UPDATE messages SET synced=1 WHERE id=?", (mid,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Messages (with attachments) ---------------

    def _paginate_params(self, default_limit=30, max_limit=200):
        """Parse limit, before_id, offset from query params. Invalid values fall back to defaults."""
        params = self._query_params()
        def _to_int(v, dflt):
            try:
                return int(v)
            except (ValueError, TypeError):
                return dflt
        limit = min(max(1, _to_int(params.get('limit', [default_limit])[0], default_limit)), max_limit)
        before_id_raw = params.get('before_id', [None])[0]
        before_id = _to_int(before_id_raw, None) if before_id_raw is not None else None
        offset = max(0, _to_int(params.get('offset', [0])[0], 0))
        use_pagination = 'limit' in params
        return limit, before_id, offset, use_pagination

    def _send_paginated(self, items, has_more, use_pagination, total=None):
        """Send paginated or plain response depending on whether limit param was provided."""
        if use_pagination:
            resp = {"items": items, "has_more": has_more}
            if total is not None:
                resp["total"] = total
            self._send_json(resp)
        else:
            self._send_json(items)

    def handle_list_messages(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        params = self._query_params()
        limit, before_id, _, use_pagination = self._paginate_params()
        conn = get_db()
        group_ids = get_user_group_ids(conn, session['username'])

        # Build WHERE conditions
        conditions = []
        bind = []
        if 'project_id' in params:
            pid = int(params['project_id'][0])
            proj = conn.execute("SELECT group_id FROM projects WHERE id=?", (pid,)).fetchone()
            if not proj:
                conn.close()
                return self._send_error(404, "project not found")
            if not session['is_admin']:
                if proj['group_id'] not in group_ids:
                    conn.close()
                    return self._send_error(403, "not in this group")
                uid = get_user_id(conn, session['username'])
                if not user_in_project(conn, pid, uid):
                    conn.close()
                    return self._send_error(403, "not a participant of this project")
            conditions.append("m.project_id=?")
            bind.append(pid)
        elif 'group_id' in params:
            gid = int(params['group_id'][0])
            if gid not in group_ids and not session['is_admin']:
                conn.close()
                return self._send_error(403, "not in this group")
            conditions.append("m.group_id=?")
            bind.append(gid)
        elif session['is_admin']:
            pass  # admin sees all groups
        elif group_ids:
            placeholders = ','.join('?' * len(group_ids))
            conditions.append(f"(m.group_id IN ({placeholders}) OR m.group_id IS NULL)")
            bind.extend(group_ids)
        else:
            conditions.append("m.group_id IS NULL")

        # Non-admin also filtered by project participation
        if not session['is_admin']:
            uid = get_user_id(conn, session['username'])
            conditions.append(_PARTICIPANT_WHERE_MSG)
            bind.append(uid)

        conditions.append("m.is_announcement=0")
        # Scheduled posts: only visible to author until time arrives (poller clears scheduled_at)
        conditions.append("(m.scheduled_at IS NULL OR m.author=?)")
        bind.append(session['username'])
        if 'resolved' in params:
            conditions.append("m.resolved=?")
            bind.append(int(params['resolved'][0]))
        if before_id is not None:
            conditions.append("m.id<?")
            bind.append(before_id)

        where = " AND ".join(conditions)
        rows = conn.execute(
            f"SELECT m.*, p.name AS project_name FROM messages m "
            f"LEFT JOIN projects p ON m.project_id = p.id "
            f"WHERE {where} ORDER BY m.id DESC LIMIT ?",
            bind + [limit]
        ).fetchall()

        result = []
        for r in rows:
            m = dict(r)
            if m['group_id']:
                g = conn.execute("SELECT name FROM groups_ WHERE id=?", (m['group_id'],)).fetchone()
                m['group_name'] = g['name'] if g else '?'
            else:
                m['group_name'] = None
            attachments = conn.execute("SELECT id, filename, size FROM files WHERE message_id=?", (m['id'],)).fetchall()
            m['attachments'] = [dict(a) for a in attachments]
            result.append(m)
        conn.close()
        self._send_paginated(result, len(result) == limit, use_pagination)

    def handle_create_message(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")

        content_type = self.headers.get('Content-Type', '')
        attached_filenames = []

        if 'multipart/form-data' in content_type:
            # Multipart: message with optional attachments
            boundary = _parse_boundary(content_type)
            if not boundary:
                return self._send_error(400, "no boundary")
            body = self._read_body(MAX_UPLOAD_SIZE)
            if body is None:
                return self._send_error(413, "too large")
            fields, file_lists = parse_multipart(body, boundary)
            content = fields.get('content', '').strip()
            group_id = fields.get('group_id')
            project_id = fields.get('project_id')
            scheduled_raw = fields.get('scheduled_at')
            uploaded_files = file_lists.get('file', [])
            # Filter empty file entries
            uploaded_files = [f for f in uploaded_files if f['filename']]
        else:
            # JSON: text-only message
            data = self._read_json()
            if not data:
                return self._send_error(400, "no data")
            content = (data.get('content') or '').strip()
            group_id = data.get('group_id')
            project_id = data.get('project_id')
            scheduled_raw = data.get('scheduled_at')
            uploaded_files = []

        scheduled_at = None
        if scheduled_raw:
            if not session['is_admin']:
                return self._send_error(403, "only admin can schedule")
            scheduled_at = _parse_scheduled_at(scheduled_raw)
            if not scheduled_at:
                return self._send_error(400, "invalid scheduled_at")
            if scheduled_at <= _utc_now_iso():
                return self._send_error(400, "scheduled_at must be in the future")

        if not content and not uploaded_files:
            return self._send_error(400, "content or files required")

        if group_id is not None:
            group_id = int(group_id)
        if project_id is not None:
            project_id = int(project_id)

        conn = get_db()

        # Validate group membership
        if group_id is not None:
            user_groups = get_user_group_ids(conn, session['username'])
            if group_id not in user_groups and not session['is_admin']:
                conn.close()
                return self._send_error(403, "not in this group")

        # Validate project belongs to group
        if project_id is not None:
            proj = conn.execute("SELECT group_id FROM projects WHERE id=?", (project_id,)).fetchone()
            if not proj:
                conn.close()
                return self._send_error(404, "project not found")
            if group_id is not None and proj['group_id'] != group_id:
                conn.close()
                return self._send_error(400, "project does not belong to this group")
            if group_id is None:
                group_id = proj['group_id']
            # Participant gate: non-admin must be in the project participant list (or list empty)
            if not session['is_admin']:
                uid = get_user_id(conn, session['username'])
                if not user_in_project(conn, project_id, uid):
                    conn.close()
                    return self._send_error(403, "not a participant of this project")

        # Insert message
        resolved = 1 if session['is_admin'] else 0
        cur = conn.execute(
            "INSERT INTO messages (author, content, group_id, project_id, resolved, scheduled_at) VALUES (?,?,?,?,?,?)",
            (session['username'], content, group_id, project_id, resolved, scheduled_at)
        )
        message_id = cur.lastrowid

        # Save attachments
        for f in uploaded_files:
            fn = _save_attachment(f, session['username'], group_id, message_id, conn)
            attached_filenames.append(fn)

        conn.commit()
        conn.close()

        # Email notification (skipped for scheduled posts; poller will fire it when due)
        if group_id and not scheduled_at:
            detail = content[:200] if content else ''
            if attached_filenames:
                detail += '\n\nAttachments:\n' + '\n'.join('- ' + fn for fn in attached_filenames)
            send_notification(group_id, session['username'], detail, project_id=project_id)

        self._send_json({"ok": True, "id": message_id, "scheduled_at": scheduled_at}, 201)

    def handle_update_message(self, msg_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        data = self._read_json()
        if not data:
            return self._send_error(400, "no data")
        conn = get_db()
        try:
            msg_id_int = int(msg_id)
        except (ValueError, TypeError):
            conn.close()
            return self._send_error(400, "invalid id")
        if 'resolved' in data:
            conn.execute("UPDATE messages SET resolved=? WHERE id=? AND is_announcement=0",
                         (int(bool(data['resolved'])), msg_id_int))
        if 'project_id' in data:
            new_pid = int(data['project_id'])
            msg = conn.execute("SELECT group_id FROM messages WHERE id=? AND is_announcement=0",
                               (msg_id_int,)).fetchone()
            if not msg:
                conn.close()
                return self._send_error(404, "message not found")
            proj = conn.execute("SELECT group_id FROM projects WHERE id=?", (new_pid,)).fetchone()
            if not proj:
                conn.close()
                return self._send_error(404, "project not found")
            if proj['group_id'] != msg['group_id']:
                conn.close()
                return self._send_error(400, "target project must be in the same group")
            conn.execute("UPDATE messages SET project_id=? WHERE id=? AND is_announcement=0",
                         (new_pid, msg_id_int))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_get_message(self, msg_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        try:
            msg_id = int(msg_id)
        except (ValueError, TypeError):
            return self._send_error(400, "invalid id")
        conn = get_db()
        group_ids = get_user_group_ids(conn, session['username'])
        row = conn.execute("""
            SELECT m.id, m.author, m.content, m.created_at, m.project_id, m.group_id,
                   m.scheduled_at,
                   p.name AS project_name,
                   (SELECT COUNT(*) FROM messages m2
                    WHERE m2.project_id = m.project_id AND m2.id <= m.id
                      AND m2.is_announcement = 0) AS project_seq
            FROM messages m
            LEFT JOIN projects p ON m.project_id = p.id
            WHERE m.id = ? AND m.is_announcement = 0
        """, (msg_id,)).fetchone()
        conn.close()
        if not row:
            return self._send_error(404, "not found")
        r = dict(row)
        # Scheduled posts hidden from everyone except author
        if r.get('scheduled_at') and r['author'] != session['username']:
            return self._send_error(404, "not found")
        gid = r.get('group_id')
        if not session['is_admin']:
            if gid not in group_ids:
                return self._send_error(403, "not in this group")
            pid = r.get('project_id')
            if pid:
                conn2 = get_db()
                uid = get_user_id(conn2, session['username'])
                ok = user_in_project(conn2, pid, uid)
                conn2.close()
                if not ok:
                    return self._send_error(403, "not a participant of this project")
        self._send_json(r)

    def handle_delete_message(self, msg_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        _delete_message_cascade(conn, msg_id)
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Announcements ---------------

    def handle_list_announcements(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        limit, before_id, _, use_pagination = self._paginate_params()
        conn = get_db()
        vis = "(scheduled_at IS NULL OR author=?)"
        if before_id is not None:
            rows = conn.execute(
                f"SELECT * FROM messages WHERE is_announcement=1 AND id<? AND {vis} ORDER BY id DESC LIMIT ?",
                (before_id, session['username'], limit)
            ).fetchall()
        else:
            rows = conn.execute(
                f"SELECT * FROM messages WHERE is_announcement=1 AND {vis} ORDER BY id DESC LIMIT ?",
                (session['username'], limit)
            ).fetchall()
        result = []
        for r in rows:
            m = dict(r)
            attachments = conn.execute("SELECT id, filename, size FROM files WHERE message_id=?", (m['id'],)).fetchall()
            m['attachments'] = [dict(a) for a in attachments]
            result.append(m)
        conn.close()
        self._send_paginated(result, len(result) == limit, use_pagination)

    def handle_create_announcement(self):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        content_type = self.headers.get('Content-Type', '')
        attached_filenames = []
        if 'multipart/form-data' in content_type:
            boundary = _parse_boundary(content_type)
            if not boundary:
                return self._send_error(400, "no boundary")
            body = self._read_body(MAX_UPLOAD_SIZE)
            if body is None:
                return self._send_error(413, "too large")
            fields, file_lists = parse_multipart(body, boundary)
            content = fields.get('content', '').strip()
            scheduled_raw = fields.get('scheduled_at')
            uploaded_files = [f for f in file_lists.get('file', []) if f['filename']]
        else:
            data = self._read_json()
            if not data:
                return self._send_error(400, "no data")
            content = (data.get('content') or '').strip()
            scheduled_raw = data.get('scheduled_at')
            uploaded_files = []
        if not content and not uploaded_files:
            return self._send_error(400, "content or files required")
        scheduled_at = None
        if scheduled_raw:
            scheduled_at = _parse_scheduled_at(scheduled_raw)
            if not scheduled_at:
                return self._send_error(400, "invalid scheduled_at")
            if scheduled_at <= _utc_now_iso():
                return self._send_error(400, "scheduled_at must be in the future")
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO messages (author, content, group_id, project_id, is_announcement, scheduled_at) "
            "VALUES (?,?,NULL,NULL,1,?)",
            (session['username'], content, scheduled_at))
        message_id = cur.lastrowid
        for f in uploaded_files:
            fn = _save_attachment(f, session['username'], None, message_id, conn)
            attached_filenames.append(fn)
        conn.commit()
        conn.close()
        # Notify ALL users with email (skipped for scheduled; poller fires when due)
        if not scheduled_at:
            send_bulletin_notification(session['username'], content, attached_filenames)
        self._send_json({"ok": True, "id": message_id, "scheduled_at": scheduled_at}, 201)

    def handle_delete_announcement(self, msg_id):
        session = self._get_session()
        if not session or not session['is_admin']:
            return self._send_error(403, "admin only")
        conn = get_db()
        _delete_message_cascade(conn, msg_id)
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    def handle_mark_bulletins_seen(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        latest = conn.execute(
            "SELECT MAX(id) FROM messages WHERE is_announcement=1 "
            "AND (scheduled_at IS NULL OR author=?)",
            (session['username'],)
        ).fetchone()[0] or 0
        conn.execute("UPDATE users SET last_seen_bulletin_id=? WHERE username=?", (latest, session['username']))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # --------------- Files (standalone, kept for API compat) ---------------

    def handle_list_files(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        params = self._query_params()
        conn = get_db()
        group_ids = get_user_group_ids(conn, session['username'])
        if 'group_id' in params:
            gid = int(params['group_id'][0])
            if gid not in group_ids and not session['is_admin']:
                conn.close()
                return self._send_error(403, "not in this group")
            rows = conn.execute("SELECT * FROM files WHERE group_id=? ORDER BY uploaded_at DESC LIMIT 200", (gid,)).fetchall()
        else:
            if group_ids:
                placeholders = ','.join('?' * len(group_ids))
                rows = conn.execute(
                    f"SELECT * FROM files WHERE group_id IN ({placeholders}) OR group_id IS NULL ORDER BY uploaded_at DESC LIMIT 200",
                    group_ids).fetchall()
            else:
                rows = conn.execute("SELECT * FROM files WHERE group_id IS NULL ORDER BY uploaded_at DESC LIMIT 200").fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def handle_upload_file(self):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            return self._send_error(400, "multipart/form-data required")
        boundary = _parse_boundary(content_type)
        if not boundary:
            return self._send_error(400, "no boundary")
        body = self._read_body(MAX_UPLOAD_SIZE)
        if body is None:
            return self._send_error(413, "file too large")
        fields, file_lists = parse_multipart(body, boundary)
        flist = file_lists.get('file', [])
        if not flist or not flist[0]['filename']:
            return self._send_error(400, "no file uploaded")

        group_id = fields.get('group_id')
        if group_id:
            group_id = int(group_id)
            conn = get_db()
            user_groups = get_user_group_ids(conn, session['username'])
            if group_id not in user_groups and not session['is_admin']:
                conn.close()
                return self._send_error(403, "not in this group")
            conn.close()
        else:
            group_id = None

        f = flist[0]
        stored_name = f"{uuid.uuid4().hex}_{f['filename']}"
        filepath = os.path.join(UPLOAD_DIR, stored_name)
        with open(filepath, 'wb') as out:
            out.write(f['data'])
        conn = get_db()
        conn.execute("INSERT INTO files (filename, stored_name, uploader, size, group_id) VALUES (?,?,?,?,?)",
                     (f['filename'], stored_name, session['username'], len(f['data']), group_id))
        conn.commit()
        conn.close()
        self._send_json({"ok": True, "filename": f['filename']}, 201)

    def _check_file_access(self, conn, file_row, session):
        """Return None if user may read file_row; else an (status, msg) tuple."""
        if session['is_admin']:
            return None
        gid = file_row['group_id']
        if gid:
            if gid not in get_user_group_ids(conn, session['username']):
                return (403, "not in this group")
        # If attached to a message in a project, enforce participant gate
        mid = file_row['message_id']
        if mid:
            msg = conn.execute("SELECT project_id, group_id FROM messages WHERE id=?", (mid,)).fetchone()
            if msg:
                if msg['group_id'] and msg['group_id'] not in get_user_group_ids(conn, session['username']):
                    return (403, "not in this group")
                if msg['project_id']:
                    uid = get_user_id(conn, session['username'])
                    if not user_in_project(conn, msg['project_id'], uid):
                        return (403, "not a participant of this project")
        return None

    def handle_download_file(self, file_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            conn.close()
            return self._send_error(404, "file not found")
        err = self._check_file_access(conn, row, session)
        if err:
            conn.close()
            return self._send_error(*err)
        conn.close()
        filepath = os.path.join(UPLOAD_DIR, row['stored_name'])
        if not os.path.exists(filepath):
            return self._send_error(404, "file missing from disk")
        with open(filepath, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Disposition', _content_disposition('attachment', row['filename']))
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def _guess_mime(self, filename):
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        return {
            'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
            'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml',
            'bmp': 'image/bmp', 'ico': 'image/x-icon',
            'pdf': 'application/pdf', 'txt': 'text/plain',
        }.get(ext, 'application/octet-stream')

    def handle_preview_file(self, file_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            conn.close()
            return self._send_error(404, "file not found")
        err = self._check_file_access(conn, row, session)
        if err:
            conn.close()
            return self._send_error(*err)
        conn.close()
        filepath = os.path.join(UPLOAD_DIR, row['stored_name'])
        if not os.path.exists(filepath):
            return self._send_error(404, "file missing from disk")
        with open(filepath, 'rb') as f:
            data = f.read()
        mime = self._guess_mime(row['filename'])
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Disposition', _content_disposition('inline', row['filename']))
        self.send_header('Content-Length', len(data))
        self.send_header('Cache-Control', 'max-age=86400')
        self.end_headers()
        self.wfile.write(data)

    def handle_delete_file(self, file_id):
        session = self._get_session()
        if not session:
            return self._send_error(403, "not logged in")
        conn = get_db()
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            conn.close()
            return self._send_error(404, "file not found")
        if row['uploader'] != session['username'] and not session['is_admin']:
            conn.close()
            return self._send_error(403, "not allowed")
        filepath = os.path.join(UPLOAD_DIR, row['stored_name'])
        if os.path.exists(filepath):
            os.remove(filepath)
        conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})


# --------------- Main ---------------

def create_admin():
    conn = get_db()
    admin = conn.execute("SELECT * FROM users WHERE is_admin=1").fetchone()
    if not admin:
        username = os.environ.get('NEXUS_ADMIN_USER', 'admin')
        password = os.environ.get('NEXUS_ADMIN_PASS', '')
        if not password:
            import getpass
            print(f"No admin user found. Creating admin account '{username}'.")
            password = getpass.getpass("Set admin password: ")
        conn.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?,?,1)",
                     (username, hash_password(password)))
        conn.commit()
        print(f"Admin user '{username}' created.")
    conn.close()


if __name__ == '__main__':
    init_db()
    if '--init-admin' in sys.argv or not get_db().execute("SELECT * FROM users WHERE is_admin=1").fetchone():
        create_admin()
    print(f"Nexus V3 starting on 127.0.0.1:{PORT}")
    if SMTP_HOST:
        print(f"  SMTP: {SMTP_HOST}:{SMTP_PORT} from {SMTP_FROM}")
    else:
        print("  SMTP: not configured (notifications disabled)")
    threading.Thread(target=scheduled_poller, daemon=True).start()
    server = HTTPServer(('127.0.0.1', PORT), NexusHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()
