"""Scam Detector - Flask backend.

Serves the frontend and a small JSON API:
  auth      /api/register  /api/login  /api/logout  /api/me  /api/auth/google
  password  /api/forgot-password  /api/reset-password
  data      /api/analyses  /api/history  /api/stats

Run:  python app.py      (see README.md for the one-time setup)
"""
import hashlib
import json
import os
import re
import secrets
import smtplib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

# ----------------------------------------------------------------- config
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Copy .env.example to .env and set it "
        '(python -c "import secrets; print(secrets.token_hex(32))").'
    )

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
BASE_URL = os.getenv("BASE_URL", "http://localhost:5000").rstrip("/")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "scam_detector"),
}

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",  # set to 1 when served over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),                  # "Remember me"
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERDICTS = {"safe", "suspicious", "scam"}
# Compared against when the account does not exist, so login timing doesn't reveal valid usernames.
DUMMY_HASH = generate_password_hash("not-a-real-password")


# ---------------------------------------------------------------- helpers
@contextmanager
def db():
    """Open a connection, yield (conn, cursor), commit on success, roll back on error."""
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        cur = conn.cursor(dictionary=True)
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)  # stored as naive UTC


def iso(dt):
    return dt.isoformat() + "Z"


def err(code, status=400):
    return jsonify(error=code), status


def public_user(row):
    return {"id": row["id"], "username": row["username"], "email": row["email"]}


def valid_password(p):
    return (
        isinstance(p, str)
        and 8 <= len(p) <= 128
        and bool(re.search(r"[A-Za-z]", p))
        and bool(re.search(r"\d", p))
        and bool(re.search(r"[^A-Za-z0-9]", p))
    )


def login_user(user_id, remember=False):
    session.clear()  # new session id on every login
    session["user_id"] = user_id
    session.permanent = bool(remember)


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as (_, cur):
        cur.execute("SELECT id, username, email FROM users WHERE id=%s", (uid,))
        return cur.fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return err("auth", 401)
        return fn(*args, **kwargs)

    return wrapper
def send_reset_email(to, link):
    host = os.getenv("SMTP_HOST")
    if not host:  # development: no mail server configured, print the link instead
        app.logger.warning("Password reset link for %s: %s", to, link)
        return
    msg = EmailMessage()
    msg["Subject"] = "Reset your Scam Detector password"
    msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@localhost"))
    msg["To"] = to
    msg.set_content(
        "Use this link to choose a new password (valid for 30 minutes):\n\n"
        f"{link}\n\nIf you didn't ask for this, you can ignore this email."
    )
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
            smtp.starttls()
            if os.getenv("SMTP_USER"):
                smtp.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
    except Exception as e:
        print("EMAIL ERROR:", repr(e))
        app.logger.exception("Could not send reset email")
   



def unique_username(cur, email):
    base = re.sub(r"[^A-Za-z0-9_]", "", email.split("@")[0])[:14] or "user"
    if len(base) < 3:
        base = "user" + base
    for i in range(30):
        candidate = base if i == 0 else f"{base}{secrets.randbelow(10000)}"
        cur.execute("SELECT 1 FROM users WHERE username=%s", (candidate,))
        if not cur.fetchone():
            return candidate
    return f"user{secrets.token_hex(4)}"


def clean_reasons(raw):
    """Keep only the shape the frontend sends: [{key, weight, params}]."""
    out = []
    for r in (raw if isinstance(raw, list) else [])[:30]:
        if not isinstance(r, dict) or not isinstance(r.get("key"), str):
            continue
        weight = r.get("weight")
        params = r.get("params") if isinstance(r.get("params"), dict) else {}
        out.append({
            "key": r["key"][:40],
            "weight": int(weight) if isinstance(weight, (int, float)) else 0,
            "params": {str(k)[:20]: str(v)[:100] for k, v in params.items()},
        })
    return out


# --------------------------------------------------------------- security
@app.before_request
def require_custom_header():
    """State-changing API calls must carry a custom header. Browsers only allow that
    cross-site after a CORS preflight, so other websites can't forge requests."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path.startswith("/api/"):
        if request.headers.get("X-Requested-With") != "ScamDetector":
            return err("forbidden", 403)


@app.errorhandler(mysql.connector.Error)
def database_error(e):
    app.logger.exception("Database error")
    return err("generic", 500)


# ------------------------------------------------------------------ pages
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/config")
def config():
    return jsonify(google_client_id=GOOGLE_CLIENT_ID or None)


# ------------------------------------------------------------------- auth
@app.get("/api/me")
def me():
    user = current_user()
    return jsonify(user=public_user(user) if user else None)


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not (username and email and password):
        return err("required")
    if not USERNAME_RE.match(username):
        return err("username")
    if not EMAIL_RE.match(email) or len(email) > 255:
        return err("email")
    if not valid_password(password):
        return err("weak")

    try:
        with db() as (_, cur):
            cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
            if cur.fetchone():
                return err("exists", 409)
            cur.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
                (username, email, generate_password_hash(password), utcnow()),
            )
            user_id = cur.lastrowid
    except mysql.connector.IntegrityError:  # two sign-ups racing for the same name
        return err("exists", 409)

    login_user(user_id)
    return jsonify(user={"id": user_id, "username": username, "email": email}), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    identifier = str(data.get("identifier", "")).strip()
    password = data.get("password", "")
    if not identifier or not isinstance(password, str) or not password:
        return err("required")

    with db() as (_, cur):
        cur.execute(
            "SELECT id, username, email, password_hash FROM users WHERE username=%s OR email=%s LIMIT 1",
            (identifier, identifier.lower()),
        )
        user = cur.fetchone()

    stored = user["password_hash"] if user and user["password_hash"] else DUMMY_HASH
    ok = check_password_hash(stored, password)
    if not (user and user["password_hash"] and ok):
        return err("invalid", 401)  # same answer for "no such user" and "wrong password"

    login_user(user["id"], remember=bool(data.get("remember")))
    return jsonify(user=public_user(user))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.post("/api/auth/google")
def google_login():
    if not GOOGLE_CLIENT_ID:
        return err("google", 503)
    credential = (request.get_json(silent=True) or {}).get("credential")
    if not credential:
        return err("required")

    try:
        from google.auth.transport import requests as g_requests
        from google.oauth2 import id_token

        info = id_token.verify_oauth2_token(credential, g_requests.Request(), GOOGLE_CLIENT_ID)
    except Exception:
        return err("google", 401)
    if not info.get("email_verified") or not info.get("email"):
        return err("google", 401)

    google_id = info["sub"]
    email = info["email"].lower()

    with db() as (_, cur):
        cur.execute(
            "SELECT id, username, email, google_id FROM users WHERE google_id=%s OR email=%s LIMIT 1",
            (google_id, email),
        )
        user = cur.fetchone()
        if user and not user["google_id"]:
            # First time this e-mail signs in with Google. Sign-up e-mails aren't verified, so drop any
            # existing password: someone else could have registered this address before its owner.
            # The owner can set a new password with "Forgot password".
            cur.execute("UPDATE users SET google_id=%s, password_hash=NULL WHERE id=%s", (google_id, user["id"]))
        elif not user:
            username = unique_username(cur, email)
            cur.execute(
                "INSERT INTO users (username, email, google_id, created_at) VALUES (%s, %s, %s, %s)",
                (username, email, google_id, utcnow()),
            )
            user = {"id": cur.lastrowid, "username": username, "email": email}

    login_user(user["id"], remember=True)
    return jsonify(user=public_user(user))


# --------------------------------------------------------- password reset
@app.post("/api/forgot-password")
def forgot_password():
    email = str((request.get_json(silent=True) or {}).get("email", "")).strip().lower()
    token = None
    if EMAIL_RE.match(email):
        with db() as (_, cur):
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
            if user:
                token = secrets.token_urlsafe(32)
                cur.execute("DELETE FROM password_resets WHERE user_id=%s", (user["id"],))
                cur.execute(
                    "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
                    (user["id"], hashlib.sha256(token.encode()).hexdigest(), utcnow() + timedelta(minutes=30)),
                )
    if token:
        send_reset_email(email, f"{BASE_URL}/?reset={token}")
    return jsonify(ok=True)  # identical response whether or not the email is registered


@app.post("/api/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", ""))
    password = data.get("password", "")
    if not token:
        return err("token")
    if not valid_password(password):
        return err("weak")

    with db() as (_, cur):
        cur.execute(
            "SELECT user_id FROM password_resets WHERE token_hash=%s AND expires_at > %s",
            (hashlib.sha256(token.encode()).hexdigest(), utcnow()),
        )
        row = cur.fetchone()
        if not row:
            return err("token")
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(password), row["user_id"]))
        cur.execute("DELETE FROM password_resets WHERE user_id=%s", (row["user_id"],))
    return jsonify(ok=True)


# ------------------------------------------------- analyses, history, stats
@app.post("/api/analyses")
@login_required
def save_analysis():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()[:5000]
    verdict = data.get("verdict")
    try:
        score = int(data.get("score"))
    except (TypeError, ValueError):
        return err("generic")
    if not message or verdict not in VERDICTS or not 0 <= score <= 100:
        return err("generic")

    with db() as (_, cur):
        cur.execute(
            "INSERT INTO analyses (user_id, message, risk_score, verdict, reasons, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (session["user_id"], message, score, verdict, json.dumps(clean_reasons(data.get("reasons"))), utcnow()),
        )
    return jsonify(ok=True), 201


@app.get("/api/history")
@login_required
def history():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except ValueError:
        limit = 50
    with db() as (_, cur):
        cur.execute(
            "SELECT id, message, risk_score, verdict, reasons, created_at FROM analyses "
            "WHERE user_id=%s ORDER BY created_at DESC, id DESC LIMIT %s",
            (session["user_id"], limit),
        )
        rows = cur.fetchall()
    items = [
        {
            "id": r["id"],
            "message": r["message"],
            "score": r["risk_score"],
            "verdict": r["verdict"],
            "reasons": json.loads(r["reasons"]),
            "created_at": iso(r["created_at"]),
        }
        for r in rows
    ]
    return jsonify(items=items)


@app.delete("/api/history/<int:item_id>")
@login_required
def delete_history_item(item_id):
    with db() as (_, cur):
        cur.execute("DELETE FROM analyses WHERE id=%s AND user_id=%s", (item_id, session["user_id"]))
    return jsonify(ok=True)


@app.delete("/api/history")
@login_required
def clear_history():
    with db() as (_, cur):
        cur.execute("DELETE FROM analyses WHERE user_id=%s", (session["user_id"],))
    return jsonify(ok=True)


@app.get("/api/stats")
@login_required
def stats():
    with db() as (_, cur):
        cur.execute(
            "SELECT verdict, COUNT(*) AS c, AVG(risk_score) AS a FROM analyses WHERE user_id=%s GROUP BY verdict",
            (session["user_id"],),
        )
        rows = cur.fetchall()
    by_verdict = {v: 0 for v in VERDICTS}
    total, weighted = 0, 0.0
    for r in rows:
        by_verdict[r["verdict"]] = r["c"]
        total += r["c"]
        weighted += float(r["a"]) * r["c"]
    return jsonify(total=total, avg_score=round(weighted / total) if total else 0, by_verdict=by_verdict)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1", port=int(os.getenv("PORT", "5000")))
