# ShieldDesk v1 - SECURED version
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
 
from flask import Flask, request, session, redirect, url_for, render_template, g, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
 
app = Flask(__name__)
 
# --- Logic level: secret loaded from the environment, never hard-coded -------
app.config["SECRET_KEY"] = os.environ.get("SHIELDDESK_SECRET_KEY") or os.urandom(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB_PATH = os.environ.get("SHIELDDESK_DB", "shielddesk.db")
 
# --- Security event logging (used by monitor.py in Task 5) -------------------
os.makedirs("logs", exist_ok=True)
sec_log = logging.getLogger("security")
sec_log.setLevel(logging.INFO)
_h = logging.FileHandler("logs/security.log")
_h.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
sec_log.addHandler(_h)
 
MAX_FAILED = 5
LOCK_MINUTES = 15
GENERIC_LOGIN_ERROR = ("Invalid username or password. "
                       "After 5 failed attempts the account is locked for 15 minutes.")
 
# --- Input boundary: allowlist rules -----------------------------------------
RULES = {
    "username":   re.compile(r"^[A-Za-z0-9_]{3,20}$"),
    "student_id": re.compile(r"^[0-9]{8}$"),
    "full_name":  re.compile(r"^[A-Za-z][A-Za-z '\-]{1,59}$"),
    "email":      re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,63}\.[A-Za-z]{2,10}$"),
    "q":          re.compile(r"^[A-Za-z ]{0,30}$"),
}
CATEGORIES = {"IT", "Finance", "Housing", "Registration", "Library"}
COMMON_PASSWORDS = {"123456", "password", "12345678", "qwerty", "111111", "123456789",
                    "password1", "iloveyou", "admin123", "welcome1", "password123"}
 
 
def valid(field, value):
    return value is not None and bool(RULES[field].fullmatch(value))
 
 
def password_policy_ok(pw):
    # Length-based policy (NIST SP 800-63B style): 12-128 chars, not a common password
    return 12 <= len(pw) <= 128 and pw.lower() not in COMMON_PASSWORDS
 
 
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db
 
 
@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()
 
 
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper
 
 
def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "admin":
            sec_log.info("ACCESS_DENIED user=%s path=%s ip=%s",
                         session.get("user", "-"), request.path, request.remote_addr)
            abort(403)
        return f(*a, **kw)
    return wrapper
 
 
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
 
 
# --- Logic level: safe error handling (no stack traces, no internals) --------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(e):
    code = getattr(e, "code", 500)
    app.logger.error("Error %s on %s", code, request.path)   # details stay server-side
    return render_template("error.html", code=code), code
 
 
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"), role=session.get("role"))
 
 
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        f = request.form
        u, p = f.get("username", ""), f.get("password", "")
        name, sid, email = f.get("full_name", ""), f.get("student_id", ""), f.get("email", "")
        if not (valid("username", u) and valid("full_name", name)
                and valid("student_id", sid) and valid("email", email)):
            error = "Please check the form: one or more fields are not in the expected format."
        elif not password_policy_ok(p):
            error = "Password must be at least 12 characters and not a common password. Passphrases are welcome."
        else:
            db = get_db()
            try:
                db.execute("INSERT INTO users (username, password, full_name, student_id, email, role) "
                           "VALUES (?, ?, ?, ?, ?, 'user')",
                           (u, generate_password_hash(p), name, sid, email))
                db.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Registration could not be completed. Try a different username."
    return render_template("register.html", error=error)
 
 
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        ip = request.remote_addr
        if not valid("username", u):
            sec_log.info("LOGIN_FAILED user=invalid_format ip=%s", ip)
            return render_template("login.html", error=GENERIC_LOGIN_ERROR)
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
        now = datetime.now(timezone.utc)
        if row and row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now:
            sec_log.info("LOGIN_BLOCKED_LOCKED user=%s ip=%s", u, ip)
            return render_template("login.html", error=GENERIC_LOGIN_ERROR)
        if row and check_password_hash(row["password"], p):
            db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (row["id"],))
            db.commit()
            session.clear()
            session["user"], session["role"] = row["username"], row["role"]
            sec_log.info("LOGIN_SUCCESS user=%s ip=%s", u, ip)
            return redirect(url_for("requests_page"))
        if row:
            fails = row["failed_logins"] + 1
            locked = (now + timedelta(minutes=LOCK_MINUTES)).isoformat() if fails >= MAX_FAILED else None
            db.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                       (0 if locked else fails, locked, row["id"]))
            db.commit()
            if locked:
                sec_log.info("ACCOUNT_LOCKED user=%s ip=%s", u, ip)
        sec_log.info("LOGIN_FAILED user=%s ip=%s", u, ip)
        error = GENERIC_LOGIN_ERROR          # same message whether or not the user exists
    return render_template("login.html", error=error)
 
 
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
 
 
@app.route("/requests", methods=["GET", "POST"])
@login_required
def requests_page():
    db = get_db()
    error = None
    if request.method == "POST":
        cat = request.form.get("category", "")
        details = request.form.get("details", "").strip()
        if cat not in CATEGORIES or not (1 <= len(details) <= 500):
            error = "Choose a listed category and enter 1-500 characters of detail."
        else:
            db.execute("INSERT INTO requests (username, category, details, status) VALUES (?, ?, ?, 'Open')",
                       (session["user"], cat, details))
            db.commit()
    if session.get("role") == "admin":
        rows = db.execute("SELECT * FROM requests").fetchall()
    else:
        rows = db.execute("SELECT * FROM requests WHERE username = ?", (session["user"],)).fetchall()
    return render_template("requests.html", rows=rows, role=session.get("role"), error=error)
 
 
@app.route("/search")
def search():
    q = request.args.get("q", "")
    if not valid("q", q):
        return render_template("search.html", q="", rows=[],
                               error="Search accepts letters and spaces only (max 30)."), 400
    db = get_db()
    rows = db.execute("SELECT id, category, status FROM requests WHERE category LIKE ?",
                      (f"%{q}%",)).fetchall()
    return render_template("search.html", q=q, rows=rows, error=None)   # Jinja autoescapes q
 
 
@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    rows = get_db().execute("SELECT username, role, failed_logins, locked_until FROM users").fetchall()
    return "<h2>Users</h2><ul>" + "".join(
        f"<li>{escape(r['username'])} ({escape(r['role'])})</li>" for r in rows) + "</ul>"
 
 
if __name__ == "__main__":
    # debug off; inside Docker bind 0.0.0.0 but publish only on 127.0.0.1 (see Dockerfile/run command)
    app.run(host=os.environ.get("SHIELDDESK_HOST", "127.0.0.1"), port=5000, debug=False)

