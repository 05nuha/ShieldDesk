# ShieldDesk v0 - DELIBERATELY VULNERABLE baseline (lab use only, synthetic data only)
import hashlib
import sqlite3
import subprocess
 
from flask import Flask, request, session, redirect, url_for, render_template, g
 
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret123"          # VULN: hard-coded secret
DB_PATH = "shielddesk.db"
 
 
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
 
 
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()       # VULN: fast, unsalted hash
 
 
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"), role=session.get("role"))
 
 
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]                  # VULN: no password policy
        name = request.form["full_name"]
        sid = request.form["student_id"]
        email = request.form["email"]
        db = get_db()
        # VULN: string-built SQL
        db.execute(f"INSERT INTO users (username, password, full_name, student_id, email, role) "
                   f"VALUES ('{u}', '{hash_password(p)}', '{name}', '{sid}', '{email}', 'user')")
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")
 
 
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        db = get_db()
        # VULN: user enumeration - different message for unknown user
        exists = db.execute(f"SELECT * FROM users WHERE username = '{u}'").fetchone()
        if not exists:
            error = f"User {u} does not exist"
        else:
            # VULN: SQL injection (string-built query), no lockout
            query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{hash_password(p)}'"
            row = db.execute(query).fetchone()
            if row:
                session["user"] = row["username"]
                session["role"] = row["role"]
                return redirect(url_for("requests_page"))
            error = "Wrong password"
    return render_template("login.html", error=error)
 
 
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))
 
 
@app.route("/requests", methods=["GET", "POST"])
def requests_page():
    if "user" not in session:
        return redirect(url_for("login"))
    db = get_db()
    if request.method == "POST":
        cat = request.form["category"]
        details = request.form["details"]
        db.execute(f"INSERT INTO requests (username, category, details, status) "
                   f"VALUES ('{session['user']}', '{cat}', '{details}', 'Open')")
        db.commit()
    if session.get("role") == "admin":
        rows = db.execute("SELECT * FROM requests").fetchall()
    else:
        rows = db.execute(f"SELECT * FROM requests WHERE username = '{session['user']}'").fetchall()
    return render_template("requests.html", rows=rows, role=session.get("role"))
 
 
@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(f"SELECT id, category, status FROM requests WHERE category LIKE '%{q}%'").fetchall()
    # VULN: reflected XSS - user input placed into HTML without encoding
    html = f"<h2>Results for: {q}</h2><ul>"
    for r in rows:
        html += f"<li>#{r['id']} {r['category']} ({r['status']})</li>"
    return html + "</ul><a href='/'>Home</a>"
 
 
@app.route("/admin/ping")
def admin_ping():
    # VULN: command injection via shell=True, and no role check
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return f"<pre>{out.decode()}</pre>"
 
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)    # VULN: debug mode, all interfaces
