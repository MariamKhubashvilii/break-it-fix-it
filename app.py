"""
Break It, Fix It: an intentionally vulnerable training app.

FOR LOCAL LAB USE ONLY. It binds to 127.0.0.1 and must never be deployed
or exposed to a network. Every vulnerable route has a fixed twin.

Vulnerabilities demonstrated:
  1. SQL injection (login)       /vulnerable/login   vs  /secure/login
  2. Cross-site scripting (XSS)  /vulnerable/comments vs /secure/comments
"""
import html
import sqlite3
from flask import Flask, request, redirect, render_template_string, g

app = Flask(__name__)
DB = "lab.db"


# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB)
    con.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS comments;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT, mode TEXT);
        INSERT INTO users (username, password, role) VALUES
            ('admin', 'S3cretAdminPass!', 'admin'),
            ('alice', 'alicepass', 'user'),
            ('bob',   'bobpass',   'user');
        """
    )
    con.commit()
    con.close()


# ---------- shared page layout ----------
LAYOUT = """
<!doctype html>
<title>Break It, Fix It Lab</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:680px;margin:2rem auto;padding:0 1rem}
  nav a{margin-right:1rem}
  .bad{border-left:6px solid #d33;padding:.5rem 1rem;background:#fff0f0}
  .good{border-left:6px solid #2a7;padding:.5rem 1rem;background:#f0fff4}
  code{background:#eee;padding:2px 5px}
  input,textarea{width:100%;padding:.4rem;margin:.2rem 0 .8rem}
  button{padding:.5rem 1.2rem}
</style>
<nav>
  <a href="/">Home</a>
  <a href="/vulnerable/login">Login (vulnerable)</a>
  <a href="/secure/login">Login (secure)</a>
  <a href="/vulnerable/comments">Comments (vulnerable)</a>
  <a href="/secure/comments">Comments (secure)</a>
</nav>
<hr>
{{ body|safe }}
"""


def page(body):
    return render_template_string(LAYOUT, body=body)


@app.route("/")
def home():
    return page(
        """
        <h2>Break It, Fix It: training lab</h2>
        <p>Local practice target for a class project. Use only on your own machine.</p>
        <ul>
          <li>Topic 1: SQL injection on the login form</li>
          <li>Topic 2: Cross-site scripting in the comment box</li>
        </ul>
        <p>Test accounts: <code>alice / alicepass</code>. The admin password is not shared on purpose.</p>
        <p><a href="/reset">Reset database</a></p>
        """
    )


@app.route("/reset")
def reset():
    init_db()
    return redirect("/")


# ---------- 1. SQL injection ----------
LOGIN_FORM = """
<h2>{title}</h2>
<div class="{cls}">{note}</div>
<form method="post">
  <label>Username <input name="username" autocomplete="off"></label>
  <label>Password <input name="password" type="password"></label>
  <button>Log in</button>
</form>
{result}
"""


@app.route("/vulnerable/login", methods=["GET", "POST"])
def vulnerable_login():
    result = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # VULNERABLE: user input is concatenated straight into the SQL string.
        query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
        try:
            row = get_db().execute(query).fetchone()
        except sqlite3.Error as e:
            # Verbose errors also help an attacker (information leak).
            row = None
            result = f"<p><b>Database error:</b> {html.escape(str(e))}</p>"
        result += f"<p><small>Query run: <code>{html.escape(query)}</code></small></p>"
        if row:
            result += f"<p><b>Login successful</b> as {html.escape(row['username'])} (role: {row['role']})</p>"
        else:
            result += "<p>Invalid username or password.</p>"
    return page(
        LOGIN_FORM.format(
            title="Login (VULNERABLE)",
            cls="bad",
            note="SQL is built by string concatenation.",
            result=result,
        )
    )


@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    result = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # FIX: parameterized query. Input is treated as data, never as SQL.
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        row = get_db().execute(query, (u, p)).fetchone()
        result += f"<p><small>Query run: <code>{html.escape(query)}</code> with bound parameters</small></p>"
        if row:
            result += f"<p><b>Login successful</b> as {html.escape(row['username'])} (role: {row['role']})</p>"
        else:
            # FIX: generic message, no database error details.
            result += "<p>Invalid username or password. (injection blocked)</p>"
    return page(
        LOGIN_FORM.format(
            title="Login (SECURE)",
            cls="good",
            note="Parameterized query plus a generic error message.",
            result=result,
        )
    )


# ---------- 2. Cross-site scripting ----------
COMMENTS_PAGE = """
<h2>{title}</h2>
<div class="{cls}">{note}</div>
<form method="post">
  <label>Name <input name="author"></label>
  <label>Comment <textarea name="body" rows="3"></textarea></label>
  <button>Post</button>
</form>
<h3>Comments</h3>
{items}
"""


@app.route("/vulnerable/comments", methods=["GET", "POST"])
def vulnerable_comments():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO comments (author, body, mode) VALUES (?, ?, 'vuln')",
            (request.form.get("author", ""), request.form.get("body", "")),
        )
        db.commit()
        return redirect("/vulnerable/comments")
    rows = db.execute("SELECT * FROM comments WHERE mode='vuln' ORDER BY id").fetchall()
    # VULNERABLE: stored text is inserted into the page without escaping.
    items = "".join(f"<p><b>{r['author']}</b>: {r['body']}</p>" for r in rows) or "<p>No comments yet.</p>"
    return page(
        COMMENTS_PAGE.format(
            title="Comments (VULNERABLE)",
            cls="bad",
            note="Comments are rendered as raw HTML (stored XSS).",
            items=items,
        )
    )


@app.route("/secure/comments", methods=["GET", "POST"])
def secure_comments():
    db = get_db()
    if request.method == "POST":
        db.execute(
            "INSERT INTO comments (author, body, mode) VALUES (?, ?, 'safe')",
            (request.form.get("author", ""), request.form.get("body", "")),
        )
        db.commit()
        return redirect("/secure/comments")
    rows = db.execute("SELECT * FROM comments WHERE mode='safe' ORDER BY id").fetchall()
    # FIX: output encoding. html.escape turns < > & " ' into harmless text.
    items = "".join(
        f"<p><b>{html.escape(r['author'])}</b>: {html.escape(r['body'])}</p>" for r in rows
    ) or "<p>No comments yet.</p>"
    return page(
        COMMENTS_PAGE.format(
            title="Comments (SECURE)",
            cls="good",
            note="Output is HTML-escaped and a Content-Security-Policy header is sent.",
            items=items,
        )
    )


@app.after_request
def add_headers(resp):
    # FIX (defense in depth): CSP blocks inline scripts on the secure pages only.
    if request.path.startswith("/secure/"):
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


if __name__ == "__main__":
    init_db()
    # Bound to localhost only on purpose. Do not change to 0.0.0.0.
    app.run(host="127.0.0.1", port=5000, debug=False)
