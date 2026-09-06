import os
import sqlite3
import time
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
ACCESS_LOG = os.path.join(BASE_DIR, "access.log")

app = FastAPI(title="RedBlue Wargame — Vulnerable Target", version="0.1.0")


# --------------------------------------------------------------------------- #
# Database (SQLite, seeded fresh on startup)
# --------------------------------------------------------------------------- #
def init_db() -> None:
    """Create and seed a fresh SQLite database on every startup.

    Passwords are stored in plaintext deliberately — this is an intentionally
    insecure practice target, not a real auth system.
    """
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """)
    cur.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("alice", "s3cr3t-alice", 1),
            ("bob", "hunter2", 0),
            ("carol", "carol-pw-99", 0),
        ],
    )
    cur.execute("""
        CREATE TABLE products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT NOT NULL,
            price REAL NOT NULL
        )
        """)
    cur.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [
            ("Widget", 9.99),
            ("Gadget", 19.99),
            ("Gizmo", 29.99),
        ],
    )
    conn.commit()
    conn.close()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# In-memory session table: token -> username.
# [VULN: session_hijack] Tokens are predictable and never expire — see /login.
SESSIONS: dict[str, str] = {}


# --------------------------------------------------------------------------- #
# Access logging — the Blue Team Detector reads this file
# --------------------------------------------------------------------------- #
@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    """Append one line per request to access.log.

    Format (space-separated, quoted request line):
        2026-09-06T12:00:00Z 127.0.0.1 "GET /search?q=widget" 200 3ms
    """
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    client = request.client.host if request.client else "-"
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f'{ts} {client} "{request.method} {path}" {response.status_code} {elapsed_ms}ms\n'

    with open(ACCESS_LOG, "a", encoding="utf-8") as fh:
        fh.write(line)

    return response


@app.on_event("startup")
def _startup() -> None:
    init_db()


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
    <h1>RedBlue Wargame — Target App</h1>
    <p>Deliberately vulnerable practice target. Endpoints:</p>
    <ul>
      <li><code>GET  /admin</code></li>
      <li><code>GET  /search?q=...</code></li>
      <li><code>POST /login</code> (form: username, password)</li>
      <li><code>GET  /account?token=...</code></li>
    </ul>
    """


@app.get("/admin", response_class=HTMLResponse)
def admin() -> str:
    """
    [VULN: admin_bypass]
    This route performs NO authentication check. Anyone who requests /admin
    gets the admin dashboard. A real fix would require an authenticated admin
    session before returning this content.
    """
    conn = get_conn()
    users = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    conn.close()
    rows = "".join(
        f"<tr><td>{u['id']}</td><td>{u['username']}</td><td>{u['is_admin']}</td></tr>"
        for u in users
    )
    return f"""
    <h1>Admin Dashboard</h1>
    <p>SECRET: internal admin panel — should never be reachable unauthenticated.</p>
    <table border="1">
      <tr><th>id</th><th>username</th><th>is_admin</th></tr>
      {rows}
    </table>
    """


@app.get("/search")
def search(q: str = "") -> JSONResponse:
    """
    [VULN: sql_injection]
    The query is built by raw string interpolation, so input like
        ' UNION SELECT username, password FROM users --
    is executed directly. A real fix would use a parameterized query
    (e.g. "... WHERE name LIKE ?", (f"%{q}%",)).
    """
    conn = get_conn()
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        results = [dict(r) for r in rows]
        status = 200
        payload = {"query": query, "results": results}
    except Exception as exc:  # noqa: BLE001 — surfacing errors is part of the vuln
        status = 500
        payload = {"query": query, "error": str(exc)}
    finally:
        conn.close()
    return JSONResponse(payload, status_code=status)


@app.post("/login")
async def login(request: Request, response: Response) -> JSONResponse:
    """
    Two planted vulnerabilities live here:

    [VULN: timing_attack]
    If the username does NOT exist we return immediately. If it DOES exist we
    perform a (simulated) expensive password check with a deliberate delay.
    The response-time gap lets an attacker enumerate valid usernames without
    ever guessing a password. A real fix would spend constant time regardless
    of whether the username exists.

    [VULN: session_hijack]
    On success we mint a predictable, non-expiring token of the form
        session-<user_id>
    Any attacker can guess another user's token (session-1, session-2, ...) and
    replay it forever. A real fix would use a cryptographically random token
    with an expiry.
    """
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))

    conn = get_conn()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # [VULN: timing_attack] — fast path for unknown users, slow path for known.
    if user is None:
        conn.close()
        return JSONResponse(
            {"ok": False, "error": "invalid credentials"}, status_code=401
        )

    # Simulated expensive password verification (only reached for real users).
    time.sleep(0.4)
    if password != user["password"]:
        conn.close()
        return JSONResponse(
            {"ok": False, "error": "invalid credentials"}, status_code=401
        )

    # [VULN: session_hijack] — predictable, non-expiring token.
    token = f"session-{user['id']}"
    SESSIONS[token] = user["username"]
    conn.close()

    response.set_cookie("session", token)
    return JSONResponse({"ok": True, "token": token, "user": user["username"]})


@app.get("/account")
def account(token: str = "") -> JSONResponse:
    """
    [VULN: session_hijack]
    Returns account info for whoever presents a session token. The server
    TRUSTS the predictable token format `session-<id>`: it parses the id
    straight out of the token instead of checking it against securely-issued,
    server-side session state. So an attacker who has never logged in can guess
    `session-1` and become alice. A real fix would accept only opaque random
    tokens looked up in server-side session storage, with an expiry.
    """
    user_id = None
    if token.startswith("session-"):
        suffix = token[len("session-") :]
        if suffix.isdigit():
            user_id = int(suffix)

    if user_id is None:
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    conn = get_conn()
    user = conn.execute(
        "SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()

    if user is None:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    return JSONResponse({"account": dict(user)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
