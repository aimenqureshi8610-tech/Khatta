"""
Khaata — Production Backend
============================
Uses Resend (https://resend.com) for email — free tier = 3000 emails/month.
Setup takes 2 minutes (just an API key, no SMTP, no Gmail issues ever).

Environment variables (set in Render dashboard):
  RESEND_API_KEY   — from resend.com/api-keys  (required for real emails)
  SECRET_KEY       — any long random string     (required for security)
  DATA_DIR         — /var/data                  (set on Render for persistence)

Without RESEND_API_KEY the app runs in dev mode and prints OTPs to terminal.
"""

import os, re, json, sqlite3, secrets, hashlib, time, urllib.request, urllib.error
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g

# ── env / config ──────────────────────────────────────────────────────────────
def _load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path): return
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_load_dotenv()

DATA_DIR   = os.environ.get("DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH    = os.path.join(DATA_DIR, "khaata.db")
os.makedirs(DATA_DIR, exist_ok=True)

OTP_TTL        = 10 * 60        # 10 minutes
SESSION_TTL    = 30 * 24 * 3600 # 30 days
MAX_OTP_TRIES  = 5
RATE_WINDOW    = 60             # seconds
MAX_SIGNUPS    = 5              # per IP per minute
EMAIL_RE       = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__, static_folder="static")

# ── database ──────────────────────────────────────────────────────────────────
def db():
    if "db" not in g:
        con = sqlite3.connect(DB_PATH, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")   # better concurrency
        con.execute("PRAGMA foreign_keys=ON")
        g.db = con
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT    NOT NULL,
        email       TEXT    UNIQUE NOT NULL,
        pass_hash   TEXT    NOT NULL,
        salt        TEXT    NOT NULL,
        verified    INTEGER DEFAULT 0,
        otp_hash    TEXT,
        otp_expiry  INTEGER,
        otp_tries   INTEGER DEFAULT 0,
        created_at  INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions(
        token       TEXT    PRIMARY KEY,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        ip          TEXT,
        ua          TEXT,
        expires     INTEGER NOT NULL,
        created_at  INTEGER
    );
    CREATE TABLE IF NOT EXISTS rate_log(
        ip          TEXT    NOT NULL,
        action      TEXT    NOT NULL,
        ts          INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rate ON rate_log(ip, action, ts);
    CREATE TABLE IF NOT EXISTS userdata(
        user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        json        TEXT    NOT NULL,
        updated_at  INTEGER
    );
    """)
    con.commit(); con.close()

# ── helpers ───────────────────────────────────────────────────────────────────
def hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000).hex()

def hash_otp(otp: str) -> str:
    return hashlib.sha256((otp + SECRET_KEY).encode()).hexdigest()

def make_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

def client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

def rate_check(action: str, limit: int, window: int = RATE_WINDOW) -> bool:
    """Returns True if under limit, False if rate-limited."""
    ip  = client_ip()
    now = int(time.time())
    cut = now - window
    d   = db()
    count = d.execute(
        "SELECT COUNT(*) FROM rate_log WHERE ip=? AND action=? AND ts>?",
        (ip, action, cut)
    ).fetchone()[0]
    if count >= limit:
        return False
    d.execute("INSERT INTO rate_log(ip,action,ts) VALUES(?,?,?)", (ip, action, now))
    # prune old entries
    d.execute("DELETE FROM rate_log WHERE ts<?", (now - 3600,))
    d.commit()
    return True

def send_otp_email(to_email: str, otp: str, name: str) -> bool:
    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        print(f"\n  [DEV MODE] OTP for {to_email} → {otp}\n", flush=True)
        return True
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
      <h2 style="color:#FF2E63;margin:0 0 8px">Khaata</h2>
      <p style="color:#666;margin:0 0 24px;font-size:13px">Your personal ledger</p>
      <p style="font-size:15px">Hi {name},</p>
      <p style="font-size:15px">Your verification code is:</p>
      <div style="background:#0B1020;color:#FF2E63;font-family:monospace;font-size:36px;
                  letter-spacing:12px;text-align:center;padding:24px;border-radius:12px;
                  margin:24px 0">{otp}</div>
      <p style="color:#666;font-size:13px">Expires in 10 minutes. If you didn't request this, ignore it.</p>
    </div>"""
    payload = json.dumps({
        "from":    "Khaata <onboarding@resend.dev>",
        "to":      [to_email],
        "subject": f"{otp} — your Khaata verification code",
        "html":    html,
    }).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201)
    except Exception as e:
        print("Resend error:", e, flush=True)
        return False

def issue_session(user_id: int) -> str:
    token = secrets.token_urlsafe(40)
    now   = int(time.time())
    db().execute(
        "INSERT INTO sessions(token,user_id,ip,ua,expires,created_at) VALUES(?,?,?,?,?,?)",
        (token, user_id, client_ip(),
         request.headers.get("User-Agent","")[:200],
         now + SESSION_TTL, now)
    )
    db().commit()
    return token

def set_otp(user_id: int) -> str:
    otp = make_otp()
    db().execute(
        "UPDATE users SET otp_hash=?,otp_expiry=?,otp_tries=0 WHERE id=?",
        (hash_otp(otp), int(time.time()) + OTP_TTL, user_id)
    )
    db().commit()
    return otp

def auth_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        token = (request.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        if not token:
            return jsonify(error="Not authenticated."), 401
        row = db().execute(
            "SELECT user_id, expires FROM sessions WHERE token=?", (token,)
        ).fetchone()
        if not row or row["expires"] < time.time():
            return jsonify(error="Session expired — please log in again."), 401
        g.user_id = row["user_id"]
        return f(*a, **kw)
    return wrapper

# ── auth routes ───────────────────────────────────────────────────────────────
@app.post("/api/signup")
def signup():
    if not rate_check("signup", MAX_SIGNUPS):
        return jsonify(error="Too many requests. Please wait a minute."), 429
    d        = request.get_json(force=True) or {}
    name     = (d.get("name") or "").strip()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if len(name) < 2:
        return jsonify(error="Please enter your full name."), 400
    if not EMAIL_RE.match(email):
        return jsonify(error="That email address doesn't look valid."), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400

    existing = db().execute("SELECT id, verified FROM users WHERE email=?", (email,)).fetchone()
    if existing and existing["verified"]:
        return jsonify(error="An account with this email already exists. Log in instead."), 409

    salt = secrets.token_hex(16)
    ph   = hash_pw(password, salt)
    now  = int(time.time())

    if existing:
        uid = existing["id"]
        db().execute("UPDATE users SET name=?,pass_hash=?,salt=? WHERE id=?", (name, ph, salt, uid))
    else:
        cur = db().execute(
            "INSERT INTO users(name,email,pass_hash,salt,created_at) VALUES(?,?,?,?,?)",
            (name, email, ph, salt, now)
        )
        uid = cur.lastrowid
    db().commit()

    otp = set_otp(uid)
    if not send_otp_email(email, otp, name):
        return jsonify(error="Failed to send verification email. Please try again."), 500
    return jsonify(ok=True, message=f"Verification code sent to {email}.")

@app.post("/api/verify")
def verify():
    if not rate_check("verify", 10):
        return jsonify(error="Too many attempts. Wait a minute."), 429
    d     = request.get_json(force=True) or {}
    email = (d.get("email") or "").strip().lower()
    otp   = (d.get("otp") or "").strip()
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        return jsonify(error="No account found for that email."), 404
    if u["otp_tries"] >= MAX_OTP_TRIES:
        return jsonify(error="Too many wrong attempts. Request a new code."), 429
    if not u["otp_hash"] or u["otp_expiry"] < time.time():
        return jsonify(error="Code has expired. Please request a new one."), 410
    if hash_otp(otp) != u["otp_hash"]:
        db().execute("UPDATE users SET otp_tries=otp_tries+1 WHERE id=?", (u["id"],))
        db().commit()
        remaining = MAX_OTP_TRIES - u["otp_tries"] - 1
        return jsonify(error=f"Incorrect code. {remaining} attempt{'s' if remaining!=1 else ''} left."), 401

    db().execute("UPDATE users SET verified=1, otp_hash=NULL WHERE id=?", (u["id"],))
    db().execute(
        "INSERT OR IGNORE INTO userdata(user_id,json,updated_at) VALUES(?,?,?)",
        (u["id"], json.dumps({
            "transactions":[], "budgets":{}, "bills":[],
            "accounts":[], "goals":[],
            "settings":{"currency":"Rs","name":u["name"]}
        }), int(time.time()))
    )
    db().commit()
    return jsonify(token=issue_session(u["id"]), name=u["name"])

@app.post("/api/resend")
def resend():
    if not rate_check("resend", 3):
        return jsonify(error="Too many resend requests. Wait a minute."), 429
    email = (request.get_json(force=True).get("email") or "").strip().lower()
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        return jsonify(error="No account found for that email."), 404
    otp = set_otp(u["id"])
    if not send_otp_email(email, otp, u["name"]):
        return jsonify(error="Failed to send email. Please try again."), 500
    return jsonify(ok=True, message="A new code is on its way.")

@app.post("/api/login")
def login():
    if not rate_check("login", 10):
        return jsonify(error="Too many login attempts. Wait a minute."), 429
    d        = request.get_json(force=True) or {}
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    # constant-time comparison to prevent timing attacks
    dummy_salt = "0" * 32
    expected   = hash_pw(password, u["salt"]) if u else hash_pw(password, dummy_salt)
    if not u or expected != u["pass_hash"]:
        return jsonify(error="Email or password is incorrect."), 401
    if not u["verified"]:
        otp = set_otp(u["id"])
        send_otp_email(email, otp, u["name"])
        return jsonify(need_verify=True, message="Your email isn't verified yet. We've sent a new code.")
    return jsonify(token=issue_session(u["id"]), name=u["name"])

@app.post("/api/logout")
@auth_required
def logout():
    token = (request.headers.get("Authorization") or "").replace("Bearer ", "").strip()
    db().execute("DELETE FROM sessions WHERE token=?", (token,))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/me")
@auth_required
def me():
    u = db().execute("SELECT name, email, created_at FROM users WHERE id=?", (g.user_id,)).fetchone()
    return jsonify(name=u["name"], email=u["email"])

@app.get("/api/ping")
def ping():
    return jsonify(ok=True)

# ── data routes ───────────────────────────────────────────────────────────────
@app.get("/api/data")
@auth_required
def get_data():
    row = db().execute("SELECT json FROM userdata WHERE user_id=?", (g.user_id,)).fetchone()
    if not row:
        return jsonify({}), 200
    return app.response_class(row["json"], mimetype="application/json")

@app.put("/api/data")
@auth_required
def put_data():
    body = request.get_data(as_text=True)
    if len(body) > 5_000_000:
        return jsonify(error="Data too large."), 413
    try:
        json.loads(body)
    except ValueError:
        return jsonify(error="Invalid data format."), 400
    db().execute(
        "INSERT INTO userdata(user_id,json,updated_at) VALUES(?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at",
        (g.user_id, body, int(time.time()))
    )
    db().commit()
    return jsonify(ok=True)

# ── frontend ──────────────────────────────────────────────────────────────────
@app.get("/")
@app.get("/<path:p>")
def frontend(p=""):
    return send_from_directory("static", "index.html")

# ── init + run ────────────────────────────────────────────────────────────────
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    dev  = not os.environ.get("RESEND_API_KEY")
    print("=" * 58)
    print(f"  Khaata  →  http://localhost:{port}")
    if dev:
        print("  DEV MODE — OTPs print here (set RESEND_API_KEY for real email)")
    print("=" * 58)
    app.run(host="0.0.0.0", port=port, debug=False)
