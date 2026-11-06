"""Smart Financial Transaction Security - base project (Flask + SQLite)."""
import hashlib, json, random, sqlite3, time
from datetime import datetime
from functools import wraps

from flask import Flask, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

import risk_engine as risk

app = Flask(__name__)
app.config.update(SECRET_KEY="change-me-in-production", DB_PATH="bank.db")
OTP_TTL = 120          # seconds
MAX_LOGIN_FAILS = 5
LOCK_SECONDS = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT,
  balance REAL DEFAULT 100000, fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY, sender_id INTEGER, receiver TEXT, amount REAL,
  status TEXT, risk_score INTEGER, reasons TEXT, otp_hash TEXT, otp_expiry REAL,
  created REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts REAL, event TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
"""


# ---------- helpers ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.executescript(SCHEMA)
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def audit(event, detail):
    """Append to a hash-chained log so tampering is detectable."""
    d = db()
    row = d.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else "GENESIS"
    ts, detail = time.time(), json.dumps(detail, sort_keys=True)
    h = hashlib.sha256(f"{prev}|{ts}|{event}|{detail}".encode()).hexdigest()
    d.execute("INSERT INTO audit(ts,event,detail,prev_hash,hash) VALUES(?,?,?,?,?)",
              (ts, event, detail, prev, h))
    d.commit()


def serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def auth_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            uid = serializer().loads(token, max_age=3600)["uid"]
        except (BadSignature, SignatureExpired):
            return jsonify(error="Invalid or expired token"), 401
        g.user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return fn(*a, **kw)
    return wrapper


def hash_otp(otp, txn_id):
    return hashlib.sha256(f"{otp}:{txn_id}:{app.config['SECRET_KEY']}".encode()).hexdigest()


# ---------- auth ----------
@app.post("/register")
def register():
    j = request.get_json(force=True)
    u, p = j.get("username", "").strip(), j.get("password", "")
    if not u or len(p) < 8:
        return jsonify(error="Username required; password must be 8+ chars"), 400
    try:
        db().execute("INSERT INTO users(username,pw_hash) VALUES(?,?)",
                     (u, generate_password_hash(p)))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username taken"), 409
    audit("REGISTER", {"user": u})
    return jsonify(message="Registered"), 201


@app.post("/login")
def login():
    j = request.get_json(force=True)
    u = db().execute("SELECT * FROM users WHERE username=?", (j.get("username"),)).fetchone()
    if not u:
        return jsonify(error="Invalid credentials"), 401
    if u["locked_until"] > time.time():
        return jsonify(error="Account temporarily locked"), 423
    if not check_password_hash(u["pw_hash"], j.get("password", "")):
        fails = u["fails"] + 1
        lock = time.time() + LOCK_SECONDS if fails >= MAX_LOGIN_FAILS else 0
        db().execute("UPDATE users SET fails=?, locked_until=? WHERE id=?",
                     (0 if lock else fails, lock, u["id"]))
        db().commit()
        audit("LOGIN_FAIL", {"user": u["username"], "fails": fails})
        return jsonify(error="Invalid credentials"), 401
    db().execute("UPDATE users SET fails=0 WHERE id=?", (u["id"],))
    db().commit()
    audit("LOGIN_OK", {"user": u["username"]})
    return jsonify(token=serializer().dumps({"uid": u["id"]}))


# ---------- transactions ----------
@app.post("/transactions")
@auth_required
def create_transaction():
    j = request.get_json(force=True)
    receiver = str(j.get("receiver", "")).strip()
    try:
        amount = float(j.get("amount"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid amount"), 400
    if amount <= 0 or not receiver or receiver == g.user["username"]:
        return jsonify(error="Invalid receiver or amount"), 400

    d, uid, now = db(), g.user["id"], time.time()
    hist = [r["amount"] for r in d.execute(
        "SELECT amount FROM transactions WHERE sender_id=? AND status='COMPLETED'", (uid,))]
    known = d.execute("SELECT 1 FROM transactions WHERE sender_id=? AND receiver=? "
                      "AND status='COMPLETED'", (uid, receiver)).fetchone() is not None
    recent = d.execute("SELECT COUNT(*) c FROM transactions WHERE sender_id=? AND created>?",
                       (uid, now - 60)).fetchone()["c"]

    score, reasons = risk.score_transaction(
        amount, datetime.now().hour, known, hist, recent, g.user["balance"])
    verdict = risk.decide(score)

    otp, otp_hash, expiry = None, None, None
    status = {"ALLOWED": "COMPLETED", "OTP_REQUIRED": "PENDING_OTP", "BLOCKED": "BLOCKED"}[verdict]
    cur = d.execute("INSERT INTO transactions(sender_id,receiver,amount,status,risk_score,"
                    "reasons,created) VALUES(?,?,?,?,?,?,?)",
                    (uid, receiver, amount, status, score, json.dumps(reasons), now))
    txn_id = cur.lastrowid

    if verdict == risk.CHALLENGE:
        otp = f"{random.SystemRandom().randrange(10**6):06d}"
        expiry = now + OTP_TTL
        d.execute("UPDATE transactions SET otp_hash=?, otp_expiry=? WHERE id=?",
                  (hash_otp(otp, txn_id), expiry, txn_id))
    elif verdict == risk.ALLOW:
        d.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, uid))
    d.commit()
    audit("TXN_" + status, {"txn": txn_id, "user": g.user["username"], "amount": amount,
                            "score": score, "reasons": reasons})

    resp = dict(transaction_id=txn_id, status=status, risk_score=score, reasons=reasons)
    if otp:  # In production, send via SMS/email. Returned here for demo only.
        resp["demo_otp"] = otp
    return jsonify(resp), 201 if verdict != risk.BLOCK else 403


@app.post("/transactions/<int:txn_id>/verify")
@auth_required
def verify_otp(txn_id):
    d = db()
    t = d.execute("SELECT * FROM transactions WHERE id=? AND sender_id=?",
                  (txn_id, g.user["id"])).fetchone()
    if not t or t["status"] != "PENDING_OTP":
        return jsonify(error="No pending transaction"), 404
    if time.time() > t["otp_expiry"]:
        d.execute("UPDATE transactions SET status='EXPIRED' WHERE id=?", (txn_id,))
        d.commit()
        audit("TXN_EXPIRED", {"txn": txn_id})
        return jsonify(error="OTP expired"), 410
    otp = str(request.get_json(force=True).get("otp", ""))
    if hash_otp(otp, txn_id) != t["otp_hash"]:
        audit("OTP_FAIL", {"txn": txn_id})
        return jsonify(error="Wrong OTP"), 401
    d.execute("UPDATE transactions SET status='COMPLETED', otp_hash=NULL WHERE id=?", (txn_id,))
    d.execute("UPDATE users SET balance=balance-? WHERE id=?", (t["amount"], g.user["id"]))
    d.commit()
    audit("TXN_COMPLETED_OTP", {"txn": txn_id})
    return jsonify(status="COMPLETED")


@app.get("/transactions")
@auth_required
def list_transactions():
    rows = db().execute("SELECT id,receiver,amount,status,risk_score,reasons,created "
                        "FROM transactions WHERE sender_id=? ORDER BY id DESC", (g.user["id"],))
    return jsonify([dict(r) for r in rows])


@app.get("/balance")
@auth_required
def balance():
    return jsonify(balance=g.user["balance"])


# ---------- audit ----------
@app.get("/audit/verify")
def verify_audit():
    prev = "GENESIS"
    for r in db().execute("SELECT * FROM audit ORDER BY id"):
        h = hashlib.sha256(f"{prev}|{r['ts']}|{r['event']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return jsonify(intact=False, broken_at=r["id"]), 200
        prev = r["hash"]
    return jsonify(intact=True)


if __name__ == "__main__":
    app.run(debug=True)
