import os, tempfile
import app as m

def run():
    m.app.config["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
    c = m.app.test_client()
    c.post("/register", json={"username": "alice", "password": "password123"})
    tok = c.post("/login", json={"username": "alice", "password": "password123"}).get_json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    # normal small transfers
    r = c.post("/transactions", json={"receiver": "bob", "amount": 500}, headers=H).get_json()
    print("1) first transfer to new receiver:", r["status"], r["risk_score"], r["reasons"])
    if r["status"] == "PENDING_OTP":
        v = c.post(f"/transactions/{r['transaction_id']}/verify", json={"otp": r["demo_otp"]}, headers=H)
        print("   verify OTP ->", v.get_json())
    r = c.post("/transactions", json={"receiver": "bob", "amount": 600}, headers=H).get_json()
    print("2) known receiver, small:", r["status"], r["risk_score"])
    r = c.post("/transactions", json={"receiver": "mallory", "amount": 95000}, headers=H).get_json()
    print("3) huge transfer to stranger:", r["status"], r["risk_score"], r["reasons"])
    print("4) audit chain:", c.get("/audit/verify").get_json())
    print("5) balance:", c.get("/balance", headers=H).get_json())

run()
