# Smart Financial Transaction Security (base project)

Flask + SQLite backend that scores every transfer for fraud risk and reacts.

| Risk score | Action |
|-----------|--------|
| < 40  | Auto-approved |
| 40–69 | OTP step-up verification (2-min expiry) |
| >= 70 | Blocked |

## Security features
- Password hashing (PBKDF2), signed expiring tokens, account lockout after 5 failed logins
- Risk engine (`risk_engine.py`): large amount, z-score vs. user history, new receiver, odd hours, velocity, balance drain
- OTPs stored only as salted hashes
- Hash-chained audit log; `GET /audit/verify` detects tampering

## Run
    pip install -r requirements.txt
    python app.py          # http://127.0.0.1:5000
    python test_app.py     # smoke test

## API
POST /register, POST /login, POST /transactions, POST /transactions/<id>/verify,
GET /transactions, GET /balance, GET /audit/verify

Example:
    curl -X POST localhost:5000/transactions -H "Authorization: Bearer <token>" \
         -H "Content-Type: application/json" -d '{"receiver":"bob","amount":60000}'

## Before production
Change SECRET_KEY (use env var), deliver OTP via SMS/email (remove `demo_otp`), add HTTPS, rate limiting, and wrap balance updates in proper DB transactions.
