"""Rule-based risk scoring for financial transactions."""
from statistics import mean, pstdev

ALLOW, CHALLENGE, BLOCK = "ALLOWED", "OTP_REQUIRED", "BLOCKED"

LARGE_AMOUNT = 50_000      # absolute threshold
CHALLENGE_SCORE = 40
BLOCK_SCORE = 70


def score_transaction(amount, hour, receiver_known, history, recent_count, balance):
    """Return (score 0-100, list of reasons).

    history: list of the user's past transaction amounts
    recent_count: number of transactions by the user in the last 60 seconds
    """
    score, reasons = 0, []

    if amount > balance:
        return 100, ["Insufficient balance"]

    if amount >= LARGE_AMOUNT:
        score += 30
        reasons.append(f"Large amount (>= {LARGE_AMOUNT})")

    if len(history) >= 3:
        mu, sd = mean(history), pstdev(history) or 1.0
        z = (amount - mu) / sd
        if z > 3:
            score += 35
            reasons.append(f"Amount is {z:.1f} std-devs above your average")
        elif z > 2:
            score += 20
            reasons.append("Amount unusually high versus your history")

    if not receiver_known:
        score += 20
        reasons.append("First transfer to this receiver")

    if hour < 5 or hour >= 23:
        score += 15
        reasons.append("Unusual time of day")

    if recent_count >= 3:
        score += 30
        reasons.append("High transaction velocity")

    if amount > 0.9 * balance:
        score += 15
        reasons.append("Drains >90% of balance")

    return min(score, 100), reasons


def decide(score):
    if score >= BLOCK_SCORE:
        return BLOCK
    if score >= CHALLENGE_SCORE:
        return CHALLENGE
    return ALLOW
