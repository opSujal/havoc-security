"""
razorpay_billing.py — Razorpay payment integration for Havoc Security (India)
===========================================================================
FREE to integrate. Charges only 2% per successful transaction (no monthly fee).
Supports: UPI, Net Banking, Cards, Paytm, PhonePe, Wallets, EMI, Paylater.

Razorpay Flow:
  1. Backend creates an Order (amount in paise)
  2. Frontend opens Razorpay Checkout modal (hosted by Razorpay)
  3. User pays (UPI/Card/NetBanking/Wallet — anything works)
  4. Razorpay returns payment_id + signature to frontend
  5. Frontend sends these to backend /api/razorpay/verify
  6. Backend verifies HMAC-SHA256 signature → activates plan in DB

Setup:
  1. Sign up FREE at https://razorpay.com (takes 2 minutes)
  2. Go to Settings → API Keys → Generate Test Key
  3. Add to .env:
       RAZORPAY_KEY_ID=rzp_test_XXXXXXXXXXXXXXXX
       RAZORPAY_KEY_SECRET=XXXXXXXXXXXXXXXXXXXXXXXX
"""
import os
import hmac
import hashlib
import sqlite3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
RAZORPAY_KEY_ID     = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')
FRONTEND_URL        = os.environ.get('FRONTEND_URL', 'http://localhost:5173')

# ── Plan definitions (amount in paise: 1 INR = 100 paise) ────────────────────
RAZORPAY_PLANS = {
    'starter': {
        'name':        'Starter',
        'amount':      149900,    # ₹1,499/month
        'currency':    'INR',
        'description': '50 scans/month, AI Remediation, PDF Export',
        'features':    ['50 scans/month', '5 target domains', 'AI Remediation', 'PDF export'],
        'color':       '#3b82f6',
    },
    'pro': {
        'name':        'Pro',
        'amount':      399900,    # ₹3,999/month
        'currency':    'INR',
        'description': 'Unlimited scans, Deep Scan (SQLi, SSTI, CORS), All modules',
        'features':    ['Unlimited scans', '25 target domains', 'Deep Scan', 'All modules', 'Danger Mode'],
        'color':       '#ff3c5a',
    },
    'team': {
        'name':        'Team',
        'amount':      1199900,   # ₹11,999/month
        'currency':    'INR',
        'description': 'Unlimited everything, API access, Priority support',
        'features':    ['Unlimited scans', 'Unlimited targets', 'API access', 'Priority support'],
        'color':       '#a855f7',
    },
}

# Map Razorpay plan keys → existing billing.py plan keys for DB compatibility
PLAN_DB_MAP = {
    'starter': 'starter',
    'pro':     'pro',
    'team':    'team',
}


# ── DB helpers ────────────────────────────────────────────────────────────────
def _conn():
    return sqlite3.connect('vapt_database.db', timeout=30, check_same_thread=False)


def _activate_plan(user_id: int, plan_key: str, order_id: str, payment_id: str):
    """Upgrade user plan in the database after successful payment."""
    expires = datetime.utcnow() + timedelta(days=31)
    db_plan = PLAN_DB_MAP.get(plan_key, 'starter')
    with _conn() as conn:
        # Store plan + payment reference
        conn.execute(
            """UPDATE users
               SET plan=?, plan_expires_at=?, stripe_subscription_id=?
               WHERE id=?""",
            (db_plan, expires.isoformat(), payment_id, user_id)
        )
        conn.commit()
    logger.info(f"Plan activated: user={user_id} plan={db_plan} payment={payment_id}")


def get_user_razorpay_plan(user_id: int) -> dict:
    """Get current plan for a user (for frontend display)."""
    with _conn() as conn:
        row = conn.execute(
            'SELECT plan, plan_expires_at FROM users WHERE id=?', (user_id,)
        ).fetchone()
    if not row:
        return {'plan': 'free', 'expires': None}
    plan, expires = row
    return {'plan': plan or 'free', 'expires': expires}


# ── Razorpay API calls ────────────────────────────────────────────────────────
def _razorpay_client():
    """Return a Razorpay client instance."""
    try:
        import razorpay
        return razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    except ImportError:
        raise RuntimeError("razorpay package not installed. Run: pip install razorpay")


def create_order(user_id: int, plan_key: str) -> dict:
    """
    Create a Razorpay order for the given plan.
    Returns: { order_id, amount, currency, key_id, plan_name }
    """
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise ValueError(
            "Razorpay not configured. Add RAZORPAY_KEY_ID and "
            "RAZORPAY_KEY_SECRET to your .env file."
        )

    plan = RAZORPAY_PLANS.get(plan_key)
    if not plan:
        raise ValueError(f"Unknown plan: {plan_key}")

    client = _razorpay_client()
    order = client.order.create({
        'amount':   plan['amount'],
        'currency': plan['currency'],
        'notes': {
            'user_id':  str(user_id),
            'plan':     plan_key,
            'platform': 'HavocSecurity',
        },
        'payment_capture': 1,  # auto-capture after payment
    })

    return {
        'order_id':  order['id'],
        'amount':    plan['amount'],
        'currency':  plan['currency'],
        'key_id':    RAZORPAY_KEY_ID,
        'plan_key':  plan_key,
        'plan_name': plan['name'],
        'description': plan['description'],
    }


def verify_payment(
    razorpay_order_id: str,
    razorpay_payment_id: str,
    razorpay_signature: str,
    user_id: int,
    plan_key: str,
) -> bool:
    """
    Verify the payment signature using HMAC-SHA256.
    This is the critical security step — never activate a plan without verifying.
    Returns True if payment is genuine, False otherwise.
    """
    if not RAZORPAY_KEY_SECRET:
        raise ValueError("RAZORPAY_KEY_SECRET not configured")

    # Razorpay signature = HMAC_SHA256(order_id + "|" + payment_id, secret)
    message  = f"{razorpay_order_id}|{razorpay_payment_id}"
    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()

    if hmac.compare_digest(expected, razorpay_signature):
        # Payment verified — activate the plan
        _activate_plan(user_id, plan_key, razorpay_order_id, razorpay_payment_id)
        return True

    logger.warning(
        f"Signature mismatch! user={user_id} plan={plan_key} "
        f"order={razorpay_order_id} payment={razorpay_payment_id}"
    )
    return False


def get_plans_info() -> dict:
    """Return plan info for the frontend pricing grid."""
    return {
        key: {
            'name':        p['name'],
            'amount':      p['amount'],
            'amount_inr':  p['amount'] // 100,   # in rupees for display
            'currency':    p['currency'],
            'description': p['description'],
            'features':    p['features'],
            'color':       p['color'],
        }
        for key, p in RAZORPAY_PLANS.items()
    }
