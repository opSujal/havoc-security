"""
billing.py — Stripe subscription billing for Havoc Security.
Handles plan definitions, checkout session creation, webhook processing,
and per-user feature-gate enforcement.
"""
import os
import stripe
import sqlite3
from datetime import datetime, timedelta

# ── Stripe config ─────────────────────────────────────────────────────────────
# Set STRIPE_SECRET_KEY in your environment / Render env vars
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')

# Your Vercel frontend URL (set as FRONTEND_URL env var in Render)
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:5173')

# ── Plan definitions ──────────────────────────────────────────────────────────
PLANS = {
    'free': {
        'name': 'Free',
        'price': 0,
        'price_id': None,
        'scan_limit': 5,          # scans per month
        'target_limit': 1,        # max unique targets
        'ai_remediation': False,
        'deep_scan': False,
        'export_pdf': False,
        'export_json': True,
        'api_access': False,
        'badge_color': '#6c8ba4',
        'badge_label': 'Free',
    },
    'starter': {
        'name': 'Starter',
        'price': 1900,            # cents ($19/mo)
        'price_id': os.environ.get('STRIPE_STARTER_PRICE_ID', ''),
        'scan_limit': 50,
        'target_limit': 5,
        'ai_remediation': True,
        'deep_scan': False,
        'export_pdf': True,
        'export_json': True,
        'api_access': False,
        'badge_color': '#3b82f6',
        'badge_label': 'Starter',
    },
    'pro': {
        'name': 'Pro',
        'price': 4900,            # cents ($49/mo)
        'price_id': os.environ.get('STRIPE_PRO_PRICE_ID', ''),
        'scan_limit': 999999,     # unlimited
        'target_limit': 25,
        'ai_remediation': True,
        'deep_scan': True,
        'export_pdf': True,
        'export_json': True,
        'api_access': False,
        'badge_color': '#ff3c5a',
        'badge_label': 'Pro',
    },
    'team': {
        'name': 'Team',
        'price': 14900,           # cents ($149/mo)
        'price_id': os.environ.get('STRIPE_TEAM_PRICE_ID', ''),
        'scan_limit': 999999,     # unlimited
        'target_limit': 999999,
        'ai_remediation': True,
        'deep_scan': True,
        'export_pdf': True,
        'export_json': True,
        'api_access': True,
        'badge_color': '#a855f7',
        'badge_label': 'Team',
    },
}


# ── DB helpers ────────────────────────────────────────────────────────────────
def _get_conn():
    return sqlite3.connect('vapt_database.db', timeout=30, check_same_thread=False)


def init_billing_tables():
    """Create billing-related columns/tables if they don't exist."""
    conn = _get_conn()
    # Add plan columns to users
    for col, default in [
        ('plan', "'free'"),
        ('stripe_customer_id', "NULL"),
        ('stripe_subscription_id', "NULL"),
        ('plan_expires_at', "NULL"),
        ('scans_this_month', "0"),
        ('scans_reset_at', "NULL"),
    ]:
        try:
            conn.execute(f'ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}')
        except Exception:
            pass  # column already exists

    conn.commit()
    conn.close()


def get_user_plan(user_id: int) -> dict:
    """Return the plan dict for a user."""
    conn = _get_conn()
    row = conn.execute(
        'SELECT plan, plan_expires_at FROM users WHERE id=?', (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        return PLANS['free']
    plan_key = row[0] or 'free'
    expires = row[1]
    # If plan has expired, downgrade to free
    if expires and datetime.fromisoformat(str(expires)) < datetime.utcnow():
        _set_user_plan(user_id, 'free')
        plan_key = 'free'
    return PLANS.get(plan_key, PLANS['free'])


def _set_user_plan(user_id: int, plan_key: str, expires_at=None, stripe_customer_id=None, sub_id=None):
    conn = _get_conn()
    fields = ['plan=?']
    vals = [plan_key]
    if expires_at:
        fields.append('plan_expires_at=?')
        vals.append(expires_at.isoformat())
    if stripe_customer_id:
        fields.append('stripe_customer_id=?')
        vals.append(stripe_customer_id)
    if sub_id:
        fields.append('stripe_subscription_id=?')
        vals.append(sub_id)
    vals.append(user_id)
    conn.execute(f'UPDATE users SET {", ".join(fields)} WHERE id=?', vals)
    conn.commit()
    conn.close()


def get_user_by_stripe_customer(customer_id: str):
    conn = _get_conn()
    row = conn.execute(
        'SELECT id, plan FROM users WHERE stripe_customer_id=?', (customer_id,)
    ).fetchone()
    conn.close()
    return {'id': row[0], 'plan': row[1]} if row else None


# ── Usage tracking ────────────────────────────────────────────────────────────
def count_scans_this_month(user_id) -> int:
    """Count how many scans this user has done in the current calendar month."""
    conn = _get_conn()
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    try:
        uid = int(user_id)
        row = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND target IS NOT NULL AND scan_date >= ?",
            (uid, month_start.isoformat(),)
        ).fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:
        return 0


def can_scan(user_id) -> tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    Call this before starting a scan.
    """
    try:
        uid = int(user_id)
    except:
        return True, "ok" # Default allow if user_id malformed
        
    plan = get_user_plan(uid)
    used = count_scans_this_month(uid)
    limit = int(plan.get('scan_limit', 5))
    if used >= limit:
        return False, f"Scan limit reached ({used}/{limit} this month). Upgrade your plan to continue."
    return True, "ok"


def can_use_ai_remediation(user_id: int) -> tuple[bool, str]:
    plan = get_user_plan(user_id)
    if not plan['ai_remediation']:
        return False, "AI Remediation is a paid feature. Upgrade to Starter or higher."
    return True, "ok"


def can_deep_scan(user_id: int) -> tuple[bool, str]:
    plan = get_user_plan(user_id)
    if not plan['deep_scan']:
        return False, "Deep scan modules (SQLi, SSTI, CORS fuzzing) require the Pro plan."
    return True, "ok"


def can_export_pdf(user_id: int) -> tuple[bool, str]:
    plan = get_user_plan(user_id)
    if not plan['export_pdf']:
        return False, "PDF/HTML report export requires the Starter plan or higher."
    return True, "ok"


# ── Stripe Checkout ───────────────────────────────────────────────────────────
def create_checkout_session(user_id: int, plan_key: str, user_email: str):
    """Create a Stripe Checkout session and return the URL."""
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")

    plan = PLANS.get(plan_key)
    if not plan or not plan.get('price_id'):
        raise ValueError(f"Invalid plan or no Stripe Price ID: {plan_key}")

    # Get or create Stripe customer
    conn = _get_conn()
    row = conn.execute('SELECT stripe_customer_id FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    customer_id = row[0] if row and row[0] else None

    if not customer_id:
        customer = stripe.Customer.create(email=user_email, metadata={'user_id': user_id})
        customer_id = customer.id
        _set_user_plan(user_id, 'free', stripe_customer_id=customer_id)

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=['card'],
        mode='subscription',
        line_items=[{'price': plan['price_id'], 'quantity': 1}],
        success_url=f"{FRONTEND_URL}?billing=success&plan={plan_key}",
        cancel_url=f"{FRONTEND_URL}?billing=cancelled",
        metadata={'user_id': str(user_id), 'plan': plan_key},
    )
    return session.url


def create_portal_session(user_id: int):
    """Create a Stripe Customer Portal session for managing billing."""
    if not stripe.api_key:
        raise ValueError("STRIPE_SECRET_KEY not configured")
    conn = _get_conn()
    row = conn.execute('SELECT stripe_customer_id FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    customer_id = row[0] if row and row[0] else None
    if not customer_id:
        raise ValueError("No Stripe customer found. Please subscribe first.")
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{FRONTEND_URL}?page=settings",
    )
    return session.url


# ── Webhook handler ───────────────────────────────────────────────────────────
def handle_webhook(payload: bytes, sig_header: str):
    """Process Stripe webhook events to update user plans."""
    if not STRIPE_WEBHOOK_SECRET:
        # In development without webhook secret, skip verification
        event = stripe.Event.construct_from(
            stripe.util.convert_to_stripe_object(
                stripe.util.convert_to_dict(stripe.util.json.loads(payload))
            ), stripe.api_key
        )
    else:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)

    if event.type == 'checkout.session.completed':
        session = event.data.object
        user_id = int(session.metadata.get('user_id', 0))
        plan_key = session.metadata.get('plan', 'starter')
        sub_id = session.get('subscription')
        customer_id = session.get('customer')
        expires = datetime.utcnow() + timedelta(days=31)
        _set_user_plan(user_id, plan_key, expires_at=expires,
                       stripe_customer_id=customer_id, sub_id=sub_id)

    elif event.type in ('customer.subscription.deleted', 'customer.subscription.paused'):
        sub = event.data.object
        user = get_user_by_stripe_customer(sub.customer)
        if user:
            _set_user_plan(user['id'], 'free')

    elif event.type == 'customer.subscription.updated':
        sub = event.data.object
        user = get_user_by_stripe_customer(sub.customer)
        if user:
            # Map Stripe price to plan key
            price_id = sub.items.data[0].price.id if sub.items.data else None
            new_plan = 'free'
            for key, p in PLANS.items():
                if p.get('price_id') == price_id:
                    new_plan = key
                    break
            expires = datetime.utcfromtimestamp(sub.current_period_end)
            _set_user_plan(user['id'], new_plan, expires_at=expires)

    elif event.type == 'invoice.payment_failed':
        invoice = event.data.object
        user = get_user_by_stripe_customer(invoice.customer)
        if user:
            _set_user_plan(user['id'], 'free')

    return {'handled': event.type}
