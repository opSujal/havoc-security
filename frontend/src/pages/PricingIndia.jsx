/**
 * PricingIndia.jsx — Razorpay payment integration for Indian users
 * Supports: UPI, PhonePe, Paytm, Google Pay, Net Banking, Cards, Wallets
 * No Stripe needed. No monthly gateway fee. Only 2% per transaction.
 */
import { useState, useEffect, useRef } from 'react';
import { getRazorpayPlans, createRazorpayOrder, verifyRazorpayPayment } from '../api/api';
import { Check, Zap, Users, Rocket, Shield, CreditCard, Smartphone } from 'lucide-react';
import { notify } from '../utils/notifier';
import bgImage from '../assets/bg.png';

const GRADIENT_TEXT = {
  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  backgroundClip: 'text', color: 'transparent',
};

const PLAN_ICONS = {
  starter: <Zap    size={22} />,
  pro:     <Shield size={22} />,
  team:    <Users  size={22} />,
};

const FREE_FEATURES = [
  '5 scans / month',
  '1 target domain',
  'Basic vulnerability detection',
  'JSON export',
  'Dashboard & charts',
];

// Load Razorpay checkout.js script dynamically
function loadRazorpayScript() {
  return new Promise((resolve) => {
    if (document.getElementById('razorpay-script')) { resolve(true); return; }
    const script = document.createElement('script');
    script.id  = 'razorpay-script';
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.onload  = () => resolve(true);
    script.onerror = () => resolve(false);
    document.body.appendChild(script);
  });
}

function PaymentMethodBadge({ label, icon }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: 6, padding: '3px 8px',
      fontFamily: "'Aeonik', sans-serif", fontSize: 10, color: 'rgba(255,255,255,0.5)',
    }}>
      {icon} {label}
    </span>
  );
}

export default function PricingIndia({ user, currentPlan = 'free' }) {
  const [plans, setPlans]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [paying, setPaying]   = useState(null);   // plan key being paid
  const rzpRef = useRef(null);

  useEffect(() => {
    getRazorpayPlans()
      .then(r => setPlans(r.data))
      .catch(() => setPlans(null))
      .finally(() => setLoading(false));
  }, []);

  const handleUpgrade = async (planKey) => {
    if (!user?.id) {
      notify.error('Login Required', 'Please log in to upgrade your plan.');
      return;
    }
    setPaying(planKey);

    try {
      // 1️⃣ Load Razorpay SDK
      const loaded = await loadRazorpayScript();
      if (!loaded) {
        notify.error('Network Error', 'Could not load Razorpay. Check your internet connection.');
        setPaying(null);
        return;
      }

      // 2️⃣ Create order on backend
      const orderRes = await createRazorpayOrder(planKey);
      const order    = orderRes.data;

      if (order.error) {
        notify.error('Order Failed', order.error);
        setPaying(null);
        return;
      }

      // 3️⃣ Open Razorpay Checkout modal
      const options = {
        key:         order.key_id,
        amount:      order.amount,
        currency:    order.currency,
        name:        'Havoc Security',
        description: order.description,
        order_id:    order.order_id,
        prefill: {
          email: user.email || '',
          name:  user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : '',
        },
        theme: {
          color: '#ff3c5a',
          backdrop_color: 'rgba(0,0,0,0.85)',
        },
        modal: {
          ondismiss: () => {
            setPaying(null);
            notify.warning('Payment Cancelled', 'You closed the payment window. Your plan was not changed.');
          },
        },
        handler: async (response) => {
          // 4️⃣ Verify payment on backend
          try {
            const verifyRes = await verifyRazorpayPayment({
              razorpay_order_id:   response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature:  response.razorpay_signature,
              plan: planKey,
            });

            if (verifyRes.data.success) {
              const planName = verifyRes.data.plan_name || planKey;
              notify.success(
                `🎉 Payment Successful!`,
                `You're now on the ${planName} plan. All premium features are unlocked!`
              );
              // Reload after short delay so plan data refreshes
              setTimeout(() => window.location.reload(), 1500);
            } else {
              notify.error('Verification Failed', verifyRes.data.error || 'Payment could not be verified.');
            }
          } catch (err) {
            notify.error('Verification Error', err.response?.data?.error || err.message);
          } finally {
            setPaying(null);
          }
        },
      };

      rzpRef.current = new window.Razorpay(options);
      rzpRef.current.open();

    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Payment failed';
      if (msg.includes('not configured')) {
        notify.error(
          'Razorpay Not Configured',
          'Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to your .env file.'
        );
      } else {
        notify.error('Payment Error', msg);
      }
      setPaying(null);
    }
  };

  const planOrder = ['starter', 'pro', 'team'];
  const fmtINR   = (paise) => `₹${(paise / 100).toLocaleString('en-IN')}`;

  return (
    <div
      className="dashboard-grid fadein"
      style={{ display: 'flex', flexDirection: 'column', gap: 24, height: 'calc(100vh - 130px)', overflowY: 'auto' }}
    >
      {/* ── Header ── */}
      <div style={{ textAlign: 'center', padding: '8px 0 4px' }}>
        <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 32, ...GRADIENT_TEXT, marginBottom: 6 }}>
          Simple Pricing for India
        </div>
        <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 14, color: 'var(--text-40)' }}>
          Pay with UPI · PhonePe · Google Pay · Paytm · Net Banking · Cards
        </div>
        {/* Payment method badges */}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12, flexWrap: 'wrap' }}>
          {[
            { label: 'UPI', icon: '⚡' },
            { label: 'PhonePe', icon: '💜' },
            { label: 'Google Pay', icon: '🔵' },
            { label: 'Paytm', icon: '🔷' },
            { label: 'Net Banking', icon: '🏦' },
            { label: 'Credit / Debit Card', icon: '💳' },
            { label: 'Wallets', icon: '👜' },
            { label: 'EMI', icon: '📅' },
          ].map(m => (
            <span key={m.label} style={{
              background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 20, padding: '4px 12px',
              fontFamily: "'Aeonik', sans-serif", fontSize: 11, color: 'rgba(255,255,255,0.55)',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {m.icon} {m.label}
            </span>
          ))}
        </div>
      </div>

      {/* ── Plan cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>

        {/* Free Plan Card */}
        <div className="liquid-glass-strong" style={{ borderRadius: 20, padding: '28px 24px', display: 'flex', flexDirection: 'column', gap: 18, position: 'relative', overflow: 'hidden' }}>
          <img src={bgImage} alt="" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', opacity: 0.08, zIndex: 0, pointerEvents: 'none', filter: 'blur(6px)' }} />
          <div style={{ position: 'relative', zIndex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <div style={{ width: 36, height: 36, borderRadius: '50%', background: 'rgba(108,139,164,0.12)', border: '1px solid rgba(108,139,164,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6c8ba4' }}>
                <Rocket size={18} />
              </div>
              <div>
                <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 16, color: '#fff' }}>Free</div>
                {currentPlan === 'free' && <div style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 10, color: '#6c8ba4', fontWeight: 500 }}>Current Plan</div>}
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 16 }}>
              <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 700, fontSize: 36, color: 'rgba(255,255,255,0.7)' }}>₹0</span>
              <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: 'var(--text-40)' }}>/mo</span>
            </div>
            <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 16 }} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {FREE_FEATURES.map(f => (
                <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Check size={12} color="#22c55e" strokeWidth={2.5} />
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 12, color: 'var(--text-60)' }}>{f}</span>
                </div>
              ))}
            </div>
            <button disabled style={{ marginTop: 20, width: '100%', padding: '12px 0', borderRadius: 12, border: '1px solid rgba(255,255,255,0.08)', background: 'rgba(255,255,255,0.04)', color: 'var(--text-40)', fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 13, cursor: 'default' }}>
              Free Forever
            </button>
          </div>
        </div>

        {/* Paid Plan Cards */}
        {loading ? (
          <div style={{ gridColumn: 'span 3', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-40)', fontFamily: "'Aeonik', sans-serif", fontSize: 14 }}>
            Loading plans…
          </div>
        ) : planOrder.map(key => {
          const plan = plans?.[key];
          if (!plan) return null;
          const isPro      = key === 'pro';
          const isCurrent  = currentPlan === key;
          const isLoading  = paying === key;
          const color      = plan.color || '#ff3c5a';

          return (
            <div
              key={key}
              className="liquid-glass-strong"
              style={{
                borderRadius: 20, padding: '28px 24px',
                display: 'flex', flexDirection: 'column', gap: 18,
                position: 'relative', overflow: 'hidden',
                border: isPro ? '1px solid rgba(255,60,90,0.35)' : '1px solid rgba(255,255,255,0.06)',
                boxShadow: isPro ? '0 0 30px rgba(255,60,90,0.12)' : 'none',
              }}
            >
              <img src={bgImage} alt="" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', opacity: 0.08, zIndex: 0, pointerEvents: 'none', filter: 'blur(6px)' }} />

              {isPro && (
                <div style={{ position: 'absolute', top: 14, right: 14, zIndex: 2, background: 'rgba(255,60,90,0.15)', border: '1px solid rgba(255,60,90,0.35)', borderRadius: 20, padding: '3px 10px', fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 10, color: '#ff3c5a', letterSpacing: '0.5px', textTransform: 'uppercase' }}>
                  Most Popular
                </div>
              )}

              <div style={{ position: 'relative', zIndex: 1 }}>
                {/* Plan header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: `${color}14`, border: `1px solid ${color}40`, display: 'flex', alignItems: 'center', justifyContent: 'center', color }}>
                    {PLAN_ICONS[key]}
                  </div>
                  <div>
                    <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 16, color: '#fff' }}>{plan.name}</div>
                    {isCurrent && <div style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 10, color, fontWeight: 500 }}>Current Plan</div>}
                  </div>
                </div>

                {/* Price in INR */}
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 6 }}>
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 700, fontSize: 36, color }}>{fmtINR(plan.amount)}</span>
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: 'var(--text-40)' }}>/mo</span>
                </div>
                <div style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 11, color: 'var(--text-40)', marginBottom: 16 }}>
                  {plan.description}
                </div>

                <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 16 }} />

                {/* Features */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 20 }}>
                  {plan.features?.map(f => (
                    <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Check size={12} color="#22c55e" strokeWidth={2.5} />
                      <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 12, color: 'var(--text-70)' }}>{f}</span>
                    </div>
                  ))}
                </div>

                {/* CTA — opens Razorpay checkout */}
                <button
                  id={`upgrade-btn-${key}`}
                  onClick={() => !isCurrent && handleUpgrade(key)}
                  disabled={isCurrent || isLoading}
                  style={{
                    width: '100%', padding: '13px 0', borderRadius: 12,
                    border: isPro ? 'none' : `1px solid ${color}50`,
                    background: isPro
                      ? 'linear-gradient(135deg, #ff3c5a, #ff6b35)'
                      : isCurrent
                        ? 'rgba(255,255,255,0.04)'
                        : `${color}14`,
                    color: isCurrent ? 'var(--text-40)' : (isPro ? '#fff' : color),
                    fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 13,
                    cursor: isCurrent ? 'default' : 'pointer',
                    boxShadow: isPro ? '0 4px 24px rgba(255,60,90,0.3)' : 'none',
                    opacity: isLoading ? 0.6 : 1,
                    transition: 'opacity 0.2s, transform 0.15s',
                  }}
                >
                  {isLoading
                    ? '⏳ Opening checkout…'
                    : isCurrent
                      ? '✓ Current Plan'
                      : `Pay with UPI / Card`}
                </button>

                {/* Trust badges */}
                {!isCurrent && (
                  <div style={{ marginTop: 10, display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'center' }}>
                    <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 10, color: 'var(--text-30)', display: 'flex', alignItems: 'center', gap: 3 }}>
                      🔒 Secured by Razorpay
                    </span>
                    <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 10, color: 'var(--text-30)' }}>
                      · Cancel anytime
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Trust footer ── */}
      <div className="liquid-glass" style={{ borderRadius: 16, padding: '16px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <CreditCard size={16} color="var(--text-40)" />
          <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: 'var(--text-50)' }}>
            All payments processed securely via <strong style={{ color: '#3b82f6' }}>Razorpay</strong> — India's most trusted payment gateway
          </span>
        </div>
        <div style={{ display: 'flex', gap: 16 }}>
          {['🔒 256-bit SSL', '✅ PCI-DSS compliant', '🇮🇳 RBI-regulated'].map(b => (
            <span key={b} style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 11, color: 'var(--text-40)' }}>{b}</span>
          ))}
        </div>
      </div>

      {/* ── Test mode notice (shown when using test keys) ── */}
      <div style={{ textAlign: 'center', padding: '4px 0 8px' }}>
        <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 11, color: 'var(--text-30)' }}>
          💡 Test mode: Use UPI ID <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: 4 }}>success@razorpay</code> · Card: <code style={{ background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: 4 }}>4111 1111 1111 1111</code>
        </span>
      </div>
    </div>
  );
}
