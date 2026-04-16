import { useState, useEffect } from 'react';
import { getPlans, createCheckout } from '../api/api';
import { Check, X, Zap, Users, Building2, Rocket } from 'lucide-react';
import bgImage from '../assets/bg.png';

const PLAN_ICONS = {
  free:    <Rocket size={20} color="#6c8ba4" />,
  starter: <Zap size={20} color="#3b82f6" />,
  pro:     <Zap size={20} color="#ff3c5a" />,
  team:    <Users size={20} color="#a855f7" />,
};

const PLAN_ORDER = ['free', 'starter', 'pro', 'team'];

const PLAN_FEATURES = {
  free:    ['5 scans / month', '1 target domain', 'JSON export', 'Basic vulnerability detection', 'Dashboard & charts'],
  starter: ['50 scans / month', '5 target domains', 'AI Remediation', 'PDF & JSON export', 'Dashboard & charts', 'Scan history'],
  pro:     ['Unlimited scans', '25 target domains', 'AI Remediation', 'PDF & JSON export', 'Deep scan (SQLi, SSTI, CORS)', 'Secret key scanning', 'Priority detection'],
  team:    ['Unlimited scans', 'Unlimited targets', 'AI Remediation', 'PDF & JSON export', 'Deep scan modules', 'API access', 'Multi-user (5 seats)', 'Priority support'],
};

const PLAN_MISSING = {
  free:    ['AI Remediation', 'PDF/HTML export', 'Deep scan modules', 'API access'],
  starter: ['Deep scan modules', 'API access'],
  pro:     ['API access', 'Multi-user seats'],
  team:    [],
};

const GRADIENT_TEXT = {
  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
  color: 'transparent',
};

export default function PricingPage({ user, currentPlan = 'free' }) {
  const [plans, setPlans] = useState({});
  const [loading, setLoading] = useState(true);
  const [checkingOut, setCheckingOut] = useState(null);
  const [annual, setAnnual] = useState(false);

  useEffect(() => {
    getPlans()
      .then(r => setPlans(r.data))
      .catch(() => {
        // Fallback static plans if API not available
        setPlans({
          free:    { name: 'Free',    price: 0,     badge_color: '#6c8ba4', badge_label: 'Free' },
          starter: { name: 'Starter', price: 1900,  badge_color: '#3b82f6', badge_label: 'Starter' },
          pro:     { name: 'Pro',     price: 4900,  badge_color: '#ff3c5a', badge_label: 'Pro' },
          team:    { name: 'Team',    price: 14900, badge_color: '#a855f7', badge_label: 'Team' },
        });
      })
      .finally(() => setLoading(false));
  }, []);

  const handleUpgrade = async (planKey) => {
    if (planKey === 'free') return;
    if (!user?.id) { alert('Please log in to upgrade.'); return; }
    setCheckingOut(planKey);
    try {
      const res = await createCheckout(user.id, planKey, user.email || '');
      if (res.data.checkout_url) {
        window.location.href = res.data.checkout_url;
      } else {
        alert(res.data.error || 'Could not start checkout');
      }
    } catch (e) {
      const msg = e.response?.data?.error || e.message;
      if (msg && msg.includes('STRIPE_SECRET_KEY')) {
        alert('Stripe is not yet configured. Set STRIPE_SECRET_KEY on the backend to enable payments.');
      } else {
        alert(msg || 'Checkout failed');
      }
    } finally {
      setCheckingOut(null);
    }
  };

  const fmtPrice = (cents) => {
    if (cents === 0) return 'Free';
    const monthly = cents / 100;
    const displayed = annual ? (monthly * 0.8).toFixed(0) : monthly.toFixed(0);
    return `$${displayed}`;
  };

  return (
    <div className="dashboard-grid fadein" style={{ display: 'flex', flexDirection: 'column', gap: 24, height: 'calc(100vh - 130px)', overflowY: 'auto' }}>

      {/* Header */}
      <div style={{ textAlign: 'center', padding: '8px 0 4px' }}>
        <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 32, ...GRADIENT_TEXT, marginBottom: 8 }}>
          Simple, Transparent Pricing
        </div>
        <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 14, color: 'var(--text-40)', maxWidth: 480, margin: '0 auto' }}>
          Start free. Upgrade when you need more power. Cancel anytime.
        </div>

        {/* Annual Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center', marginTop: 16 }}>
          <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: annual ? 'var(--text-50)' : 'var(--text-80)' }}>Monthly</span>
          <div
            onClick={() => setAnnual(a => !a)}
            style={{
              width: 44, height: 24, borderRadius: 12, cursor: 'pointer', position: 'relative',
              background: annual ? 'rgba(255, 60, 90, 0.4)' : 'rgba(255,255,255,0.1)',
              border: '1px solid rgba(255,255,255,0.1)',
              transition: 'background 0.3s',
            }}
          >
            <div style={{
              position: 'absolute', top: 3, left: annual ? 22 : 3,
              width: 16, height: 16, borderRadius: '50%', background: '#fff',
              transition: 'left 0.25s',
            }} />
          </div>
          <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: annual ? 'var(--text-80)' : 'var(--text-50)' }}>
            Annual <span style={{ color: '#22c55e', fontSize: 11 }}>Save 20%</span>
          </span>
        </div>
      </div>

      {/* Pricing grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        {PLAN_ORDER.map(key => {
          const plan = plans[key];
          if (!plan) return null;
          const isCurrentPlan = currentPlan === key;
          const isPro = key === 'pro';
          const color = plan.badge_color || '#6c8ba4';
          const price = fmtPrice(plan.price || 0);

          return (
            <div
              key={key}
              className="liquid-glass-strong"
              style={{
                borderRadius: 20,
                padding: '28px 24px',
                display: 'flex',
                flexDirection: 'column',
                gap: 20,
                position: 'relative',
                overflow: 'hidden',
                border: isPro ? `1px solid rgba(255,60,90,0.35)` : '1px solid rgba(255,255,255,0.06)',
                boxShadow: isPro ? '0 0 30px rgba(255,60,90,0.08)' : 'none',
                transition: 'transform 0.2s, box-shadow 0.2s',
              }}
            >
              <img src={bgImage} alt="" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', opacity: 0.1, zIndex: 0, pointerEvents: 'none', filter: 'blur(6px)' }} />

              {isPro && (
                <div style={{
                  position: 'absolute', top: 14, right: 14, zIndex: 2,
                  background: 'rgba(255,60,90,0.15)', border: '1px solid rgba(255,60,90,0.35)',
                  borderRadius: 20, padding: '3px 10px',
                  fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 10,
                  color: '#ff3c5a', letterSpacing: '0.5px', textTransform: 'uppercase',
                }}>Most Popular</div>
              )}

              <div style={{ position: 'relative', zIndex: 1 }}>
                {/* Plan header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <div style={{ width: 34, height: 34, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `${color}18`, border: `1px solid ${color}40` }}>
                    {PLAN_ICONS[key]}
                  </div>
                  <div>
                    <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 600, fontSize: 16, color: '#fff' }}>{plan.name}</div>
                    {isCurrentPlan && (
                      <div style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 10, color: color, fontWeight: 500 }}>Current Plan</div>
                    )}
                  </div>
                </div>

                {/* Price */}
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 4 }}>
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 700, fontSize: 36, color: price === 'Free' ? 'var(--text-80)' : color }}>{price}</span>
                  {price !== 'Free' && <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: 'var(--text-40)' }}>/mo{annual ? ' (billed annually)' : ''}</span>}
                </div>

                {/* Divider */}
                <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', margin: '16px 0' }} />

                {/* Features included */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
                  {PLAN_FEATURES[key]?.map(f => (
                    <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Check size={13} color="#22c55e" strokeWidth={2.5} />
                      <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 12, color: 'var(--text-70)' }}>{f}</span>
                    </div>
                  ))}
                  {PLAN_MISSING[key]?.map(f => (
                    <div key={f} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <X size={13} color="rgba(255,255,255,0.2)" strokeWidth={2.5} />
                      <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 12, color: 'var(--text-30)' }}>{f}</span>
                    </div>
                  ))}
                </div>

                {/* CTA Button */}
                <button
                  onClick={() => handleUpgrade(key)}
                  disabled={isCurrentPlan || key === 'free' || checkingOut === key}
                  style={{
                    width: '100%',
                    padding: '12px 0',
                    borderRadius: 12,
                    border: isPro ? 'none' : `1px solid ${isCurrentPlan ? 'rgba(255,255,255,0.1)' : color + '60'}`,
                    background: isPro
                      ? 'linear-gradient(135deg, #ff3c5a, #ff6b35)'
                      : isCurrentPlan
                        ? 'rgba(255,255,255,0.04)'
                        : `${color}18`,
                    color: isCurrentPlan ? 'var(--text-40)' : (isPro ? '#fff' : color),
                    fontFamily: "'Aeonik', sans-serif",
                    fontWeight: 600,
                    fontSize: 13,
                    cursor: (isCurrentPlan || key === 'free') ? 'default' : 'pointer',
                    transition: 'opacity 0.2s, transform 0.15s',
                    opacity: checkingOut === key ? 0.7 : 1,
                    boxShadow: isPro ? '0 4px 20px rgba(255,60,90,0.3)' : 'none',
                  }}
                >
                  {checkingOut === key ? 'Redirecting...' :
                    isCurrentPlan ? '✓ Current Plan' :
                    key === 'free' ? 'Free Forever' :
                    `Upgrade to ${plan.name}`}
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* FAQ / Note */}
      <div className="liquid-glass" style={{ borderRadius: 16, padding: '16px 24px', display: 'flex', alignItems: 'center', gap: 12 }}>
        <Building2 size={16} color="var(--text-40)" />
        <span style={{ fontFamily: "'Aeonik', sans-serif", fontSize: 13, color: 'var(--text-50)' }}>
          Need a custom Enterprise plan with SSO, white-labeling, or compliance reporting?{' '}
          <a href="mailto:sales@havoc-security.com" style={{ color: '#ff3c5a', textDecoration: 'none' }}>Contact us →</a>
        </span>
      </div>

    </div>
  );
}
