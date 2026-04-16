import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { notify } from '../utils/notifier';
import { clearDatabase, removeAccount } from '../api/api';
import { Trash2, Info, Database, AlertTriangle, UserX } from 'lucide-react';
import shieldStarIcon from '../assets/svgs/ShieldStar.svg';
import './Settings.css';
import iconSvg from '../assets/svgs/Icon.svg';

import bgImage from '../assets/bg.png';

const GRADIENT_TEXT = {
  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  backgroundClip: 'text', color: 'transparent',
};

const SUBTLE_GRADIENT = {
  background: 'linear-gradient(180deg, rgba(255,255,255,0.6) 0%, rgba(255,255,255,0.25) 100%)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  backgroundClip: 'text', color: 'transparent',
};

function SectionLabel({ icon: Icon, iconSrc, children }) {
  return (
    <div className="settings-section-label">
      <div className="settings-section-icon">
        {iconSrc
          ? <img src={iconSrc} alt="" style={{ width: 16, height: 16, opacity: 0.6 }} />
          : Icon ? <Icon size={14} color="rgba(255,255,255,0.5)" strokeWidth={1.5} /> : null
        }
      </div>
      <span className="settings-section-title settings-subtle-gradient">
        {children}
      </span>
    </div>
  );
}

function GlassCard({ children, style = {} }) {
  return (
    <div className="liquid-glass-strong settings-card" style={style}>
      <img src={bgImage} alt="" className="settings-card-bg" />
      <div className="settings-card-inner">{children}</div>
    </div>
  );
}

export default function SettingsPage() {
  const [confirming, setConfirming] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const navigate = useNavigate();

  const sessionUser = JSON.parse(localStorage.getItem('havoc_user') || '{}');
  const isAdmin = sessionUser?.role === 'Admin';

  const handleClear = async () => {
    if (!confirming) { setConfirming(true); return; }
    try {
      await clearDatabase();
      notify.success('Database cleared', 'All scan data cleared successfully.');
    } catch {
      notify.error('Clear failed', 'Failed to clear database. Ensure the API server is running.');
    }
    setConfirming(false);
  };

  const handleRemoveAccount = async () => {
    try {
      await removeAccount();
      localStorage.removeItem('havoc_token');
      localStorage.removeItem('havoc_user');
      notify.success('Account Deleted', 'Your account has been permanently removed.');
      setShowDeleteModal(false);
      navigate('/auth'); // redirect to sign up/login
    } catch {
      notify.error('Action failed', 'Failed to remove account. Please contact support.');
      setShowDeleteModal(false);
    }
  };

  return (
    <div className="dashboard-grid fadein settings-page">

      <div className="liquid-glass settings-header">
        <div className="settings-header-icon">
          <img src={iconSvg} alt="Settings" />
        </div>
        <div>
          <div className="settings-page-title settings-gradient-text">Settings</div>
          <div className="settings-page-subtitle">Platform configuration and data management</div>
        </div>
      </div>

      <div className="settings-grid">

        {/* ── Database Management ── */}
        <GlassCard>
          <SectionLabel icon={Database}>Database Management</SectionLabel>
          <p className="settings-card-desc">
            Permanently deletes your scan data or removes your user account completely. <span className="settings-danger-text">These actions cannot be undone.</span>
          </p>

          <div
            className="liquid-glass settings-action-row"
            style={{
              background: confirming ? 'rgba(220,38,38,0.08)' : 'rgba(255,255,255,0.02)',
              border: confirming ? '1px solid rgba(220,38,38,0.3)' : '1px solid rgba(255,255,255,0.07)',
            }}
          >
            <div className="settings-action-row-header" style={{ marginBottom: confirming ? 14 : 0 }}>
              <div className="settings-action-row-header-left">
                <Trash2 size={16} color={confirming ? '#f87171' : 'var(--text-50)'} strokeWidth={1.5} />
                <span className="settings-action-label" style={{ color: confirming ? '#f87171' : 'var(--text-80)' }}>
                  Clear All Scan Data
                </span>
              </div>
              <button
                onClick={handleClear}
                         className="settings-action-btn"
                style={{
                  border: `1px solid ${confirming ? 'rgba(220,38,38,0.6)' : 'rgba(255,255,255,0.12)'}`,
                  background: confirming ? 'rgba(220,38,38,0.2)' : 'rgba(255,255,255,0.05)',
                  color: confirming ? '#f87171' : 'var(--text-70)',
                }}
              >
                {confirming ? '⚠️ Confirm Delete' : 'Clear Data'}
              </button>
            </div>
            {confirming && (
              <div className="settings-warning-row">
                <AlertTriangle size={13} color='#fbbf24' strokeWidth={1.5} />
                <span className="settings-warning-text">
                  Click again to confirm — this will erase all data permanently.
                </span>
                <button
                  onClick={() => setConfirming(false)}
                  className="settings-cancel-btn"
                >Cancel</button>
              </div>
            )}
          </div>

          {/* ── Remove Account ── */}
          <div className="liquid-glass settings-action-row" style={{ marginTop: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)' }}>
            <div className="settings-action-row-header">
              <div className="settings-action-row-header-left">
                <UserX size={16} color="var(--text-50)" strokeWidth={1.5} />
                <span className="settings-action-label" style={{ color: 'var(--text-80)' }}>
                  Remove Target Account
                </span>
              </div>
              <button
                onClick={() => setShowDeleteModal(true)}
                className="settings-action-btn"
                style={{
                  border: '1px solid rgba(255,255,255,0.12)',
                  background: 'rgba(255,255,255,0.05)',
                  color: 'var(--text-70)',
                }}
              >
                Delete Account
              </button>
            </div>
          </div>

          {/* ── Admin Database Access ── */}
          {isAdmin && (
            <div className="liquid-glass settings-action-row" style={{ marginTop: 16, background: 'rgba(255,51,51,0.05)', border: '1px solid rgba(255,51,51,0.15)' }}>
              <div className="settings-action-row-header">
                <div className="settings-action-row-header-left">
                  <Database size={16} color="#ff3c5a" strokeWidth={1.5} />
                  <span className="settings-action-label" style={{ color: 'var(--text-90)', fontWeight: 500 }}>
                    Access Raw Database
                  </span>
                </div>
                <button
                  className="settings-action-btn"
                  style={{
                    border: '1px solid #ff3c5a',
                    background: 'transparent',
                    color: '#ff3c5a',
                    fontWeight: 500,
                  }}
                  onClick={() => navigate('/admin-database')}
                >
                  Access
                </button>
              </div>
            </div>
          )}
        </GlassCard>

        <GlassCard>
          <SectionLabel icon={Info}>About</SectionLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {[
              { label: 'Platform', value: 'Havoc Security' },
              { label: 'Version', value: 'AutoVAPT-AI · React + Flask Edition' },
              { label: 'Purpose', value: 'Vulnerability Assessment & Penetration Testing' },
              { label: 'Backend', value: 'Python / Flask' },
              { label: 'Database', value: 'SQLite' },
              { label: 'Scanners', value: 'Nmap, OWASP ZAP, Manual Checks' },
            ].map(({ label, value }) => (
              <div key={label} className="settings-about-row">
                <span className="settings-about-label">{label}</span>
                <span className="settings-about-value">{value}</span>
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard style={{ gridColumn: '1 / -1' }}>
          <SectionLabel iconSrc={shieldStarIcon}>Scan Configuration</SectionLabel>
          <div className="settings-scan-grid">
            {[
              { title: 'Quick Scan', desc: 'Fast surface-level scan covering common vulnerability vectors. Ideal for rapid assessments.' },
              { title: 'Full Scan', desc: 'Deep crawl with comprehensive checks across all endpoints. May take several minutes.' },
              { title: 'Report Export', desc: 'Export scan results as PDF, JSON, or CSV from the Vulnerabilities page export strip.' },
            ].map(({ title, desc }) => (
              <div key={title} className="settings-scan-item liquid-glass">
                <div className="settings-scan-item-title settings-subtle-gradient">{title}</div>
                <div className="settings-scan-item-desc">{desc}</div>
              </div>
            ))}
          </div>
        </GlassCard>

      </div>

      {showDeleteModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(10px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
        }}>
          <div className="liquid-glass-strong" style={{ padding: 32, maxWidth: 420, borderRadius: 24, border: '1px solid rgba(220,38,38,0.3)', boxShadow: '0 24px 64px rgba(0,0,0,0.5), inset 0 1px 1px rgba(255,255,255,0.1)' }}>
             <h3 style={{ color: '#f87171', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 10, fontFamily: 'Aeonik, sans-serif', fontSize: 18, fontWeight: 500 }}>
                <AlertTriangle size={20} color="#f87171" /> Warning: Irreversible Action
             </h3>
             <p style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 24, fontSize: 14, lineHeight: 1.6, fontFamily: 'Aeonik, sans-serif' }}>
               Are you sure you want to completely remove your account? Once deleted, your account and all associated data will be permanently erased. <strong style={{ color: '#f87171' }}>This data will not be retrieved.</strong>
             </p>
             <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
               <button onClick={() => setShowDeleteModal(false)} className="settings-cancel-btn" style={{ padding: '10px 18px', borderRadius: 12 }}>Cancel</button>
               <button onClick={handleRemoveAccount} className="settings-action-btn" style={{ background: 'rgba(220,38,38,0.2)', color: '#f87171', border: '1px solid rgba(220,38,38,0.4)', padding: '10px 18px', borderRadius: 12, fontWeight: 600 }}>
                 Yes, Delete Account
               </button>
             </div>
          </div>
        </div>
      )}

    </div>
  );
}
