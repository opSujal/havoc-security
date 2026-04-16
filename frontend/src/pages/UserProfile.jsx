import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Eye, EyeOff, User, Mail, Shield, Key, ArrowLeft, Edit3, Lock,
  Activity, Clock, AlertTriangle, CheckCircle, Wifi, Globe, Pen
} from 'lucide-react';
import { notify } from '../utils/notifier';
import { resetPassword, getMetrics, getScanHistory } from '../api/api';
import './UserProfile.css';

export default function UserProfile({ user }) {
  const navigate = useNavigate();
  const [showPassword, setShowPassword] = useState(false);
  const [pwdSection, setPwdSection]     = useState(false);
  const [oldPwd, setOldPwd]             = useState('');
  const [newPwd, setNewPwd]             = useState('');
  const [confirmPwd, setConfirmPwd]     = useState('');
  const [showOld, setShowOld]           = useState(false);
  const [showNew, setShowNew]           = useState(false);
  const [showConfirm, setShowConfirm]   = useState(false);
  const [saving, setSaving]             = useState(false);
  const [metrics, setMetrics]           = useState(null);
  const [scanHistory, setScanHistory]   = useState([]);
  const avatarKey                       = `havoc_custom_avatar_${user?.email || 'default'}`;
  const [customAvatar, setCustomAvatar] = useState(localStorage.getItem(avatarKey));
  const fileInputRef                    = useRef(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [m, h] = await Promise.all([getMetrics(), getScanHistory()]);
        setMetrics(m.data);
        setScanHistory(h.data);
      } catch { /* suppress */ }
    };
    load();
  }, []);

  if (!user) return null;

  const fullName  = [user.first_name, user.last_name].filter(Boolean).join(' ') || 'Unknown User';
  const avatarSeed = user.first_name || user.email || 'Havoc';
  const sessionToken = localStorage.getItem('havoc_token') || '';
  const tokenPreview = sessionToken ? `${sessionToken.slice(0, 20)}…` : '—';

  // Derive last scan info
  const lastScan  = scanHistory[0];
  const lastScanDate = lastScan?.date
    ? new Date(lastScan.date).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'No scans yet';

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (!oldPwd) { notify.warning('Enter your current password.'); return; }
    if (newPwd.length < 8) { notify.warning('New password must be at least 8 characters.'); return; }
    if (newPwd !== confirmPwd) { notify.warning('New passwords do not match.'); return; }
    setSaving(true);
    try {
      const res = await resetPassword(user.email, oldPwd, newPwd);
      if (res.data.status === 'success') {
        notify.success('Password updated successfully!', 'Your account is secured with a new password.');
        setOldPwd(''); setNewPwd(''); setConfirmPwd('');
        setPwdSection(false);
      }
    } catch {
      notify.error('Failed to change password.', 'Incorrect current password or server error.');
    } finally {
      setSaving(false);
    }
  };

  const handleAvatarClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Check size (max 2MB to fit in localStorage)
    if (file.size > 2 * 1024 * 1024) {
      notify.warning('Image too large', 'Please keep your profile picture under 2MB.');
      return;
    }

    const reader = new FileReader();
    reader.onloadend = () => {
      const b64 = reader.result;
      try {
        localStorage.setItem(avatarKey, b64);
        setCustomAvatar(b64);
        notify.success('Profile updated', 'Your new profile picture has been saved.');
        window.dispatchEvent(new CustomEvent('havoc_avatar_update', { detail: { email: user?.email } }));
      } catch {
        notify.error('Failed to save', 'Image might be too large for local storage.');
      }
    };
    reader.readAsDataURL(file);
  };

  return (
    <div className="profile-page fadein">

      {/* ── Back ── */}
      <button className="profile-back-btn" onClick={() => navigate(-1)}>
        <ArrowLeft size={15} />
        <span>Back</span>
      </button>

      {/* ── Hero ── */}
      <div className="profile-hero">
        <div className="profile-avatar-wrap">
          <img
            src={customAvatar || `https://api.dicebear.com/7.x/avataaars/svg?seed=${avatarSeed}`}
            alt={fullName}
            className="profile-avatar-img"
            style={customAvatar ? { objectFit: 'cover' } : {}}
          />
          <div className="profile-avatar-ring" />
          <button className="profile-avatar-edit-btn" title="Upload new picture" onClick={handleAvatarClick}>
            <Pen size={14} />
          </button>
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            accept="image/*" 
            style={{ display: 'none' }} 
          />
        </div>
        <div className="profile-hero-info">
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <h1 className="profile-full-name">{fullName}</h1>
            <div className="profile-meta-row">
              <div className="profile-role-badge">
                <Shield size={11} />
                {user.role || 'User'}
              </div>
              <span className="profile-id-chip">ID #{user.id || '—'}</span>
            </div>
          </div>
          <p className="profile-email-sub" style={{ marginTop: '2px' }}>
            <Mail size={12} style={{ opacity: 0.4, flexShrink: 0 }} />
            {user.email || '—'}
          </p>
        </div>

        {/* Quick stats in hero */}
        {metrics && (
          <div className="profile-hero-stats">
            <HeroStat label="Total Scans" value={metrics.scans ?? 0} color="#60a5fa" />
            <HeroStat label="Vulns Found" value={metrics.total ?? 0} color="#f87171" />
            <HeroStat label="Critical"    value={metrics.critical ?? 0} color="#ff3c5a" />
            <HeroStat label="Remediated"  value={metrics.remediated ?? 0} color="#4ade80" />
          </div>
        )}
      </div>

      {/* ── Main Grid ── */}
      <div className="profile-grid">

        {/* ── Personal Information ── */}
        <div className="profile-card liquid-glass-strong">
          <SectionHeader icon={User} title="Personal Information" />
          <div className="profile-field-group">
            <ProfileField label="First Name"    value={user.first_name || '—'} />
            <ProfileField label="Last Name"     value={user.last_name  || '—'} />
            <ProfileField label="Email Address" value={user.email || '—'} mono />
            <ProfileField label="Display Name"  value={fullName} />
          </div>
        </div>

        {/* ── Account & Security ── */}
        <div className="profile-card liquid-glass-strong">
          <SectionHeader icon={Lock} title="Account & Security" />
          <div className="profile-field-group">

            {/* Password row */}
            <div className="profile-field">
              <div className="profile-field-label">Password</div>
              <div className="profile-field-value-row">
                <span className="profile-field-value" style={{ fontFamily: showPassword ? 'Aeonik' : 'monospace', letterSpacing: showPassword ? 'normal' : 2, flex: 1 }}>
                  {showPassword ? '(Encrypted — stored with bcrypt)' : '••••••••••••'}
                </span>
                <button className="profile-eye-btn" onClick={() => setShowPassword(p => !p)}>
                  {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            <ProfileField label="Account Role"  value={user.role || 'User'} />
            <ProfileField label="User ID"       value={user.id ? `#${user.id}` : '—'} mono />
            <ProfileField label="Auth Method"   value="Email & Password" />
          </div>

          <button
            className={`profile-change-pwd-btn ${pwdSection ? 'open' : ''}`}
            onClick={() => setPwdSection(p => !p)}
          >
            <Edit3 size={13} />
            {pwdSection ? 'Cancel' : 'Change Password'}
          </button>

          {pwdSection && (
            <form className="profile-pwd-form" onSubmit={handlePasswordChange}>
              <PasswordInput label="Current Password"     value={oldPwd}     onChange={setOldPwd}     show={showOld}     toggleShow={() => setShowOld(p=>!p)} />
              <PasswordInput label="New Password"         value={newPwd}     onChange={setNewPwd}     show={showNew}     toggleShow={() => setShowNew(p=>!p)} />
              <PasswordInput label="Confirm New Password" value={confirmPwd} onChange={setConfirmPwd} show={showConfirm} toggleShow={() => setShowConfirm(p=>!p)} />
              <button type="submit" className="profile-save-btn" disabled={saving}>
                {saving ? 'Saving…' : 'Update Password'}
              </button>
            </form>
          )}
        </div>

        {/* ── Activity Summary ── */}
        <div className="profile-card liquid-glass-strong">
          <SectionHeader icon={Activity} title="Scan Activity" />
          <div className="profile-field-group">
            <ProfileField label="Total Scans Run"    value={metrics ? String(metrics.scans ?? 0) : '—'} />
            <ProfileField label="Last Scan"          value={lastScanDate} />
            <ProfileField label="Last Scan Target"   value={lastScan?.target ? lastScan.target.replace(/https?:\/\//, '') : 'N/A'} mono />
            <ProfileField label="Vulns Last Scan"    value={lastScan?.vulns_found != null ? String(lastScan.vulns_found) : '—'} />
          </div>

          {/* Mini scan status bar */}
          {metrics && metrics.total > 0 && (
            <div className="profile-vuln-bar-section">
              <div className="profile-vuln-bar-label">
                <span>Vulnerability Breakdown</span>
                <span style={{ color: 'rgba(255,255,255,0.3)', fontSize: 11 }}>{metrics.total} total</span>
              </div>
              <div className="profile-vuln-bar-track">
                {metrics.critical > 0 && <div className="profile-vuln-segment seg-critical" style={{ width: `${(metrics.critical/metrics.total)*100}%` }} title={`Critical: ${metrics.critical}`} />}
                {metrics.high     > 0 && <div className="profile-vuln-segment seg-high"     style={{ width: `${(metrics.high/metrics.total)*100}%` }} title={`High: ${metrics.high}`} />}
                {metrics.medium   > 0 && <div className="profile-vuln-segment seg-medium"   style={{ width: `${(metrics.medium/metrics.total)*100}%` }} title={`Medium: ${metrics.medium}`} />}
                {metrics.low      > 0 && <div className="profile-vuln-segment seg-low"      style={{ width: `${(metrics.low/metrics.total)*100}%` }} title={`Low: ${metrics.low}`} />}
              </div>
              <div className="profile-vuln-legend">
                <LegendDot color="#ff3c5a" label={`Critical ${metrics.critical}`} />
                <LegendDot color="#ff8c42" label={`High ${metrics.high}`} />
                <LegendDot color="#f0c040" label={`Medium ${metrics.medium}`} />
                <LegendDot color="#4ade80" label={`Low ${metrics.low}`} />
              </div>
            </div>
          )}
        </div>

        {/* ── Session Info ── */}
        <div className="profile-card liquid-glass-strong">
          <SectionHeader icon={Wifi} title="Active Session" />
          <div className="profile-field-group">
            <ProfileField label="Session Status"  value="Active ●" valueStyle={{ color: '#4ade80' }} />
            <ProfileField label="Token Type"      value="JWT Bearer (HS256)" />
            <ProfileField label="Token Preview"   value={tokenPreview} mono />
            <ProfileField label="Expiry"          value="24 hours after login" />
          </div>

          {/* Session warning */}
          <div className="profile-session-note">
            <AlertTriangle size={12} color="#f0c040" />
            <span>Logging out invalidates your session token. Keep your credentials safe.</span>
          </div>
        </div>

        {/* ── Recent Scan History ── */}
        {scanHistory.length > 0 && (
          <div className="profile-card profile-card-wide liquid-glass-strong">
            <SectionHeader icon={Clock} title="Recent Scan History" />
            <div className="profile-history-table">
              <div className="profile-history-header">
                <span>Target</span>
                <span>Status</span>
                <span>Vulns</span>
                <span>Duration</span>
                <span>Date</span>
              </div>
              {scanHistory.slice(0, 6).map((h, i) => {
                const st = (h.status || '').toLowerCase();
                const isCompleted = !st.includes('incomplete') && !st.includes('error') && !st.includes('fail');
                const statusColor = isCompleted ? '#4ade80' : st.includes('running') ? '#60a5fa' : '#f87171';
                return (
                  <div key={h.id ?? i} className="profile-history-row">
                    <span className="profile-history-target">{(h.target || 'unknown').replace(/https?:\/\//, '')}</span>
                    <span style={{ color: statusColor, fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                      {isCompleted ? <CheckCircle size={11} /> : <AlertTriangle size={11} />}
                      {h.status || 'Unknown'}
                    </span>
                    <span style={{ color: h.vulns_found > 0 ? '#f87171' : 'rgba(255,255,255,0.4)' }}>{h.vulns_found ?? '—'}</span>
                    <span style={{ color: 'rgba(255,255,255,0.4)', fontFamily: 'monospace', fontSize: 12 }}>{h.duration ? `${h.duration}s` : '—'}</span>
                    <span style={{ color: 'rgba(255,255,255,0.3)', fontSize: 11 }}>
                      {h.date ? new Date(h.date).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Platform Info ── */}
        <div className={`profile-card ${scanHistory.length === 0 ? 'profile-card-wide' : ''} liquid-glass-strong`}>
          <SectionHeader icon={Globe} title="Platform Details" />
          <div className="profile-platform-grid">
            {[
              { label: 'Platform',   value: 'Havoc Security' },
              { label: 'Version',    value: 'AutoVAPT-AI · React + Flask' },
              { label: 'Backend',    value: 'Python / Flask' },
              { label: 'Database',   value: 'SQLite' },
              { label: 'Encryption', value: 'bcrypt (10 rounds)' },
              { label: 'Auth',       value: 'JWT HS256 · 24h expiry' },
            ].map(({ label, value }) => (
              <div key={label} className="profile-platform-row">
                <span className="profile-platform-label">{label}</span>
                <span className="profile-platform-value">{value}</span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}

/* ── Helper Sub-components ──────────────────────────────────────────────────── */
function SectionHeader(props) {
  const IconComp = props.icon;
  return (
    <div className="profile-card-header">
      <IconComp size={14} strokeWidth={1.5} color="rgba(255,255,255,0.4)" />
      <span>{props.title}</span>
    </div>
  );
}

function HeroStat({ label, value, color }) {
  return (
    <div className="profile-hero-stat">
      <span className="profile-hero-stat-value" style={{ color }}>{value}</span>
      <span className="profile-hero-stat-label">{label}</span>
    </div>
  );
}

function ProfileField({ label, value, mono = false, valueStyle = {} }) {
  return (
    <div className="profile-field">
      <div className="profile-field-label">{label}</div>
      <span className="profile-field-value" style={{ ...(mono ? { fontFamily: 'monospace', fontSize: 13 } : {}), ...valueStyle }}>
        {value}
      </span>
    </div>
  );
}

function LegendDot({ color, label }) {
  return (
    <span className="profile-legend-item">
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
      {label}
    </span>
  );
}

function PasswordInput({ label, value, onChange, show, toggleShow }) {
  return (
    <div className="profile-pwd-field">
      <label className="profile-pwd-label">{label}</label>
      <div className="profile-pwd-input-wrap">
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder="••••••••"
          className="profile-pwd-input"
        />
        <button type="button" className="profile-eye-btn" onClick={toggleShow}>
          {show ? <EyeOff size={13} /> : <Eye size={13} />}
        </button>
      </div>
    </div>
  );
}
