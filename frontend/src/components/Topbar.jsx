import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import searchStop from '../assets/svgs/search Stop.svg';
import magnifyingGlass from '../assets/svgs/MagnifyingGlass.svg';
import filterIcon from '../assets/svgs/Filter 5.svg';
import havocLogo from '../assets/Havoc Sec LOGO red white.png';
import notifIcon from '../assets/svgs/notification.svg';
import { getScanHistory } from '../api/api';
import { getLocalNotifications } from '../utils/notifier';

const MODULE_LIST = [
  { key: 'portScan',     label: 'Port Scan (Recon)' },
  { key: 'webVuln',      label: 'Web Vuln Scan (OWASP)' },
  { key: 'manualChecks', label: 'Manual Checks (Headers/SSL)' },
  { key: 'deepChecks',   label: 'Deep Checks (SQLi/XSS)', premium: true },
  { key: 'secretKey',    label: 'Secret Key Scanning', premium: true },
  { key: 'advFuzzing',   label: 'Adv. Fuzzing (SSTI/CORS)', premium: true },
  { key: 'dataLeakage',  label: 'Data Leakage & PII Scan', premium: true },
  { key: 'dangerMode',   label: 'Danger Mode (Aggressive Scan)', premium: true },
  { key: 'agenticAi',    label: "Agentic AI Risks (OWASP '26)" },
  { key: 'owaspTop10',   label: 'OWASP Top 10 (2025)' },
];

// Map scan status strings to notification metadata
function buildNotifications(history) {
  if (!history || history.length === 0) return [];
  return history.slice(0, 15).map((h) => {
    const st = (h.status || '').toLowerCase();
    let type = 'completed';
    let icon = '✅';
    let color = '#4ade80';
    if (st.includes('incomplete') || st.includes('stop')) { type = 'stopped'; icon = '⏹️'; color = '#f59e0b'; }
    else if (st.includes('error') || st.includes('fail')) { type = 'error'; icon = '❌'; color = '#f87171'; }
    else if (st.includes('running') || st.includes('progress')) { type = 'running'; icon = '⏳'; color = '#60a5fa'; }

    const host = (h.target || 'unknown').replace(/https?:\/\//, '');
    const label =
      type === 'completed' ? `Scan completed on ${host}` :
      type === 'stopped'   ? `Scan stopped for ${host}` :
      type === 'error'     ? `Scan failed on ${host}` :
                             `Scan running on ${host}`;

    const sub = h.vulns_found != null
      ? `${h.vulns_found} vulnerabilities found · ${h.duration ?? 0}s`
      : '';

    const date = h.date ? new Date(h.date) : null;
    const timeLabel = date
      ? date.toLocaleString('en-IN', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' })
      : '';

    const dateObj = date || new Date(0);

    return { id: h.id, icon, color, label, sub, timeLabel, type, dateObj };
  });
}

export default function Topbar({ onStartScan, scanning, onCancelScan, onLogoClick, targetUrl, setTargetUrl, modules, toggleModule, user }) {
  const navigate = useNavigate();
  const [filterOpen, setFilterOpen]   = useState(false);
  const [isClosing, setIsClosing]     = useState(false);
  const [notifOpen, setNotifOpen]     = useState(false);
  const [notifClosing, setNotifClosing] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  
  // Local state for scan filter UI tracking
  const [localModules, setLocalModules] = useState(modules);

  const headerRef    = useRef(null);
  const searchRef    = useRef(null);
  const notifRef     = useRef(null);

  // Fetch scan history + local activities
  useEffect(() => {
    const load = async () => {
      try {
        const res = await getScanHistory();
        const apiItems = buildNotifications(res.data);
        
        // Fetch local UI activities & format to match the dropdown schema
        const localActivities = getLocalNotifications().map(n => {
          const isError = n._typeTag === 'error';
          const isSuccess = n._typeTag === 'success';
          const isWarn = n._typeTag === 'warning';
          return {
            id: n.id,
            icon: isError ? '❌' : isSuccess ? '✅' : isWarn ? '⚠️' : 'ℹ️',
            color: isError ? '#f87171' : isSuccess ? '#4ade80' : isWarn ? '#f59e0b' : '#60a5fa',
            label: n.label,
            sub: n.sub,
            timeLabel: new Date(n.date).toLocaleString('en-IN', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' }),
            type: n._typeTag,
            dateObj: new Date(n.date)
          };
        });

        // Combine & Sort by newest first
        const combined = [...localActivities, ...apiItems].sort((a, b) => b.dateObj - a.dateObj);
        
        setNotifications(combined);
        setUnreadCount(combined.filter(n => n.type !== 'running').length);
      } catch { /* ignore */ }
    };
    
    load();
    const t = setInterval(load, 10000);
    window.addEventListener('havoc_notification_update', load);
    
    return () => {
      clearInterval(t);
      window.removeEventListener('havoc_notification_update', load);
    };
  }, []);

  // Animate-out helpers
  const closeFilter = () => {
    setIsClosing(true);
    setTimeout(() => { setFilterOpen(false); setIsClosing(false); }, 180);
  };
  const closeNotif = () => {
    setNotifClosing(true);
    setTimeout(() => { setNotifOpen(false); setNotifClosing(false); }, 180);
  };

  // Close both panels on outside click
  useEffect(() => {
    if (!filterOpen && !notifOpen) return;
    const handler = (e) => {
      if (headerRef.current && !headerRef.current.contains(e.target)) {
        if (filterOpen) closeFilter();
        if (notifOpen) closeNotif();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [filterOpen, notifOpen]);

  // Track custom avatar
  const avatarKey = `havoc_custom_avatar_${user?.email || 'default'}`;
  const [customAvatar, setCustomAvatar] = useState(localStorage.getItem(avatarKey));
  useEffect(() => {
    // If the user logs in/out, check the new avatar string
    setCustomAvatar(localStorage.getItem(avatarKey));
    
    const handleAvatarUpdate = (e) => {
      // only update if the event matches this component's active user
      if (e.detail?.email === user?.email) {
        setCustomAvatar(localStorage.getItem(avatarKey));
      }
    };
    window.addEventListener('havoc_avatar_update', handleAvatarUpdate);
    return () => window.removeEventListener('havoc_avatar_update', handleAvatarUpdate);
  }, [user?.email, avatarKey]);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && targetUrl?.trim()) onStartScan(targetUrl, { mode: 'custom', modules });
    if (e.key === 'Escape') { closeFilter(); closeNotif(); }
  };

  // Measure search bar position for the filter dropdown
  const [dropStyle, setDropStyle] = useState({ left: 0, width: 400 });
  useEffect(() => {
    const measure = () => {
      if (searchRef.current && headerRef.current) {
        const sr = searchRef.current.getBoundingClientRect();
        const hr = headerRef.current.getBoundingClientRect();
        setDropStyle({ left: sr.left - hr.left, width: sr.width });
      }
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);
  useEffect(() => {
    if (filterOpen && searchRef.current && headerRef.current) {
      const sr = searchRef.current.getBoundingClientRect();
      const hr = headerRef.current.getBoundingClientRect();
      setDropStyle({ left: sr.left - hr.left, width: sr.width });
    }
  }, [filterOpen]);

  // Notif dropdown position (align to right pill)
  const [notifStyle, setNotifStyle] = useState({ right: 0, width: 360 });
  useEffect(() => {
    const measure = () => {
      if (notifRef.current && headerRef.current) {
        const nr = notifRef.current.getBoundingClientRect();
        const hr = headerRef.current.getBoundingClientRect();
        setNotifStyle({ right: hr.right - nr.right, width: 360 });
      }
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  // Avatar seed from user name for dicebear
  const avatarSeed = user ? (user.first_name || user.email || 'Havoc') : 'Havoc';

  return (
    <header ref={headerRef} className="topbar" style={{ position: 'relative' }}>

      {/* LEFT: Logo */}
      <div
        className="logo-container"
        style={{ height: '56px', marginLeft: '10px', cursor: 'pointer' }}
        onClick={onLogoClick}
      >
        <img src={havocLogo} alt="Havoc Security" style={{ height: '100%', objectFit: 'contain' }} />
      </div>

      {/* CENTER: Search Bar */}
      <div
        ref={searchRef}
        className="search-wrapper liquid-glass"
        style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 10 }}
      >
        <img src={magnifyingGlass} alt="Search" style={{ width: 16, height: 16, opacity: 0.5, flexShrink: 0 }} />
        <input
          type="text"
          className="search-input"
          placeholder={scanning ? 'Scanning in progress...' : 'paste the link / url / domain'}
          value={targetUrl || ''}
          onChange={(e) => setTargetUrl?.(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={scanning}
          style={{ opacity: scanning ? 0.5 : 1, flex: 1 }}
        />

        <button
          onClick={() => {
            if (filterOpen) {
              closeFilter();
            } else {
              setLocalModules(modules); // Reset local state to latest applied before opening
              setFilterOpen(true);
            }
          }}
          title="Scan Modules"
          style={{
            background: filterOpen ? 'rgba(255,51,51,0.18)' : 'transparent',
            border: 'none', cursor: 'pointer', padding: '4px 8px', borderRadius: 8,
            display: 'flex', alignItems: 'center', flexShrink: 0, transition: 'background 0.2s',
          }}
        >
          <img src={filterIcon} alt="Modules" style={{ width: 20, height: 20, opacity: filterOpen ? 1 : 0.55 }} />
        </button>

        {!scanning ? (
          <button
            onClick={() => {
                if (targetUrl?.trim()) {
                    onStartScan(targetUrl, { mode: 'custom', modules: localModules });
                }
            }}
            title="Start Scan"
            className="topbar-action-btn run-btn"
            style={{
                marginLeft: 4, background: targetUrl?.trim() ? '#ff3c5a' : 'rgba(255,60,90,0.2)', 
                color: 'white', border: 'none', borderRadius: 8, padding: '4px 12px', fontSize: 13,
                fontWeight: 600, cursor: targetUrl?.trim() ? 'pointer' : 'not-allowed', transition: 'background 0.2s', fontFamily: 'Aeonik'
            }}
          >
            Run
          </button>
        ) : (
          <img
            src={searchStop} alt="Stop Scan" onClick={onCancelScan}
            style={{ cursor: 'pointer', width: 20, height: 20, flexShrink: 0 }}
          />
        )}
      </div>

      {/* ── Filter / Modules Dropdown ── */}
      {(filterOpen || isClosing) && (
        <div
          className={isClosing ? 'dropdown-anim-out' : 'dropdown-anim'}
          style={{
            position: 'absolute', top: 'calc(100% + 10px)',
            left: dropStyle.left, width: dropStyle.width,
            backgroundColor: '#0d0d0d', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 16, padding: '18px 22px', zIndex: 99999,
            boxShadow: '0 16px 48px rgba(0,0,0,0.7)',
            display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px 24px',
          }}
        >
          <div style={{ gridColumn: '1 / -1', fontSize: 11, fontWeight: 600, letterSpacing: 1.5, textTransform: 'uppercase', color: 'rgba(255,255,255,0.3)', fontFamily: 'Aeonik', marginBottom: 4, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 10 }}>
            Scan Modules — select to enable
          </div>
          {MODULE_LIST.map(({ key, label, premium }) => (
            <div
              key={key}
              onClick={() => setLocalModules(prev => ({ ...prev, [key]: !prev[key] }))}
              style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', padding: '6px 8px', borderRadius: 8, transition: 'background 0.15s', background: localModules?.[key] ? 'rgba(255,51,51,0.07)' : 'transparent', userSelect: 'none' }}
              onMouseEnter={e => e.currentTarget.style.background = localModules?.[key] ? 'rgba(255,51,51,0.12)' : 'rgba(255,255,255,0.04)'}
              onMouseLeave={e => e.currentTarget.style.background = localModules?.[key] ? 'rgba(255,51,51,0.07)' : 'transparent'}
            >
              <div className={`custom-switch ${localModules?.[key] ? 'on' : 'off'}`}><div className="knob" /></div>
              <span style={{ fontSize: 14.5, fontWeight: key === 'dangerMode' ? 700 : 400, color: key === 'dangerMode' && localModules?.[key] ? '#ff4040' : (localModules?.[key] ? 'rgba(255,255,255,0.85)' : 'var(--text-50)'), fontFamily: 'Aeonik', lineHeight: 1.3, display: 'flex', alignItems: 'center', gap: 6 }}>
                {label}
                {premium && <span style={{ color: '#fbbf24', fontSize: 12, transform: 'translateY(-1px)' }} title="Premium Module">★</span>}
              </span>
            </div>
          ))}
          <div style={{ gridColumn: '1 / -1', borderTop: '1px solid rgba(255,255,255,0.06)', margin: '10px -22px -18px', padding: '12px 22px', display: 'flex', justifyContent: 'space-between', background: 'rgba(0,0,0,0.3)', borderRadius: '0 0 16px 16px' }}>
            <span style={{ fontSize: 11, color: 'var(--text-50)', alignSelf: 'center', fontFamily: 'Aeonik' }}>Changes await apply</span>
            <button
               onClick={(e) => {
                 e.stopPropagation();
                 toggleModule(localModules);
                 closeFilter();
               }}
               style={{ background: '#ff3c5a', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: 'pointer', fontFamily: 'Aeonik' }}
            >
              Apply Filters
            </button>
          </div>
        </div>
      )}

      {/* RIGHT: Pill Group */}
      <div className="topbar-right-pill liquid-glass" style={{ position: 'relative' }}>

        {/* ── Notification Bell ── */}
        <div
          ref={notifRef}
          onClick={() => {
            if (notifOpen) { closeNotif(); } else { setNotifOpen(true); setUnreadCount(0); }
          }}
          style={{ position: 'relative', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
          title="Notifications"
        >
          <img
            src={notifIcon} alt="Notifications"
            style={{ width: 18, height: 18, opacity: notifOpen ? 1 : 0.7, transition: 'opacity 0.2s', filter: notifOpen ? 'brightness(1.4)' : 'none' }}
          />
          {unreadCount > 0 && (
            <span style={{
              position: 'absolute', top: -5, right: -6,
              background: '#ff3c5a', color: '#fff',
              fontSize: 9, fontWeight: 700, lineHeight: 1,
              minWidth: 16, height: 16, borderRadius: 8,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              padding: '0 3px', border: '1.5px solid #050505',
            }}>
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </div>

        {/* ── Profile Avatar (Navigates to Profile Page) ── */}
        <div
          className="topbar-avatar-wrapper"
          onClick={() => navigate('/profile')}
          title="User Profile"
          style={{ cursor: 'pointer', transition: 'transform 0.2s, box-shadow 0.2s' }}
          onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.08)'; e.currentTarget.style.boxShadow = '0 0 0 2px rgba(255,60,90,0.5)'; }}
          onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.boxShadow = 'none'; }}
        >
          <img 
            src={customAvatar || `https://api.dicebear.com/7.x/avataaars/svg?seed=${avatarSeed}`}
            alt="User Avatar" 
            className="topbar-avatar" 
            style={customAvatar ? { width: '32px', height: '32px', borderRadius: '50%', objectFit: 'cover' } : { width: '32px', height: '32px', borderRadius: '50%' }}
          />
        </div>
      </div>

      {/* ── Notifications Dropdown ── */}
      {(notifOpen || notifClosing) && (
        <div
          className={notifClosing ? 'dropdown-anim-out' : 'dropdown-anim'}
          style={{
            position: 'absolute', top: 'calc(100% + 10px)',
            right: notifStyle.right, width: notifStyle.width,
            backgroundColor: '#0d0d0d', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 16, zIndex: 99999,
            boxShadow: '0 16px 48px rgba(0,0,0,0.7)',
            overflow: 'hidden',
          }}
        >
          {/* Header */}
          <div style={{ padding: '14px 18px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: 1.2, textTransform: 'uppercase', color: 'rgba(255,255,255,0.4)', fontFamily: 'Aeonik' }}>Notifications</span>
            <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)', fontFamily: 'Aeonik' }}>Recent scan events</span>
          </div>

          {/* List */}
          <div style={{ maxHeight: 380, overflowY: 'auto', scrollbarWidth: 'none' }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '32px 18px', textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: 13, fontFamily: 'Aeonik' }}>
                No scan activity yet.<br />
                <span style={{ fontSize: 11, opacity: 0.6 }}>Run a scan to see events here.</span>
              </div>
            ) : (
              notifications.map((n, i) => (
                <div
                  key={n.id ?? i}
                  style={{
                    padding: '12px 18px', display: 'flex', alignItems: 'flex-start', gap: 12,
                    borderBottom: i < notifications.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    transition: 'background 0.15s', cursor: 'default',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {/* Icon chip */}
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: `${n.color}18`, border: `1px solid ${n.color}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 14 }}>
                    {n.icon}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 500, color: 'rgba(255,255,255,0.85)', fontFamily: 'Aeonik', lineHeight: 1.4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {n.label}
                    </div>
                    {n.sub && (
                      <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)', marginTop: 2, fontFamily: 'Aeonik' }}>
                        {n.sub}
                      </div>
                    )}
                  </div>
                  <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', fontFamily: 'Aeonik', flexShrink: 0, marginTop: 2 }}>
                    {n.timeLabel}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </header>
  );
}
