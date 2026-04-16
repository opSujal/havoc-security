import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Dashboard from './pages/Dashboard';
import Vulnerabilities from './pages/Vulnerabilities';
import AIRemediation from './pages/AIRemediation';
import Settings from './pages/Settings';
import AdminDatabase from './pages/AdminDatabase';
import AuthPage from './pages/AuthPage';
import TermsModal from './components/TermsModal';
import CyberIntelligence from './pages/CyberIntelligence';
import UserProfile from './pages/UserProfile';
import { startScan, stopScan, getScanStatus } from './api/api';
import { notify } from './utils/notifier';
import PricingIndia from './pages/PricingIndia';
import './index.css';

import bgImage from './assets/chroma gradient op2 1.png';



export default function App() {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('havoc_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  // Track whether the current user has accepted T&C
  const [tosAccepted, setTosAccepted] = useState(() => {
    try {
      const saved = localStorage.getItem('havoc_user');
      if (!saved) return false;
      const u = JSON.parse(saved);
      return localStorage.getItem(`havoc_tos_accepted_${u.email}`) === 'true';
    } catch {
      return false;
    }
  });

  // Persist user and sync token
  useEffect(() => {
    if (user) {
      localStorage.setItem('havoc_user', JSON.stringify(user));
      // Check T&C acceptance for current user
      setTosAccepted(localStorage.getItem(`havoc_tos_accepted_${user.email}`) === 'true');
    } else {
      localStorage.removeItem('havoc_user');
      localStorage.removeItem('havoc_token');
      setTosAccepted(false);
    }
  }, [user]);

  // Called after successful login/register — saves both user and JWT
  const handleLogin = (user, token) => {
    if (token) localStorage.setItem('havoc_token', token);
    setUser(user);
  };

  const handleLogout = () => {
    localStorage.removeItem('havoc_token');
    setUser(null);
  };

  const navigate  = useNavigate();
  const location   = useLocation();
  const [scanning, setScanning] = useState(false);
  const [currentScanUrl, setCurrentScanUrl] = useState('');
  const [scanVersion, setScanVersion] = useState(0);

  // ── Stripe billing redirect handler ──────────────────────────────────────
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const billing = params.get('billing');
    const plan    = params.get('plan');
    if (billing === 'success') {
      const label = plan ? plan.charAt(0).toUpperCase() + plan.slice(1) : 'Premium';
      notify.success(
        `🎉 Payment Successful!`,
        `You're now on the ${label} plan. All features are unlocked.`
      );
      // Clean URL without reload
      window.history.replaceState({}, '', window.location.pathname);
      navigate('/dashboard');
    } else if (billing === 'cancelled') {
      notify.warning('Payment Cancelled', 'Your plan was not changed. You can upgrade anytime.');
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, [location.search]); // eslint-disable-line

  const [targetUrl, setTargetUrl] = useState('');
  const [modules, setModules] = useState({
    portScan: true, webVuln: false, manualChecks: true,
    deepChecks: false, secretKey: false, advFuzzing: false,
    agenticAi: true, owaspTop10: true, dangerMode: false
  });
  const updateModules = (newModules) => setModules(newModules);

  // Mobile filter sheet state
  const [mobileFilterOpen, setMobileFilterOpen] = useState(false);
  const [mobileLocalModules, setMobileLocalModules] = useState(modules);

  // Poll scan status while scanning
  const idleGrace = useRef(0);
  const poll = useCallback(async () => {
    try {
      const r = await getScanStatus();
      const st = r.data.status;
      if (st === 'completed' || st === 'error') {
        idleGrace.current = 0;
        setScanning(false);
        setScanVersion(v => v + 1);
      } else if (st === 'idle') {
        idleGrace.current += 1;
        if (idleGrace.current >= 3) {
          idleGrace.current = 0;
          setScanning(false);
          setScanVersion(v => v + 1);
        }
      } else {
        idleGrace.current = 0;
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (!scanning) return;
    idleGrace.current = 0;
    const t = setInterval(poll, 2000);
    return () => clearInterval(t);
  }, [scanning, poll]);

  const handleStartScan = async (url, options = { mode: 'quick' }) => {
    if (!url.trim()) return;
    
    if (options.modules && Object.values(options.modules).every(v => v === false)) {
      notify.warning('No Modules Selected', 'Please select at least one scan module from the filters.');
      return;
    }

    setScanning(true);
    setCurrentScanUrl(url.trim());
    try {
      await startScan(url.trim(), options);
      notify.success('Scan Started', `Initiating scan on ${url.trim()}`);
    } catch (err) {
      setScanning(false);
      setCurrentScanUrl('');
      const status = err.response?.status;
      const msg = err.response?.data?.error || err.message || 'Failed to initialize scan engine.';
      notify.error(`Scan Blocked (${status || 'Network Error'})`, msg);
    }
  };

  const handleCancelScan = async () => {
    setScanning(false);
    if (currentScanUrl) {
      try { await stopScan(currentScanUrl); } catch { /* ignore */ }
    }
    setCurrentScanUrl('');
    setScanVersion(v => v + 1);
  };

  if (!user) {
    return (
      <>
        <Toaster position="top-right" toastOptions={{ style: { background: '#1a1f2e', color: '#e2eaf3', border: '1px solid rgba(255,255,255,0.1)', fontFamily: "'Aeonik', sans-serif" } }} />
        <Routes>
          <Route path="*" element={<AuthPage onLogin={handleLogin} />} />
        </Routes>
      </>
    );
  }

  // Show T&C modal if user is logged in but hasn't accepted
  if (user && !tosAccepted) {
    return (
      <>
        <Toaster position="top-right" toastOptions={{ style: { background: '#1a1f2e', color: '#e2eaf3', border: '1px solid rgba(255,255,255,0.1)', fontFamily: "'Aeonik', sans-serif" } }} />
        <TermsModal user={user} onAccept={() => setTosAccepted(true)} />
      </>
    );
  }

  return (
    <>
      <Toaster position="top-right" toastOptions={{ style: { background: '#1a1f2e', color: '#e2eaf3', border: '1px solid rgba(255,255,255,0.1)', fontFamily: "'Aeonik', sans-serif" } }} />
      <div className="video-bg">
        <img src={bgImage} alt="Chroma Gradient Background" />
      </div>

      <div className={`app-shell ${scanning ? 'scanning-aura' : ''}`}>
        <Sidebar onLogout={handleLogout} />
        <main className="main-area">
          <Topbar
            onStartScan={handleStartScan}
            scanning={scanning}
            onCancelScan={handleCancelScan}
            onLogoClick={() => navigate('/dashboard')}
            targetUrl={targetUrl}
            setTargetUrl={setTargetUrl}
            modules={modules}
            toggleModule={updateModules}
            user={user}
          />
          {/* ─── Mobile-only scan bar (hidden on desktop via CSS) ─── */}
          <div className="mobile-scan-bar" style={{ display: 'none', flexDirection: 'column', gap: 0, padding: 0, background: 'transparent', border: 'none', backdropFilter: 'none' }}>
            {/* Input row */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 16, padding: '10px 12px',
              backdropFilter: 'blur(20px)',
            }}>
              <input
                type="url"
                placeholder={scanning ? 'Scan in progress…' : 'Paste URL / domain to scan'}
                value={targetUrl || ''}
                onChange={e => setTargetUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && targetUrl?.trim() && handleStartScan(targetUrl, { mode: 'custom', modules })}
                disabled={scanning}
                style={{
                  flex: 1, background: 'transparent', border: 'none', outline: 'none',
                  color: 'rgba(255,255,255,0.85)', fontFamily: "'Aeonik', sans-serif", fontSize: 14,
                }}
              />
              {/* Filter button */}
              <button
                onClick={() => { setMobileLocalModules(modules); setMobileFilterOpen(true); }}
                style={{
                  position: 'relative', background: mobileFilterOpen ? 'rgba(255,60,90,0.18)' : 'rgba(255,255,255,0.07)',
                  border: '1px solid rgba(255,255,255,0.12)', borderRadius: 10,
                  padding: '6px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
                  color: 'rgba(255,255,255,0.7)', fontSize: 13, fontFamily: "'Aeonik', sans-serif",
                  transition: 'all 0.2s',
                }}
              >
                ⚙️
                {/* Active module count badge */}
                {Object.values(modules).filter(Boolean).length > 0 && (
                  <span style={{
                    background: '#ff3c5a', color: '#fff', fontSize: 9, fontWeight: 700,
                    minWidth: 15, height: 15, borderRadius: 8, display: 'flex',
                    alignItems: 'center', justifyContent: 'center', padding: '0 3px',
                  }}>
                    {Object.values(modules).filter(Boolean).length}
                  </span>
                )}
              </button>
              {/* Scan / Stop button */}
              {scanning ? (
                <button
                  onClick={handleCancelScan}
                  style={{
                    background: '#555', color: '#fff', border: 'none', borderRadius: 10,
                    padding: '7px 14px', fontFamily: "'Aeonik', sans-serif", fontSize: 13,
                    fontWeight: 600, cursor: 'pointer', whiteSpace: 'nowrap',
                  }}
                >Stop</button>
              ) : (
                <button
                  onClick={() => targetUrl?.trim() && handleStartScan(targetUrl, { mode: 'custom', modules })}
                  disabled={!targetUrl?.trim()}
                  style={{
                    background: targetUrl?.trim() ? '#ff3c5a' : 'rgba(255,60,90,0.25)',
                    color: '#fff', border: 'none', borderRadius: 10,
                    padding: '7px 14px', fontFamily: "'Aeonik', sans-serif", fontSize: 13,
                    fontWeight: 600, cursor: targetUrl?.trim() ? 'pointer' : 'not-allowed',
                    whiteSpace: 'nowrap', transition: 'background 0.2s',
                  }}
                >Scan</button>
              )}
            </div>
          </div>

          {/* ─── Mobile Filter Bottom Sheet ─── */}
          {mobileFilterOpen && (
            <>
              {/* Backdrop */}
              <div
                onClick={() => setMobileFilterOpen(false)}
                style={{
                  position: 'fixed', inset: 0, zIndex: 1998,
                  background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
                }}
              />
              {/* Sheet */}
              <div style={{
                position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 1999,
                background: 'rgba(10,12,20,0.97)',
                borderTop: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '24px 24px 0 0',
                padding: '20px 20px 32px',
                boxShadow: '0 -16px 48px rgba(0,0,0,0.7)',
                animation: 'slideUpSheet 0.25s cubic-bezier(0.16,1,0.3,1)',
              }}>
                {/* Handle + header */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
                  <div>
                    <div style={{ width: 36, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.15)', margin: '0 auto 14px' }} />
                    <span style={{
                      fontFamily: "'Aeonik', sans-serif", fontSize: 11, fontWeight: 600,
                      letterSpacing: 1.5, textTransform: 'uppercase', color: 'rgba(255,255,255,0.3)',
                    }}>Scan Modules</span>
                  </div>
                  <button
                    onClick={() => setMobileFilterOpen(false)}
                    style={{
                      background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '50%', width: 30, height: 30, color: 'rgba(255,255,255,0.5)',
                      cursor: 'pointer', fontSize: 16, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}
                  >×</button>
                </div>

                {/* Module toggles */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 20, maxHeight: '40vh', overflowY: 'auto' }}>
                  {[
                    { key: 'portScan',     label: 'Port Scan (Recon)' },
                    { key: 'webVuln',      label: 'Web Vuln Scan (OWASP)' },
                    { key: 'manualChecks', label: 'Manual Checks (Headers/SSL)' },
                    { key: 'deepChecks',   label: 'Deep Checks (SQLi/XSS)', premium: true },
                    { key: 'secretKey',    label: 'Secret Key Scanning', premium: true },
                    { key: 'advFuzzing',   label: 'Adv. Fuzzing (SSTI/CORS)', premium: true },
                    { key: 'dataLeakage', label: 'Data Leakage & PII Scan', premium: true },
                    { key: 'dangerMode',   label: 'Danger Mode (Aggressive)', premium: true },
                    { key: 'agenticAi',    label: "Agentic AI Risks (OWASP '26)" },
                    { key: 'owaspTop10',   label: 'OWASP Top 10 (2025)' },
                  ].map(({ key, label, premium }) => {
                    const on = mobileLocalModules?.[key];
                    return (
                      <div
                        key={key}
                        onClick={() => setMobileLocalModules(prev => ({ ...prev, [key]: !prev[key] }))}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 12,
                          padding: '12px 14px', borderRadius: 12, cursor: 'pointer',
                          background: on
                            ? (key === 'dangerMode' ? 'rgba(255,60,90,0.1)' : 'rgba(255,255,255,0.04)')
                            : 'transparent',
                          border: `1px solid ${on ? (key === 'dangerMode' ? 'rgba(255,60,90,0.25)' : 'rgba(255,255,255,0.08)') : 'transparent'}`,
                          transition: 'all 0.15s',
                        }}
                      >
                        {/* Mini toggle */}
                        <div style={{
                          width: 36, height: 20, borderRadius: 10, position: 'relative',
                          background: on ? (key === 'dangerMode' ? '#ff3c5a' : '#ff3c5a') : 'rgba(255,255,255,0.1)',
                          border: `1px solid ${on ? '#ff3c5a' : 'rgba(255,255,255,0.15)'}`,
                          flexShrink: 0, transition: 'all 0.2s',
                        }}>
                          <div style={{
                            position: 'absolute', top: 3, left: on ? 17 : 3,
                            width: 12, height: 12, borderRadius: '50%', background: '#fff',
                            transition: 'left 0.2s',
                          }} />
                        </div>
                        <span style={{
                          flex: 1,
                          fontFamily: "'Aeonik', sans-serif",
                          fontSize: 14,
                          fontWeight: key === 'dangerMode' ? 700 : 400,
                          color: on
                            ? (key === 'dangerMode' ? '#ff6b6b' : 'rgba(255,255,255,0.9)')
                            : 'rgba(255,255,255,0.45)',
                        }}>
                          {label}
                          {premium && <span style={{ color: '#fbbf24', marginLeft: 6, fontSize: 11 }}>★</span>}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {/* Apply button */}
                <button
                  onClick={() => {
                    updateModules(mobileLocalModules);
                    setMobileFilterOpen(false);
                  }}
                  style={{
                    width: '100%', background: '#ff3c5a', color: '#fff',
                    border: 'none', borderRadius: 14, padding: '14px 0',
                    fontFamily: "'Aeonik', sans-serif", fontSize: 15, fontWeight: 600,
                    cursor: 'pointer', letterSpacing: 0.3,
                  }}
                >
                  Apply Modules ({Object.values(mobileLocalModules).filter(Boolean).length} active)
                </button>
              </div>
            </>
          )}
          <Routes>
            <Route path="/dashboard" element={<Dashboard onStartScan={handleStartScan} scanning={scanning} scanVersion={scanVersion} onNavigate={(path) => navigate(`/${path}`)} targetUrl={targetUrl} modules={modules} />} />
            <Route path="/cyber-intelligence" element={<CyberIntelligence />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/remediation" element={<AIRemediation />} />
            <Route path="/pricing" element={<PricingIndia user={user} currentPlan={user?.plan || 'free'} />} />
            <Route path="/settings" element={<Settings user={user} />} />
            <Route path="/admin-database" element={<AdminDatabase />} />
            <Route path="/profile" element={<UserProfile user={user} />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </main>
      </div>
    </>
  );
}
