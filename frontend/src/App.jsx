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
