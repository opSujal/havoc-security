import React, { useState, useRef, useEffect } from 'react';
import Hls from 'hls.js';
import { notify, clearLocalNotifications } from '../utils/notifier';
import './AuthPage.css';
import { loginUser, registerUser } from '../api/api';
import logoImg from '../assets/Havoc Sec LOGO red white.png';

const MUX_VIDEO_URL = 'https://stream.mux.com/Aa02T7oM1wH5Mk5EEVDYhbZ1ChcdhRsS2m1NYyx4Ua1g.m3u8';

export default function AuthPage({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [isAdminLogin, setIsAdminLogin] = useState(false);  // Added Admin state
  const [showPassword, setShowPassword] = useState(false);
  const [animating, setAnimating] = useState(false);   // true while exit anim plays
  const switchTimer = useRef(null);
  const videoRef = useRef(null);

  // HLS video setup
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    if (Hls.isSupported()) {
      const hls = new Hls({ enableWorker: true });
      hls.loadSource(MUX_VIDEO_URL);
      hls.attachMedia(video);
      hls.on(Hls.Events.MANIFEST_PARSED, () => {
        video.play().catch(() => { });
      });
      return () => hls.destroy();
    } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
      // Safari native HLS
      video.src = MUX_VIDEO_URL;
      video.addEventListener('loadedmetadata', () => {
        video.play().catch(() => { });
      });
    }
  }, []);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: ''
  });

  // Orchestrate: exit anim (220ms) → swap mode → enter anim via key change
  const handleSwitch = () => {
    if (animating) return;
    setAnimating(true);
    clearTimeout(switchTimer.current);
    switchTimer.current = setTimeout(() => {
      setIsLogin(prev => !prev);
      setIsAdminLogin(false); // Reset admin state when switching sign up/sign in
      setFormData({ firstName: '', lastName: '', email: '', password: '' });
      setShowPassword(false);
      setAnimating(false);
    }, 220); // matches form-exit duration
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (isAdminLogin || isLogin) {
        const res = await loginUser(formData.email, formData.password);
        if (res.data.token) {
          clearLocalNotifications();
          notify.success('Welcome back!', isAdminLogin ? 'Admin authentication successful.' : 'You have successfully logged in.');
          onLogin(res.data.user, res.data.token);
        } else {
          notify.error('Login failed', res.data.error || 'Login failed');
        }
      } else {
        const res = await registerUser(formData.firstName, formData.lastName, formData.email, formData.password);
        if (res.data.token) {
          clearLocalNotifications();
          notify.success('Account created!', 'Welcome to Havoc Security.');
          onLogin(res.data.user, res.data.token);
        } else {
          notify.error('Registration failed', res.data.error || 'Registration failed');
        }
      }
    } catch (err) {
      if (err.response) {
        // We received an explicit error from the server (e.g. 401 Unauthorized, 400 Bad Request)
        const title = isLogin ? 'Login Failed' : 'Registration Failed';
        const msg = err.response.data?.error || 'Please check your credentials and try again.';
        notify.error(title, msg);
      } else {
        // True network disconnected/timeout error
        notify.error('Network Error', err.message || 'Could not connect to the server. Please check your connection.');
      }
    }
  };

  return (
    <div className="auth-container">
      {/* Left side: video background + branding */}
      <div className="auth-left">
        <video
          ref={videoRef}
          className="auth-bg-video"
          autoPlay
          muted
          loop
          playsInline
        />
        <div className="auth-video-overlay" />
        <div className="auth-branding">
          <img src={logoImg} alt="Havoc Security" className="auth-logo" />
          <p className="auth-tagline">Havoc Security: Controlled Chaos<br />for Unbreakable Defences.</p>
        </div>
      </div>

      {/* Right side: form */}
      <div className="auth-right">
        {/* key changes on isLogin so React remounts the wrapper → CSS enter anim replays */}
        <div
          key={String(isLogin) + String(isAdminLogin)}
          className={`auth-form-wrapper ${animating ? 'form-exit' : 'form-enter'}`}
        >
          <h1 className="auth-title">
            {isAdminLogin ? 'Admin Portal' : (isLogin ? 'Welcome Back' : 'Create an Account')}
          </h1>
          <p className="auth-subtitle">
            {isAdminLogin ? 'Sign in with elevated credentials' : (isLogin ? 'Sign in to access your dashboard' : 'Join to monitor your Webstes and stay in Control!')}
          </p>

          <form onSubmit={handleSubmit} className="auth-form">
            {(!isLogin && !isAdminLogin) && (
              <div className="name-row">
                <div className="input-group">
                  <label>First Name</label>
                  <input type="text" name="firstName" placeholder="Maddison" value={formData.firstName} onChange={handleChange} required />
                </div>
                <div className="input-group">
                  <label>Last Name</label>
                  <input type="text" name="lastName" placeholder="Beer" value={formData.lastName} onChange={handleChange} required />
                </div>
              </div>
            )}

            <div className="input-group">
              <label>{isAdminLogin ? 'Admin Username' : 'Email'}</label>
              <input
                type={isAdminLogin ? "text" : "email"}
                name="email"
                placeholder={isAdminLogin ? "Username" : "business.maddison@gmail.com"}
                value={formData.email}
                onChange={handleChange}
                required
              />
            </div>

            <div className="input-group">
              <label>{isAdminLogin ? 'Admin Password' : 'Password'}</label>
              <div className="password-input">
                <input
                  type={showPassword ? "text" : "password"}
                  name="password"
                  placeholder="Enter your password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                  minLength={(!isLogin && !isAdminLogin) ? 8 : 4}
                />
                <span
                  className="eye-icon"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ cursor: 'pointer', userSelect: 'none', opacity: showPassword ? 1 : 0.6 }}
                >
                  👁️‍🗨️
                </span>
              </div>
              {(!isLogin && !isAdminLogin) && <span className="helper-text">Must be at least 8 characters</span>}
            </div>

            {/* inline error removed — now using react-hot-toast */}

            <button type="submit" className="auth-submit-btn">
              {isAdminLogin ? 'Admin Log In' : (isLogin ? 'Log In' : 'Create Account')}
            </button>
          </form>

          {!isAdminLogin && (
            <>
              <div className="auth-switch">
                {isLogin ? "Don't have an account? " : "Already have an account? "}
                <span role="button" onClick={handleSwitch} className="auth-link">
                  {isLogin ? 'Sign Up' : 'Log In'}
                </span>
              </div>

              <div className="auth-divider">
                <span>or</span>
              </div>

              <button className="oauth-btn google-btn">
                Sign in with Google
                <svg style={{ width: 18, marginLeft: 8 }} viewBox="0 0 48 48" fill="none">
                  <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
                  <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6C44.43 38.03 46.98 31.91 46.98 24.55z" />
                  <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
                  <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
                </svg>
              </button>
            </>
          )}

          <div style={{ marginTop: 24, textAlign: 'center', fontSize: '0.95rem', color: '#666' }}>
            {isAdminLogin ? (
              <span
                role="button"
                onClick={() => {
                  if (animating) return;
                  setAnimating(true);
                  setTimeout(() => { setIsAdminLogin(false); setAnimating(false); }, 220);
                }}
                style={{ color: '#ff3c5a', fontWeight: 600, cursor: 'pointer' }}
              >
                Return to standard login
              </span>
            ) : (
              <>
                Admin login?{' '}
                <span
                  role="button"
                  onClick={() => {
                    if (animating) return;
                    setAnimating(true);
                    setTimeout(() => { setIsAdminLogin(true); setIsLogin(true); setAnimating(false); }, 220);
                  }}
                  style={{ color: '#000', fontWeight: 600, cursor: 'pointer', borderBottom: '1px solid #ccc' }}
                >
                  Here
                </span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
