import grid01     from '../assets/svgs/grid-01.svg';
import layout02   from '../assets/svgs/layout-02 side abr 2nd.svg';
import shieldPlus from '../assets/svgs/Shield Plus side bar 3rd.svg';
import iconSvg    from '../assets/svgs/Icon.svg';
import moon01     from '../assets/svgs/moon-01.svg';
import logout01   from '../assets/svgs/logout-01.svg';
import bgImage    from '../assets/bg.png';
import shieldStar from '../assets/svgs/ShieldStar.svg';
import { useLocation, useNavigate } from 'react-router-dom';

export default function Sidebar({ onLogout }) {
  const location = useLocation();
  const navigate = useNavigate();
  const NAV_ITEMS = [
    { id: 'dashboard',         icon: grid01,     label: 'Dashboard' },
    { id: 'cyber-intelligence',icon: shieldStar, label: 'Cyber Intelligence' },
    { id: 'vulnerabilities',   icon: layout02,   label: 'Vulnerabilities' },
    { id: 'remediation',       icon: shieldPlus, label: 'Remediation' },
    { id: 'settings',          icon: iconSvg,    label: 'Settings' },
    { id: 'theme',             icon: moon01,     label: 'Theme' },
    { id: 'logout',            icon: logout01,   label: 'Logout' },
  ];


  return (
    <aside className="sidebar liquid-glass" style={{
      overflow: 'hidden',
      position: 'relative',
      borderRadius: '40px'
    }}>
      {/* Background image */}
      <img
        src={bgImage}
        alt=""
        style={{
          position: 'absolute', inset: 0,
          width: '100%', height: '100%',
          objectFit: 'cover', zIndex: -1, opacity: 0.9,
          pointerEvents: 'none'
        }}
      />

      {/* Nav icons */}
      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', gap: '32px' }}>
        {NAV_ITEMS.map((item) => {
          const isActive = location.pathname.includes(item.id);
          return (
            <button
              key={item.id}
              className={`sidebar-icon-btn ${isActive ? 'active' : ''}`}
              onClick={() => {
                if (item.id === 'logout' && onLogout) onLogout();
                else if (item.id !== 'theme' && item.id !== 'logout') navigate(`/${item.id}`);
              }}
              title={item.label}
            >
              <img
                src={item.icon}
                alt={item.label}
                className="sidebar-icon"
                style={{
                  opacity: isActive ? 1 : 0.5,
                  transition: 'opacity 0.2s',
                  filter: isActive ? 'drop-shadow(0 0 6px rgba(255,255,255,0.9))' : 'none'
                }}
              />
            </button>
          )
        })}
      </div>
    </aside>
  );
}
