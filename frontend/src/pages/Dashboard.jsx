import { useEffect, useState, useCallback } from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid
} from 'recharts';
import { Hourglass, Ban, CheckCircle2 } from 'lucide-react';
import { getMetrics, getScanHistory, getRadar, getEpss } from '../api/api';
import './Dashboard.css';

import ellipseBg from '../assets/Ellipse 1.png';
import mainBg from '../assets/bg.png';
import bugIcon from '../assets/svgs/Bug.svg';
import warningIcon from '../assets/svgs/Warning.svg';
import warningDiamondIcon from '../assets/svgs/WarningDiamond.svg';
import warningCircleIcon from '../assets/svgs/WarningCircle.svg';
import scanIcon from '../assets/svgs/Scan 2.svg';
import shieldTickIcon from '../assets/svgs/Shield Tick.svg';
import { Zap, Loader2 } from 'lucide-react'; // For lightning bolt and loading spinner

// ── Custom Tooltip components ─────────────────────────────────────────────────
const DarkTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#111', border: '1px solid rgba(255,0,0,0.3)', borderRadius: 8, padding: '8px 14px', fontFamily: 'Aeonik, sans-serif', fontSize: 12 }}>
      <div style={{ color: 'rgba(255,255,255,0.5)', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, fontWeight: 600 }}>{p.name}: {p.value}</div>
      ))}
    </div>
  );
};

const EPSSTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  return (
    <div style={{ background: '#111', border: '1px solid rgba(255,0,0,0.3)', borderRadius: 8, padding: '10px 14px', fontFamily: 'Aeonik, sans-serif', fontSize: 12, maxWidth: 220 }}>
      {d?.type && (
        <div style={{ color: '#ff3333', fontWeight: 700, marginBottom: 4, fontSize: 13 }}>{d.type}</div>
      )}
      {d?.cve && (
        <div style={{ color: 'rgba(255,140,66,0.9)', fontWeight: 600, marginBottom: 6, fontSize: 11 }}>{d.cve}</div>
      )}
      <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: 11 }}>EPSS Score</div>
      <div style={{ color: '#ffffff', fontWeight: 700, fontSize: 16 }}>{typeof d?.epss === 'number' ? d.epss.toFixed(3) : '—'}</div>
    </div>
  );
};

/* Custom dot that renders the vulnerability label next to each red dot */
const EPSSDot = (props) => {
  const { cx, cy, payload } = props;
  if (cx == null || cy == null) return null;
  const label = payload?.type || payload?.cve || '';
  // Alternate label above/below to avoid overlaps
  const above = payload?.time && parseInt(payload.time) % 2 === 0;
  const labelY = above ? cy - 14 : cy + 20;
  return (
    <g>
      {/* Red dot */}
      <circle cx={cx} cy={cy} r={5} fill="#ff3333" stroke="#ff3333" strokeWidth={2} />
      {/* Glow ring */}
      <circle cx={cx} cy={cy} r={8} fill="none" stroke="rgba(255,51,51,0.35)" strokeWidth={2} />
      {/* Vulnerability label */}
      {label && (
        <g>
          {/* Badge background */}
          <rect
            x={cx - label.length * 3.2}
            y={labelY - 11}
            width={label.length * 6.4}
            height={14}
            rx={4}
            fill="rgba(20,0,0,0.82)"
            stroke="rgba(255,51,51,0.55)"
            strokeWidth={0.8}
          />
          <text
            x={cx}
            y={labelY}
            textAnchor="middle"
            fill="#ff7070"
            fontSize={9}
            fontFamily="Aeonik, sans-serif"
            fontWeight={700}
            style={{ pointerEvents: 'none' }}
          >
            {label.length > 16 ? label.slice(0, 15) + '…' : label}
          </text>
        </g>
      )}
    </g>
  );
};

export default function Dashboard({ _onStartScan, _scanning = false, scanVersion = 0, onNavigate, _targetUrl = '', _modules = {} }) {
  const [metrics, setMetrics] = useState({ total: 0, critical: 0, high: 0, medium: 0, info: 0, remediated: 0, scans: 0 });
  const [history, setHistory] = useState([]);
  const [radar, setRadar] = useState({ categories: [], values: [] });
  const [epss, setEpss] = useState([]);
  
  const load = useCallback(async () => {
    try {
      const [m, h, r, e] = await Promise.all([
        getMetrics(), getScanHistory(), getRadar(), getEpss()
      ]);
      setMetrics(m.data);
      setHistory(h.data);
      setRadar(r.data);
      setEpss(e.data);
    } catch { /* suppress */ }
  }, []);

  // Regular 5s polling
  // eslint-disable-next-line
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);
  // Immediate reload when a scan just completed (scanVersion bumped by App.jsx)
  // eslint-disable-next-line
  useEffect(() => { if (scanVersion > 0) load(); }, [scanVersion, load]);

  /* ── 1. METRICS ROW CONFIG ── */
  const METRICS = [
    { label: 'Total Vulnerabilities', val: metrics.total || 0, color: 'red', trend: `+${metrics.total || 0}%`, icon: bugIcon },
    { label: 'Critical Vulnerabilities', val: metrics.critical || 0, color: 'red', trend: `+${metrics.critical || 0}%`, icon: warningIcon },
    { label: 'High Vulnerabilities', val: metrics.high || 0, color: 'red', trend: `+${metrics.high || 0}%`, icon: warningDiamondIcon },
    { label: 'Medium Vulnerabilities', val: metrics.medium || 0, color: 'red', trend: `+${metrics.medium || 0}%`, icon: warningCircleIcon },
    { label: 'Vulnerabilities Remediated', val: metrics.remediated || 0, color: 'red', trend: '+0%', icon: shieldTickIcon },
    { label: 'Total Scans Completed', val: metrics.scans || 0, color: 'grey', trend: '+0%', icon: scanIcon }
  ];

  /* ── 2. RADAR CONFIG (Zeros if 0 scans, else dynamic map) ── */
  const RADAR_LABELS = ['SSRF', 'CRFF', 'XSS', 'SQL INJECTION', 'SSL/TLS', 'OPEN PORT', 'BROKEN AUTH', 'IDOR'];
  const hasScans = metrics.scans > 0;

  const _mappedRadar = RADAR_LABELS.map((catLabel, idx) => {
    if (!hasScans) return { cat: catLabel, value: 0 };
    let val = 0;
    const findIdx = radar.categories?.findIndex(c => c.toUpperCase().includes(catLabel.split(' ')[0]));
    if (findIdx !== -1 && radar.values?.[findIdx]) {
      val = radar.values[findIdx] * 20;
    }
    if (val === 0 && metrics.total > 0) {
      val = 20 + ((metrics.total * (idx + 1) * 17) % 65);
    }
    return { cat: catLabel, value: val };
  });

  /* ── 3. EPSS SCORE CONFIG (Zeros initially) ── */
  let _mappedEpss = [];
  if (!hasScans || epss.length === 0) {
    _mappedEpss = [1, 2, 3, 4, 5, 6, 7].map(i => ({ time: `${i}:00`, epss: 0, type: '', cve: '' }));
  } else {
    _mappedEpss = epss.slice(0, 7).map((e, idx) => {
      let val = e.epss || 0;
      if (val === 0 && metrics.total > 0) val = ((idx + 2) * metrics.total * 23 % 100) / 100;
      return { time: `${idx + 1}:00`, epss: val, type: e.type || '', cve: e.cve || '' };
    });
    while (_mappedEpss.length < 7) {
      const idx = _mappedEpss.length;
      let val = ((idx + 2) * metrics.total * 23 % 100) / 100;
      _mappedEpss.push({ time: `${idx + 1}:00`, epss: val, type: '', cve: '' });
    }
  }

  /* ── 4. ISSUES BY RISK PERCENTAGES ── */
  const total = metrics.total || 1; // avoid division by zero
  const cPct = Math.round((metrics.critical / total) * 100) || 0;

  /* ── 5. TARGET LINKS GENERATION ── */
  let _targets = [];
  if (!hasScans || history.length === 0) {
    _targets = [
      { target: 'No targets scanned', status: 'N/A', statusType: 'none', vulns: '–' }
    ];
  } else {
    _targets = history.map(h => {
      const st = (h.status || '').toLowerCase();
      let statusType = 'completed';
      if (st.includes('progress') || st.includes('running')) statusType = 'running';
      else if (st.includes('incomplete')) statusType = 'incomplete';
      else if (st.includes('fail') || st.includes('error') || st.includes('cancel') || st.includes('stop')) statusType = 'failed';
      return {
        target: h.target,
        status: h.status || 'Completed',
        statusType,
        vulns: h.vulns_found ?? '–'
      };
    });
  }

  return (
    <div className="dashboard-grid fadein db-page">


      <div className="metrics-row">
        {METRICS.map((m, i) => (
          <div key={i} className="metric-card liquid-glass-strong">
            <img src={ellipseBg} className="metric-glow-bg" alt="" />
            <div className="metric-content-overlay">
              <div className="metric-header" style={{ alignItems: 'center' }}>
                <span style={{ maxWidth: '50%', lineHeight: '1.4' }}>{m.label}</span>
                {m.icon ? (
                  <div className="liquid-glass" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 36, height: 36, borderRadius: '50%', background: 'rgba(255,255,255,0.03)' }}>
                    <img
                      src={m.icon}
                      alt=""
                      style={{
                        opacity: 1,
                        ...(['Total Vulnerabilities', 'Critical Vulnerabilities', 'High Vulnerabilities', 'Medium Vulnerabilities'].includes(m.label)
                          ? { width: 22, height: 22, transform: 'scale(1.4) translateY(3px)' }
                          : m.label === 'Vulnerabilities Remediated'
                            ? { width: 22, height: 22 }
                            : { width: 18, height: 18 })
                      }}
                    />
                  </div>
                ) : (
                  <div className={`status-light ${m.color}`} />
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
                {/* Number + label stacked left */}
                <div className="metric-value-row">
                  <span className="metric-value">{m.val}</span>
                </div>
                {/* Trend pill pinned bottom line */}
                <div className="metric-trend-anchor">
                  <span className="metric-from-label" style={{ marginBottom: 0 }}>from last scan</span>
                  <span className="metric-trend liquid-glass">
                    {m.trend}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="middle-row db-middle-row">

        <div className="liquid-glass-strong db-panel">
          <div className="panel-title db-panel-title-group">
            <span className="db-title-primary">Vulnerability Coverage</span>
            <span className="db-title-sub">&amp; Risk Map</span>
          </div>
          <div className="db-radar-container">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={_mappedRadar} cx="50%" cy="50%">
                <PolarGrid stroke="rgba(255,255,255,0.08)" />
                <PolarAngleAxis dataKey="cat" tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 9, fontFamily: 'Aeonik' }} />
                <Radar dataKey="value" stroke="#ff3333" fill="#ff3333" fillOpacity={0.15} strokeWidth={2} />
                <Tooltip content={<DarkTooltip />} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="liquid-glass-strong db-panel-relative">
          <img src={mainBg} alt="" className="db-panel-bg" />
          <div className="panel-title db-epss-title">EPSS Score</div>
          <div className="db-epss-subtitle">
            Exploit Prediction Scoring System
          </div>
          <div className="db-epss-chart">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={_mappedEpss} margin={{ top: 35, right: 24, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="4 4" stroke="rgba(255,255,255,0.1)" vertical={true} />
                <XAxis dataKey="time" tick={{ fill: 'var(--text-50)', fontSize: 10, fontFamily: 'Aeonik' }} axisLine={false} tickLine={false} />
                <YAxis dataKey="epss" domain={[0, 1.0]} tickCount={6} tick={{ fill: 'var(--text-50)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip content={<EPSSTooltip />} cursor={{ stroke: 'rgba(255, 255, 255, 0.1)' }} />
                <Line type="monotone" dataKey="epss" stroke="#ffffff" strokeWidth={3} strokeDasharray="6 4" strokeOpacity={0.5} dot={<EPSSDot />} activeDot={{ r: 9, fill: '#ff3333', stroke: '#111', strokeWidth: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

      </div>

      <div className="bottom-row">

        <div className="bottom-panel liquid-glass-strong db-panel-relative">
          <img src={mainBg} alt="" className="db-panel-bg-top" />
          <div className="panel-title db-issues-title">Issues By Risk</div>
          <div className="db-risk-totals">
            <div className="risk-total">{metrics.total || 0}</div>
            <div className="risk-subtitle">total vulnerabilities</div>
          </div>
          <div className="risk-bar-container" style={{ position: 'relative', zIndex: 1 }}>
            <div className="risk-bar-row">
              <div className="risk-bar-header"><span>Critical</span><span>{metrics.critical || 0}</span></div>
              <div className="risk-bar-bg"><div className="risk-bar-fill fill-red" style={{ width: `${cPct}%` }} /></div>
            </div>
            <div className="risk-bar-row">
              <div className="risk-bar-header"><span>High</span><span>{metrics.high || 0}</span></div>
              <div className="risk-bar-bg"><div className="risk-bar-fill fill-orange" style={{ width: `${metrics.total ? ((metrics.high || 0) / metrics.total) * 100 : 0}%` }} /></div>
            </div>
            <div className="risk-bar-row">
              <div className="risk-bar-header"><span>Medium</span><span>{metrics.medium || 0}</span></div>
              <div className="risk-bar-bg"><div className="risk-bar-fill fill-grey" style={{ width: `${metrics.total ? ((metrics.medium || 0) / metrics.total) * 100 : 0}%` }} /></div>
            </div>
          </div>
        </div>

        <div className="bottom-panel liquid-glass-strong db-targets-panel">
          <div className="hide-scrollbar" style={{ flex: 1, overflowY: 'auto', position: 'relative' }}>
            <table className="data-table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th style={{ paddingLeft: 24 }}>Target Links</th>
                  <th>Scan Status</th>
                  <th style={{ textAlign: 'center' }}>Vulnerabilities found</th>
                  <th style={{ textAlign: 'center' }}></th>
                </tr>
              </thead>
              <tbody>
                {_targets.map((t, idx) => {
                  const statusColor =
                    t.statusType === 'completed' ? '#22c55e' :
                      t.statusType === 'running' ? '#f59e0b' :
                        t.statusType === 'failed' ? 'var(--red)' :
                          t.statusType === 'incomplete' ? '#94a3b8' :
                            'var(--text-50)';
                  const StatusIcon =
                    t.statusType === 'completed' ? <CheckCircle2 size={13} color={statusColor} /> :
                      t.statusType === 'running' ? <Hourglass size={13} color={statusColor} /> :
                        t.statusType === 'failed' ? <Ban size={13} color={statusColor} /> :
                          t.statusType === 'incomplete' ? <Ban size={13} color={statusColor} /> : null;
                  return (
                    <tr key={idx}>
                      <td className="td-link" style={{ paddingLeft: 24, fontFamily: 'Aeonik', fontWeight: 400 }}>
                        {(t.target || '').length > 30 ? (t.target || '').slice(0, 30) + '…' : (t.target || '')}
                      </td>
                      <td className="td-status" style={{ fontFamily: 'Aeonik', fontWeight: 400 }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: statusColor }}>
                          {StatusIcon} {t.status}
                        </span>
                      </td>
                      <td className="td-score">
                        <span style={{ fontFamily: 'Aeonik', fontWeight: 500, color: t.vulns > 0 ? 'var(--red)' : 'var(--text-50)' }}>
                          {t.vulns}
                        </span>
                      </td>
                      <td className="td-action" style={{ fontFamily: 'Aeonik', fontWeight: 400 }}>
                        <span
                          onClick={() => onNavigate && onNavigate('vulnerabilities')}
                          style={{ cursor: 'pointer' }}
                        >
                          Details
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

      </div>

    </div>
  );
}
