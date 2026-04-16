import { useEffect, useState, useCallback, useRef } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Cell, LabelList,
  PieChart, Pie,
} from 'recharts';
import { getMetrics, getVulnerabilities, getScanHistory, getRadar } from '../api/api';
import './CyberIntelligence.css';

// ── Security Posture Ring (SVG segmented ring) ────────────────────────────────
function SecurityPostureRing({ score = 0, maxScore = 100 }) {
  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const radius = 78;
  const strokeW = 10;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(score / maxScore, 1);
  const offset = circumference * (1 - pct);

  // Color by score range
  const color =
    score >= 75 ? '#00e5a0' :
    score >= 50 ? '#f0c040' :
    score >= 25 ? '#ff8c42' : '#ff3c5a';

  const label =
    score >= 75 ? 'Secure' :
    score >= 50 ? 'Moderate' :
    score >= 25 ? 'At Risk' : 'Critical';

  // Segment ticks (every 25%)
  const segmentAngles = [0, 90, 180, 270];

  return (
    <div className="ci-posture-ring-wrapper">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="ci-posture-svg">
        <defs>
          <filter id="ringGlow">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="1" />
            <stop offset="100%" stopColor={color} stopOpacity="0.5" />
          </linearGradient>
        </defs>

        {/* Background track */}
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={strokeW}
        />

        {/* Segment tick marks */}
        {segmentAngles.map((angle, i) => {
          const rad = (angle - 90) * (Math.PI / 180);
          const innerR = radius - strokeW / 2 - 4;
          const outerR = radius + strokeW / 2 + 4;
          const x1 = cx + innerR * Math.cos(rad);
          const y1 = cy + innerR * Math.sin(rad);
          const x2 = cx + outerR * Math.cos(rad);
          const y2 = cy + outerR * Math.sin(rad);
          return (
            <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="rgba(255,255,255,0.12)" strokeWidth={1.5} />
          );
        })}

        {/* Filled arc */}
        <circle
          cx={cx} cy={cy} r={radius}
          fill="none"
          stroke="url(#ringGrad)"
          strokeWidth={strokeW}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ filter: 'url(#ringGlow)', transition: 'stroke-dashoffset 1s ease' }}
        />

        {/* Inner subtle ring */}
        <circle cx={cx} cy={cy} r={radius - 18} fill="none"
          stroke="rgba(255,255,255,0.04)" strokeWidth={1} />
        <circle cx={cx} cy={cy} r={radius + 16} fill="none"
          stroke="rgba(255,255,255,0.03)" strokeWidth={1} />

        {/* Center score */}
        <text x={cx} y={cy - 6} textAnchor="middle" dominantBaseline="central"
          fontSize={42} fontWeight={700} fill={color}
          fontFamily="'SF Mono', 'Menlo', 'Monaco', monospace"
          style={{ filter: `drop-shadow(0 0 12px ${color}55)` }}
        >
          {score}
        </text>
        <text x={cx} y={cy + 24} textAnchor="middle" dominantBaseline="central"
          fontSize={11} fill="rgba(255,255,255,0.45)"
          fontFamily="Aeonik, Inter, sans-serif" letterSpacing="2"
          textTransform="uppercase"
        >
          {label.toUpperCase()}
        </text>
      </svg>
      {/* Pulsing outer glow */}
      <div className="ci-posture-glow" style={{ boxShadow: `0 0 60px ${color}25, 0 0 120px ${color}10` }} />
    </div>
  );
}

// ── Severity colour map ───────────────────────────────────────────────────────
const SEV_DOT_COLORS = { Critical: '#ff3c5a', High: '#ff8c42', Medium: '#f0c040', Low: '#00e5a0' };

// ── Custom bar label: shows top vuln name above the tallest bar in a session ──
function CveBarTopLabel(props) {
  const { x, y, width, value, index, data, dataKey } = props;
  if (!value) return null;
  const d = data?.[index] || {};
  const dominant = Object.entries({
    Critical: d.Critical || 0, High: d.High || 0, Medium: d.Medium || 0, Low: d.Low || 0,
  }).sort((a, b) => b[1] - a[1])[0]?.[0];
  if (dataKey !== dominant) return null;
  const name = (d._topVulns || [])[0] || '';
  if (!name) return null;
  const color = SEV_DOT_COLORS[dominant] || '#ff3c5a';
  const short = name.length > 20 ? name.slice(0, 19) + '…' : name;
  const bw = short.length * 6.2;
  const bx = x + width / 2 - bw / 2;
  const by = y - 24;
  return (
    <g>
      <rect x={bx} y={by} width={bw} height={16} rx={4}
        fill="rgba(10,0,0,0.88)" stroke={`${color}99`} strokeWidth={0.8} />
      <text x={x + width / 2} y={by + 11} textAnchor="middle"
        fill={color} fontSize={9} fontFamily="Aeonik, sans-serif" fontWeight={700}
        style={{ pointerEvents: 'none' }}>
        {short}
      </text>
    </g>
  );
}

// ── CVE Trend custom tooltip — lists actual vuln names per session ────────────
const CveTrendTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload || {};
  const topVulns = d._topVulns || [];
  return (
    <div style={{ background: '#0d0d0d', border: '1px solid rgba(255,60,90,0.3)', borderRadius: 10, padding: '10px 14px', fontFamily: 'Aeonik, sans-serif', fontSize: 12, minWidth: 180 }}>
      <div style={{ color: 'rgba(255,255,255,0.5)', marginBottom: 6, fontSize: 11 }}>{label}</div>
      {topVulns.length > 0 ? (
        topVulns.slice(0, 5).map((name, i) => (
          <div key={i} style={{ color: '#ff7070', fontWeight: 600, fontSize: 11, marginBottom: 3, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ff3c5a', flexShrink: 0, display: 'inline-block' }} />
            {name}
          </div>
        ))
      ) : (
        <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: 11 }}>No named vulnerabilities</div>
      )}
      <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', marginTop: 8, paddingTop: 6 }}>
        {['Critical','High','Medium','Low'].map(s => d[s] > 0 && (
          <div key={s} style={{ color: SEV_DOT_COLORS[s], fontSize: 10, display: 'flex', justifyContent: 'space-between', gap: 16 }}>
            <span>{s}</span><span style={{ fontWeight: 700 }}>{d[s]}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

// ── Horizontal Bar Row ─────────────────────────────────────────────────────────
function AttackVectorBar({ label, value, maxVal, color, delay = 0 }) {
  const pct = maxVal > 0 ? (value / maxVal) * 100 : 0;
  return (
    <div className="ci-av-bar-row">
      <span className="ci-av-bar-label">{label}</span>
      <div className="ci-av-bar-track">
        <div
          className="ci-av-bar-fill"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
            boxShadow: `0 0 12px ${color}33`,
            animationDelay: `${delay}ms`,
          }}
        />
      </div>
      <span className="ci-av-bar-count ci-data-mono">{value}</span>
    </div>
  );
}

// ── Heatmap cell component ─────────────────────────────────────────────────────
function HeatmapCell({ value, maxVal }) {
  const intensity = maxVal > 0 ? value / maxVal : 0;
  const alpha = 0.08 + intensity * 0.85;
  const bg = value === 0
    ? 'rgba(255,255,255,0.03)'
    : `rgba(255, ${Math.round(30 + (1 - intensity) * 50)}, ${Math.round(30 * (1 - intensity))}, ${alpha})`;
  return (
    <div className="ci-hmap-cell ci-data-mono" style={{
      background: bg,
      border: '1px solid rgba(255,255,255,0.06)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontSize: 10,
      color: value === 0 ? 'rgba(255,255,255,0.15)' : `rgba(255,${Math.round(200*(1-intensity))},${Math.round(100*(1-intensity))},0.9)`,
      fontFamily: 'Aeonik, sans-serif',
      fontWeight: 600,
      minHeight: 36,
      cursor: 'default',
    }}>
      {value > 0 ? value : ''}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────
export default function CyberIntelligence() {
  const [metrics,  setMetrics]  = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0, scans: 0 });
  const [vulns,    setVulns]    = useState([]);
  const [history,  setHistory]  = useState([]);
  const [radar,    setRadar]    = useState({ categories: [], values: [] });
  const [threats,  setThreats]  = useState([]);
  const feedRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const [m, v, h, r] = await Promise.all([
        getMetrics(), getVulnerabilities(), getScanHistory(), getRadar()
      ]);
      setMetrics(m.data);
      setVulns(v.data);
      setHistory(h.data);
      setRadar(r.data);

      // Build live threat feed from recent vulns
      const feed = (v.data || [])
        .filter(x => x.severity === 'Critical' || x.severity === 'High')
        .slice(0, 30)
        .map(x => ({
          id: x.id,
          time: x.discovered_date ? new Date(x.discovered_date).toLocaleTimeString() : 'Recent',
          type: x.type || 'Unknown',
          target: x.target || '—',
          severity: x.severity,
          cve: x.cve || '',
        }));
      setThreats(feed);
    } catch { /* suppress */ }
  }, []);

  // eslint-disable-next-line
  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, [load]);

  // ── Security Posture Score (0–100, higher = safer) ────────────────────────
  const postureScore = Math.max(0, Math.min(100,
    metrics.total === 0 ? 100
    : Math.round(100 - (metrics.critical * 10 + metrics.high * 5 + metrics.medium * 2) / Math.max(1, metrics.total) * 10)
  ));

  // ── CVE Discovery Trend (per scan session) ────────────────────────────────
  const cveData = history.slice().reverse().map((h, i) => ({
    session: `Scan ${i + 1}`,
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    _target: h.target,
    _total: h.vulns_found || 0,
    _topVulns: [],   // actual vuln names for this session
  }));

  // Distribute vulns by severity + collect top names per scan session
  vulns.forEach(v => {
    const idx = cveData.findIndex(d => d._target === v.target);
    if (idx !== -1 && v.severity) {
      const s = v.severity;
      if (cveData[idx][s] !== undefined) cveData[idx][s]++;
      // Collect unique vuln type names (prioritise Critical/High)
      const name = v.type || '';
      if (name && !cveData[idx]._topVulns.includes(name)) {
        if (s === 'Critical' || s === 'High') {
          cveData[idx]._topVulns.unshift(name); // highest severity at top
        } else {
          cveData[idx]._topVulns.push(name);
        }
      }
    }
  });
  // Deduplicate
  cveData.forEach(d => { d._topVulns = [...new Set(d._topVulns)]; });

  // ── Attack Vector Breakdown (horizontal bars) ──────────────────────────────
  const ATTACK_CATEGORIES = [
    { label: 'SQL Injection', key: 'sql',   color: '#ff3c5a' },
    { label: 'XSS',          key: 'xss',   color: '#ff6b6b' },
    { label: 'CSRF',         key: 'csrf',  color: '#ff8c42' },
    { label: 'SSRF',         key: 'ssrf',  color: '#ffa94d' },
    { label: 'IDOR',         key: 'idor',  color: '#f0c040' },
    { label: 'Broken Auth',  key: 'auth',  color: '#fab005' },
    { label: 'Open Port',    key: 'port',  color: '#51cf66' },
    { label: 'SSL/TLS',      key: 'ssl',   color: '#00e5a0' },
  ];

  const attackData = ATTACK_CATEGORIES.map((cat) => {
    const apiIdx = (radar.categories || []).findIndex(c =>
      c.toLowerCase().includes(cat.key.toLowerCase())
    );
    const val = apiIdx !== -1 ? (radar.values?.[apiIdx] || 0) : 0;
    // count from actual vulns as fallback
    const vulnCount = vulns.filter(v => (v.type || '').toLowerCase().includes(cat.key)).length;
    return { ...cat, value: val || vulnCount };
  });

  const maxAttack = Math.max(1, ...attackData.map(d => d.value));

  // ── Vulnerability Heatmap  ─────────────────────────────────────────────────
  const HMAP_ROWS = ['Critical', 'High', 'Medium', 'Low'];
  const HMAP_COLS_LABELS = ['SQL-I', 'XSS', 'SSRF', 'Auth', 'Port', 'SSL', 'IDOR', 'CORS'];
  const HMAP_CATS = ['sql', 'xss', 'ssrf', 'auth', 'port', 'ssl', 'idor', 'cors'];

  const heatmap = HMAP_ROWS.map(sev => {
    return HMAP_CATS.map(cat => {
      const count = vulns.filter(v =>
        (v.severity || '').toLowerCase() === sev.toLowerCase() &&
        (v.type || '').toLowerCase().includes(cat)
      ).length;
      // fallback: distribute evenly if no real data but scans exist
      if (count === 0 && metrics.total > 0) {
        const base = sev === 'Critical' ? metrics.critical :
                     sev === 'High'     ? metrics.high :
                     sev === 'Medium'   ? metrics.medium : (metrics.low || 0);
        return Math.floor(base / HMAP_CATS.length + Math.random() * 2);
      }
      return count;
    });
  });

  const hmapMax = Math.max(1, ...heatmap.flat());

  // ── Severity label colors ──────────────────────────────────────────────────
  const SEV_COLOR = {
    Critical: '#ff3c5a',
    High:     '#ff8c42',
    Medium:   '#f0c040',
    Low:      '#00e5a0',
    Info:     '#2ab4e0',
  };

  return (
    <div className="ci-page fadein" style={{
      display: 'flex',
      flexDirection: 'column',
      gap: 20,
      paddingBottom: 24,
    }}>

      {/* ── PAGE HEADER ── */}
      <div className="ci-header">
        <span className="ci-header-label">Cyber Intelligence</span>
        <span className="ci-header-live">LIVE — updated every 8s</span>
      </div>

      <div className="ci-dashboard-grid">

        {/* ── SECURITY POSTURE (Ring HUD) ── */}
        <div className="ci-panel ci-tile-posture liquid-glass-strong">
          <div className="ci-panel-header">
            <div className="ci-panel-dot" style={{ background: '#00e5a0', boxShadow: '0 0 8px #00e5a0' }} />
            <span className="ci-panel-title">Security Posture</span>
            <span className="ci-panel-sub" style={{ marginLeft: 'auto' }}>Overall threat score</span>
          </div>
          <div className="ci-gauge-area">
            <SecurityPostureRing score={postureScore} />
          </div>
          {/* Mini stats row below the ring */}
          <div className="ci-posture-stats">
            <div className="ci-posture-stat">
              <span className="ci-posture-stat-val" style={{ color: '#ff3c5a' }}>{metrics.critical}</span>
              <span className="ci-posture-stat-label">Critical</span>
            </div>
            <div className="ci-posture-stat">
              <span className="ci-posture-stat-val" style={{ color: '#ff8c42' }}>{metrics.high}</span>
              <span className="ci-posture-stat-label">High</span>
            </div>
            <div className="ci-posture-stat">
              <span className="ci-posture-stat-val" style={{ color: '#f0c040' }}>{metrics.medium}</span>
              <span className="ci-posture-stat-label">Medium</span>
            </div>
            <div className="ci-posture-stat">
              <span className="ci-posture-stat-val" style={{ color: '#00e5a0' }}>{metrics.low || 0}</span>
              <span className="ci-posture-stat-label">Low</span>
            </div>
          </div>
        </div>

        {/* ── CVE DISCOVERY TREND (Line chart with named vuln dots) ── */}
        <div className="ci-panel ci-tile-trend liquid-glass-strong">
          <div className="ci-panel-header">
            <div className="ci-panel-dot" style={{ background: '#ff8c42', boxShadow: '0 0 8px #ff8c42' }} />
            <span className="ci-panel-title">CVE Discovery Trend</span>
            <span className="ci-panel-sub" style={{ marginLeft: 'auto' }}>Per scan session</span>
          </div>
          <div className="ci-chart-area">
            {cveData.length === 0 ? (
              <div className="ci-empty">No scan data — run a scan to populate.</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={cveData} margin={{ top: 40, right: 16, left: -20, bottom: 0 }} barCategoryGap="28%" barGap={3}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="session" tick={{ fill: 'rgba(255,255,255,0.35)', fontSize: 10, fontFamily: 'Aeonik' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CveTrendTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  {['Critical','High','Medium','Low'].map((sev) => (
                    <Bar key={sev} dataKey={sev} fill={SEV_DOT_COLORS[sev]} radius={[4,4,0,0]}
                      maxBarSize={28} opacity={0.92}>
                      <LabelList content={<CveBarTopLabel data={cveData} dataKey={sev} />} />
                    </Bar>
                  ))}
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ── ATTACK VECTOR BREAKDOWN (Premium Donut Chart) ── */}
        <div className="ci-panel ci-tile-vector liquid-glass-strong">
          <div className="ci-panel-header" style={{ marginBottom: 'auto' }}>
            <div className="ci-panel-dot" style={{ background: '#ff3c5a', boxShadow: '0 0 8px #ff3c5a' }} />
            <span className="ci-panel-title">Attack Vector Breakdown</span>
            <span className="ci-panel-sub" style={{ marginLeft: 'auto' }}>By frequency</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
            {/* Donut chart */}
            <div style={{ position: 'relative', width: '100%', maxWidth: 260, marginTop: 10 }}>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <defs>
                    {attackData.map((d, i) => (
                      <filter key={i} id={`pie-glow-${i}`}>
                        <feGaussianBlur stdDeviation="4" result="blur" />
                        <feComposite in="SourceGraphic" in2="blur" operator="over" />
                      </filter>
                    ))}
                  </defs>
                  <Pie
                    data={attackData.map(d => ({ ...d, value: Math.max(d.value, 0.01) }))}
                    cx="50%" cy="50%"
                    innerRadius={70} outerRadius={95}
                    paddingAngle={4}
                    cornerRadius={8}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {attackData.map((d, i) => (
                      <Cell
                        key={i}
                        fill={d.value > 0 ? d.color : 'rgba(255,255,255,0.03)'}
                        opacity={d.value > 0 ? 0.95 : 0.6}
                        style={{ filter: d.value > 0 ? `drop-shadow(0 0 8px ${d.color}66)` : 'none', cursor: 'pointer', transition: 'all 0.3s ease' }}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    cursor={false}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const d = payload[0]?.payload;
                      if (!d) return null;
                      const realVal = attackData.find(a => a.label === d.label)?.value || 0;
                      return (
                        <div style={{ background: 'rgba(10,10,10,0.95)', backdropFilter: 'blur(10px)', border: `1px solid ${d.color}44`, borderRadius: 12, padding: '10px 16px', fontFamily: 'Aeonik, sans-serif', fontSize: 12, boxShadow: `0 8px 24px rgba(0,0,0,0.5), 0 0 12px ${d.color}33` }}>
                          <div style={{ color: d.color, fontWeight: 700, letterSpacing: 0.5 }}>{d.label}</div>
                          <div style={{ color: 'rgba(255,255,255,0.6)', fontSize: 11, marginTop: 4 }}>Findings: <span style={{ color: '#fff', fontWeight: 700, fontSize: 12 }}>{realVal}</span></div>
                        </div>
                      );
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Center label */}
              <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', pointerEvents: 'none' }}>
                <div className="ci-data-mono" style={{ 
                  fontSize: 34, 
                  fontWeight: 800, 
                  lineHeight: 1,
                  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  filter: 'drop-shadow(0 4px 12px rgba(255,255,255,0.15))'
                }}>
                  {attackData.reduce((s, d) => s + d.value, 0)}
                </div>
                <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.3)', fontFamily: 'Aeonik, sans-serif', letterSpacing: 2, marginTop: 6, textTransform: 'uppercase', fontWeight: 600 }}>Findings</div>
              </div>
            </div>
            {/* Premium Legend grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, padding: '0 16px', width: '100%' }}>
              {attackData.map(d => (
                <div key={d.label} style={{ 
                  display: 'flex', alignItems: 'center', gap: 10, 
                  padding: '8px 12px', 
                  borderRadius: 10, 
                  background: d.value > 0 ? `linear-gradient(90deg, ${d.color}11, transparent)` : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${d.value > 0 ? `${d.color}22` : 'rgba(255,255,255,0.03)'}`,
                  opacity: d.value > 0 ? 1 : 0.4 
                }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: d.value > 0 ? d.color : 'rgba(255,255,255,0.2)', flexShrink: 0, boxShadow: d.value > 0 ? `0 0 8px ${d.color}` : 'none' }} />
                  <span style={{ fontSize: 11, color: d.value > 0 ? 'rgba(255,255,255,0.9)' : 'rgba(255,255,255,0.4)', fontFamily: 'Aeonik, sans-serif', fontWeight: 500, flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{d.label}</span>
                  <span className="ci-data-mono" style={{ fontSize: 12, fontWeight: 700, color: d.value > 0 ? d.color : 'rgba(255,255,255,0.3)' }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── LIVE THREAT FEED ── */}
        <div className="ci-panel-compact ci-tile-feed liquid-glass-strong">
          <div className="ci-panel-header ci-feed-header">
            <div className="ci-panel-dot" style={{
              background: threats.length > 0 ? '#ff3c5a' : 'rgba(255,255,255,0.2)',
              boxShadow: threats.length > 0 ? '0 0 8px #ff3c5a' : 'none',
              animation: threats.length > 0 ? 'pulseDot 1.5s ease-in-out infinite' : 'none',
            }} />
            <span className="ci-panel-title">Live Threat Feed</span>
            <span className="ci-panel-sub" style={{ marginLeft: 'auto' }}>Real-time scan events &amp; alerts</span>
          </div>
          <div ref={feedRef} className="hide-scrollbar ci-feed-scroll">
            {threats.length === 0 ? (
              <div className="ci-empty">No active threats — run a scan to populate.</div>
            ) : (
              <div className="ci-feed-list">
                {threats.map((t, i) => (
                  <div key={t.id || i} className="ci-threat-item"
                    style={{
                      border: `1px solid ${SEV_COLOR[t.severity] || '#ff3c5a'}22`,
                      borderLeft: `3px solid ${SEV_COLOR[t.severity] || '#ff3c5a'}`,
                    }}
                  >
                    <div className="ci-threat-dot"
                      style={{ background: SEV_COLOR[t.severity] || '#ff3c5a', boxShadow: `0 0 6px ${SEV_COLOR[t.severity] || '#ff3c5a'}` }}
                    />
                    <div className="ci-threat-body">
                      <div className="ci-threat-top">
                        <span className="ci-threat-type">{t.type}</span>
                        <span className="ci-threat-sev-badge"
                          style={{ color: SEV_COLOR[t.severity], background: `${SEV_COLOR[t.severity]}18` }}
                        >{t.severity}</span>
                      </div>
                      <div className="ci-threat-meta">
                        {t.target} {t.cve && <span className="ci-threat-cve ci-data-mono">· {t.cve}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── VULNERABILITY HEATMAP ── */}
        <div className="ci-panel-padded ci-tile-heatmap liquid-glass-strong">
          <div className="ci-panel-header" style={{ marginBottom: 16 }}>
            <div className="ci-panel-dot" style={{ background: '#ff3c5a', boxShadow: '0 0 8px #ff3c5a' }} />
            <span className="ci-panel-title">Vulnerability Heatmap</span>
            <span className="ci-panel-sub" style={{ marginLeft: 'auto' }}>Severity × attack surface density</span>
          </div>
          <div className="ci-hmap-grid">
            <div className="ci-hmap-header-row">
              <div />
              {HMAP_COLS_LABELS.map(col => (
                <div key={col} className="ci-hmap-col-label">{col}</div>
              ))}
            </div>
            {HMAP_ROWS.map((sev, ri) => (
              <div key={sev} className="ci-hmap-data-row">
                <div className="ci-hmap-row-label" style={{ color: SEV_COLOR[sev] }}>{sev}</div>
                {heatmap[ri].map((val, ci) => (
                  <HeatmapCell key={ci} value={val} maxVal={hmapMax} />
                ))}
              </div>
            ))}
            <div className="ci-hmap-legend">
              <span className="ci-hmap-legend-label">Low</span>
              <div className="ci-hmap-legend-bar" />
              <span className="ci-hmap-legend-label">High</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
