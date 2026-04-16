import { useEffect, useState, useCallback } from 'react';
import { getVulnerabilities, downloadJson, downloadCsv, downloadHtml, triggerDownload } from '../api/api';
import { FileText, FileJson, FileSpreadsheet, ShieldAlert } from 'lucide-react';
import bugIcon from '../assets/svgs/Bug.svg';
import bgImage from '../assets/bg.png';
import './Vulnerabilities.css';

const GRADIENT_TEXT = {
  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent',
  backgroundClip: 'text',
  color: 'transparent',
};

const SEV_STYLES = {
  Critical: { bg: 'rgba(220,38,38,0.15)', border: 'rgba(220,38,38,0.4)', text: '#f87171' },
  High: { bg: 'rgba(234,88,12,0.12)', border: 'rgba(234,88,12,0.35)', text: '#fb923c' },
  Medium: { bg: 'rgba(161,161,170,0.12)', border: 'rgba(161,161,170,0.3)', text: '#a1a1aa' },
  Low: { bg: 'rgba(59,130,246,0.10)', border: 'rgba(59,130,246,0.3)', text: '#60a5fa' },
  Info: { bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.15)', text: '#94a3b8' },
};

const STS_STYLES = {
  Open: { text: '#f87171', border: 'rgba(220,38,38,0.4)', bg: 'rgba(220,38,38,0.10)' },
  'In Progress': { text: '#fbbf24', border: 'rgba(251,191,36,0.4)', bg: 'rgba(251,191,36,0.10)' },
  Remediated: { text: '#4ade80', border: 'rgba(74,222,128,0.4)', bg: 'rgba(74,222,128,0.10)' },
};

function GlassBadge({ label, styles }) {
  const s = styles || { text: '#94a3b8', border: 'rgba(148,163,184,0.3)', bg: 'rgba(148,163,184,0.08)' };
  return (
    <span className="glass-badge" style={{ color: s.text, background: s.bg, border: `1px solid ${s.border}` }}>
      {label}
    </span>
  );
}

const HEADERS = ['CVE', 'Type', 'Severity', 'EPSS', 'Description', 'URL', 'Target', 'Status'];

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('All');
  const [downloading, setDownloading] = useState(false);

  const load = useCallback(async () => {
    try { const r = await getVulnerabilities(); setVulns(r.data); } catch { /* no-op */ }
  }, []);

  // eslint-disable-next-line
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  const handleDownload = async (type) => {
    if (downloading) return;
    setDownloading(true);
    try {
      if (type === 'json') await triggerDownload(downloadJson(), 'havoc_all_vulns.json');
      else if (type === 'csv') await triggerDownload(downloadCsv(), 'havoc_all_vulns.csv');
      else await triggerDownload(downloadHtml(), 'havoc_all_vulns.html');
    } catch (err) {
      console.error('Failed to download report:', err);
      alert('Failed to download report. Check console for details.');
    } finally {
      setDownloading(false);
    }
  };

  const filtered = vulns.filter(v => {
    const matchSev = sevFilter === 'All' || v.severity === sevFilter;
    const q = search.toLowerCase();
    const matchSearch = !q || [v.cve, v.type, v.severity, v.description, v.url, v.target, v.status]
      .some(f => (f || '').toLowerCase().includes(q));
    return matchSev && matchSearch;
  });

  return (
    <div className="dashboard-grid fadein vuln-page">
      {/* ── Header bar ── */}
      <div className="liquid-glass vuln-header">
        <div className="vuln-header-left">
          <div className="liquid-glass vuln-icon-circle">
            <img src={bugIcon} alt="Bug" />
          </div>
          <div>
            <div className="vuln-page-title">All Vulnerabilities</div>
            <div className="vuln-page-subtitle">
              {vulns.length} total findings · auto-refreshes every 5s
            </div>
          </div>
        </div>
        <div className="vuln-filters">
          {['All', 'Critical', 'High', 'Medium', 'Low', 'Info'].map(s => {
            const active = sevFilter === s;
            const sty = s !== 'All' ? SEV_STYLES[s] : null;
            return (
            <button
                key={s}
                onClick={() => setSevFilter(s)}
                className="vuln-filter-btn"
                style={{
                  border: active ? `1px solid ${sty?.border || 'rgba(255,255,255,0.3)'}` : '1px solid rgba(255,255,255,0.1)',
                  background: active ? (sty?.bg || 'rgba(255,255,255,0.08)') : 'transparent',
                  color: active ? (sty?.text || '#fff') : 'var(--text-50)',
                }}
              >{s}</button>
            );
          })}
          <div className="liquid-glass vuln-search-wrap">
            <input
              type="text"
              placeholder="Search…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="vuln-search-input"
            />
          </div>
        </div>
      </div>

      <div className="liquid-glass-strong vuln-table-card">
        <img src={bgImage} alt="" className="vuln-bg-img" />
        <div className="hide-scrollbar vuln-scroll">
          {filtered.length === 0 ? (
            <div className="vuln-empty">
              <ShieldAlert size={48} color="rgba(255,255,255,0.12)" strokeWidth={1} />
              <div className="vuln-empty-text">
                {vulns.length === 0 ? 'No vulnerabilities found. Run a scan to populate data.' : 'No results match your filter.'}
              </div>
            </div>
          ) : (
            <table className="vuln-table">
              <thead>
                <tr>
                  {HEADERS.map((h) => (
                    <th key={h} className="vuln-th">
                      <span className="vuln-th-text">{h}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(v => (
                  <tr key={v.id} className="vuln-tr">
                    <td className="vuln-td vuln-td-cve">{v.cve}</td>
                    <td className="vuln-td vuln-td-text">{v.type}</td>
                    <td className="vuln-td"><GlassBadge label={v.severity} styles={SEV_STYLES[v.severity]} /></td>
                    <td className="vuln-td vuln-td-epss">{(v.epss || 0).toFixed(3)}</td>
                    <td className="vuln-td vuln-td-desc">
                      {v.description ? (v.description.length > 70 ? v.description.slice(0, 70) + '…' : v.description) : '—'}
                    </td>
                    <td className="vuln-td vuln-td-url">{v.url || '—'}</td>
                    <td className="vuln-td vuln-td-text">{v.target}</td>
                    <td className="vuln-td"><GlassBadge label={v.status} styles={STS_STYLES[v.status]} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="liquid-glass vuln-export-strip">
        <span className="vuln-export-label">Export</span>
        <button 
          onClick={() => handleDownload('html')} 
          disabled={downloading}
          className="vuln-export-btn vuln-export-btn-primary"
          style={{ cursor: downloading ? 'not-allowed' : 'pointer', border: 'none', outline: 'none' }}
        >
          <FileText size={14} strokeWidth={1.5} /> {downloading ? '...' : 'PDF Report'}
        </button>
        <button 
          onClick={() => handleDownload('json')} 
          disabled={downloading}
          className="vuln-export-btn vuln-export-btn-secondary"
          style={{ cursor: downloading ? 'not-allowed' : 'pointer', border: 'none', outline: 'none' }}
        >
          <FileJson size={14} strokeWidth={1.5} /> JSON
        </button>
        <button 
          onClick={() => handleDownload('csv')} 
          disabled={downloading}
          className="vuln-export-btn vuln-export-btn-secondary"
          style={{ cursor: downloading ? 'not-allowed' : 'pointer', border: 'none', outline: 'none' }}
        >
          <FileSpreadsheet size={14} strokeWidth={1.5} /> CSV
        </button>
        <span className="vuln-count">Showing {filtered.length} of {vulns.length} vulnerabilities</span>
      </div>

    </div>
  );
}
