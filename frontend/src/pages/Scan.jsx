import { useState, useEffect, useCallback } from 'react';
import { startScan, getScanStatus, getVulnerabilities, downloadJson, downloadCsv, downloadHtml, triggerDownload } from '../api/api';
import './Scan.css';

const SEV_CLS = { Critical:'badge-crit', High:'badge-high', Medium:'badge-med', Low:'badge-low', Info:'badge-info' };
const STS_CLS = { Open:'badge-open', 'In Progress':'badge-progress', Remediated:'badge-done' };

function SevBadge({ s }) { return <span className={`badge ${SEV_CLS[s]||'badge-info'}`}>{s}</span>; }
function StsBadge({ s }) { return <span className={`badge ${STS_CLS[s]||'badge'}`}>{s}</span>; }

export default function Scan() {
  const [url,       setUrl]       = useState('');
  const [mode,      setMode]      = useState('quick');
  const [scanning,  setScanning]  = useState(false);
  const [progress,  setProgress]  = useState(0);
  const [phase,     setPhase]     = useState('');
  const [done,      setDone]      = useState(null);   // { vulns, dur } | null
  const [vulns,     setVulns]     = useState([]);
  const [downloading, setDownloading] = useState(false);

  /* Poll scan status while scanning */
  const poll = useCallback(async () => {
    try { const r = await getScanStatus();
      const d = r.data;
      setProgress(d.progress || 0);
      if (d.phases?.length) setPhase(d.phases[d.phases.length - 1]);
      if (d.status === 'completed') {
        setScanning(false);
        setDone({ vulns: d.vulns_found, dur: d.duration });
      } else if (d.status === 'error') {
        setScanning(false);
        setPhase(`❌ Error: ${d.error}`);
      }
    } catch { /* no-op */ }
  }, []);

  /* Load vuln table */
  const loadVulns = useCallback(async () => {
    try { const r = await getVulnerabilities(); setVulns(r.data); } catch { /* no-op */ }
  }, []);

  // eslint-disable-next-line
  useEffect(() => { loadVulns(); const t = setInterval(loadVulns, 5000); return () => clearInterval(t); }, [loadVulns]);

  useEffect(() => {
    if (!scanning) return;
    const t = setInterval(poll, 1000);
    return () => clearInterval(t);
  }, [scanning, poll]);

  const handleStart = async () => {
    if (!url.trim()) return;
    setDone(null); setProgress(0); setPhase(''); setScanning(true);
    try { await startScan(url.trim(), mode); } catch { setScanning(false); }
  };

  const handleDownload = async (type) => {
    if (downloading) return;
    setDownloading(true);
    try {
      if (type === 'json') await triggerDownload(downloadJson(), 'havoc_scan_report.json');
      else if (type === 'csv') await triggerDownload(downloadCsv(), 'havoc_scan_report.csv');
      else await triggerDownload(downloadHtml(), 'havoc_scan_report.html');
    } catch (err) {
      console.error('Failed to download report:', err);
      alert('Failed to download report. Check console for details.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="dashboard-grid fadein">
      {/* ── Scan control panel ── */}
      <div className="scan-panel liquid-glass-strong">
        <div className="scan-title">⚡ Launch New Scan</div>
        <input
          className="scan-input"
          type="text"
          placeholder="Enter target URL or IP  (e.g. example.com or 192.168.1.1)"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleStart()}
        />
        <div className="scan-row">
          <div className="radio-group">
            {[
              { val:'quick', label:'⚡ Quick Scan (Top 100 Ports)' },
              { val:'deep',  label:'🔬 Deep Scan (Top 1000 + OS Detect)' },
            ].map(({ val, label }) => (
              <label key={val} className="radio-label">
                <input type="radio" name="scan-mode" value={val}
                       checked={mode === val} onChange={() => setMode(val)} />
                {label}
              </label>
            ))}
          </div>
          <div className="scan-actions">
            <button className="btn-primary" onClick={handleStart} disabled={scanning}>
              {scanning ? '⏳ Scanning…' : '▶ Start Scan'}
            </button>
            <button onClick={() => handleDownload('html')} className="btn-export" disabled={downloading}>
              📄 {downloading ? '...' : 'PDF'}
            </button>
            <button onClick={() => handleDownload('json')} className="btn-export" disabled={downloading}>
              📋 JSON
            </button>
            <button onClick={() => handleDownload('csv')}  className="btn-export" disabled={downloading}>
              📊 CSV
            </button>
          </div>
        </div>

        {/* Progress area */}
        {scanning && (
          <div style={{ marginTop: 10 }}>
            <div style={{ fontSize: 12, color: 'var(--text-40)', marginBottom: 6 }}>
              {phase || 'Running…'}
            </div>
            <div className="prog-wrap">
              <div className="prog-fill" style={{ width: `${progress}%`, animation: progress < 100 ? undefined : 'none' }} />
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-40)', marginTop: 4 }}>{progress}%</div>
          </div>
        )}
        {done && (
          <div style={{ marginTop: 10, fontSize: 12, color: 'var(--success)' }}>
            ✅ Scan complete — {done.vulns} vulnerabilities found in {done.dur}s.
          </div>
        )}
        {!scanning && !done && phase.startsWith('❌') && (
          <div style={{ marginTop: 10, fontSize: 12, color: 'var(--red)' }}>{phase}</div>
        )}
      </div>

      {/* ── Vuln table ── */}
      <div className="card liquid-glass-strong">
        <div className="card-hd" style={{ paddingBottom: 12 }}>
          <span className="card-title">Discovered Vulnerabilities</span>
        </div>
        <div className="card-body scan-table-inner">
          {vulns.length === 0
            ? <div className="scan-empty-table">
                No vulnerabilities found. Run a scan to populate data.
              </div>
            : <table className="vtable">
                <thead>
                  <tr>{['CVE','Type','Severity','EPSS','Description','URL','Target','Status']
                        .map(h=><th key={h}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {vulns.map(v => (
                    <tr key={v.id}>
                      <td><b style={{ color: 'var(--red)' }}>{v.cve}</b></td>
                      <td>{v.type}</td>
                      <td><SevBadge s={v.severity} /></td>
                      <td>{(v.epss||0).toFixed(3)}</td>
                      <td>{v.description ? (v.description.length>50 ? v.description.slice(0,50)+'…' : v.description) : ''}</td>
                      <td>{v.url}</td>
                      <td>{v.target}</td>
                      <td><StsBadge s={v.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </div>
      </div>
    </div>
  );
}
