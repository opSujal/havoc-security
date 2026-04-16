import { useEffect, useState, useCallback } from 'react';
import { getScanHistory, downloadJson, downloadCsv, downloadHtml, triggerDownload } from '../api/api';
import './Reports.css';

export default function Reports() {
  const [history, setHistory] = useState([]);
  const [downloading, setDownloading] = useState(false);

  const load = useCallback(async () => {
    try { const r = await getScanHistory(); setHistory(r.data); } catch { /* no-op */ }
  }, []);

  // eslint-disable-next-line
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, [load]);

  const handleDownload = async (type) => {
    if (downloading) return;
    setDownloading(true);
    try {
      if (type === 'json') await triggerDownload(downloadJson(), 'havoc_report.json');
      else if (type === 'csv') await triggerDownload(downloadCsv(), 'havoc_report.csv');
      else await triggerDownload(downloadHtml(), 'havoc_report.html');
    } catch (err) {
      console.error('Failed to download report:', err);
      alert('Failed to download report. Check console for details.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="dashboard-grid fadein">
      <div className="card liquid-glass-strong">
        <div className="card-hd">
          <span className="card-title">📈 Scan History &amp; Reports</span>
        </div>
        <div className="card-body">
          {history.length === 0
            ? <div className="reports-empty">No scans recorded yet.</div>
            : <table className="vtable">
                <thead>
                  <tr>{['Target','Date','Vulns','Duration','Status'].map(h=><th key={h}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {[...history].reverse().map(h => (
                    <tr key={h.id}>
                      <td>{h.target}</td>
                      <td>{String(h.date).slice(0,19)}</td>
                      <td className="reports-vuln-count">{h.vulns_found}</td>
                      <td>{h.duration}s</td>
                      <td><span className="badge badge-done">Completed</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }

          <div style={{ height: 16 }} />
          <div className="reports-actions">
            <button 
              onClick={() => handleDownload('html')} 
              className="btn-primary reports-btn-pdf"
              disabled={downloading}
            >
              📄 {downloading ? 'Downloading...' : 'Export PDF Report'}
            </button>
            <button 
              onClick={() => handleDownload('json')} 
              className="btn-export"
              disabled={downloading}
            >
              📋 JSON
            </button>
            <button 
              onClick={() => handleDownload('csv')} 
              className="btn-export"
              disabled={downloading}
            >
              📊 CSV
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
