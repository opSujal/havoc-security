import { useEffect, useState, useCallback } from 'react';
import { getVulnerabilities, getAISolution } from '../api/api';
import { Sparkles, ChevronDown, ShieldAlert, Zap, Copy, Check, BookOpen, AlertTriangle, Code2, Activity, ListChecks, FlaskConical } from 'lucide-react';
import brainIcon from '../assets/svgs/Brain.svg';
import bgImage from '../assets/bg.png';
import './AIRemediation.css';

const GRADIENT_TEXT = {
  background: 'linear-gradient(180deg, #ffffff 0%, rgba(255,255,255,0.5) 100%)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  backgroundClip: 'text', color: 'transparent',
};
const SUBTLE_GRADIENT = {
  background: 'linear-gradient(180deg, rgba(255,255,255,0.6) 0%, rgba(255,255,255,0.22) 100%)',
  WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
  backgroundClip: 'text', color: 'transparent',
};
const SEV_STYLES = {
  Critical: { bg: 'rgba(220,38,38,0.15)', border: 'rgba(220,38,38,0.4)', text: '#f87171' },
  High:     { bg: 'rgba(234,88,12,0.12)',  border: 'rgba(234,88,12,0.35)',  text: '#fb923c' },
  Medium:   { bg: 'rgba(234,179,8,0.1)',   border: 'rgba(234,179,8,0.3)',   text: '#fbbf24' },
  Low:      { bg: 'rgba(34,197,94,0.1)',   border: 'rgba(34,197,94,0.3)',   text: '#4ade80' },
  Info:     { bg: 'rgba(255,255,255,0.05)',border: 'rgba(255,255,255,0.12)',text: '#94a3b8' },
};
const LANG_COLORS = {
  python: '#3b82f6', javascript: '#f59e0b', jsx: '#06b6d4',
  php: '#8b5cf6', nginx: '#10b981', apache: '#ef4444',
  text: '#94a3b8', django: '#10b981', sql: '#f97316',
};

function GlassBadge({ label, styles }) {
  const s = styles || SEV_STYLES.Info;
  return (
    <span className="glass-badge" style={{ color: s.text, background: s.bg, border: `1px solid ${s.border}` }}>
      {label}
    </span>
  );
}

function MetaField({ label, children }) {
  return (
    <div className="ai-meta-field">
      <div className="ai-meta-label">{label}</div>
      <div className="ai-meta-value">{children}</div>
    </div>
  );
}

function SpinnerDots() {
  return (
    <div className="ai-spinner">
      <div className="ai-spinner-dots">
        {[0, 1, 2].map(i => (
          <div key={i} className="ai-spinner-dot"
            style={{ animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite` }} />
        ))}
      </div>
      <span className="ai-spinner-text">Loading exact patches…</span>
      <style>{`@keyframes pulse { 0%,80%,100%{transform:scale(0.6);opacity:0.4} 40%{transform:scale(1);opacity:1} }`}</style>
    </div>
  );
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const doCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button onClick={doCopy} style={{
      display: 'flex', alignItems: 'center', gap: 5,
      background: copied ? 'rgba(74,222,128,0.12)' : 'rgba(255,255,255,0.06)',
      border: `1px solid ${copied ? 'rgba(74,222,128,0.3)' : 'rgba(255,255,255,0.12)'}`,
      borderRadius: 8, padding: '5px 11px', cursor: 'pointer',
      color: copied ? '#4ade80' : 'rgba(255,255,255,0.5)',
      fontFamily: "'Aeonik', sans-serif", fontSize: 11, fontWeight: 400,
      transition: 'all 0.2s',
    }}>
      {copied ? <Check size={12} strokeWidth={2} /> : <Copy size={12} strokeWidth={1.5} />}
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

function CodeBlock({ code, lang, variant }) {
  const isVuln = variant === 'before';
  const langColor = LANG_COLORS[lang] || '#94a3b8';
  return (
    <div style={{
      background: isVuln ? 'rgba(220,38,38,0.06)' : 'rgba(34,197,94,0.05)',
      border: `1px solid ${isVuln ? 'rgba(220,38,38,0.18)' : 'rgba(74,222,128,0.18)'}`,
      borderRadius: 14, overflow: 'hidden', marginBottom: 8,
    }}>
      {/* Code header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 14px',
        background: isVuln ? 'rgba(220,38,38,0.08)' : 'rgba(34,197,94,0.07)',
        borderBottom: `1px solid ${isVuln ? 'rgba(220,38,38,0.12)' : 'rgba(74,222,128,0.12)'}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontFamily: "'Aeonik', sans-serif", fontSize: 10, fontWeight: 500,
            color: isVuln ? '#f87171' : '#4ade80', letterSpacing: '0.5px', textTransform: 'uppercase',
          }}>
            {isVuln ? '❌ VULNERABLE' : '✅ FIXED'}
          </span>
          <span style={{
            background: langColor + '22', border: `1px solid ${langColor}44`,
            color: langColor, borderRadius: 5, padding: '1px 7px',
            fontFamily: 'monospace', fontSize: 10, fontWeight: 600,
          }}>{lang || 'code'}</span>
        </div>
        <CopyButton text={code} />
      </div>
      {/* Code body */}
      <pre style={{
        margin: 0, padding: '14px 16px',
        fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
        fontSize: 12.5, lineHeight: 1.75,
        color: 'rgba(255,255,255,0.82)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
        overflowX: 'auto',
      }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

function PatchPanel({ patchData }) {
  const tabs = Object.keys(patchData.patches || {});
  const [activeTab, setActiveTab] = useState(tabs[0] || '');

  if (!tabs.length) return null;

  const currentPatch = patchData.patches[activeTab];
  const steps   = patchData.steps   || [];
  const verify  = patchData.verify  || '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Summary + Impact cards ── */}
      <div className="ai-patch-cards">
        <div className="ai-summary-card">
          <div className="ai-card-label">
            <BookOpen size={13} color="rgba(167,139,250,0.7)" strokeWidth={1.5} />
            <span className="ai-card-label-text" style={{ color: 'var(--text-40)' }}>What is it?</span>
          </div>
          <p className="ai-card-body" style={{ color: 'var(--text-70)' }}>{patchData.summary}</p>
        </div>
        <div className="ai-impact-card">
          <div className="ai-card-label">
            <AlertTriangle size={13} color="rgba(248,113,113,0.7)" strokeWidth={1.5} />
            <span className="ai-card-label-text" style={{ color: 'rgba(248,113,113,0.5)' }}>Impact</span>
          </div>
          <p className="ai-card-body" style={{ color: '#fb923c' }}>{patchData.impact}</p>
        </div>
      </div>

      {/* ── Remediation Steps checklist ── */}
      {steps.length > 0 && (
        <div style={{
          background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.18)',
          borderRadius: 14, padding: '14px 18px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <ListChecks size={14} color="rgba(167,139,250,0.8)" strokeWidth={1.5} />
            <span style={{
              fontFamily: "'Aeonik', sans-serif", fontWeight: 500, fontSize: 12,
              color: 'rgba(167,139,250,0.8)', textTransform: 'uppercase', letterSpacing: '0.5px',
            }}>Fix Steps — Do These In Order</span>
          </div>
          <ol style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {steps.map((step, i) => (
              <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <span style={{
                  flexShrink: 0, width: 22, height: 22, borderRadius: '50%',
                  background: 'rgba(139,92,246,0.18)', border: '1px solid rgba(139,92,246,0.35)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'monospace', fontSize: 10, fontWeight: 700, color: 'rgba(167,139,250,0.9)',
                }}>{i + 1}</span>
                <span style={{
                  fontFamily: "'Aeonik', sans-serif", fontSize: 12.5, lineHeight: 1.65,
                  color: 'rgba(255,255,255,0.72)',
                }}>{step.replace(/^\d+\.\s*/, '')}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* ── Language tabs ── */}
      <div className="ai-lang-tabs">
        <Code2 size={13} color="rgba(255,255,255,0.3)" strokeWidth={1.5} />
        {tabs.map(tab => {
          const isActive = tab === activeTab;
          const lang = patchData.patches[tab]?.lang || 'code';
          const langColor = LANG_COLORS[lang] || '#94a3b8';
          return (
            <button key={tab} onClick={() => setActiveTab(tab)} style={{
              background: isActive ? langColor + '18' : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isActive ? langColor + '44' : 'rgba(255,255,255,0.08)'}`,
              borderRadius: 8, padding: '5px 13px', cursor: 'pointer',
              color: isActive ? langColor : 'rgba(255,255,255,0.4)',
              fontFamily: "'Aeonik', sans-serif", fontSize: 12, fontWeight: isActive ? 500 : 400,
              transition: 'all 0.2s',
            }}>
              {tab}
            </button>
          );
        })}
      </div>

      {/* ── Code blocks ── */}
      {currentPatch && (
        <div>
          {currentPatch.before && (
            <CodeBlock label="Vulnerable Code" code={currentPatch.before} lang={currentPatch.lang} variant="before" />
          )}
          {currentPatch.after && (
            <CodeBlock label="Fixed Code" code={currentPatch.after} lang={currentPatch.lang} variant="after" />
          )}
        </div>
      )}

      {/* ── How to verify the fix ── */}
      {verify && (
        <div style={{
          background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.2)',
          borderRadius: 14, padding: '14px 18px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <FlaskConical size={14} color="rgba(52,211,153,0.8)" strokeWidth={1.5} />
            <span style={{
              fontFamily: "'Aeonik', sans-serif", fontWeight: 500, fontSize: 12,
              color: 'rgba(52,211,153,0.8)', textTransform: 'uppercase', letterSpacing: '0.5px',
            }}>How to Verify the Fix</span>
          </div>
          <pre style={{
            margin: 0, fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
            fontSize: 12, lineHeight: 1.7, color: 'rgba(255,255,255,0.65)',
            whiteSpace: 'pre-wrap', wordBreak: 'break-word',
          }}>{verify}</pre>
        </div>
      )}

      {/* ── References ── */}
      {patchData.references?.length > 0 && (
        <div className="ai-refs">
          <div className="ai-refs-label">References</div>
          <div className="ai-refs-list">
            {patchData.references.map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noreferrer" className="ai-ref-link">
                🔗 {ref}
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function BurpProofPanel({ req, resp }) {
  const [tab, setTab] = useState('Request');
  // Only show if we actually have some data in either
  if (!req && !resp) return null;
  const currentCode = tab === 'Request' ? req : resp;
  
  return (
    <div className="liquid-glass-strong ai-patch-viewer" style={{ marginTop: 16 }}>
      <img src={bgImage} alt="" className="ai-panel-bg" />
      <div className="ai-panel-inner">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div className="ai-section-label" style={{ marginBottom: 0 }}>
            <div className="liquid-glass ai-section-icon" style={{ background: 'rgba(234,179,8,0.1)' }}>
              <Activity size={14} color="#fbbf24" strokeWidth={1.5} />
            </div>
            <span className="ai-section-title">HTTP Proof Evidence</span>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
             {['Request', 'Response'].map(t => {
               const active = tab === t;
               return (
                 <button key={t} onClick={() => setTab(t)} style={{
                   background: active ? 'rgba(234,179,8,0.15)' : 'rgba(255,255,255,0.05)',
                   border: `1px solid ${active ? 'rgba(234,179,8,0.4)' : 'rgba(255,255,255,0.1)'}`,
                   color: active ? '#fbbf24' : 'rgba(255,255,255,0.5)',
                   borderRadius: 6, padding: '4px 10px', fontSize: 11, fontFamily: "'Aeonik', sans-serif",
                   cursor: 'pointer', transition: 'all 0.2s'
                 }}>{t}</button>
               );
             })}
          </div>
        </div>
        <div style={{
          background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12,
          padding: 16, overflow: 'auto', maxHeight: 350
        }}>
          <pre style={{
            margin: 0, fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
            fontSize: 12.5, lineHeight: 1.6, color: 'rgba(255,255,255,0.8)',
            whiteSpace: 'pre-wrap', wordBreak: 'break-all'
          }}>
            {currentCode || <span style={{ color: 'rgba(255,255,255,0.3)' }}>No {tab.toLowerCase()} evidence captured.</span>}
          </pre>
        </div>
      </div>
    </div>
  );
}

export default function AIRemediation() {
  const [vulns, setVulns]       = useState([]);
  const [selected, setSelected] = useState('');
  const [selVuln, setSelVuln]   = useState(null);
  const [patchData, setPatchData] = useState(null);
  const [rawSolution, setRawSolution] = useState('');
  const [loading, setLoading]   = useState(false);
  const [open, setOpen]         = useState(false);

  const loadVulns = useCallback(async () => {
    try { const r = await getVulnerabilities(); setVulns(r.data); } catch { /* ignore empty block */ }
  }, []);

  // eslint-disable-next-line
  useEffect(() => { loadVulns(); const t = setInterval(loadVulns, 5000); return () => clearInterval(t); }, [loadVulns]);

  const handleSelect = async (vuln) => {
    setOpen(false);
    setSelected(String(vuln.id));
    setSelVuln(vuln);
    setPatchData(null);
    setRawSolution('');
    setLoading(true);
    try {
      const r = await getAISolution(vuln.id);
      let sol = r.data.solution || '';
      
      // ── Robust JSON Extraction ──
      // 1. Remove markdown code blocks if present
      const jsonMatch = sol.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (jsonMatch) {
        sol = jsonMatch[1];
      }

      try {
        const parsed = JSON.parse(sol.trim());
        if (parsed && (parsed.mode === 'patch' || parsed.mode === 'generic' || parsed.patches || parsed.summary)) {
          setPatchData(parsed);
        } else {
          setRawSolution(sol);
        }
      } catch (e) {
        console.warn('AI JSON Parse Error, attempting recovery...', e);
        // Fallback: search for first { and last } to isolate JSON
        const firstBrace = sol.indexOf('{');
        const lastBrace  = sol.lastIndexOf('}');
        if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
          try {
            const recovery = sol.substring(firstBrace, lastBrace + 1);
            const parsed = JSON.parse(recovery);
            setPatchData(parsed);
          } catch {
            setRawSolution(sol);
          }
        } else {
          setRawSolution(sol);
        }
      }
    } catch (err) {
      console.error('API Error fetching solution:', err);
      setRawSolution('Error fetching patch. Ensure the API server is running.');
    }
    setLoading(false);
  };

  const sevStyle = selVuln ? (SEV_STYLES[selVuln.severity] || SEV_STYLES.Info) : null;

  return (
    <div
      className="dashboard-grid"
      style={{ display: 'flex', flexDirection: 'column', gap: 16, height: 'calc(100vh - 130px)', overflowY: 'auto' }}
    >
      {/* ── Header ── */}
      <div className="liquid-glass" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '18px 28px', borderRadius: 20, flexShrink: 0 }}>
        <div className="liquid-glass" style={{ width: 42, height: 42, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(139,92,246,0.1)' }}>
          <img src={brainIcon} alt="Brain" style={{ width: 22, height: 22, opacity: 0.9 }} />
        </div>
        <div>
          <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 500, fontSize: 22, ...GRADIENT_TEXT }}>Exact Patch Engine</div>
          <div style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 12, color: 'var(--text-50)', marginTop: 2 }}>
            Select a vulnerability to get copy-pasteable code fixes across Python, PHP, Node.js, Nginx & more
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Zap size={13} color="rgba(248,113,113,0.7)" strokeWidth={1.5} />
          <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 12, color: 'rgba(248,113,113,0.7)' }}>Exact Code Patches</span>
        </div>
      </div>

      <div className="ai-body">
        <div className="ai-dropdown-wrapper">
          <div
            className="liquid-glass-strong"
            onClick={() => setOpen(o => !o)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '16px 22px', borderRadius: 20, cursor: 'pointer',
              background: open ? 'rgba(255,255,255,0.06)' : undefined,
              transition: 'all 0.2s',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <ShieldAlert size={16} color={selVuln ? (sevStyle?.text || '#fff') : 'rgba(255,255,255,0.3)'} strokeWidth={1.5} />
              {selVuln ? (
                <div>
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 500, fontSize: 14, color: sevStyle?.text }}>{selVuln.cve}</span>
                  <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 13, color: 'var(--text-50)', marginLeft: 10 }}>{selVuln.type} — {selVuln.target}</span>
                </div>
              ) : (
                <span style={{ fontFamily: "'Aeonik', sans-serif", fontWeight: 400, fontSize: 14, color: 'var(--text-40)' }}>
                  {vulns.length === 0 ? 'No vulnerabilities found — run a scan first' : 'Choose a vulnerability to get exact patch…'}
                </span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {selVuln && <GlassBadge label={selVuln.severity} styles={sevStyle} />}
              <ChevronDown size={16} color="rgba(255,255,255,0.4)" strokeWidth={1.5}
                style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.25s' }} />
            </div>
          </div>

          {open && vulns.length > 0 && (
            <div className="liquid-glass-strong hide-scrollbar ai-dropdown-list">
              {vulns.map((v, idx) => {
                const sty = SEV_STYLES[v.severity] || SEV_STYLES.Info;
                const isActive = String(v.id) === selected;
                return (
                  <div key={v.id} onClick={() => handleSelect(v)}
                    className="ai-dropdown-item"
                    style={{
                      background: isActive ? 'rgba(255,255,255,0.06)' : 'transparent',
                      borderBottom: idx < vulns.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                    }}
                  >
                    <div className="ai-dropdown-item-info">
                      <span className="ai-dropdown-item-cve" style={{ color: sty.text }}>{v.cve}</span>
                      <span className="ai-dropdown-item-sub">{v.type} — {v.target}</span>
                    </div>
                    <GlassBadge label={v.severity} styles={sty} />
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="ai-content">
          {selVuln && (
            <div className="liquid-glass-strong ai-meta-panel">
              <img src={bgImage} alt="" className="ai-panel-bg" />
              <div className="ai-panel-inner">
                <div className="ai-meta-cve-header">
                  <div className="ai-meta-cve-title" style={{ color: sevStyle?.text }}>{selVuln.cve}</div>
                  <div className="ai-meta-cve-type">{selVuln.type}</div>
                </div>
                <MetaField label="Severity"><GlassBadge label={selVuln.severity} styles={sevStyle} /></MetaField>
                <MetaField label="EPSS Score"><span style={{ color: 'var(--text-80)' }}>{(selVuln.epss || 0).toFixed(3)}</span></MetaField>
                <MetaField label="Target"><span style={{ color: 'var(--text-80)', wordBreak: 'break-all' }}>{selVuln.target}</span></MetaField>
                <MetaField label="Status">
                  <span style={{ color: selVuln.status === 'Remediated' ? '#4ade80' : selVuln.status === 'In Progress' ? '#fbbf24' : '#f87171' }}>{selVuln.status}</span>
                </MetaField>
                {selVuln.description && (
                  <MetaField label="Finding"><span style={{ color: 'var(--text-50)', fontWeight: 400, fontSize: 12, lineHeight: 1.6 }}>{selVuln.description}</span></MetaField>
                )}
              </div>
            </div>
          )}

          {selVuln && <BurpProofPanel req={selVuln.proof_request} resp={selVuln.proof_response} />}

          <div className="liquid-glass-strong hide-scrollbar ai-patch-viewer">
            <img src={bgImage} alt="" className="ai-panel-bg" />
            <div className="ai-panel-inner">
              <div className="ai-section-label">
                <div className="liquid-glass ai-section-icon">
                  <Sparkles size={14} color="rgba(167,139,250,0.8)" strokeWidth={1.5} />
                </div>
                <span className="ai-section-title">Exact Code Patch</span>
              </div>

              {loading ? (
                <SpinnerDots />
              ) : patchData ? (
                <PatchPanel patchData={patchData} />
              ) : rawSolution ? (
                <div className="ai-raw-solution">{rawSolution}</div>
              ) : (
                <div className="ai-empty-state">
                  <Sparkles size={48} color="rgba(139,92,246,0.18)" strokeWidth={1} />
                  <div className="ai-empty-text">
                    Select a vulnerability from the dropdown above<br />to get copy-pasteable code patches.
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
