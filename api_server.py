"""
api_server.py — Flask REST API backend for Havoc Security React dashboard.
Exposes all the same functionality as dashboard.py (metrics, scan, vuln table,
AI remediation, reports, settings) via JSON endpoints so the React SPA can
consume them.
"""
# Load .env file first (before any os.environ.get calls in imported modules)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — rely on OS environment variables

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import threading, time, json, csv, io, sqlite3, os, functools
from datetime import datetime, timedelta
import jwt

from data_manager import DatabaseManager
from scanner_integrated import IntegratedVAPTScanner
from ai_remediation import AIRemediationGenerator
import billing
import razorpay_billing

app = Flask(__name__)
# Allow all origins for deployed frontend
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

# Secret key for JWT signing – change this in production via environment variable
JWT_SECRET = os.environ.get('JWT_SECRET', 'havoc-security-jwt-secret-2026-changeme-in-prod')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24

db      = DatabaseManager('vapt_database.db')
scanner = IntegratedVAPTScanner()
ai_gen  = AIRemediationGenerator()

# Init billing tables (adds plan columns to users table)
billing.init_billing_tables()

# Initialize Admin User automatically on server start
import create_admin
create_admin.create_admin()
# Force admin to PRO plan to ensure the default login works for all modules
try:
    with sqlite3.connect('vapt_database.db', timeout=30) as conn:
        conn.execute("UPDATE users SET plan='pro' WHERE email='admin@havoc.com'")
        conn.commit()
except:
    pass

# ── JWT helpers ───────────────────────────────────────────────────────────────
def _generate_token(user: dict) -> str:
    payload = {
        'sub': str(user['id']),
        'email': user['email'],
        'role': user.get('role', 'User'),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

def auth_required(f):
    """Decorator: requires a valid Bearer JWT in the Authorization header."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({}), 200
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            print(f"Auth failed: header missing or no Bearer. Header: {auth_header}")
            return jsonify({'error': 'Authorization token required'}), 401
        token = auth_header.split(' ', 1)[1]
        try:
            payload = _decode_token(token)
            request.auth_user = payload
        except jwt.ExpiredSignatureError:
            print("Auth failed: Token expired")
            return jsonify({'error': 'Token expired, please log in again'}), 401
        except jwt.InvalidTokenError as e:
            print(f"Auth failed: Invalid token - {str(e)}")
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        return f(*args, **kwargs)
    return decorated

# ── Ephemeral scan-state table (survives in-process, resets on dyno restart) ──
# We persist current scan status to SQLite so any Gunicorn worker can read it.
def _init_scan_state_table():
    conn = sqlite3.connect('vapt_database.db', timeout=30)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT DEFAULT 'idle',
            target TEXT,
            start_time REAL,
            progress INTEGER DEFAULT 0,
            vulns_found INTEGER DEFAULT 0,
            duration INTEGER DEFAULT 0,
            error TEXT,
            updated_at REAL
        )
    ''')
    conn.commit()
    conn.close()

_init_scan_state_table()

def _write_scan_state(**kwargs):
    """Upsert a single row into scan_state using REPLACE for maximum compatibility."""
    try:
        kwargs['updated_at'] = time.time()
        cols = ', '.join(kwargs.keys())
        placeholders = ', '.join(['?'] * len(kwargs))
        vals = list(kwargs.values())
        
        # We always use id=1 to ensure only one scan state exists
        conn = sqlite3.connect('vapt_database.db', timeout=30)
        conn.execute(f"REPLACE INTO scan_state (id, {cols}) VALUES (1, {placeholders})", vals)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'[scan_state write error] {e}')

def _read_scan_state():
    """Read the persisted scan state row."""
    try:
        conn = sqlite3.connect('vapt_database.db', timeout=30)
        row = conn.execute('SELECT status, target, start_time, progress, vulns_found, duration, error FROM scan_state WHERE id=1').fetchone()
        conn.close()
        if row:
            return {'status': row[0], 'target': row[1], 'start_time': row[2],
                    'progress': row[3], 'vulns_found': row[4], 'duration': row[5], 'error': row[6]}
    except Exception:
        pass
    return None


# ── helpers ────────────────────────────────────────────────────────────────────
def vuln_to_dict(v):
    return {
        "id": v[0], "cve": v[1], "type": v[2], "severity": v[3],
        "epss": v[4], "description": v[5], "url": v[6],
        "target": v[7], "status": v[8],
        "discovered_date": str(v[9]) if v[9] else None,
        "remediation_date": str(v[10]) if v[10] else None,
        "ai_solution": v[11] if len(v) > 11 else "",
        "proof_request":  v[13] if len(v) > 13 else "",
        "proof_response": v[14] if len(v) > 14 else "",
    }

def scan_to_dict(h):
    return {
        "id": h[0], "target": h[1], "date": str(h[2]),
        "vulns_found": h[3], "duration": h[4], "status": h[5]
    }

def get_latest_target(user_id):
    hist = db.get_scan_history(user_id)
    if not hist:
        return None
    raw = hist[0][1]  # e.g. "https://dypiu.ac.in" or "dypiu.ac.in"
    # Strip protocol so we can fuzzy-match against both stored formats
    from urllib.parse import urlparse
    parsed = urlparse(raw)
    return parsed.netloc or parsed.path  # returns "dypiu.ac.in"

def filter_by_latest(vulns, user_id):
    """Filter vulnerabilities to those belonging to the most-recent scan target."""
    latest = get_latest_target(user_id)
    if not latest:
        return []
    # Match if stored target contains the hostname (handles https://host and plain host)
    return [v for v in vulns if latest in (v[7] or '')]


# ── metrics ───────────────────────────────────────────────────────────────────
@app.route('/api/metrics')
@auth_required
def metrics():
    user_id = request.auth_user.get('sub')
    target_filter = request.args.get('latest', 'false').lower() == 'true'
    vulns = db.get_all_vulnerabilities(user_id)
    hist  = db.get_scan_history(user_id)
    
    if target_filter:
        vulns = filter_by_latest(vulns, user_id)

    return jsonify({
        "total":      len(vulns),
        "critical":   len([v for v in vulns if v[3] == "Critical"]),
        "high":       len([v for v in vulns if v[3] == "High"]),
        "medium":     len([v for v in vulns if v[3] == "Medium"]),
        "low":        len([v for v in vulns if v[3] == "Low"]),
        "info":       len([v for v in vulns if v[3] == "Info" or not v[3]]),
        "remediated": len([v for v in vulns if v[8] == "Remediated"]),
        "in_progress":len([v for v in vulns if v[8] == "In Progress"]),
        "open":       len([v for v in vulns if v[8] == "Open" or v[8] == "Active"]),
        "scans":      len(hist),
    })


# ── vulnerabilities ───────────────────────────────────────────────────────────
@app.route('/api/vulnerabilities')
@auth_required
def vulnerabilities():
    user_id = request.auth_user.get('sub')
    target_filter = request.args.get('latest', 'false').lower() == 'true'
    vulns = db.get_all_vulnerabilities(user_id)
    if target_filter:
        vulns = filter_by_latest(vulns, user_id)
    return jsonify([vuln_to_dict(v) for v in vulns])


# ── scan history ──────────────────────────────────────────────────────────────
@app.route('/api/scan-history')
@auth_required
def scan_history():
    user_id = request.auth_user.get('sub')
    hist = db.get_scan_history(user_id)
    return jsonify([scan_to_dict(h) for h in hist])


# ── radar data ────────────────────────────────────────────────────────────────
@app.route('/api/radar')
@auth_required
def radar():
    user_id = request.auth_user.get('sub')
    target_filter = request.args.get('latest', 'false').lower() == 'true'
    vulns = db.get_all_vulnerabilities(user_id)
    if target_filter:
        vulns = filter_by_latest(vulns, user_id)

    cats  = ["SQL Injection", "XSS", "CSRF", "SSRF", "IDOR",
             "Broken Auth", "Open Port", "SSL/TLS"]
    vals  = [len([v for v in vulns if c.lower() in (v[2] or "").lower()]) for c in cats]
    return jsonify({"categories": cats, "values": vals})


# ── EPSS scatter data ─────────────────────────────────────────────────────────
@app.route('/api/epss')
@auth_required
def epss():
    user_id = request.auth_user.get('sub')
    target_filter = request.args.get('latest', 'false').lower() == 'true'
    vulns = db.get_all_vulnerabilities(user_id)
    if target_filter:
        vulns = filter_by_latest(vulns, user_id)
    return jsonify([{"cve": v[1], "type": v[2], "epss": v[4], "severity": v[3]} for v in vulns])


# ── remediation progress ──────────────────────────────────────────────────────
@app.route('/api/remediation')
@auth_required
def remediation():
    user_id = request.auth_user.get('sub')
    return jsonify(db.get_remediation_progress(user_id))


# ── AI solution ───────────────────────────────────────────────────────────────
@app.route('/api/ai-solution/<int:vuln_id>')
@auth_required
def ai_solution(vuln_id):
    user_id = request.auth_user.get('sub')
    vulns = db.get_all_vulnerabilities(user_id)
    vuln  = next((v for v in vulns if v[0] == vuln_id), None)
    if not vuln:
        return jsonify({"error": "Vulnerability not found"}), 404

    # ── Plan enforcement for AI remediation ──────────────────────────────
    user_id = request.args.get('user_id', type=int)
    if user_id:
        ok, msg = billing.can_use_ai_remediation(user_id)
        if not ok:
            return jsonify({"error": msg, "upgrade_required": True, "solution": "⚠️ Upgrade to Starter plan to unlock AI Remediation."}), 403
    solution = (vuln[11] if len(vuln) > 11 else "") or ""
    if not solution or "No AI" in solution or "General" in solution:
        solution = ai_gen.generate_solution(vuln[1], vuln[2], vuln[5])
    return jsonify({"solution": solution})


# ── start scan ────────────────────────────────────────────────────────────────
@app.route('/api/scan/start', methods=['POST'])
@auth_required
def start_scan():
    user_id = request.auth_user.get('sub')
    body   = request.get_json(force=True)
    target = body.get("target", "").strip()
    mode   = body.get("mode", "quick")
    modules = body.get("modules", {})

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # ── Plan enforcement (only when user_id provided) ─────────────────────────
    if user_id:
        try:
            uid = int(user_id)
        except:
            uid = user_id
            
        # ── Admin Bypass ──────────────────────────────────────────────────────
        is_admin = (request.auth_user.get('email') == 'admin@havoc.com')
        
        allowed, reason = billing.can_scan(uid)
        if not allowed and not is_admin:
            return jsonify({"error": reason, "upgrade_required": True}), 403

        # Block deep scan modules on free/starter (except for Admin)
        deep_requested = any([
            modules.get('deepChecks'), modules.get('advFuzzing'), 
            modules.get('secretKey'), modules.get('dangerMode')
        ])
        if deep_requested and not is_admin:
            ok, msg = billing.can_deep_scan(uid)
            if not ok:
                return jsonify({"error": msg, "upgrade_required": True}), 403

    # Persist 'running' state immediately so all workers know a scan is active
    _write_scan_state(status='running', target=target, start_time=time.time(),
                      progress=0, vulns_found=0, duration=0, error=None)

    threading.Thread(target=_run_scan_and_persist, args=(target, mode, modules, user_id), daemon=True).start()
    return jsonify({"status": "started", "target": target, "mode": mode, "modules": modules})


def _run_scan_and_persist(target, mode, modules, user_id):
    """Wrapper that runs the scan and writes final state to the DB."""
    try:
        # Check targets in the thread to avoid blocking the API response
        import requests
        test_url = target if target.startswith('http') else f"http://{target}"
        try:
            requests.get(test_url, timeout=10, verify=False)
        except Exception as e:
            _write_scan_state(status='error', target=target, error=f"Target unreachable: {str(e)}")
            return

        result = scanner.start_scan(target, mode, modules)
        status = result.get('status', 'completed')
        vulns  = result.get('vulnerabilities', [])
        start  = result.get('start_time', time.time())
        dur    = int(time.time() - start)
        
        # 1. Update ephemeral scan_state (for polling)
        _write_scan_state(status=status, target=target, progress=100,
                          vulns_found=len(vulns), duration=dur, error=result.get('error'))
        
        # 2. Persist to permanent scan_history
        db.add_scan_history(
            user_id=user_id,
            target=target,
            vulns_found=len(vulns),
            duration=dur,
            status=status
        )
        
        # 3. Persist each vulnerability
        for v in vulns:
            db.add_vulnerability(
                user_id=user_id,
                cve=v.get('cve', 'CVE-UNKNOWN'),
                vuln_type=v.get('type', 'Unknown'),
                severity=v.get('severity', 'Medium'),
                epss_score=float(v.get('epss_score', 0.5)),
                description=v.get('description', ''),
                affected_url=v.get('affected_url', target),
                target=target,
                status='Open',
                ai_solution=v.get('ai_solution', '')
            )
    except Exception as e:
        print(f"Scan thread error: {e}")
        _write_scan_state(status='error', target=target, error=str(e))


# ── poll scan status ──────────────────────────────────────────────────────────

@app.route('/api/scan/status')
@auth_required
def scan_status_api():
    user_id = request.auth_user.get('sub')
    status   = scanner.get_scan_status()
    progress = scanner.get_scan_progress()
    results  = scanner.get_scan_results()
    phases   = results.get("scan_phases", []) if results else []

    # ── CRITICAL FIX: If this worker has no in-memory scan state (fresh Gunicorn
    # worker on Render), fall back to the DB-persisted scan_state row.
    db_state = _read_scan_state()
    if status == 'idle' and db_state and db_state['status'] in ('running', 'completed', 'error'):
        status   = db_state['status']
        progress = db_state.get('progress', 0)

    payload = {
        "status":   status,
        "progress": progress,
        "phases":   phases,
    }

    if status == "completed":
        vulns       = results.get("vulnerabilities", []) if results else []
        target      = (results.get("target") if results else None) or (db_state or {}).get('target')
        start_time  = (results.get("start_time") if results else None) or (db_state or {}).get('start_time', time.time())
        dur         = int(time.time() - start_time) if start_time else 0

        # NOTE: Persistence is handled entirely by _run_scan_and_persist().
        # This endpoint only reports status — no duplicate DB writes.
        # Clear the ephemeral scan_state so subsequent polls see 'idle'.
        if db_state and db_state['status'] == 'completed':
            _write_scan_state(status='idle', target=None, progress=0,
                              vulns_found=len(vulns), duration=dur, error=None)

        payload.update({"vulns_found": len(vulns), "duration": dur})

    elif status == "error":
        err = (results.get("error") if results else None) or (db_state or {}).get('error', 'Unknown error')
        payload["error"] = err

    return jsonify(payload)


# ── stop scan ─────────────────────────────────────────────────────────────────
@app.route('/api/scan/stop', methods=['POST'])
@auth_required
def stop_scan_api():
    user_id = request.auth_user.get('sub')
    body   = request.get_json(force=True)
    target = body.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400
    # Record an incomplete scan entry so the URL appears in the dashboard table
    db.add_scan_history(user_id, target, 0, 0, status="Incomplete")
    return jsonify({"status": "stopped", "target": target})


# ── Auth Endpoints ────────────────────────────────────────────────────────────
@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    body = request.get_json(force=True)
    first_name = body.get('firstName', '').strip()
    last_name = body.get('lastName', '').strip()
    email = body.get('email', '').strip()
    password = body.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
        
    user = db.add_user(first_name, last_name, email, password)
    if "error" in user:
        return jsonify({"error": user["error"]}), 400

    token = _generate_token(user)
    return jsonify({"token": token, "user": user})

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    body = request.get_json(force=True)
    email = body.get('email', '').strip()
    password = body.get('password', '')

    user = db.verify_user(email, password)
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    token = _generate_token(user)
    return jsonify({"token": token, "user": user})

@app.route('/api/auth/reset-password', methods=['POST', 'OPTIONS'])
@auth_required
def auth_reset_password():
    body = request.get_json(force=True)
    email = body.get('email', '').strip()
    old_password = body.get('oldPassword', '')
    new_password = body.get('newPassword', '')

    if not email or not old_password or not new_password:
        return jsonify({"error": "Missing required fields"}), 400

    success = db.reset_password(email, old_password, new_password)
    if not success:
        return jsonify({"error": "Incorrect current password"}), 400

    return jsonify({"status": "success"})

# ── settings: clear DB ────────────────────────────────────────────────────────
@app.route('/api/settings/clear', methods=['POST', 'OPTIONS'])
@auth_required
def clear_db_api():
    user_id = request.auth_user.get('sub')
    db.clear_database(user_id)
    return jsonify({"success": True})


@app.route('/api/settings/remove-account', methods=['POST', 'OPTIONS'])
@auth_required
def remove_account_api():
    user_id = request.auth_user.get('sub')
    if not user_id:
        return jsonify({"error": "Invalid auth token"}), 401
    
    success = db.delete_user(user_id)
    if success:
        return jsonify({"success": True})
    return jsonify({"error": "Failed to remove account"}), 500


# ── export JSON ───────────────────────────────────────────────────────────────
@app.route('/api/export/json')
@auth_required
def export_json():
    user_id = request.auth_user.get('sub')
    vulns = db.get_all_vulnerabilities(user_id)
    data  = [{"cve": v[1], "type": v[2], "severity": v[3], "epss": v[4],
               "description": v[5], "url": v[6], "target": v[7], "status": v[8]}
              for v in vulns]
    return Response(
        json.dumps(data, indent=2),
        mimetype='application/json',
        headers={"Content-Disposition": "attachment; filename=vapt_report.json"}
    )


# ── export CSV ────────────────────────────────────────────────────────────────
@app.route('/api/export/csv')
@auth_required
def export_csv():
    user_id = request.auth_user.get('sub')
    vulns = db.get_all_vulnerabilities(user_id)
    buf   = io.StringIO()
    w     = csv.writer(buf)
    w.writerow(["CVE", "Type", "Severity", "EPSS", "Description", "URL", "Target", "Status"])
    for v in vulns:
        w.writerow([v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]])
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment; filename=vapt_report.csv"}
    )


# ── export HTML/PDF report ────────────────────────────────────────────────────
@app.route('/api/export/html')
@auth_required
def export_html():
    user_id = request.auth_user.get('sub')
    # ── Plan enforcement for PDF export ──────────────────────────────────
    if user_id:
        ok, msg = billing.can_export_pdf(user_id)
        if not ok:
            return jsonify({"error": msg, "upgrade_required": True}), 403
    vulns = db.get_all_vulnerabilities(user_id)
    now   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    n_crit = len([v for v in vulns if v[3] == "Critical"])
    n_high = len([v for v in vulns if v[3] == "High"])
    n_med  = len([v for v in vulns if v[3] == "Medium"])
    n_low  = len([v for v in vulns if v[3] == "Low"])
    n_open = len([v for v in vulns if v[8] == "Open"])
    n_rem  = len([v for v in vulns if v[8] == "Remediated"])
    targets = list(set(v[7] for v in vulns if v[7])) or ["—"]

    SEV_COLOR = {"Critical": "#ff3c5a", "High": "#ff8c42", "Medium": "#f0c040",
                 "Low": "#00e5a0", "Info": "#2ab4e0"}
    SEV_BG    = {"Critical": "rgba(255,60,90,0.08)", "High": "rgba(255,140,66,0.08)",
                 "Medium": "rgba(240,192,64,0.08)", "Low": "rgba(0,229,160,0.06)",
                 "Info": "rgba(42,180,224,0.06)"}
    SEV_BADGE = {"Critical": "rgba(255,60,90,.15)", "High": "rgba(255,140,66,.15)",
                 "Medium": "rgba(240,192,64,.15)", "Low": "rgba(0,229,160,.15)",
                 "Info": "rgba(42,180,224,.15)"}

    # ── Sev bar chart ──
    total_vulns = len(vulns) or 1
    def bar(n): return (n / total_vulns) * 100
    
    sev_rows = ""
    for s, n in [("Critical", n_crit), ("High", n_high), ("Medium", n_med), ("Low", n_low)]:
        c = SEV_COLOR.get(s, "#6c8ba4")
        pct = bar(n)
        sev_rows += f"""
        <tr>
          <td style="width:100px;"><span class="sc" style="background:{SEV_BADGE[s]};color:{c};">{s}</span></td>
          <td style="width:40px;text-align:center;font-weight:700;">{n}</td>
          <td>
            <div style="background:rgba(255,255,255,0.05);height:8px;border-radius:4px;overflow:hidden;width:100%;">
              <div style="background:{c};height:100%;width:{pct}%;"></div>
            </div>
          </td>
        </tr>"""

    def _format_ai(raw):
        if not raw or "No AI" in raw: return f"<p>{raw}</p>"
        try:
            import json, re
            # Extract JSON from markdown blocks if present
            json_str = raw
            match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', raw)
            if match:
                json_str = match.group(1)
            else:
                # Try finding the first { and last }
                start = raw.find('{')
                end = raw.rfind('}')
                if start != -1 and end != -1 and end > start:
                    json_str = raw[start:end+1]
            
            d = json.loads(json_str.strip())
            out = "<div style='margin-bottom: 12px;'><strong style='color:#fff;font-size:1.05rem;letter-spacing:0.5px;'>Developer Remediation Plan</strong></div>"
            if 'summary' in d: out += f"<div class='ai-sub'><span style='color:#2ab4e0;font-weight:bold;'>Root Cause Analysis:</span> {d['summary']}</div>"
            if 'impact' in d:  out += f"<div class='ai-sub'><span style='color:#ff3c5a;font-weight:bold;'>Business Impact:</span> <span>{d['impact']}</span></div>"
            if 'steps' in d:     out += f"<div class='ai-sub'><span style='color:#00e5a0;font-weight:bold;'>Actionable Steps:</span><ul style='margin-top:8px;padding-left:20px'>" + "".join([f"<li style='margin-bottom:6px;'>{s}</li>" for s in d['steps']]) + "</ul></div>"
            if 'patches' in d:
                out += "<div class='ai-sub' style='margin-top:16px;'><span style='color:#f0c040;font-weight:bold;'>Suggested Code Patch:</span>"
                for lang_name, p in d['patches'].items():
                    lang = p.get('lang', 'patch')
                    out += f"<div style='background:#0a0d14;padding:12px;border-radius:8px;margin-top:8px;border:1px solid rgba(255,255,255,0.1);'>"
                    out += f"<div style='font-size:11px;font-weight:bold;text-transform:uppercase;color:#8b9eb0;margin-bottom:8px;'>{lang_name} Implementation</div>"
                    if 'before' in p: out += f"<div style='color:#ff3c5a;font-size:12px;margin-bottom:4px;font-weight:600;'>- Vulnerable Code:</div><pre style='background:rgba(255,60,90,0.08);color:#ff3c5a;border-left:3px solid #ff3c5a;margin-bottom:12px;padding:10px;font-size:0.85rem;'>{p['before']}</pre>"
                    if 'after' in p:  out += f"<div style='color:#00e5a0;font-size:12px;margin-bottom:4px;font-weight:600;'>+ Secured Code:</div><pre style='background:rgba(0,229,160,0.08);color:#00e5a0;border-left:3px solid #00e5a0;padding:10px;font-size:0.85rem;'>{p['after']}</pre>"
                    out += "</div>"
                out += "</div>"
            return out if out != "<div style='margin-bottom: 12px;'><strong style='color:#fff;font-size:1.05rem;letter-spacing:0.5px;'>Developer Remediation Plan</strong></div>" else f"<p>{raw}</p>"
        except Exception as e:
            # Safely escape HTML if dumping raw
            import html
            return f"<pre style='font-size: 0.85rem; color: #b0c4d9; white-space: pre-wrap;'>{html.escape(raw)}</pre>"

    finding_blocks = ""
    for i, v in enumerate(vulns, 1):
        sev    = v[3] if v[3] else "Info"
        color  = SEV_COLOR.get(sev, "#6c8ba4")
        bg     = SEV_BG.get(sev, "rgba(255,255,255,0.02)")
        badge_bg = SEV_BADGE.get(sev, "rgba(42,180,224,.15)")
        cve    = v[1] or "N/A"
        vtype  = v[2] or "Unknown"
        epss   = f"{v[4]:.3f}" if v[4] else "0.000"
        desc   = v[5] or "No description available."
        url    = v[6] or "/"
        target = v[7] or "—"
        status = v[8] or "Open"
        ai_sol = _format_ai((v[11] if len(v) > 11 else ""))
        stat_c = "#ff3c5a" if status == "Open" else ("#f0c040" if status == "In Progress" else "#00e5a0")
        finding_blocks += f"""
  <div class="vuln" style="border-left-color:{color};background:{bg};">
    <div class="vuln-header">
        <span class="num">VULN-{i:03d}</span>
        <span class="vtype">{vtype}</span>
        <span class="badge" style="background:{badge_bg};color:{color};">{sev} Severity</span>
        <span class="vstatus" style="background:{badge_bg};color:{stat_c};">{status}</span>
    </div>
    <table class="meta-table">
        <tr><td>CVE Identifier</td><td><code>{cve}</code></td></tr>
        <tr><td>Asset Target</td><td><code>{target}</code></td></tr>
        <tr><td>Risk Level</td><td style="color:{color};font-weight:700;">{sev}</td></tr>
        <tr><td>EPSS Probability</td><td><code>{epss}</code></td></tr>
    </table>
    <div class="section-label">📋 Technical Description</div>
    <p class="desc">{desc}</p>
    <div class="section-label">📍 Vulnerable Endpoint</div>
    <pre class="location-box">{url}</pre>
    <div class="section-label">🛠 Actionable Remediation</div>
    <div class="solution-box">{ai_sol}</div>
  </div>"""

    html_str = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Havoc Security Audit Report — VAPT Assessment</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
    body{{font-family:'Plus Jakarta Sans',sans-serif;background:#05070a;color:#e2eaf3;padding:40px 10%;line-height:1.6;}}
    .report-wrap{{max-width:1000px;margin:0 auto;}}
    .report-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:48px;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:32px;}}
    .report-title{{font-size:2.4rem;font-weight:800;color:#fff;letter-spacing:-1px;}}
    .report-title span{{color:#ff3c5a;}}
    .report-meta{{text-align:right;font-size:0.85rem;color:#8b9eb0;line-height:1.8;font-family:'JetBrains Mono',monospace;}}
    .exec-summary{{background:linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:32px;margin-bottom:48px;box-shadow:0 8px 32px rgba(0,0,0,0.2);}}
    .exec-summary h2{{font-size:1.2rem;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:24px;display:flex;align-items:center;gap:12px;}}
    .exec-summary h2::after{{content:'';height:1px;background:rgba(255,255,255,0.1);flex:1;}}
    .sev-table{{width:100%;border-collapse:collapse;}}
    .sev-table td{{padding:14px 8px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:0.9rem;}}
    .sc{{font-weight:700;font-size:0.75rem;padding:4px 12px;border-radius:20px;display:inline-block;letter-spacing:0.5px;text-transform:uppercase;}}
    .section-title{{font-size:1.1rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#fff;margin-bottom:32px;border-bottom:1px solid rgba(255,255,255,0.08);padding-bottom:12px;}}
    .vuln{{border-left:4px solid;border-radius:12px;padding:32px;margin-bottom:40px;page-break-inside:avoid;border:1px solid rgba(255,255,255,0.05);border-left-width:6px;box-shadow:0 10px 30px rgba(0,0,0,0.15);}}
    .vuln-header{{display:flex;align-items:center;gap:12px;margin-bottom:24px;flex-wrap:wrap;border-bottom:1px solid rgba(255,255,255,0.05);padding-bottom:16px;}}
    .num{{font-size:0.8rem;color:#8b9eb0;font-family:'JetBrains Mono',monospace;font-weight:600;}}
    .vtype{{font-weight:700;font-size:1.25rem;color:#fff;flex:1;}}
    .badge{{font-size:0.7rem;font-weight:700;padding:5px 14px;border-radius:20px;text-transform:uppercase;letter-spacing:0.5px;}}
    .epss{{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#8b9eb0;}}
    .vstatus{{font-size:0.75rem;padding:4px 12px;border-radius:20px;font-weight:600;text-transform:uppercase;}}
    .meta-table{{width:100%;border-collapse:collapse;font-size:0.85rem;margin-bottom:32px;background:rgba(0,0,0,0.2);border-radius:8px;overflow:hidden;border:1px solid rgba(255,255,255,0.05);}}
    .meta-table td{{padding:10px 16px;border-bottom:1px solid rgba(255,255,255,0.03);}}
    .meta-table td:first-child{{color:#8b9eb0;width:150px;font-weight:500;}}
    code{{font-family:'JetBrains Mono',monospace;font-size:0.85rem;color:#2ab4e0;background:rgba(42,180,224,0.1);padding:2px 8px;border-radius:4px;}}
    .section-label{{font-size:0.8rem;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#8b9eb0;margin-bottom:12px;margin-top:32px;display:flex;align-items:center;gap:8px;}}
    .desc{{color:#b0c4d9;font-size:0.95rem;line-height:1.7;margin-bottom:16px;}}
    pre{{font-family:'JetBrains Mono',monospace;font-size:0.85rem;white-space:pre-wrap;word-break:break-all;border-radius:8px;padding:16px;line-height:1.6;}}
    .location-box{{background:#0a0d14;border:1px solid rgba(255,255,255,0.08);color:#e2eaf3;}}
    .solution-box{{background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.08);padding:24px;border-radius:10px;font-size:0.9rem;color:#b0c4d9;}}
    .ai-sub{{margin-bottom:16px;}}
    .ai-sub li{{margin-bottom:8px;line-height:1.5;}}
    @media print{{
      body{{padding:20px;background:#fff;color:#111;}}
      .vuln{{box-shadow:none;border-color:#e0e0e0;background:#fafafa!important;}}
      .meta-table{{background:#f0f0f0;border-color:#e0e0e0;}}
      .meta-table td{{border-color:#e0e0e0;}}
      .report-header{{border-bottom-color:#e0e0e0;}}
      .report-title, .report-title span{{color:#000;}}
      .exec-summary{{background:#f9f9f9;border-color:#e0e0e0;box-shadow:none;}}
      .exec-summary h2, .section-title, .vtype{{color:#000;}}
      .location-box, .solution-box{{background:#f5f5f5;border-color:#e0e0e0;color:#111;}}
      .ai-sub{{color:#222;}}
      code{{background:#eaeaea;color:#000;}}
    }}
  </style>
</head>
<body>
  <div class="report-wrap">
    <div class="report-header">
      <div>
        <div class="report-title">HAVOC <span>SECURITY</span></div>
        <div style="font-size:1rem;color:#8b9eb0;font-weight:600;margin-top:6px;">Vulnerability Assessment & Penetration Testing Report</div>
      </div>
      <div class="report-meta">
        <strong>Report Ref:</strong> VAPT-{now.split(' ')[0].replace('-','')}<br>
        <strong>Timestamp:</strong> {now}<br>
        <strong>Scope:</strong> {len(targets)} Asset(s)
      </div>
    </div>

    <div class="exec-summary">
      <h2>Executive Summary</h2>
      <div style="font-size:0.95rem;color:#b0c4d9;margin-bottom:32px;line-height:1.7;">
        This document represents the findings from the automated Vulnerability Assessment and Penetration Testing (VAPT) performed on <strong>{", ".join(targets[:3]) + ("..." if len(targets)>3 else "")}</strong>. 
        During this assessment, a total of <strong>{len(vulns)}</strong> vulnerabilities were successfully identified and corroborated by our scanning engines. The following table provides a high-level breakdown of findings by risk severity.
      </div>
      <table class="sev-table">
        {sev_rows}
      </table>
    </div>

    <div class="section-title">Comprehensive Technical Findings</div>
    {finding_blocks}
  </div>
</body>
</html>"""

    return Response(
        html_str,
        mimetype='text/html',
        headers={"Content-Disposition": f"attachment; filename=havoc_report_{now.split(' ')[0]}.html"}
    )


# ──────────────────────────────────────────────────────────────────────
# BILLING ENDPOINTS
# ──────────────────────────────────────────────────────────────────────

@app.route('/api/billing/plans')
def billing_plans():
    """Return all available plan definitions (no auth required — used for pricing page)."""
    plans_out = {}
    for key, p in billing.PLANS.items():
        plans_out[key] = {
            'name': p['name'],
            'price': p['price'],          # in cents
            'scan_limit': p['scan_limit'] if p['scan_limit'] < 999000 else -1,  # -1 = unlimited
            'target_limit': p['target_limit'] if p['target_limit'] < 999000 else -1,
            'ai_remediation': p['ai_remediation'],
            'deep_scan': p['deep_scan'],
            'export_pdf': p['export_pdf'],
            'api_access': p['api_access'],
            'badge_color': p['badge_color'],
            'badge_label': p['badge_label'],
        }
    return jsonify(plans_out)


@app.route('/api/billing/my-plan')
def my_plan():
    """Return the current plan for a user."""
    user_id = request.args.get('user_id', type=int)
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    plan = billing.get_user_plan(user_id)
    used = billing.count_scans_this_month(user_id)
    return jsonify({
        **plan,
        'scans_used_this_month': used,
        'scans_remaining': max(0, plan['scan_limit'] - used) if plan['scan_limit'] < 999000 else -1,
    })


@app.route('/api/billing/checkout', methods=['POST'])
def billing_checkout():
    """Create a Stripe Checkout session and return redirect URL."""
    body = request.get_json(force=True)
    user_id  = body.get('user_id')
    plan_key = body.get('plan', 'pro')
    email    = body.get('email', '')
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    try:
        url = billing.create_checkout_session(user_id, plan_key, email)
        return jsonify({"checkout_url": url})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Stripe error: {e}"}), 500


@app.route('/api/billing/portal', methods=['POST'])
def billing_portal():
    """Create a Stripe Customer Portal session for managing subscriptions."""
    body = request.get_json(force=True)
    user_id = body.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    try:
        url = billing.create_portal_session(user_id)
        return jsonify({"portal_url": url})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Stripe error: {e}"}), 500


@app.route('/api/billing/webhook', methods=['POST'])
def billing_webhook():
    """Stripe webhook — updates user plans on payment events."""
    payload    = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')
    try:
        result = billing.handle_webhook(payload, sig_header)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ═══════════════════════════════════════════════════════════════════════════
#  RAZORPAY PAYMENT ROUTES  (India — free, no monthly fee)
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/api/razorpay/plans', methods=['GET'])
def razorpay_plans():
    """Return Razorpay plan details for the frontend pricing grid."""
    return jsonify(razorpay_billing.get_plans_info())


@app.route('/api/razorpay/create-order', methods=['POST'])
@auth_required
def razorpay_create_order():
    """
    Step 1: Create a Razorpay order.
    Frontend opens the Razorpay Checkout modal with the returned order_id.
    """
    body     = request.get_json(force=True)
    user_id  = int(request.auth_user.get('sub', 0))
    plan_key = body.get('plan', 'pro')

    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    try:
        order = razorpay_billing.create_order(user_id, plan_key)
        return jsonify(order)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Razorpay error: {e}'}), 500


@app.route('/api/razorpay/verify', methods=['POST'])
@auth_required
def razorpay_verify():
    """
    Step 2: Verify payment signature sent by Razorpay to the frontend,
    then activate the user plan.
    """
    body       = request.get_json(force=True)
    user_id    = int(request.auth_user.get('sub', 0))
    order_id   = body.get('razorpay_order_id', '')
    payment_id = body.get('razorpay_payment_id', '')
    signature  = body.get('razorpay_signature', '')
    plan_key   = body.get('plan', 'pro')

    if not all([order_id, payment_id, signature]):
        return jsonify({'error': 'Missing payment fields'}), 400

    try:
        ok = razorpay_billing.verify_payment(
            order_id, payment_id, signature, user_id, plan_key
        )
        if ok:
            plan_info = razorpay_billing.RAZORPAY_PLANS.get(plan_key, {})
            return jsonify({
                'success':    True,
                'plan':       plan_key,
                'plan_name':  plan_info.get('name', plan_key.capitalize()),
                'message':    f"Payment verified! Your {plan_info.get('name', plan_key)} plan is now active.",
            })
        else:
            return jsonify({'error': 'Payment signature verification failed'}), 400
    except Exception as e:
        return jsonify({'error': f'Verification error: {e}'}), 500


# ══════════════════════════════════════════════════════════════════════════
#  ADMIN DATABASE MANAGEMENT ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

def _admin_required(f):
    """Decorator: requires auth + Admin role."""
    @functools.wraps(f)
    @auth_required
    def decorated(*args, **kwargs):
        role = request.auth_user.get('role', '')
        if role != 'Admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated


@app.route('/api/admin/tables')
@_admin_required
def admin_list_tables():
    """Return all table names and their row counts."""
    conn = sqlite3.connect('vapt_database.db', timeout=30)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    tables = []
    for (name,) in cursor.fetchall():
        cnt = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        tables.append({'name': name, 'rows': cnt})
    conn.close()
    return jsonify(tables)


@app.route('/api/admin/tables/<table_name>')
@_admin_required
def admin_query_table(table_name):
    """Return paginated rows from a table with column names."""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    search = request.args.get('search', '').strip()
    per_page = min(per_page, 200)
    offset = (page - 1) * per_page

    conn = sqlite3.connect('vapt_database.db', timeout=30)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Validate table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': f'Table "{table_name}" not found'}), 404

    # Get columns
    cursor.execute(f'PRAGMA table_info("{table_name}")')
    columns = [{'name': r[1], 'type': r[2]} for r in cursor.fetchall()]
    col_names = [c['name'] for c in columns]

    # Build query with optional search
    if search:
        where_parts = []
        params = []
        for col in col_names:
            where_parts.append(f'CAST("{col}" AS TEXT) LIKE ?')
            params.append(f'%{search}%')
        where_clause = ' OR '.join(where_parts)
        count = conn.execute(f'SELECT COUNT(*) FROM "{table_name}" WHERE {where_clause}', params).fetchone()[0]
        rows = conn.execute(
            f'SELECT * FROM "{table_name}" WHERE {where_clause} LIMIT ? OFFSET ?',
            params + [per_page, offset]
        ).fetchall()
    else:
        count = conn.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0]
        rows = conn.execute(f'SELECT * FROM "{table_name}" LIMIT ? OFFSET ?', (per_page, offset)).fetchall()

    data = []
    for row in rows:
        row_dict = {}
        for i, col in enumerate(col_names):
            val = row[i]
            # Mask password hashes for security
            if col == 'password' and val:
                row_dict[col] = '••••••••'
            else:
                row_dict[col] = val
        data.append(row_dict)

    conn.close()
    return jsonify({
        'table': table_name,
        'columns': columns,
        'rows': data,
        'total': count,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, -(-count // per_page)),  # ceil division
    })


@app.route('/api/admin/tables/<table_name>/rows/<int:row_id>', methods=['DELETE'])
@_admin_required
def admin_delete_row(table_name, row_id):
    """Delete a row by its id (primary key)."""
    conn = sqlite3.connect('vapt_database.db', timeout=30)
    cursor = conn.cursor()
    # Validate table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': f'Table "{table_name}" not found'}), 404

    cursor.execute(f'DELETE FROM "{table_name}" WHERE id=?', (row_id,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return jsonify({'deleted': deleted, 'id': row_id})


@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@_admin_required
def admin_update_user_role(user_id):
    """Update a user's role."""
    body = request.get_json(force=True)
    new_role = body.get('role', '').strip()
    if new_role not in ('User', 'Admin'):
        return jsonify({'error': 'Role must be "User" or "Admin"'}), 400
    conn = sqlite3.connect('vapt_database.db', timeout=30)
    conn.execute('UPDATE users SET role=? WHERE id=?', (new_role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'user_id': user_id, 'role': new_role})


@app.route('/api/admin/stats')
@_admin_required
def admin_stats():
    """Return aggregate database statistics for the admin dashboard."""
    conn = sqlite3.connect('vapt_database.db', timeout=30)
    c = conn.cursor()
    total_users = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_scans = c.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0]
    total_vulns = c.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
    # DB file size
    import os as _os
    db_size = _os.path.getsize('vapt_database.db')
    conn.close()
    return jsonify({
        'total_users': total_users,
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'db_size_bytes': db_size,
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
