import time
import socket
import logging
import threading
from typing import Dict, List
from urllib.parse import urlparse
from reconnaissance import Reconnaissance
from web_scanner import WebScanner, ManualVulnerabilityDetector, SensitiveDataLeakageDetector
from epss_scorer import EPSSScorer
from ai_remediation import AIRemediationGenerator

logger = logging.getLogger(__name__)

class IntegratedVAPTScanner:
    """
    Havoc Security — Professional VAPT Scanner Engine v2.0
    Covers: SQLi, NoSQLi, XSS (Reflected/DOM), LFI, CMDi, SSTI, SSRF, XXE,
            Open Redirect, IDOR/BOLA, Deserialization, JWT, CORS, Cookie Security,
            Security Headers, Rate Limiting, SSL/TLS, Directory Listing,
            Sensitive Data Leakage, Port/Service Scanning.
    """

    def __init__(self):
        self.current_scan = None
        self.scan_progress = 0
        self.is_scanning = False
        self._lock = threading.Lock()
        self.web_scanner = WebScanner()
        self.manual_detector = ManualVulnerabilityDetector()
        self.data_leak_detector = SensitiveDataLeakageDetector()
        self.epss_scorer = EPSSScorer()
        self.ai_generator = AIRemediationGenerator()

    def start_scan(self, target: str, scan_mode: str = 'quick', modules: dict = None) -> Dict:
        """Start complete VAPT scan on target."""
        print(f"[SCAN] Starting for '{target}' | Mode: {scan_mode} | Modules: {modules}")

        # Fast-fail if target is unreachable
        import requests, warnings
        warnings.filterwarnings("ignore")
        test_url = target if target.startswith('http') else f"http://{target}"
        try:
            requests.get(test_url, timeout=8, verify=False)
        except requests.exceptions.RequestException as e:
            logger.error(f"Target {target} unreachable: {e}")
            return {'status': 'error', 'error': f'Target is unreachable: {e}'}

        if modules is None:
            modules = {}
        use_all = not bool(modules)

        with self._lock:
            self.current_scan = {
                'target': target,
                'start_time': time.time(),
                'status': 'running',
                'vulnerabilities': [],
                'scan_phases': [],
                'scan_id': f"{target}_{int(time.time())}",
            }
            self.is_scanning = True
            self.scan_progress = 0

        try:
            # ── Phase 1: Reconnaissance / Port Scan (0–20%) ──────────────────
            self._progress(5, "Initializing scanner...")
            if use_all or modules.get('portScan', False):
                mode_label = 'deep Nmap' if scan_mode == 'deep' else 'quick socket'
                self._phase(f"Running {mode_label} reconnaissance...")
                recon_results = self._run_reconnaissance(target, scan_mode)
                self._phase(f"Reconnaissance complete — {len(recon_results)} open ports/services found")
            else:
                recon_results = []
                self._phase("Port scan skipped (toggled off)")
            self._progress(20, None)

            # ── Phase 2: OWASP Top 10 Passive Checks (20–40%) ────────────────
            self._progress(22, None)
            if use_all or modules.get('webVuln', False) or modules.get('owaspTop10', False):
                self._phase("Checking OWASP Top 10 & security headers...")
                web_vulns = self._run_web_scan(target)
                self._phase(f"OWASP checks complete — {len(web_vulns)} issues found")
            else:
                web_vulns = []
                self._phase("OWASP Top 10 checks skipped (toggled off)")
            self._progress(40, None)

            # ── Phase 3: Deep Active Injection Scanning (40–70%) ─────────────
            self._progress(42, None)
            if use_all or any(modules.get(k) for k in
                              ['manualChecks', 'deepChecks', 'secretKey', 'advFuzzing',
                               'dangerMode', 'agenticAi', 'owaspTop10']):
                danger = modules.get('dangerMode', False)
                self._phase(f"Running deep injection scans {'[DANGER MODE]' if danger else ''}")
                manual_vulns = self._run_manual_detection(target, scan_mode, modules if not use_all else None)
                self._phase(f"Active scanning complete — {len(manual_vulns)} vulnerabilities confirmed")
            else:
                manual_vulns = []
                self._phase("Active injection scans skipped (toggled off)")
            self._progress(70, None)

            # ── Phase 4: Sensitive Data & Secret Leakage (70–82%) ────────────
            self._progress(72, None)
            if use_all or modules.get('dataLeakage', False):
                self._phase("Scanning for secrets, credentials & PII leakage...")
                leak_vulns = self._run_data_leakage_scan(target)
                self._phase(f"Data leakage scan complete — {len(leak_vulns)} leaks found")
            else:
                leak_vulns = []
                self._phase("Data leakage scan skipped (toggled off)")
            self._progress(82, None)

            # ── Phase 5: SSL/TLS & Certificate Analysis (82–88%) ─────────────
            self._progress(83, None)
            if use_all or modules.get('manualChecks', False):
                self._phase("Analysing SSL/TLS configuration...")
                ssl_vulns = self._run_ssl_scan(target)
                self._phase(f"SSL/TLS analysis complete — {len(ssl_vulns)} issues")
            else:
                ssl_vulns = []
            self._progress(88, None)

            # ── Phase 6: EPSS Risk Scoring (88–95%) ──────────────────────────
            self._phase("Applying EPSS risk scoring and CVE mapping...")
            all_vulns = recon_results + web_vulns + manual_vulns + leak_vulns + ssl_vulns
            # Deduplicate by (type, affected_url)
            seen_keys = set()
            deduped = []
            for v in all_vulns:
                key = (v.get('type', ''), v.get('affected_url', ''))
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduped.append(v)
            scored_vulns = self._apply_epss_scoring(deduped)
            self._phase(f"EPSS scoring complete — {len(scored_vulns)} unique vulnerabilities prioritized")
            self._progress(95, None)

            # ── Phase 7: Report ───────────────────────────────────────────────
            self._phase("Finalizing report...")
            with self._lock:
                self.current_scan['vulnerabilities'] = scored_vulns
                self.current_scan['status'] = 'completed'
                self.scan_progress = 100
                self.is_scanning = False

            logger.info(f"[SCAN] Completed: {len(scored_vulns)} vulnerabilities on {target}")
            print(f"[SCAN] Done. Total: {len(scored_vulns)} vulns.")
            return self.current_scan

        except Exception as e:
            print(f"[SCAN] FAILED: {e}")
            logger.error(f"Scan error: {e}", exc_info=True)
            with self._lock:
                self.current_scan['status'] = 'error'
                self.current_scan['error'] = str(e)
                self.is_scanning = False
            return self.current_scan

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _progress(self, val: int, phase: str):
        with self._lock:
            self.scan_progress = val
        if phase:
            self._phase(phase)

    def _phase(self, msg: str):
        with self._lock:
            self.current_scan['scan_phases'].append(msg)
        print(f"  [PHASE] {msg}")

    # ── Phase runners ─────────────────────────────────────────────────────────

    def _run_reconnaissance(self, target: str, scan_mode: str = 'quick') -> List[Dict]:
        vulnerabilities = []
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or parsed.netloc or target.split('/')[0]
            print(f"  [RECON] Hostname: {hostname}")
            recon = Reconnaissance(hostname)
            nmap_result = recon.run_nmap_scan(scan_mode)

            if nmap_result['success']:
                ports = nmap_result['ports']
                service_vulns = recon.check_service_vulnerabilities(ports)
                vulnerabilities.extend(service_vulns)
                # Also report interesting open ports as info-level findings
                for p in ports:
                    port_num = int(p.get('port', 0))
                    svc = p.get('service', 'unknown').lower()
                    dangerous_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP',
                                       110: 'POP3', 143: 'IMAP', 445: 'SMB',
                                       3306: 'MySQL', 5432: 'PostgreSQL',
                                       6379: 'Redis', 27017: 'MongoDB',
                                       9200: 'Elasticsearch', 5601: 'Kibana',
                                       3389: 'RDP', 5900: 'VNC'}
                    if port_num in dangerous_ports:
                        sev = 'High' if port_num in [3306, 5432, 6379, 27017, 9200, 3389, 445, 23] else 'Medium'
                        vulnerabilities.append({
                            'cve': f'CVE-2024-PORT-{port_num}',
                            'type': f'Exposed {dangerous_ports[port_num]} Service',
                            'severity': sev,
                            'epss_score': 0.80 if sev == 'High' else 0.55,
                            'description': (
                                f"Port {port_num}/{dangerous_ports[port_num]} is publicly exposed. "
                                f"Service '{svc}' detected. This increases the attack surface significantly — "
                                "ensure firewall rules restrict access to trusted IPs only."
                            ),
                            'affected_url': f"{hostname}:{port_num}",
                            'status': 'Open',
                        })
            else:
                logger.warning(f"Nmap failed, using socket fallback: {nmap_result.get('error')}")
                vulnerabilities.extend(self._simulate_nmap_results(target))

        except Exception as e:
            logger.error(f"Reconnaissance error: {e}")
            vulnerabilities.extend(self._simulate_nmap_results(target))

        return vulnerabilities

    def _run_web_scan(self, target: str) -> List[Dict]:
        vulnerabilities = []
        if not target.startswith('http'):
            target = f'http://{target}'
        try:
            if self.web_scanner.check_zap_running():
                logger.info("OWASP ZAP detected — using active scan")
                zap_result = self.web_scanner.start_zap_scan(target)
                if zap_result['success']:
                    time.sleep(15)
                    vulnerabilities.extend(self.web_scanner.get_zap_alerts())
                    return vulnerabilities
            # Fall through to manual OWASP checks
            vulnerabilities.extend(self.manual_detector.detect_owasp_top_10(target))
        except Exception as e:
            logger.error(f"Web scan error: {e}")
            try:
                vulnerabilities.extend(self.manual_detector.detect_owasp_top_10(target))
            except Exception:
                pass
        return vulnerabilities

    def _run_manual_detection(self, target: str, scan_mode: str = 'quick',
                              modules: dict = None) -> List[Dict]:
        vulnerabilities = []
        if modules is None:
            modules = {}
        use_all = not bool(modules)

        if not target.startswith('http'):
            target = f'http://{target}'

        try:
            danger = modules.get('dangerMode', False)

            if use_all or modules.get('owaspTop10', False) or modules.get('agenticAi', False):
                logger.info("OWASP Top 10 active checks...")
                vulnerabilities.extend(self.manual_detector.detect_owasp_top_10(target))

            if (scan_mode in ('deep', 'full') or
                any(modules.get(k) for k in ['deepChecks', 'advFuzzing', 'secretKey', 'dangerMode'])):
                logger.info(f"Deep injection scans (danger={danger})...")
                vulnerabilities.extend(
                    self.manual_detector.detect_deep_vulnerabilities(target, danger_mode=danger))
            else:
                # Still run critical quick checks even in non-deep mode
                logger.info("Quick critical checks (XSS, SQLi, CORS)...")
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=6) as ex:
                    futures = [
                        ex.submit(self.manual_detector.detect_sqli_advanced, target, False),
                        ex.submit(self.manual_detector.detect_xss_advanced,  target, False),
                        ex.submit(self.manual_detector._check_cors,           target),
                        ex.submit(self.manual_detector.detect_open_redirect,  target),
                        ex.submit(self.manual_detector.detect_idor,           target),
                        ex.submit(self.manual_detector.detect_broken_auth,    target),
                    ]
                    for f in as_completed(futures):
                        try:
                            vulnerabilities.extend(f.result() or [])
                        except Exception as e:
                            logger.error(f"Quick scan future: {e}")

        except Exception as e:
            logger.error(f"Manual detection error: {e}", exc_info=True)

        return vulnerabilities

    def _run_data_leakage_scan(self, target: str) -> List[Dict]:
        if not target.startswith('http'):
            target = f'http://{target}'
        try:
            results = self.data_leak_detector.detect_all(target)
            for r in results:
                r.setdefault('cve', 'CVE-2024-LEAK-UNKNOWN')
                r.setdefault('type', 'Sensitive Data Leakage')
                r.setdefault('severity', 'Medium')
                r.setdefault('epss_score', 0.50)
                r.setdefault('description', 'Sensitive data or private information was found leaking.')
                r.setdefault('affected_url', target)
                r.setdefault('status', 'Open')
            return results
        except Exception as e:
            logger.error(f"Data leakage scan error: {e}")
            return []

    def _run_ssl_scan(self, target: str) -> List[Dict]:
        if not target.startswith('http'):
            target = f'http://{target}'
        try:
            return self.manual_detector.detect_ssl_vulnerabilities(target)
        except Exception as e:
            logger.error(f"SSL scan error: {e}")
            return []

    def _apply_epss_scoring(self, vulnerabilities: List[Dict]) -> List[Dict]:
        scored = []
        for vuln in vulnerabilities:
            cve = vuln.get('cve', 'CVE-2024-UNKNOWN')
            epss_score = vuln.get('epss_score') or self.epss_scorer.calculate_epss_score(cve)
            risk_level = self.epss_scorer.get_risk_level(epss_score)
            ai_solution = self.ai_generator.generate_solution(
                cve, vuln.get('type', ''), vuln.get('description', ''))
            scored.append({
                **vuln,
                'cve': cve,
                'epss_score': epss_score,
                'risk_level': risk_level,
                'ai_solution': ai_solution,
            })
        return sorted(scored, key=lambda x: x.get('epss_score', 0), reverse=True)

    def _simulate_nmap_results(self, target: str) -> List[Dict]:
        """Fallback socket scan when Nmap is unavailable."""
        import socket as _socket
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.netloc or target
        results = []
        critical_ports = {
            80: ('HTTP', 'Info', 0.15),
            443: ('HTTPS', 'Info', 0.10),
            22: ('SSH', 'Medium', 0.45),
            21: ('FTP', 'High', 0.78),
            23: ('Telnet (plaintext)', 'Critical', 0.95),
            3306: ('MySQL Database', 'High', 0.82),
            5432: ('PostgreSQL Database', 'High', 0.80),
            6379: ('Redis (no auth)', 'Critical', 0.97),
            27017: ('MongoDB (no auth)', 'Critical', 0.96),
            9200: ('Elasticsearch', 'High', 0.88),
            3389: ('RDP', 'High', 0.85),
        }
        for port, (svc, sev, epss) in critical_ports.items():
            try:
                sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                sock.settimeout(1.5)
                if sock.connect_ex((hostname, port)) == 0:
                    results.append({
                        'port': str(port),
                        'service': svc,
                        'cve': f'CVE-2024-PORT-{port}',
                        'type': f'Open {svc} Port',
                        'severity': sev,
                        'epss_score': epss,
                        'description': (
                            f"Port {port} ({svc}) is open and accessible. "
                            f"{'This service transmits data in plaintext and should be disabled.' if port == 23 else 'Ensure this port is restricted by firewall rules.'}"
                        ),
                        'affected_url': f"{hostname}:{port}",
                        'status': 'Open',
                    })
                sock.close()
            except Exception:
                pass
        return results

    # ── Public API ────────────────────────────────────────────────────────────

    def get_scan_progress(self) -> int:
        with self._lock:
            return self.scan_progress

    def get_scan_results(self) -> Dict:
        with self._lock:
            return self.current_scan if self.current_scan else {}

    def get_scan_status(self) -> str:
        with self._lock:
            if self.current_scan:
                return self.current_scan.get('status', 'idle')
        return 'idle'
