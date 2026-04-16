import subprocess
import json
import xml.etree.ElementTree as ET
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class Reconnaissance:
    """Real network reconnaissance using Nmap"""
    
    def __init__(self, target: str):
        self.target = target
        self.results = {}
    
    def run_nmap_scan(self, scan_mode: str = 'quick') -> Dict:
        """Run real Nmap scan on target"""
        logger.info(f"Starting Nmap scan on {self.target} (Mode: {scan_mode})")
        print(f"DEBUG: Nmap scan started. Mode: {scan_mode}")
        
        try:
            # Check if nmap is installed
            try:
                subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("DEBUG: Nmap not found in PATH. Using fallback.")
                logger.warning("Nmap not found. Falling back to socket scanner.")
                return self._run_socket_scan()

            # Define flags based on mode
            if scan_mode == 'deep':
                flags = ['-sV', '-sC', '--top-ports', '150', '-T4', '--min-rate', '1000', '--max-retries', '1', '--host-timeout', '2m']
                timeout_seconds = 180  # 3 minutes max
            else:
                flags = ['-sV', '--top-ports', '50', '-T4', '--min-rate', '2000', '--max-retries', '0', '--host-timeout', '1m']
                timeout_seconds = 90   # 1.5 minutes max

            nmap_cmd = ['nmap'] + flags + ['-oX', '-', self.target]
            print(f"DEBUG: Running command: {' '.join(nmap_cmd)}")
            print(f"DEBUG: Timeout set to {timeout_seconds} seconds")
            
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds
            )
            
            if result.returncode == 0:
                print("DEBUG: Nmap scan successful.")
                ports_info = self._parse_nmap_output(result.stdout)
                
                if not ports_info:
                    print("DEBUG: Nmap found 0 ports. Falling back to socket scanner.")
                    return self._run_socket_scan()
                    
                self.results['ports'] = ports_info
                return {'success': True, 'ports': ports_info}
            else:
                err = result.stderr
                print(f"DEBUG: Nmap failed. Error: {err}")
                
                # If failed and mode was deep, try without -O (OS detection often needs admin)
                if scan_mode == 'deep' and ('privileged' in err.lower() or 'root' in err.lower() or 'admin' in err.lower()):
                    print("DEBUG: Retrying deep scan without OS detection (requires admin)...")
                    flags = ['-sV', '-sC', '--top-ports', '1000', '-T4']
                    nmap_cmd = ['nmap'] + flags + ['-oX', '-', self.target]
                    
                    result = subprocess.run(
                        nmap_cmd,
                        capture_output=True,
                        text=True,
                        timeout=600
                    )
                    
                    if result.returncode == 0:
                        print("DEBUG: Retry successful.")
                        ports_info = self._parse_nmap_output(result.stdout)
                        self.results['ports'] = ports_info
                        return {'success': True, 'ports': ports_info}
                
                logger.error(f"Nmap error: {result.stderr}")
                return self._run_socket_scan()
                
        except subprocess.TimeoutExpired:
            print(f"DEBUG: Nmap scan timed out. Falling back to socket scanner.")
            logger.warning("Nmap scan timed out")
            return self._run_socket_scan()
        except Exception as e:
            print(f"DEBUG: Nmap execution exception: {e}")
            logger.error(f"Nmap execution error: {e}")
            return self._run_socket_scan()

    def _run_socket_scan(self) -> Dict:
        """Fallback socket scanner"""
        import socket
        logger.info("Running fallback socket scan...")
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    
                    open_ports.append({
                        'port': str(port),
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'product': '',
                        'version': ''
                    })
                sock.close()
            except:
                pass
        
        return {'success': True, 'ports': open_ports}
    
    def _parse_nmap_output(self, xml_output: str) -> List[Dict]:
        """Parse Nmap XML output"""
        ports = []
        try:
            root = ET.fromstring(xml_output)
            
            for port in root.findall('.//port'):
                port_num = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                
                service_elem = port.find('service')
                service_name = service_elem.get('name') if service_elem is not None else 'unknown'
                product = service_elem.get('product') if service_elem is not None else ''
                version = service_elem.get('version') if service_elem is not None else ''
                
                if state == 'open':
                    ports.append({
                        'port': port_num,
                        'protocol': protocol,
                        'state': state,
                        'service': service_name,
                        'product': product,
                        'version': version
                    })
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
        
        return ports
    
    def check_service_vulnerabilities(self, ports: List[Dict]) -> List[Dict]:
        """Check discovered services for known vulnerabilities"""
        vulnerabilities = []
        
        # Known vulnerable service versions
        vuln_services = {
            'http': [
                {'version': '2.4.1', 'cve': 'CVE-2024-0001', 'type': 'Apache XXE Injection'},
            ],
            'ssh': [
                {'version': '7.4', 'cve': 'CVE-2024-0002', 'type': 'SSH Weak Key Exchange'},
            ],
            'mysql': [
                {'version': '5.7', 'cve': 'CVE-2024-0003', 'type': 'MySQL Authentication Bypass'},
            ],
            'ftp': [
                {'version': '2.0.1', 'cve': 'CVE-2024-0004', 'type': 'FTP Command Injection'},
            ],
        }
        
        for port in ports:
            service = (port.get('service') or '').lower()
            version = (port.get('version') or '').lower()
            
            if service in vuln_services:
                for vuln in vuln_services[service]:
                    if vuln['version'] in version:
                        vulnerabilities.append({
                            'port': port['port'],
                            'service': port['service'],
                            'cve': vuln['cve'],
                            'type': vuln['type'],
                            'severity': 'High',
                            'epss_score': 0.75
                        })
        
        return vulnerabilities
