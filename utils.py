# Color scheme for UI
COLOR_SCHEME = {
    'background': '#1f3339',
    'text': '#ffffff',
    'critical': '#c01530',
    'high': '#a84b2f',
    'medium': '#62757d',
    'low': '#208a78',
    'success': '#208a78'
}

# OWASP Top 10 vulnerability definitions
OWASP_TOP_10 = {
    'Broken Access Control': {
        'description': 'Users acting outside their intended permissions',
        'affected_url': '/admin',
        'severity': 'Critical'
    },
    'Cryptographic Failures': {
        'description': 'Sensitive data exposed without proper encryption',
        'affected_url': '/api/data',
        'severity': 'Critical'
    },
    'Injection': {
        'description': 'SQL, NoSQL, OS command injection attacks',
        'affected_url': '/search',
        'severity': 'Critical'
    },
    'Insecure Design': {
        'description': 'Missing security controls in application design',
        'affected_url': '/register',
        'severity': 'High'
    },
    'Security Misconfiguration': {
        'description': 'Insecure default configurations and unnecessary features',
        'affected_url': '/config',
        'severity': 'High'
    },
}

# Vulnerability data
VULNERABILITY_DATA = {
    'SQL_INJECTION': {
        'description': 'SQL injection in user input fields',
        'remediation': ['Use parameterized queries', 'Input validation', 'WAF deployment'],
        'affected_url': '/login.php',
        'severity': 'Critical'
    },
    'XSS': {
        'description': 'Cross-Site Scripting vulnerability',
        'remediation': ['Output encoding', 'CSP headers', 'Input sanitization'],
        'affected_url': '/search',
        'severity': 'High'
    },
    'CSRF': {
        'description': 'Cross-Site Request Forgery',
        'remediation': ['CSRF tokens', 'SameSite cookies', 'Referer validation'],
        'affected_url': '/transfer',
        'severity': 'High'
    },
    'BROKEN_AUTH': {
        'description': 'Broken authentication mechanisms',
        'remediation': ['Enforce strong passwords', 'MFA', 'Secure session management'],
        'affected_url': '/admin',
        'severity': 'Critical'
    },
    'IDOR': {
        'description': 'Insecure direct object reference',
        'remediation': ['Authorization checks', 'Access control lists', 'Indirect references'],
        'affected_url': '/api/user/{id}',
        'severity': 'High'
    }
}

# Remediation templates
REMEDIATION_STEPS = {
    'SQL Injection': [
        'Use parameterized queries or prepared statements',
        'Implement input validation and whitelist allowed characters',
        'Deploy Web Application Firewall (WAF)',
        'Conduct code review and security testing',
        'Update database frameworks to latest versions'
    ],
    'XSS': [
        'Implement output encoding (HTML, JavaScript, URL)',
        'Set Content Security Policy (CSP) headers',
        'Sanitize user input on both client and server side',
        'Use security headers (X-XSS-Protection, X-Content-Type-Options)',
        'Validate all input and output'
    ],
    'Broken Authentication': [
        'Enforce strong password policies',
        'Implement Multi-Factor Authentication (MFA)',
        'Secure session management with proper timeout',
        'Use OAuth 2.0 or SAML where applicable',
        'Implement account lockout after failed attempts'
    ],
}

def get_remediation_steps(vulnerability_type: str) -> list:
    """Get remediation steps for vulnerability type"""
    return REMEDIATION_STEPS.get(vulnerability_type, ['Contact security team for remediation guidance'])

def severity_to_points(severity: str) -> int:
    """Convert severity level to risk points"""
    severity_map = {
        'Critical': 5,
        'High': 4,
        'Medium': 3,
        'Low': 2,
        'Info': 1
    }
    return severity_map.get(severity, 0)

def calculate_overall_risk(vulnerabilities: list) -> float:
    """Calculate overall risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 0.0
    
    total_points = sum(severity_to_points(v[3]) for v in vulnerabilities)
    max_points = len(vulnerabilities) * 5
    
    return (total_points / max_points) * 100 if max_points > 0 else 0.0
