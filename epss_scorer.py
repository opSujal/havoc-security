import hashlib
import random
from typing import Dict, List

class EPSSScorer:
    """Implements EPSS-like vulnerability scoring"""
    
    def __init__(self):
        random.seed(42)
    
    def calculate_epss_score(self, cve: str) -> float:
        """Calculate EPSS score for a CVE (0-1 scale)"""
        cve_hash = int(hashlib.md5(cve.encode()).hexdigest(), 16)
        base_score = (cve_hash % 100) / 100.0
        
        year = int(cve.split('-')[1])
        recency_factor = 1.0 if year >= 2024 else 0.8
        
        epss_score = min(base_score * recency_factor, 0.99)
        
        return round(epss_score, 2)
    
    def score_multiple_vulnerabilities(self, cve_list: List[str]) -> List[Dict]:
        """Score multiple CVEs and return sorted by EPSS"""
        results = []
        
        for cve in cve_list:
            epss = self.calculate_epss_score(cve)
            results.append({
                'cve': cve,
                'epss_score': epss,
                'risk_level': self.get_risk_level(epss)
            })
        
        return sorted(results, key=lambda x: x['epss_score'], reverse=True)
    
    def get_risk_level(self, epss_score: float) -> str:
        """Convert EPSS score to risk level"""
        if epss_score >= 0.80:
            return 'CRITICAL'
        elif epss_score >= 0.60:
            return 'HIGH'
        elif epss_score >= 0.40:
            return 'MEDIUM'
        elif epss_score >= 0.20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def get_exploitation_likelihood(self, epss_score: float) -> str:
        """Get exploitation likelihood description"""
        if epss_score >= 0.85:
            return 'Very Likely to be Exploited'
        elif epss_score >= 0.60:
            return 'Likely to be Exploited'
        elif epss_score >= 0.40:
            return 'Possible to be Exploited'
        elif epss_score >= 0.20:
            return 'Unlikely to be Exploited'
        else:
            return 'Very Unlikely to be Exploited'
