class RiskEngine:
    """
    Evaluates the overall risk of an email by aggregating scores
    from various analyzers (URLs, headers, attachments).
    """

    def __init__(self, results_dict):
        """
        Accepts a dictionary of all analyzer results for dynamic, weighted scoring.
        """
        self.results = results_dict
        self.total_score = 0
        self.risk_level = "LOW"
        self.recommendation = ""
        self.confidence_level = 0.0

    def _has_findings(self, data):
        """Helper to determine if a specific subsystem found threats."""
        if isinstance(data, list):
            return any(d.get("findings") for d in data)
        elif isinstance(data, dict):
            return bool(data.get("findings"))
        return False

    def calculate_risk(self):
        """
        Aggregates the scores using calculated weights simulating SOC severity matrices.
        """
        # Module Weights - Simulating enterprise security threat modeling
        weights = {
            "attachments": 1.5,   # Highly dangerous (Malware payloads)
            "brand": 1.4,         # Core phishing tactic
            "headers": 1.2,       # Spoofed headers
            "html": 1.2,          # Concealed payloads
            "domains": 1.1,       # Evasion
            "urls": 1.0           
        }

        # Aggregate weighted scores
        for url_res in self.results.get('urls', []):
            self.total_score += (url_res.get("score", 0) * weights["urls"])
            
        self.total_score += (self.results.get('domains', {}).get("score", 0) * weights["domains"])
        self.total_score += (self.results.get('brand', {}).get("score", 0) * weights["brand"])
        self.total_score += (self.results.get('html', {}).get("score", 0) * weights["html"])
        self.total_score += (self.results.get('headers', {}).get("score", 0) * weights["headers"])
        self.total_score += (self.results.get('attachments', {}).get("score", 0) * weights["attachments"])

        self.total_score = round(self.total_score, 1)

        # Confidence Level Assessment
        modules_flagged = sum(1 for res in self.results.values() if self._has_findings(res))
        total_modules = 6
        self.confidence_level = min(100.0, (modules_flagged / total_modules) * 100 + (self.total_score * 2.5))
        self.confidence_level = round(self.confidence_level, 1)

        # Output threat categorization
        if self.total_score == 0:
            self.risk_level = "SAFE"
            self.recommendation = "No suspicious indicators found. Proceed with standard caution."
        elif self.total_score <= 5:
            self.risk_level = "LOW (Suspicious)"
            self.recommendation = "Low risk detected. Verify the sender proactively before clicking any links."
        elif self.total_score <= 15:
            self.risk_level = "MEDIUM (Elevated Threat)"
            self.recommendation = "Multiple suspicious indicators found. Highly likely to be a phishing attempt. Quarantine."
        else:
            self.risk_level = "CRITICAL (Active Threat)"
            self.recommendation = "Severe threat indicators (Spoofed header/Brand impersonation/Malicious Attachment). Immediate block and purge recommended."

        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "confidence": self.confidence_level
        }
