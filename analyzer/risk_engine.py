class RiskEngine:
    """
    Evaluates the risk of an email using a deterministic scoring model.
    Each indicator contributes a specific point value.
    Scores above 50 are considered Suspicious, above 75 are Critical.
    """

    def __init__(self, results_dict):
        """
        results_dict: Contains the findings from all analyzers.
        """
        self.results = results_dict
        self.total_score = 0
        self.risk_level = "LOW"
        self.explanations = []

    def calculate_risk(self):
        """
        Dynamically calculate risk using fixed weights for specific findings.
        Returns a score out of 100 with category explanations.
        """
        # Indicator scoring weights
        # Note: In a future commit, we will move these to a configuration file.
        weights = {
            "suspicious_domain": 10,
            "spf_failure": 15,
            "executable_attachment": 30,
            "brand_impersonation": 20,
            "obfuscated_url": 15,
            "generic_threat": 5
        }

        # Header findings (SPF, DKIM, DMARC)
        headers = self.results.get('headers', {})
        if headers.get('score', 0) > 0:
            self.total_score += weights["spf_failure"]
            self.explanations.append(f"Header Authentication Failure (+{weights['spf_failure']})")
            
        # Domain findings
        domains = self.results.get('domains', {})
        if domains.get('score', 0) > 0:
            self.total_score += weights["suspicious_domain"]
            self.explanations.append(f"Suspicious Domain Found (+{weights['suspicious_domain']})")
            
        # Brand Impersonation
        brand = self.results.get('brand', {})
        if brand.get('score', 0) > 0:
            self.total_score += weights["brand_impersonation"]
            self.explanations.append(f"Brand Impersonation Detected (+{weights['brand_impersonation']})")
            
        # HTML/URL findings
        html = self.results.get('html', {})
        if html.get('score', 0) > 0 or any(u.get('score', 0) > 0 for u in self.results.get('urls', [])):
            self.total_score += weights["obfuscated_url"]
            self.explanations.append(f"Suspicious/Obfuscated Link (+{weights['obfuscated_url']})")

        # Attachment findings
        attachments = self.results.get('attachments', {})
        if attachments.get('score', 0) > 0:
            self.total_score += weights["executable_attachment"]
            self.explanations.append(f"Dangerous Attachment (+{weights['executable_attachment']})")

        # Cap the score safely at 100
        final_score = int(min(self.total_score, 100))

        if final_score < 30:
            self.risk_level = "LOW (Safe)"
        elif final_score < 75:
            self.risk_level = "MEDIUM (Suspicious)"
        else:
            self.risk_level = "CRITICAL (Action Required)"

        return {
            "score": final_score,
            "level": self.risk_level,
            "factors": self.explanations
        }
