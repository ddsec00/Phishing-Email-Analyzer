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
        Returns a capped integer score out of 100.
        """
        # Module Weights - Simulating enterprise security threat modeling
        weights = {
            "attachments": 3,
            "brand": 2.5,
            "headers": 2,
            "html": 2,
            "domains": 1.5,
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

        # Convert to an intuitive 0-100 scale (Assuming a max raw score is around 40-50 in worst cases)
        scaled_score = int(min(100, self.total_score * 2))

        # Confidence Level Assessment
        modules_flagged = sum(1 for res in self.results.values() if self._has_findings(res))
        total_modules = 6
        
        # We rename to Detection Confidence because we are not using AI models.
        # It represents how much of the email triggered our static rule modules.
        confidence_level = int(min(100.0, (modules_flagged / total_modules) * 100))

        # Output threat categorization
        recommendations = []
        if scaled_score == 0:
            self.risk_level = "SAFE"
            recommendations = ["• Allow email to inbox"]
        elif scaled_score <= 30:
            self.risk_level = "LOW (Suspicious)"
            recommendations = [
                "• Deliver to Junk/Spam folder",
                "• Append '[EXTERNAL]' warning to subject",
                "• Monitor sender reputation"
            ]
        elif scaled_score <= 70:
            self.risk_level = "MEDIUM (Elevated Threat)"
            recommendations = [
                "• Quarantine the email",
                "• Prevent user interaction",
                "• Remove clickable links (Defang)",
                "• Investigate similar emails"
            ]
        else:
            self.risk_level = "CRITICAL (Active Threat)"
            recommendations = [
                "• Block the sender immediately",
                "• Purge email from all user inboxes",
                "• Notify the security team (SOC)",
                "• Search for additional indicators (Threat Hunting)"
            ]

        return {
            "threat_score": scaled_score,
            "max_score": 100,
            "risk_level": self.risk_level,
            "recommendations": recommendations,
            "confidence": confidence_level
        }
