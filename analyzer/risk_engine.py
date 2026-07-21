class RiskEngine:
    """
    Evaluates the overall risk of an email by aggregating scores
    from various analyzers (URLs, headers, attachments).
    """

    def __init__(self, url_results, header_result, attachment_result):
        self.url_results = url_results
        self.header_result = header_result
        self.attachment_result = attachment_result
        self.total_score = 0
        self.risk_level = "LOW"
        self.recommendation = ""

    def calculate_risk(self):
        """
        Aggregates the scores and determines the overall risk level.
        """
        # 1. Aggregate URL scores
        for result in self.url_results:
            self.total_score += result.get("score", 0)
        
        # 2. Add Header score
        self.total_score += self.header_result.get("score", 0)
        
        # 3. Add Attachment score
        self.total_score += self.attachment_result.get("score", 0)

        # Determine risk level based on the total score
        if self.total_score == 0:
            self.risk_level = "SAFE"
            self.recommendation = "No suspicious indicators found. Proceed with normal caution."
        elif self.total_score <= 3:
            self.risk_level = "LOW"
            self.recommendation = "Low risk detected. Be careful before clicking any links."
        elif self.total_score <= 7:
            self.risk_level = "MEDIUM"
            self.recommendation = "Suspicious indicators found. Do not interact unless confirmed safe."
        else:
            self.risk_level = "HIGH"
            self.recommendation = "Do not interact with this email. Report it to your security team."

        return {
            "total_score": self.total_score,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation
        }
