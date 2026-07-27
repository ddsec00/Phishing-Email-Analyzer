from email.utils import parseaddr


class HeaderAnalyzer:
    """
    Analyzes email headers for
    phishing indicators.
    """

    def __init__(self, email_data):
        self.email = email_data


    def analyze(self):

        findings = []
        score = 0


        # Check required headers

        required_headers = [
            "From",
            "To",
            "Subject",
            "Date"
        ]


        for header in required_headers:

            if not self.email.get(header):

                findings.append(
                    f"Missing header: {header}"
                )

                score += 1



        # Analyze From address

        sender_name, sender_email = parseaddr(
            self.email.get("From", "")
        )


        if sender_email:

            domain = sender_email.split("@")[-1]


            if domain.count(".") == 0:

                findings.append(
                    "Suspicious sender domain"
                )

                score += 2



        # Check Reply-To mismatch
        reply_to = self.email.get("Reply-To")
        if reply_to:
            _, reply_email = parseaddr(reply_to)

            if reply_email and sender_email:
                sender_domain = sender_email.split("@")[-1]
                reply_domain = reply_email.split("@")[-1]

                if sender_domain != reply_domain:
                    findings.append("Header Evasion: Reply-To domain differs from sender")
                    score += 3

        # Parse Authentication Results (SPF, DKIM, DMARC)
        message_obj = self.email.get("message")
        auth_results = message_obj.get_all("Authentication-Results", []) if message_obj else []
        auth_str = " ".join(auth_results).lower()
        
        if auth_results:
            # Look for explicit failures
            if "spf=fail" in auth_str or "spf=softfail" in auth_str:
                findings.append("Authentication Failure: SPF Check Failed (Sender IP not authorized by domain).")
                score += 4
            if "dkim=fail" in auth_str:
                findings.append("Authentication Failure: DKIM Check Failed (Message integrity compromised).")
                score += 4
            if "dmarc=fail" in auth_str:
                findings.append("Authentication Failure: DMARC Policy Evaluation Failed.")
                score += 5
        else:
            findings.append("Authentication Warning: Missing Authentication-Results header (Suspicious for modern email).")
            score += 2

        return {
            "score": score,
            "findings": findings
        }