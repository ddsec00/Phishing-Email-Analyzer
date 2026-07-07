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

                sender_domain = (
                    sender_email.split("@")[-1]
                )

                reply_domain = (
                    reply_email.split("@")[-1]
                )


                if sender_domain != reply_domain:

                    findings.append(
                        "Reply-To domain differs from sender"
                    )

                    score += 3



        return {
            "score": score,
            "findings": findings
        }