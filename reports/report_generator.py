class ReportGenerator:
    """
    Generates a professional text-based report from the aggregated
    analysis results.
    """

    def __init__(self, email_info, url_results, header_result, attachment_result, risk_summary):
        self.email_info = email_info
        self.url_results = url_results
        self.header_result = header_result
        self.attachment_result = attachment_result
        self.risk_summary = risk_summary

    def _format_email_info(self):
        """Formats the basic email metadata."""
        return (
            "Email Information\n"
            "-----------------\n"
            f"From: {self.email_info.get('From', 'Unknown')}\n"
            f"Subject: {self.email_info.get('Subject', 'No Subject')}\n"
            f"Date: {self.email_info.get('Date', 'Unknown')}\n"
        )

    def _format_url_analysis(self):
        """Formats the URL analysis findings."""
        lines = ["URL Analysis"]
        
        if not self.url_results:
            lines.append("✓ No URLs found.")
        else:
            for result in self.url_results:
                lines.append(f"✓ URL: {result['url']}")
                lines.append(f"  Score: {result['score']}")
                for finding in result.get("findings", []):
                    lines.append(f"  - {finding}")
                lines.append("") # Empty line for spacing
                
        return "\n".join(lines).strip()

    def _format_header_analysis(self):
        """Formats the header analysis findings."""
        lines = ["Header Analysis"]
        
        if not self.header_result.get("findings"):
            lines.append("✓ No suspicious header indicators.")
        else:
            lines.append(f"Score: {self.header_result.get('score', 0)}")
            for finding in self.header_result.get("findings", []):
                lines.append(f"✓ {finding}")
                
        return "\n".join(lines).strip()

    def _format_attachment_analysis(self):
        """Formats the attachment analysis findings."""
        lines = ["Attachment Analysis"]
        
        if not self.attachment_result.get("attachments") and not self.attachment_result.get("findings"):
            lines.append("✓ No attachments found or no suspicious findings.")
        else:
            lines.append(f"Score: {self.attachment_result.get('score', 0)}")
            for att in self.attachment_result.get("attachments", []):
                lines.append(f"✓ File: {att}")
            for finding in self.attachment_result.get("findings", []):
                lines.append(f"✓ {finding}")

        return "\n".join(lines).strip()

    def generate(self):
        """
        Assembles all components into a single formatted string.
        """
        divider = "-" * 36
        major_divider = "=" * 52

        report = (
            f"{major_divider}\n"
            "PHISHING EMAIL ANALYSIS REPORT\n"
            f"{major_divider}\n\n"
            f"{self._format_email_info()}\n"
            f"{divider}\n\n"
            f"{self._format_url_analysis()}\n\n"
            f"{divider}\n\n"
            f"{self._format_header_analysis()}\n\n"
            f"{divider}\n\n"
            f"{self._format_attachment_analysis()}\n\n"
            f"{divider}\n\n"
            "OVERALL RISK\n\n"
            f"{self.risk_summary['risk_level']}\n\n"
            f"Total Score: {self.risk_summary['total_score']}\n\n"
            "Recommendation\n\n"
            f"{self.risk_summary['recommendation']}\n"
        )
        return report
