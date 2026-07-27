class ReportGenerator:
    """
    Generates a professional text-based report from the aggregated
    analysis results.
    """

    def __init__(self, email_info, analysis_results, risk_summary):
        self.email_info = email_info
        self.results = analysis_results
        self.risk_summary = risk_summary

    def _format_email_info(self):
        """Formats the basic email metadata."""
        return (
            "[ EMAIL METADATA ]\n"
            f"  > From: {self.email_info.get('From', 'Unknown')}\n"
            f"  > Subject: {self.email_info.get('Subject', 'No Subject')}\n"
            f"  > Date: {self.email_info.get('Date', 'Unknown')}\n"
        )
        
    def _format_section(self, title, data, is_list=False):
        """Standardized SOC output format for different modules."""
        lines = [f"[ {title} ]"]
        has_findings = False
        
        if is_list:
            if not data:
                pass
            else:
                for item in data:
                    if item.get("findings"):
                        has_findings = True
                        lines.append(f"  Target: {item.get('url', 'Unknown')}")
                        for finding in item.get("findings"):
                            lines.append(f"    [!] {finding}")
        else:
            if data and data.get("findings"):
                has_findings = True
                for finding in data.get("findings"):
                    lines.append(f"  [!] {finding}")
                    
        if not has_findings:
            lines.append("  [OK] No anomalies detected.")
            
        return "\n".join(lines).strip()

    def generate(self):
        """
        Assembles all components into a SOC-style incident report string.
        """
        divider = "-" * 60
        major_divider = "=" * 60

        report = (
            f"\n{major_divider}\n"
            f"*** SOC PHISHING THREAT INTEL REPORT ***\n"
            f"{major_divider}\n\n"
            
            f"{self._format_email_info()}\n\n"
            f"{divider}\n"
            "THREAT INDICATORS (IOCs)\n"
            f"{divider}\n\n"
            
            f"{self._format_section('AUTHENTICATION & HEADERS', self.results.get('headers'))}\n\n"
            f"{self._format_section('BRAND IMPERSONATION', self.results.get('brand'))}\n\n"
            f"{self._format_section('DOMAIN ANOMALIES', self.results.get('domains'))}\n\n"
            f"{self._format_section('HTML PAYLOAD', self.results.get('html'))}\n\n"
            f"{self._format_section('URL OBFUSCATION', self.results.get('urls'), is_list=True)}\n\n"
            f"{self._format_section('ATTACHMENT RISKS', self.results.get('attachments'))}\n\n"
            
            f"{divider}\n"
            "THREAT ASSESSMENT SUMMARY\n"
            f"{divider}\n\n"
            
            f"  RISK LEVEL      : {self.risk_summary['risk_level']}\n"
            f"  THREAT SCORE    : {self.risk_summary['total_score']}\n"
            f"  AI CONFIDENCE   : {self.risk_summary['confidence']}%\n\n"
            f"  RECOMMENDATION  : {self.risk_summary['recommendation']}\n"
            f"{major_divider}\n"
        )
        return report
