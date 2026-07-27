class BrandAnalyzer:
    """
    Detects brand impersonation by cross-referencing Display Names with
    sending email domains.
    """
    def __init__(self, email_data):
        self.email_data = email_data
        
        # Dictionary of high value targets often impersonated
        self.brands = {
            "microsoft": ["microsoft.com", "onmicrosoft.com"],
            "amazon": ["amazon.com", "aws.com"],
            "paypal": ["paypal.com"],
            "google": ["google.com", "gmail.com", "googleapis.com"],
            "apple": ["apple.com", "icloud.com"],
            "support": [] # Generic high-risk word in display names
        }

    def analyze(self):
        score = 0
        findings = []
        from_header = self.email_data.get("From", "").lower()
        sender_email = ""
        display_name = ""
        
        # The from_header might look like: "Microsoft Support" <support@evil.xyz>
        if "<" in from_header:
            parts = from_header.split("<")
            display_name = parts[0].strip().replace('"', '')
            sender_email = parts[1].replace(">", "").strip()
        else:
            sender_email = from_header.strip()
            
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        
        # 1. Compare Display Name vs Known Brands
        for brand, valid_domains in self.brands.items():
            if brand in display_name or brand in sender_email.split("@")[0]:
                # If they claim to be a brand, check if the domain is legit
                if valid_domains and sender_domain not in valid_domains:
                    score += 5  # High severity
                    findings.append(f"Brand Impersonation: Claims identity '{brand.title()}' but sent from '{sender_domain}'.")

        return {"score": score, "findings": list(set(findings))}
