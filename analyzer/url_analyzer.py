import os
import re
import json
from urllib.parse import urlparse


class URLAnalyzer:
    """
    Analyzes URLs and identifies
    suspicious characteristics.
    """

    def __init__(self, urls):
        self.urls = urls
        
        self.SUSPICIOUS_KEYWORDS = []
        self.SHORTENERS = []
        self.SUSPICIOUS_TLDS = []
        
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'rules.json')
        if os.path.exists(rules_path):
            with open(rules_path, 'r') as f:
                rules = json.load(f)
                self.SUSPICIOUS_KEYWORDS = rules.get('suspicious_keywords', [])
                self.SHORTENERS = rules.get('url_shorteners', [])
                self.SUSPICIOUS_TLDS = rules.get('suspicious_tlds', [])


    def analyze(self):
        results = []
        for url in self.urls:
            findings = []
            score = 0
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            lower_url = url.lower()

            # URL Obfuscation Detection
            if "@" in domain:
                findings.append("URL Obfuscation: '@' symbol used to hide true destination domain.")
                score += 4
                
            if "%" in url:
                findings.append("URL Obfuscation: Hexadecimal encoding detected in URL.")
                score += 1
                
            if len(url) > 150:
                findings.append("URL Obfuscation: Extremely long URL (Possible evasion attempt).")
                score += 2

            # Check keywords
            for keyword in self.SUSPICIOUS_KEYWORDS:
                if keyword in lower_url:
                    findings.append(f"Suspicious keyword: {keyword}")
                    score += 1

            # Check IP address (avoid DNS lookup)
            if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
                findings.append("URL uses IP address instead of domain")
                score += 2

            # Check URL shortener
            if domain in self.SHORTENERS:
                findings.append("URL shortener detected")
                score += 2

            # Check TLD
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    findings.append(f"Suspicious TLD: {tld}")
                    score += 1

            results.append({
                "url": url,
                "score": score,
                "findings": findings
            })

        return results