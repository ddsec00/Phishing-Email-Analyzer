import urllib.parse

class DomainAnalyzer:
    """
    Analyzes hostnames and domains to detect phishing architectures.
    """
    
    def __init__(self):
        # We use a 'set' to store keywords. In Python, sets are highly optimized
        # hash tables offering O(1) average time complexity for lookups.
        self.suspicious_keywords = {
            "login", "secure", "account", "update", "verify", 
            "support", "billing", "auth", "microsoft", "apple", "google"
        }
        
        # We use a threshold to determine what constitutes "too many" subdomains.
        self.subdomain_threshold = 2

    def _extract_hostname(self, url: str) -> str:
        """
        Extracts the hostname from a raw URL.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            # If the URL doesn't have a protocol (e.g. just 'example.com'), 
            # netloc might be empty, so we defensively fall back to the path.
            hostname = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
            return hostname.lower()
        except Exception:
            return ""

    def _parse_domain(self, hostname: str) -> tuple:
        """
        Separates subdomains from the registered domain.
        Returns: (subdomains: list, registered_domain: str)
        """
        if not hostname:
            return [], ""
            
        parts = hostname.split('.')
        
        # If it's a simple IP address or a top-level domain (like example.com)
        # it has 2 or fewer parts. There are no subdomains to extract.
        if len(parts) <= 2:
            return [], hostname
            
        # We assume the last two parts constitute the registered domain (e.g., example.com)
        # We slice the list to get everything before the last two parts as subdomains.
        registered_domain = f"{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-2]
        
        return subdomains, registered_domain

    def analyze(self, urls: list) -> dict:
        """
        Analyzes a list of URLs for subdomain abuse.
        """
        score = 0
        findings = []
        
        for url in urls:
            hostname = self._extract_hostname(url)
            subdomains, registered_domain = self._parse_domain(hostname)
            
            if len(subdomains) > self.subdomain_threshold:
                penalty = len(subdomains) - self.subdomain_threshold
                score += penalty
                findings.append(f"Domain Anomalies: Excessive subdomains detected in {hostname}")
                
            for sub in subdomains:
                for keyword in self.suspicious_keywords:
                    if keyword in sub.lower():
                        score += 2
                        findings.append(f"Domain Anomalies: Suspicious keyword '{keyword}' in subdomain: {sub}. Likely impersonation attempt.")
                        
        return {"score": score, "findings": findings}
