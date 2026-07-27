import re
from html.parser import HTMLParser

class PhishingHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.findings = []
        self.score = 0
        self.current_tag = None
        self.current_href = None

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        attrs_dict = dict(attrs)
        
        # Determine if text is being hidden 
        if tag in ["div", "span", "p"]:
            style = attrs_dict.get("style", "").lower()
            if "display:none" in style or "visibility:hidden" in style or "opacity:0" in style:
                self.score += 2
                self.findings.append("HTML Evasion: Invisible text/elements detected (Could be bypassing spam filters).")
                
        if tag == "a":
            self.current_href = attrs_dict.get("href", "")

    def handle_data(self, data):
        # Mismatched anchor detection: Visible text looks like URL but href is something else
        if self.current_tag == "a" and self.current_href:
            text = data.strip().lower()
            if text.startswith("http") and not text.startswith(self.current_href.lower()):
                self.score += 5
                self.findings.append(f"Critical HTML Evasion: Anchor link mismatch. User sees '{text}' but links to '{self.current_href}'.")

    def handle_endtag(self, tag):
        self.current_tag = None
        if tag == "a":
            self.current_href = None

class HTMLAnalyzer:
    """
    Parses complex HTML structures within emails to detect rendering evasions.
    """
    def __init__(self, html_content):
        self.html_content = html_content

    def analyze(self):
        if not self.html_content:
            return {"score": 0, "findings": []}
            
        parser = PhishingHTMLParser()
        try:
            parser.feed(self.html_content)
        except Exception:
            pass # We catch general exceptions because of poorly malformed phishing HTML
            
        return {"score": parser.score, "findings": list(set(parser.findings))}
