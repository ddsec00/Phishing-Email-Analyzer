import re
from urllib.parse import urlparse


class URLAnalyzer:
    """
    Analyzes URLs and identifies
    suspicious characteristics.
    """

    SUSPICIOUS_KEYWORDS = [
        "login",
        "verify",
        "verification",
        "secure",
        "update",
        "account",
        "password",
        "confirm",
        "billing",
    ]

    SHORTENERS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
    ]

    SUSPICIOUS_TLDS = [
        ".xyz",
        ".top",
        ".click",
        ".ru",
    ]


    def __init__(self, urls):
        self.urls = urls


    def analyze(self):

        results = []

        for url in self.urls:

            findings = []
            score = 0

            parsed = urlparse(url)

            domain = parsed.netloc.lower()


            # Check keywords
            for keyword in self.SUSPICIOUS_KEYWORDS:

                if keyword in url.lower():
                    findings.append(
                        f"Suspicious keyword: {keyword}"
                    )

                    score += 1


            # Check IP address
            if re.match(
                r"https?://\d+\.\d+\.\d+\.\d+",
                url
            ):

                findings.append(
                    "URL uses IP address instead of domain"
                )

                score += 2


            # Check URL shortener

            if domain in self.SHORTENERS:

                findings.append(
                    "URL shortener detected"
                )

                score += 2


            # Check TLD

            for tld in self.SUSPICIOUS_TLDS:

                if domain.endswith(tld):

                    findings.append(
                        f"Suspicious TLD: {tld}"
                    )

                    score += 1


            results.append(
                {
                    "url": url,
                    "score": score,
                    "findings": findings
                }
            )


        return results