import re


class URLExtractor:
    """
    Extracts URLs from an email body.
    """

    URL_PATTERN = r"https?://[^\s<>\"']+"

    def __init__(self, body):
        self.body = body

    def extract(self):
        """
        Return all URLs found in the email body.
        """
        return re.findall(self.URL_PATTERN, self.body)