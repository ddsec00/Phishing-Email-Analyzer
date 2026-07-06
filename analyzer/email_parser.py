"""
email_parser.py

This module is responsible for reading an email (.eml) file
and converting it into a structured Python object.

Every other analysis module will use the information
produced here.
"""

from email import policy
from email.parser import BytesParser

class EmailParser:
    """
    Reads an email file and extracts its contents.
    """

    def __init__(self, file_path):
        """
        Save the location of the email file.
        """
        self.file_path = file_path
    def load_email(self):
        """
        Open the email file and convert it into
        a Python email object.
        """

        with open(self.file_path, "rb") as email_file:

            email = BytesParser(
                policy=policy.default
            ).parse(email_file)

        return email