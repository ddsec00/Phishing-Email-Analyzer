from email import policy
from email.parser import BytesParser


class EmailParser:
    """
    Responsible only for reading an email file
    and returning structured email data.
    """

    def __init__(self, file_path):
        self.file_path = file_path

    def load_email(self):
        """
        Read the email file and return
        a dictionary containing the
        important information.
        """

        with open(self.file_path, "rb") as email_file:
            message = BytesParser(
                policy=policy.default
            ).parse(email_file)

        body = ""

        if message.is_multipart():

            for part in message.walk():

                content_type = part.get_content_type()

                disposition = str(
                    part.get("Content-Disposition")
                )

                if (
                    content_type == "text/plain"
                    and "attachment" not in disposition
                ):
                    body = part.get_content()
                    break

                elif content_type == "text/html":
                    if body == "":
                        body = part.get_content()
                    message.html_payload = part.get_content()

        else:
            body = message.get_content()
            if message.get_content_type() == "text/html":
                message.html_payload = body

        return {
            "message": message,
            "From": message["From"],
            "To": message["To"],
            "Subject": message["Subject"],
            "Date": message["Date"],
            "Body": body,
            "HtmlBody": getattr(message, "html_payload", "")
        }