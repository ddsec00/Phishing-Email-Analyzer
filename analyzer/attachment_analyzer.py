class AttachmentAnalyzer:
    """
    Analyzes email attachments and
    identifies potentially risky files.
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe": 3,
        ".bat": 3,
        ".cmd": 3,
        ".ps1": 3,
        ".js": 2,
        ".vbs": 2,
        ".scr": 3,
        ".docm": 2,
        ".xlsm": 2,
        ".zip": 1,
        ".rar": 1,
    }

    def __init__(self, message):
        self.message = message

    def analyze(self):

        findings = []

        score = 0

        attachments = []

        for part in self.message.walk():

            filename = part.get_filename()

            if filename:

                attachments.append(filename)

                lower_name = filename.lower()

                for extension, risk in self.SUSPICIOUS_EXTENSIONS.items():

                    if lower_name.endswith(extension):

                        findings.append(
                            f"Suspicious attachment: {filename}"
                        )

                        score += risk

        return {
            "attachments": attachments,
            "score": score,
            "findings": findings,
        }