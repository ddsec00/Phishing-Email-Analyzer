"""
main.py

This is the main entry point of the application.

Its job is to coordinate the different modules
that make up the phishing email analyzer.
"""
from analyzer.url_extractor import URLExtractor
from analyzer.email_parser import EmailParser
from analyzer.url_analyzer import URLAnalyzer
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.attachment_analyzer import AttachmentAnalyzer

def main():
    """
    Main application workflow.
    """

    print("=" * 60)
    print("Phishing Email Analyzer")
    print("=" * 60)

    print("\nLoading email...\n")

    parser = EmailParser("samples/sample_email.eml")

    email = parser.load_email()
    print("Email loaded successfully.\n")

    print("FROM:")
    print(email["From"])

    print("\nTO:")
    print(email["To"])

    print("\nSUBJECT:")
    print(email["Subject"])

    print("\nDATE:")
    print(email["Date"])

    print("\nBODY:")
    print(email["Body"])
    extractor = URLExtractor(email["Body"])

    urls = extractor.extract()

    print("\nURLs Found:")

    if urls:
        for url in urls:
            print("-", url)
    else:
        print("No URLs found.")
    analyzer = URLAnalyzer(urls)

    results = analyzer.analyze()


    print("\nURL ANALYSIS:")

    for result in results:

        print("\nURL:", result["url"])

        print("Risk Score:", result["score"])

        if result["findings"]:

            print("Findings:")

            for finding in result["findings"]:
                print("-", finding)

        else:
            print("No suspicious indicators found.")
    header_analyzer = HeaderAnalyzer(email)

    header_result = header_analyzer.analyze()


    print("\nHEADER ANALYSIS")

    print(
        "Risk Score:",
        header_result["score"]
    )


    for finding in header_result["findings"]:

        print("-", finding)


    attachment_analyzer = AttachmentAnalyzer(
         email["message"]
    )

    attachment_result = attachment_analyzer.analyze()

    print("\nATTACHMENT ANALYSIS")

    print("Risk Score:", attachment_result["score"])

    if attachment_result["attachments"]:

        print("\nAttachments:")

        for attachment in attachment_result["attachments"]:

            print("-", attachment)

    else:

        print("No attachments found.")

    if attachment_result["findings"]:

        print("\nFindings:")

        for finding in attachment_result["findings"]:

          print("-", finding)
if __name__ == "__main__":
    main()