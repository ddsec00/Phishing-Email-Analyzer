"""
main.py

This is the main entry point of the application.

Its job is to coordinate the different modules
that make up the phishing email analyzer.
"""
from analyzer.url_extractor import URLExtractor
from analyzer.email_parser import EmailParser

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

if __name__ == "__main__":
    main()