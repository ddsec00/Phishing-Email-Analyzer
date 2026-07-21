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
from analyzer.risk_engine import RiskEngine
from reports.report_generator import ReportGenerator

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

    print("Analyzing... Please wait.\n")

    # 1. Parse URLs
    extractor = URLExtractor(email["Body"])
    urls = extractor.extract()

    # 2. Analyze URLs
    url_analyzer = URLAnalyzer(urls)
    url_results = url_analyzer.analyze()

    # 3. Analyze Headers
    header_analyzer = HeaderAnalyzer(email)
    header_result = header_analyzer.analyze()

    # 4. Analyze Attachments
    attachment_analyzer = AttachmentAnalyzer(email["message"])
    attachment_result = attachment_analyzer.analyze()

    # 5. Evaluate Overall Risk
    risk_engine = RiskEngine(url_results, header_result, attachment_result)
    risk_summary = risk_engine.calculate_risk()

    # 6. Generate Report
    email_info = {
        "From": email.get("From"),
        "Subject": email.get("Subject"),
        "Date": email.get("Date")
    }
    
    report_generator = ReportGenerator(
        email_info, 
        url_results, 
        header_result, 
        attachment_result, 
        risk_summary
    )
    final_report = report_generator.generate()

    # Output the result
    print(final_report)

if __name__ == "__main__":
    main()