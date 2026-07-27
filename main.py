from analyzer.url_extractor import URLExtractor
from analyzer.email_parser import EmailParser
from analyzer.url_analyzer import URLAnalyzer
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.attachment_analyzer import AttachmentAnalyzer
from analyzer.domain_analyzer import DomainAnalyzer
from analyzer.brand_analyzer import BrandAnalyzer
from analyzer.html_analyzer import HTMLAnalyzer
from analyzer.risk_engine import RiskEngine
from reports.report_generator import ReportGenerator

def main():
    """
    Main application workflow.
    """
    print("=" * 60)
    print("SOC Email Threat Analyzer (v2.0)")
    print("=" * 60)
    print("\nIngesting email evidence...\n")

    parser = EmailParser("samples/sample_email.eml")
    email = parser.load_email()
    print("Evidence extraction complete.\n")
    print("Executing comprehensive threat analysis pipeline...\n")

    # 1. Parse URLs
    extractor = URLExtractor(email["Body"])
    urls = extractor.extract()

    # 2. Execute Analyzers
    domain_analyzer = DomainAnalyzer()
    domain_results = domain_analyzer.analyze(urls)
    
    brand_analyzer = BrandAnalyzer(email)
    brand_results = brand_analyzer.analyze()
    
    html_analyzer = HTMLAnalyzer(email.get("HtmlBody", ""))
    html_results = html_analyzer.analyze()

    url_analyzer = URLAnalyzer(urls)
    url_results = url_analyzer.analyze()

    header_analyzer = HeaderAnalyzer(email)
    header_result = header_analyzer.analyze()

    attachment_analyzer = AttachmentAnalyzer(email["message"])
    attachment_result = attachment_analyzer.analyze()

    # 3. Compile all findings for the Risk Engine
    analysis_results = {
        "urls": url_results,
        "domains": domain_results,
        "brand": brand_results,
        "html": html_results,
        "headers": header_result,
        "attachments": attachment_result
    }

    # 4. Evaluate Overall Risk
    risk_engine = RiskEngine(analysis_results)
    risk_summary = risk_engine.calculate_risk()

    # 5. Generate Report
    email_info = {
        "From": email.get("From"),
        "Subject": email.get("Subject"),
        "Date": email.get("Date")
    }
    
    report_generator = ReportGenerator(
        email_info, 
        analysis_results, 
        risk_summary
    )
    final_report = report_generator.generate()

    # Output the result
    print(final_report)

if __name__ == "__main__":
    main()