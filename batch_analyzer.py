import os
import sys
import json
from pathlib import Path

from analyzer.url_extractor import URLExtractor
from analyzer.email_parser import EmailParser
from analyzer.url_analyzer import URLAnalyzer
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.attachment_analyzer import AttachmentAnalyzer
from analyzer.domain_analyzer import DomainAnalyzer
from analyzer.brand_analyzer import BrandAnalyzer
from analyzer.html_analyzer import HTMLAnalyzer
from analyzer.risk_engine import RiskEngine

def analyze_file(filepath):
    parser = EmailParser(filepath)
    email = parser.load_email()
    if not email:
        return None

    extractor = URLExtractor(email.get("Body", ""))
    urls = extractor.extract()

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

    attachment_analyzer = AttachmentAnalyzer(email.get("message"))
    attachment_result = attachment_analyzer.analyze()

    analysis_results = {
        "urls": url_results,
        "domains": domain_results,
        "brand": brand_results,
        "html": html_results,
        "headers": header_result,
        "attachments": attachment_result
    }

    risk_engine = RiskEngine(analysis_results)
    risk_summary = risk_engine.calculate_risk()
    
    return risk_summary

def main():
    if len(sys.argv) < 2:
        print("Usage: python batch_analyzer.py <directory>")
        sys.exit(1)
        
    directory = sys.argv[1]
    
    print("====================================")
    print(" Batch Email Analysis")
    print("====================================\n")
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".eml"):
                filepath = os.path.join(root, file)
                meta_path = filepath.replace(".eml", ".meta.json")
                
                expected = "Unknown"
                if os.path.exists(meta_path):
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                        expected = meta.get("expected_classification", "Unknown")
                
                risk_summary = analyze_file(filepath)
                if not risk_summary:
                    continue
                    
                risk_level = risk_summary.get("level", "UNKNOWN").upper()
                score = risk_summary.get("score", 0)
                
                # Simple logic for PASS/FAIL
                is_detected_phish = score >= 50
                is_expected_phish = expected.lower() == "phishing"
                
                result = "PASS" if is_detected_phish == is_expected_phish else "FAIL"
                
                print(f"Email:    {file}")
                print(f"Expected: {expected}")
                print(f"Detected: {risk_level} ({score}/100)")
                print(f"Result:   {result}\n")
                print("-" * 36 + "\n")

if __name__ == "__main__":
    main()
