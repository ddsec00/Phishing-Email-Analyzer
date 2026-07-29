import pytest
from analyzer.url_extractor import URLExtractor
from analyzer.domain_analyzer import DomainAnalyzer
from analyzer.risk_engine import RiskEngine

def test_url_extractor():
    text = "Check this link: https://www.google.com/login and http://paypal.com-update.xyz"
    extractor = URLExtractor(text)
    urls = extractor.extract()
    assert len(urls) == 2
    assert "https://www.google.com/login" in urls
    assert "http://paypal.com-update.xyz" in urls

def test_domain_analyzer():
    analyzer = DomainAnalyzer()
    urls = ["http://secure.login.paypaI.com-update.xyz/login"]
    result = analyzer.analyze(urls)
    assert result["score"] > 0
    assert len(result["findings"]) > 0

def test_risk_scoring():
    # Mock some findings to test risk calculation
    mock_results = {
        "headers": {"score": 10, "findings": ["SPF fail"]},
        "domains": {"score": 5, "findings": ["suspicious"]},
        "brand": {"score": 0, "findings": []},
        "html": {"score": 0, "findings": []},
        "urls": [{"score": 2, "findings": ["obfuscation"]}],
        "attachments": {"score": 30, "findings": ["Executable"]}
    }
    engine = RiskEngine(mock_results)
    summary = engine.calculate_risk()
    
    # spf_failure (+15), suspicious_domain (+10), executable_attachment (+30), obfuscated_url (+15)
    # Total expected score = 70
    assert summary["score"] == 70
    assert summary["level"] == "MEDIUM (Suspicious)"
