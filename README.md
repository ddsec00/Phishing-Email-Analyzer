# 📧 Phishing Email Analyzer

A professional, automated phishing email analysis platform built in Python.

## 📖 Project Description

The Phishing Email Analyzer is a modular security assessment tool designed to parse and investigate `.eml` files for malicious indicators. Moving beyond simple keyword detection, this tool utilizes a comprehensive ruleset to evaluate email headers, extract and analyze URLs, detect brand impersonation, and score the overall threat level, ultimately generating a SOC-style incident report.

## ✨ Features

- **Email Parsing**: Ingests raw `.eml` files and extracts headers, body text, HTML, and attachments.
- **Header Analysis**: Validates vital authentication protocols including SPF, DKIM, and DMARC.
- **URL & Domain Analysis**: Extracts URLs, detects obfuscation techniques, and evaluates domain reputation.
- **Brand Impersonation Detection**: Identifies subtle typosquatting and fake corporate branding.
- **Risk Scoring Engine**: Calculates a dynamic threat score dynamically weighting various malicious indicators.
- **SOC-style Reporting**: Generates structured, professional reports detailing findings and confidence levels.

## 🏗️ Architecture

This project follows a modular, object-oriented design built on the **Single Responsibility Principle**. 
- `main.py`: The orchestrator pipeline that runs the analyzers in sequence.
- `analyzer/`: Contains independent threat detection modules (e.g., `header_analyzer.py`, `url_analyzer.py`).
- `reports/`: The output destination for generated JSON/TXT incident reports.

## ⚙️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Phishing-Email-Analyzer.git
   cd Phishing-Email-Analyzer
   ```
2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

Currently, the analyzer operates on single `.eml` files via the core script:

```bash
python main.py samples/suspicious_email.eml
```

## 📊 Example Output

```text
==================================================
🚨 THREAT REPORT GENERATED 🚨
==================================================
Score: 85/100 (CRITICAL)
Confidence: HIGH

Key Findings:
- [Header] Missing DMARC record
- [URL] Obfuscated domain detected (g00gle.com)
- [Brand] Paypal impersonation detected in HTML
==================================================
```

## ⚠️ Limitations

- The tool currently relies on static heuristic analysis. It does not execute attachments dynamically in a sandbox environment.
- Domain reputation lookups rely on local lists rather than live APIs (like VirusTotal) to remain lightweight and air-gap friendly.