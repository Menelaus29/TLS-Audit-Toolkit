# TLS AUDIT TOOLKIT
## Description

TLS Audit Toolkit is a Python-based command-line tool designed to probe network services, extract TLS handshake information, parse X.509 certificates, detect common misconfigurations, and generate structured reports. The toolkit is Windows-friendly and fully non-intrusive. It supports direct TLS services (HTTPS, IMAPS, SMTPS, LDAPS) as well as STARTTLS-enabled protocols (SMTP, IMAP, POP3, FTP AUTH TLS).

This project is built for academic purposes only and is not intended for commercial use.

## Key Features

- Direct TLS handshake probing on ports such as 443, 465, 636, 993, 995, with STARTTLS upgrade for SMTP, IMAP, POP3, and FTP
- X.509 certificate extraction and detailed metadata parsing
- Detects weak ciphers, outdated protocols, small key sizes, SHA1 signatures, expired certificates, and more
- JSON, CSV, and HTML output generation
- Human-readable viewer for interactive inspection

## Installation (Windows)
1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Open Command Prompt in the project directory.
3. Create and activate virtual environment:
```bash
python -m venv .venv.\.venv\Scripts\activate
```

## Running a Scan

To scan the list of targets in experiments\targets.txt, run:
```bash
python -m src.scanner --targets experiments\targets.txt --out-json experiments\sample_outputs\results.json --out-csv experiments\sample_outputs\summary.csv --out-html experiments\sample_outputs\report.html --delay 3 --timeout 15
```

The delay option controls politeness. The timeout option controls maximum connection time.

## Viewing Results

To print results in a readable format, run:
```bash
python src\viewer.py --file experiments\sample_outputs\results.json
```
- JSON file contains full metadata, findings, and errors.
- CSV file contains summary information for spreadsheet analysis.
- HTML file contains a ready-to-share report with a table of results.
