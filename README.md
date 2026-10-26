# Automated Web Scanner

A Python command-line tool that audits websites for **missing or weak HTTP security headers** and **CORS misconfigurations**. Built as a project for a Cybersecurity bootcamp.

> ⚠️ **Legal notice:** Use only on websites you own or have explicit written permission to test. The author is not responsible for misuse.

## Features
- Checks 6 key security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Detects weak values (short HSTS max-age, `unsafe-inline` in CSP)
- Detects information-leaking headers (`Server`, `X-Powered-By`)
- Tests CORS with arbitrary, `null`, and suffix-bypass origins
- Flags wildcard + credentials and reflected-origin issues
- Severity levels (High / Medium / Low) and an A–F security grade
- Colored console output and optional JSON export
- Scan multiple URLs or read targets from a file

## Installation
```bash
git clone https://github.com/<your-username>/automated-web-scanner.git
cd automated-web-scanner
pip install -r requirements.txt
```
Requires Python 3.8+.

## Usage
```bash
# Single site
python web_scanner.py https://example.com

# Multiple sites + JSON report
python web_scanner.py https://example.com https://example.org --json results.json

# From a file (one URL per line)
python web_scanner.py -f urls.txt --timeout 15
```

### Options
| Option | Description |
|---|---|
| `urls` | One or more target URLs |
| `-f, --file` | File with URLs, one per line |
| `-t, --timeout` | Request timeout in seconds (default 10) |
| `--json FILE` | Save results as JSON |

## Sample Output
```
=== https://example.com ===
  HTTP status : 200
  Security grade: D
  [High  ] Missing Header: Content-Security-Policy
           Mitigates XSS and data-injection attacks.
           Fix: Add a CSP, e.g. default-src 'self'
  [Medium] Missing Header: X-Frame-Options
           ...
```

## How It Works
1. Sends a normal GET request and inspects response headers.
2. Compares them with a security-header baseline (based on OWASP Secure Headers Project).
3. Re-sends requests with crafted `Origin` headers and analyses `Access-Control-Allow-*` responses.
4. Scores findings and prints/exports a report.

## Project Structure
```
automated-web-scanner/
├── web_scanner.py
├── requirements.txt
├── README.md
└── Project_Report.pdf
```

## Limitations
- Passive checks only; no exploitation
- Does not crawl; scans the given URL only
- CORS preflight (OPTIONS) is not tested

## References
- OWASP Secure Headers Project
- MDN Web Docs: CORS and HTTP security headers

## License
MIT
