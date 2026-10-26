#!/usr/bin/env python3
"""
Automated Web Scanner
---------------------
Passive audit of a website for:
  1. Missing / weak HTTP security headers
  2. CORS misconfigurations

Only sends normal GET requests (plus one Origin-header probe for CORS).
Use ONLY on sites you own or have written permission to test.

Usage:
    python web_scanner.py https://example.com
    python web_scanner.py https://example.com https://example.org --json report.json
    python web_scanner.py -f urls.txt --timeout 15
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENT = "AutoWebScanner/1.0 (educational security audit)"

# header -> (severity, description, recommendation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "High",
        "Forces browsers to use HTTPS (prevents SSL-stripping).",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        "High",
        "Mitigates XSS and data-injection attacks.",
        "Add a CSP, e.g. default-src 'self'",
    ),
    "X-Frame-Options": (
        "Medium",
        "Protects against clickjacking.",
        "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Stops MIME-type sniffing.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        "Low",
        "Controls how much referrer info is leaked.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "Low",
        "Restricts access to browser features (camera, mic, etc.).",
        "Add: Permissions-Policy: geolocation=(), camera=()",
    ),
}

# headers that leak technology info
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def fetch(url: str, timeout: int, headers=None):
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=timeout, allow_redirects=True)


def check_security_headers(resp) -> list:
    findings = []
    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    for name, (sev, desc, fix) in SECURITY_HEADERS.items():
        if name.lower() not in hdrs:
            findings.append({"type": "Missing Header", "header": name,
                             "severity": sev, "detail": desc, "fix": fix})

    # weak-value checks
    hsts = hdrs.get("strict-transport-security")
    if hsts:
        try:
            age = int(hsts.lower().split("max-age=")[1].split(";")[0])
            if age < 15768000:
                findings.append({"type": "Weak Header", "header": "Strict-Transport-Security",
                                 "severity": "Medium",
                                 "detail": f"max-age={age} is under 6 months.",
                                 "fix": "Use max-age of at least 31536000."})
        except (IndexError, ValueError):
            pass

    csp = hdrs.get("content-security-policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append({"type": "Weak Header", "header": "Content-Security-Policy",
                         "severity": "Medium",
                         "detail": "CSP allows 'unsafe-inline' or 'unsafe-eval'.",
                         "fix": "Remove unsafe directives; use nonces or hashes."})

    for name in INFO_LEAK_HEADERS:
        if name.lower() in hdrs:
            findings.append({"type": "Information Disclosure", "header": name,
                             "severity": "Low",
                             "detail": f"Reveals technology: {hdrs[name.lower()]}",
                             "fix": f"Remove or obscure the {name} header."})

    if not resp.url.startswith("https://"):
        findings.append({"type": "No HTTPS", "header": "-", "severity": "High",
                         "detail": "Site is served over plain HTTP.",
                         "fix": "Enable HTTPS and redirect all HTTP traffic."})
    return findings


def check_cors(url: str, timeout: int) -> list:
    """Send requests with different Origin headers and inspect the CORS response."""
    findings = []
    host = urlparse(url).netloc
    probes = {
        "arbitrary origin": "https://evil-attacker.com",
        "null origin": "null",
        "subdomain-suffix bypass": f"https://{host}.evil-attacker.com",
    }

    for label, origin in probes.items():
        try:
            r = fetch(url, timeout, {"Origin": origin})
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if not acao:
            continue

        if acao == "*" and acac == "true":
            findings.append({"type": "CORS", "header": "Access-Control-Allow-Origin",
                             "severity": "High",
                             "detail": "Wildcard origin combined with credentials=true.",
                             "fix": "Never combine * with credentials; use an allow-list."})
        elif acao == origin and acac == "true":
            findings.append({"type": "CORS", "header": "Access-Control-Allow-Origin",
                             "severity": "High",
                             "detail": f"Reflects {label} ({origin}) with credentials allowed.",
                             "fix": "Validate Origin against a strict allow-list."})
        elif acao == origin:
            findings.append({"type": "CORS", "header": "Access-Control-Allow-Origin",
                             "severity": "Medium",
                             "detail": f"Reflects {label} ({origin}) without validation.",
                             "fix": "Validate Origin against a strict allow-list."})
        elif acao == "*":
            findings.append({"type": "CORS", "header": "Access-Control-Allow-Origin",
                             "severity": "Low",
                             "detail": "Wildcard origin (*) allowed. Fine for public data only.",
                             "fix": "Restrict to trusted origins if data is not public."})

    # remove duplicates
    seen, unique = set(), []
    for f in findings:
        key = (f["detail"], f["severity"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan(url: str, timeout: int) -> dict:
    url = normalize(url)
    result = {"url": url, "scanned_at": datetime.now().isoformat(timespec="seconds"),
              "status": None, "findings": [], "error": None}
    try:
        resp = fetch(url, timeout)
        result["status"] = resp.status_code
        result["final_url"] = resp.url
        result["findings"] += check_security_headers(resp)
        result["findings"] += check_cors(resp.url, timeout)
    except requests.RequestException as e:
        result["error"] = str(e)
    return result


def grade(findings: list) -> str:
    score = 100
    penalty = {"High": 20, "Medium": 10, "Low": 4}
    for f in findings:
        score -= penalty.get(f["severity"], 0)
    score = max(score, 0)
    return ("A" if score >= 90 else "B" if score >= 75 else
            "C" if score >= 55 else "D" if score >= 35 else "F")


COLORS = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.CYAN}


def print_report(res: dict):
    print(Style.BRIGHT + f"\n=== {res['url']} ===")
    if res["error"]:
        print(Fore.RED + f"  Error: {res['error']}")
        return
    print(f"  HTTP status : {res['status']}")
    print(f"  Security grade: {grade(res['findings'])}")
    if not res["findings"]:
        print(Fore.GREEN + "  No issues found.")
        return
    order = {"High": 0, "Medium": 1, "Low": 2}
    for f in sorted(res["findings"], key=lambda x: order[x["severity"]]):
        c = COLORS[f["severity"]]
        print(c + f"  [{f['severity']:<6}] {f['type']}: {f['header']}")
        print(f"           {f['detail']}")
        print(f"           Fix: {f['fix']}")


def main():
    p = argparse.ArgumentParser(description="Automated Web Scanner: secure headers and CORS audit")
    p.add_argument("urls", nargs="*", help="Target URL(s)")
    p.add_argument("-f", "--file", help="File containing one URL per line")
    p.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (seconds)")
    p.add_argument("--json", metavar="FILE", help="Save results to a JSON file")
    args = p.parse_args()

    targets = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        p.error("Provide at least one URL or use -f urls.txt")

    print(Fore.YELLOW + "[!] Only scan sites you own or have permission to test.")
    results = [scan(t, args.timeout) for t in targets]
    for r in results:
        print_report(r)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nResults saved to {args.json}")


if __name__ == "__main__":
    sys.exit(main())
