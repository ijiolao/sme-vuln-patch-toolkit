#!/usr/bin/env python3
"""
weak_configuration_scanner.py

Lightweight "weak configuration" scanner for websites aimed at SMEs.

It checks for:
  - Basic redirect behaviour (HTTP → HTTPS, HTTPS → HTTP downgrade)
  - Presence/absence of common security headers:
      * Strict-Transport-Security
      * Content-Security-Policy
      * X-Content-Type-Options
      * X-Frame-Options
      * Referrer-Policy
      * Permissions-Policy
      * X-XSS-Protection (legacy, informational)
  - Simple heuristics for weak/missing settings

This is NOT a replacement for full scanners (e.g. securityheaders.com, zap),
but it gives a fast, low-friction view of obvious misconfigurations.

Usage examples:
    python weak_configuration_scanner.py --url https://example.com
    python weak_configuration_scanner.py --urls https://example.com,https://app.example.com
    python weak_configuration_scanner.py --input urls.txt --output weak_config_report.csv

Input file format (one URL per line):
    https://example.com
    http://example.com
    https://app.example.com
"""

import argparse
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests import Response


# Common security headers to check
REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]

OPTIONAL_HEADERS = [
    "permissions-policy",
    "x-xss-protection",  # legacy but still interesting
]


@dataclass
class SiteCheckResult:
    url: str
    final_url: Optional[str]
    scheme: Optional[str]
    status_code: Optional[int]
    redirect_chain: str
    https_downgrade: bool
    missing_required_headers: str
    missing_optional_headers: str
    header_findings: str
    error: Optional[str]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")
    parsed = urlparse(url)
    if not parsed.scheme:
        # Default to https if no scheme provided
        url = "https://" + url
    return url


def fetch_url(url: str, timeout: float = 10.0) -> Tuple[List[Response], Optional[Exception]]:
    """
    Request URL and collect the redirect chain (responses list).
    Returns (responses, error).
    """
    try:
        session = requests.Session()
        responses: List[Response] = []
        # Track redirects manually so we can see each hop
        resp = session.get(url, allow_redirects=False, timeout=timeout)
        responses.append(resp)
        max_redirects = 10

        while 300 <= resp.status_code < 400 and "location" in resp.headers and len(responses) < max_redirects:
            location = resp.headers["location"]
            # Follow relative or absolute
            next_url = requests.compat.urljoin(resp.url, location)
            resp = session.get(next_url, allow_redirects=False, timeout=timeout)
            responses.append(resp)

        # If last one is still a redirect after max redirects, we stop
        return responses, None
    except Exception as e:
        return [], e


def check_security_headers(resp: Response) -> Tuple[List[str], List[str], List[str]]:
    """
    Analyse headers and return:
      (missing_required, missing_optional, findings)
    where findings is a list of textual observations.
    """
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing_required: List[str] = []
    missing_optional: List[str] = []
    findings: List[str] = []

    # Required presence
    for h in REQUIRED_HEADERS:
        if h not in headers:
            missing_required.append(h)

    for h in OPTIONAL_HEADERS:
        if h not in headers:
            missing_optional.append(h)

    # HSTS checks
    hsts = headers.get("strict-transport-security")
    if hsts:
        # Simple max-age check
        if "max-age" not in hsts.lower():
            findings.append("HSTS present but max-age missing")
        else:
            # crude parse
            try:
                parts = [p.strip() for p in hsts.split(";")]
                max_age_part = next((p for p in parts if p.lower().startswith("max-age")), "")
                if "=" in max_age_part:
                    val = int(max_age_part.split("=", 1)[1])
                    if val < 15552000:  # < 180 days
                        findings.append("HSTS max-age < 6 months (consider increasing)")
            except Exception:
                findings.append("Could not parse HSTS max-age")
    else:
        findings.append("HSTS missing (for HTTPS site)")

    # CSP checks
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append("Content-Security-Policy header missing")

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if not xcto:
        findings.append("X-Content-Type-Options missing")
    elif xcto.lower() != "nosniff":
        findings.append(f"X-Content-Type-Options is '{xcto}', expected 'nosniff'")

    # X-Frame-Options
    xfo = headers.get("x-frame-options")
    if not xfo:
        findings.append("X-Frame-Options missing (consider SAMEORIGIN or DENY)")
    else:
        v = xfo.lower()
        if v not in ("deny", "sameorigin"):
            findings.append(f"X-Frame-Options value '{xfo}' is non-standard; prefer DENY or SAMEORIGIN")

    # Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        findings.append("Referrer-Policy missing (consider 'strict-origin-when-cross-origin')")
    else:
        weak_policies = {"no-referrer-when-downgrade", "unsafe-url"}
        if rp.lower() in weak_policies:
            findings.append(f"Referrer-Policy '{rp}' is weaker than recommended")

    # Permissions-Policy
    pp = headers.get("permissions-policy")
    if not pp:
        findings.append("Permissions-Policy missing (not critical but recommended)")

    # X-XSS-Protection (legacy)
    xxp = headers.get("x-xss-protection")
    if xxp:
        findings.append(f"X-XSS-Protection present (legacy): '{xxp}'")

    return missing_required, missing_optional, findings


def analyse_target(url: str, timeout: float = 10.0) -> SiteCheckResult:
    url = normalize_url(url)
    responses, error = fetch_url(url, timeout=timeout)

    if error or not responses:
        return SiteCheckResult(
            url=url,
            final_url=None,
            scheme=None,
            status_code=None,
            redirect_chain="",
            https_downgrade=False,
            missing_required_headers="",
            missing_optional_headers="",
            header_findings="",
            error=str(error) if error else "No response",
        )

    # Build redirect chain and downgrade flag
    chain_urls = [r.url for r in responses]
    redirect_chain = " -> ".join(chain_urls)
    first_scheme = urlparse(responses[0].url).scheme
    final_resp = responses[-1]
    final_parsed = urlparse(final_resp.url)
    final_scheme = final_parsed.scheme

    https_downgrade = first_scheme == "https" and final_scheme == "http"

    missing_required: List[str] = []
    missing_optional: List[str] = []
    findings: List[str] = []

    # Only check headers if we got a "final" non-3xx response
    if not (300 <= final_resp.status_code < 400):
        missing_required, missing_optional, findings = check_security_headers(final_resp)

    return SiteCheckResult(
        url=url,
        final_url=final_resp.url,
        scheme=final_scheme,
        status_code=final_resp.status_code,
        redirect_chain=redirect_chain,
        https_downgrade=https_downgrade,
        missing_required_headers=";".join(missing_required),
        missing_optional_headers=";".join(missing_optional),
        header_findings=" | ".join(findings),
        error=None,
    )


def load_urls_from_file(path: Path) -> List[str]:
    urls: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan websites for weak security headers and redirect issues."
    )
    parser.add_argument(
        "--url",
        help="Single URL to scan (e.g. https://example.com). If no scheme, https is assumed.",
    )
    parser.add_argument(
        "--urls",
        help="Comma-separated list of URLs to scan.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to text file with one URL per line.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to CSV file for results.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0).",
    )
    return parser.parse_args()


def gather_urls(args: argparse.Namespace) -> List[str]:
    urls: List[str] = []

    if args.url:
        urls.append(args.url)

    if args.urls:
        for u in args.urls.split(","):
            u = u.strip()
            if u:
                urls.append(u)

    if args.input:
        if not args.input.exists():
            raise FileNotFoundError(f"Input file not found: {args.input}")
        from_file = load_urls_from_file(args.input)
        urls.extend(from_file)

    # Deduplicate while preserving order
    seen = set()
    unique_urls: List[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    if not unique_urls:
        raise ValueError("No URLs specified. Use --url, --urls, or --input.")

    return unique_urls


def print_console(results: List[SiteCheckResult]) -> None:
    print("Weak Configuration Scan Results")
    print("--------------------------------")
    for r in results:
        if r.error:
            print(f"[{r.url}] ERROR: {r.error}")
            continue

        issues = []
        if r.https_downgrade:
            issues.append("HTTPS_DOWNGRADE")
        if r.missing_required_headers:
            issues.append("MISSING_REQUIRED_HEADERS")
        if not issues:
            issues.append("OK")

        print(
            f"[{r.url}] -> {r.final_url} "
            f"(HTTP {r.status_code}, scheme={r.scheme}) "
            f"Issues: {', '.join(issues)}"
        )


def write_csv(results: List[SiteCheckResult], path: Path) -> None:
    fieldnames = [
        "url",
        "final_url",
        "scheme",
        "status_code",
        "redirect_chain",
        "https_downgrade",
        "missing_required_headers",
        "missing_optional_headers",
        "header_findings",
        "error",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))


def main() -> int:
    args = parse_args()

    try:
        urls = gather_urls(args)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    results: List[SiteCheckResult] = []

    for u in urls:
        res = analyse_target(u, timeout=args.timeout)
        results.append(res)

    print_console(results)

    if args.output:
        write_csv(results, args.output)
        print(f"\nCSV report written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
