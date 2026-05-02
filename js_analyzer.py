#!/usr/bin/env python3
# =============================================================================
#
#  ██╗   ██╗██████╗ ███╗   ██╗ ██████╗ ███╗   ███╗
#  ██║   ██║╚════██╗████╗  ██║██╔═══██╗████╗ ████║
#  ██║   ██║ █████╔╝██╔██╗ ██║██║   ██║██╔████╔██║
#  ╚██╗ ██╔╝ ╚═══██╗██║╚██╗██║██║   ██║██║╚██╔╝██║
#   ╚████╔╝ ██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
#    ╚═══╝  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
#
#  ████████╗███████╗ ██████╗██╗  ██╗
#  ╚══██╔══╝██╔════╝██╔════╝██║  ██║
#     ██║   █████╗  ██║     ███████║
#     ██║   ██╔══╝  ██║     ██╔══██║
#     ██║   ███████╗╚██████╗██║  ██║
#     ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝
#
#  [ v3nom tech ]
#  Instagram : @venom.tech.official
#  GitHub    : https://github.com/v3nomtech
#
# =============================================================================
"""
js_analyzer.py — Deep JS Secret & Endpoint Hunter
Input: js_files.txt from venomeye output (one URL per line)
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ── colours ──────────────────────────────────────────────────────────────────
class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def crit(m):  print(f"{C.RED}{C.BOLD}[CRIT]{C.RESET} {m}")
def section(m): print(f"\n{C.BOLD}{C.CYAN}{'─'*60}\n  {m}\n{'─'*60}{C.RESET}")

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██╗   ██╗██████╗ ███╗   ██╗ ██████╗ ███╗   ███╗
  ██║   ██║╚════██╗████╗  ██║██╔═══██╗████╗ ████║
  ██║   ██║ █████╔╝██╔██╗ ██║██║   ██║██╔████╔██║
  ╚██╗ ██╔╝ ╚═══██╗██║╚██╗██║██║   ██║██║╚██╔╝██║
   ╚████╔╝ ██████╔╝██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
    ╚═══╝  ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝

  ████████╗███████╗ ██████╗██╗  ██╗
  ╚══██╔══╝██╔════╝██╔════╝██║  ██║
     ██║   █████╗  ██║     ███████║
     ██║   ██╔══╝  ██║     ██╔══██║
     ██║   ███████╗╚██████╗██║  ██║
     ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝
{C.RESET}{C.GREEN}  [ v3nom tech ]  |  Instagram: @venom.tech.official  |  GitHub: https://github.com/v3nomtech
{C.RESET}""")

# ── secret patterns ───────────────────────────────────────────────────────────
SECRETS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",
    "AWS Session Token":    r"(?i)aws.{0,30}session.{0,30}['\"][A-Za-z0-9/+=]{100,}['\"]",
    "GitHub Token (classic)": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth":         r"gho_[0-9a-zA-Z]{36}",
    "GitHub Actions":       r"ghs_[0-9a-zA-Z]{36}",
    "GitLab Token":         r"glpat-[0-9a-zA-Z\-_]{20}",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth":         r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live Key":      r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Pub Key":       r"pk_live_[0-9a-zA-Z]{24,}",
    "Slack Token":          r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}",
    "Slack Webhook":        r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
    "Twilio Key":           r"SK[0-9a-fA-F]{32}",
    "Twilio Token":         r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",
    "SendGrid Key":         r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun Key":          r"key-[0-9a-zA-Z]{32}",
    "Mailchimp Key":        r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Heroku Key":           r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "JWT":                  r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private RSA Key":      r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":       r"-----BEGIN EC PRIVATE KEY-----",
    "Private Key (generic)":r"-----BEGIN PRIVATE KEY-----",
    "SSH Private Key":      r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key":      r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Firebase URL":         r"[a-z0-9-]+\.firebaseio\.com",
    "Firebase Key":         r"(?i)firebase.{0,20}['\"][A-Za-z0-9_\-]{20,}['\"]",
    "Square Access Token":  r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret":  r"sq0csp-[0-9A-Za-z\-_]{43}",
    "PayPal/Braintree":     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Dropbox Token":        r"(?i)dropbox.{0,20}['\"][a-zA-Z0-9_-]{64}['\"]",
    "Cloudinary URL":       r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+",
    "Database URL (MySQL)": r"mysql://[^\s\"'<>]+",
    "Database URL (Postgres)": r"postgres(?:ql)?://[^\s\"'<>]+",
    "Database URL (MongoDB)":  r"mongodb(?:\+srv)?://[^\s\"'<>]+",
    "Database URL (Redis)":    r"redis://[^\s\"'<>]+",
    "SMTP Credentials":     r"smtp://[^\s\"'<>]+",
    "Generic Password":     r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Bearer Token":         r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}",
    "Basic Auth in URL":    r"https?://[^:]+:[^@]+@[^\s\"']+",
    "Netlify Token":        r"(?i)netlify.{0,20}['\"][a-zA-Z0-9_-]{40,}['\"]",
    "Mapbox Token":         r"pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}",
    "NPM Token":            r"npm_[A-Za-z0-9]{36}",
    "Vault Token":          r"(?i)vault.{0,20}['\"][a-zA-Z0-9_\-.]{24,}['\"]",
    "Okta Token":           r"(?i)okta.{0,20}['\"][a-zA-Z0-9_\-.]{32,}['\"]",
    "Docker Hub Token":     r"(?i)docker.{0,20}['\"][a-zA-Z0-9_\-.]{32,}['\"]",
}

# ── endpoint patterns ─────────────────────────────────────────────────────────
ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v\d+|rest|graphql|internal|admin|backend|service|auth|oauth|login|user|account|payment|webhook)[^"\']*)["\']',
    r'["\']([a-z0-9_\-/]+\.(?:json|xml|yaml|yml|php|asp|aspx|jsp|do|action))["\']',
    r'(?:fetch|axios|xhr|http\.get|http\.post|request)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseUrl|apiUrl|api_url|host)\s*[:=]\s*["\']([^"\']{5,})["\']',
    r'(?:path|route)\s*:\s*["\']([/][^"\']+)["\']',
]

INTERNAL_IP_PATTERN = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|localhost)\b'
)

CLOUD_SERVICE_PATTERN = re.compile(
    r'(?:'
    r's3\.amazonaws\.com|\.s3-[a-z0-9-]+\.amazonaws\.com'
    r'|\.blob\.core\.windows\.net'
    r'|storage\.googleapis\.com'
    r'|\.cloudfront\.net'
    r'|execute-api\.[a-z0-9-]+\.amazonaws\.com'
    r'|\.lambda-url\.[a-z0-9-]+\.on\.aws'
    r')',
    re.IGNORECASE
)

# ── core functions ────────────────────────────────────────────────────────────
def fetch_js(url: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
             "--compressed", url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""

def beautify_js(content: str) -> str:
    """Try js-beautify if available, else return as-is."""
    try:
        r = subprocess.run(
            ["js-beautify", "--stdin"],
            input=content, capture_output=True, text=True, timeout=10
        )
        return r.stdout if r.returncode == 0 and r.stdout else content
    except Exception:
        return content

def scan_secrets(content: str, url: str) -> list[dict]:
    findings = []
    for label, pattern in SECRETS.items():
        for m in re.finditer(pattern, content):
            val = m.group(0)
            # rough dedup: skip if looks like a placeholder
            if re.search(r'(?i)(example|placeholder|your[_-]?|xxx|test|dummy|sample)', val):
                continue
            findings.append({
                "type": "secret",
                "label": label,
                "value": val[:120],
                "url": url,
                "line": content[:m.start()].count('\n') + 1,
            })
    return findings

def scan_endpoints(content: str, url: str, base_domain: str) -> list[dict]:
    findings = []
    seen = set()
    for pattern in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            ep = m.group(1).strip()
            if ep in seen or len(ep) < 3:
                continue
            seen.add(ep)
            findings.append({"type": "endpoint", "value": ep, "url": url})
    return findings

def scan_internals(content: str, url: str) -> list[dict]:
    findings = []
    for m in INTERNAL_IP_PATTERN.finditer(content):
        findings.append({"type": "internal_ip", "value": m.group(0), "url": url})
    for m in CLOUD_SERVICE_PATTERN.finditer(content):
        findings.append({"type": "cloud_service", "value": m.group(0), "url": url})
    return findings

def analyze_url(url: str, base_domain: str, beautify: bool) -> list[dict]:
    content = fetch_js(url)
    if not content:
        return []
    if beautify:
        content = beautify_js(content)
    results = []
    results.extend(scan_secrets(content, url))
    results.extend(scan_endpoints(content, url, base_domain))
    results.extend(scan_internals(content, url))
    return results

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Deep JS Secret & Endpoint Hunter")
    parser.add_argument("-i", "--input",   required=True, help="js_files.txt (one URL per line)")
    parser.add_argument("-o", "--output",  default="./js_analysis", help="Output directory")
    parser.add_argument("-d", "--domain",  default="", help="Base domain for context")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrent fetchers (default 20)")
    parser.add_argument("--no-beautify",   action="store_true", help="Skip js-beautify step")
    parser.add_argument("--limit",         type=int, default=0, help="Max JS files to process (0=all)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    section("JS Analyzer — Deep Secret & Endpoint Hunter")

    try:
        urls = [l.strip() for l in open(args.input) if l.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)

    if args.limit:
        urls = urls[:args.limit]

    info(f"Loaded {len(urls)} JS URLs | threads={args.threads} | beautify={not args.no_beautify}")

    all_findings: list[dict] = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(analyze_url, u, args.domain, not args.no_beautify): u for u in urls}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 50 == 0:
                info(f"Progress: {done}/{len(urls)} files analyzed, {len(all_findings)} findings so far")
            try:
                results = fut.result()
                for r in results:
                    if r["type"] == "secret":
                        crit(f"[{r['label']}] {r['url']} (line {r['line']}) → {r['value'][:80]}")
                    all_findings.extend(results)
            except Exception as e:
                warn(f"Error processing {futs[fut]}: {e}")

    # ── write outputs ─────────────────────────────────────────────────────────
    # JSON dump
    json_out = f"{args.output}/findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    # Secrets report
    secrets = [x for x in all_findings if x["type"] == "secret"]
    secrets_out = f"{args.output}/secrets.txt"
    with open(secrets_out, "w") as f:
        f.write(f"JS Secrets Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        by_label: dict[str, list] = {}
        for s in secrets:
            by_label.setdefault(s["label"], []).append(s)
        for label, items in sorted(by_label.items()):
            f.write(f"[{label}] ({len(items)} found)\n")
            for item in items:
                f.write(f"  URL  : {item['url']}\n")
                f.write(f"  Value: {item['value']}\n\n")

    # Endpoints report
    endpoints = [x for x in all_findings if x["type"] == "endpoint"]
    ep_out = f"{args.output}/endpoints.txt"
    seen_ep = set()
    with open(ep_out, "w") as f:
        for e in endpoints:
            k = e["value"]
            if k not in seen_ep:
                seen_ep.add(k)
                f.write(k + "\n")

    # Internal IPs / Cloud services
    internals = [x for x in all_findings if x["type"] in ("internal_ip", "cloud_service")]
    int_out = f"{args.output}/internals.txt"
    with open(int_out, "w") as f:
        for i in internals:
            f.write(f"[{i['type']}] {i['value']} (from {i['url']})\n")

    section("Results")
    ok(f"Secrets found     : {C.BOLD}{len(secrets)}{C.RESET}")
    ok(f"Unique endpoints  : {C.BOLD}{len(seen_ep)}{C.RESET}")
    ok(f"Internal refs     : {C.BOLD}{len(internals)}{C.RESET}")
    ok(f"Secrets report    : {secrets_out}")
    ok(f"Endpoints list    : {ep_out}")
    ok(f"Full JSON         : {json_out}")

if __name__ == "__main__":
    main()
