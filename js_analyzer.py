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
# Only patterns with strong, hard-to-fake structure are kept here. Loose
# "service-name within N chars of a quoted string" patterns from the prior
# version (Twilio Token, Firebase Key, Dropbox/Netlify/Vault/Okta/Docker Hub
# tokens, Heroku Key) were dropped — they fired on any source file that
# imports or comments a service name near a long string and were the bulk
# of the FPs.
SECRETS = {
    "AWS Access Key":       r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key":       r"(?i)aws[_-]?(?:secret[_-]?(?:access[_-]?)?key|secret)\s*[:=]\s*['\"]([A-Za-z0-9/+]{40})['\"]",
    "GitHub Token (classic)": r"\bghp_[0-9a-zA-Z]{36}\b",
    "GitHub OAuth":         r"\bgho_[0-9a-zA-Z]{36}\b",
    "GitHub Actions":       r"\bghs_[0-9a-zA-Z]{36}\b",
    "GitHub User-to-Server":r"\bghu_[0-9a-zA-Z]{36}\b",
    "GitHub Refresh":       r"\bghr_[0-9a-zA-Z]{36}\b",
    "GitLab Token":         r"\bglpat-[0-9a-zA-Z\-_]{20}\b",
    "Google API Key":       r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Client":  r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b",
    "Stripe Live Secret":   r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Live Restricted": r"\brk_live_[0-9a-zA-Z]{24,}\b",
    "Slack Bot Token":      r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}\b",
    "Slack Webhook":        r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
    "Twilio API Key":       r"\bSK[0-9a-f]{32}\b",
    "Twilio Account SID":   r"\bAC[0-9a-f]{32}\b",
    "SendGrid Key":         r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b",
    "Mailgun Key":          r"\bkey-[0-9a-zA-Z]{32}\b",
    "Mailchimp Key":        r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
    "JWT":                  r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Private RSA Key":      r"-----BEGIN RSA PRIVATE KEY-----",
    "Private EC Key":       r"-----BEGIN EC PRIVATE KEY-----",
    "Private Key (PKCS8)":  r"-----BEGIN PRIVATE KEY-----",
    "SSH Private Key":      r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key":      r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Square Access Token":  r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",
    "Square OAuth Secret":  r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
    "PayPal/Braintree":     r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
    "Cloudinary URL":       r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z][a-z0-9_-]*",
    "Mapbox Token":         r"\bpk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}\b",
    "NPM Token":            r"\bnpm_[A-Za-z0-9]{36}\b",
    "Database URL (MySQL)":    r"mysql://[A-Za-z0-9_.-]+:[^\s\"'<>@]{4,}@[A-Za-z0-9._-]+(?::\d+)?/[A-Za-z0-9_.-]+",
    "Database URL (Postgres)": r"postgres(?:ql)?://[A-Za-z0-9_.-]+:[^\s\"'<>@]{4,}@[A-Za-z0-9._-]+(?::\d+)?/[A-Za-z0-9_.-]+",
    "Database URL (MongoDB)":  r"mongodb(?:\+srv)?://[A-Za-z0-9_.-]+:[^\s\"'<>@]{4,}@[A-Za-z0-9._-]+",
    "Database URL (Redis)":    r"redis://[A-Za-z0-9_.-]+:[^\s\"'<>@]{4,}@[A-Za-z0-9._-]+",
    # Quoted, KEY=VAL style — placeholder + entropy filter applied later.
    "Quoted Credential":    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([^'\"\s]{8,256})['\"]",
    "Bearer Token":         r"(?i)bearer\s+([A-Za-z0-9][A-Za-z0-9_\-.]{19,})",
    "Basic Auth URL":       r"\bhttps?://[A-Za-z0-9._%+-]{1,64}:[^@\s\"'<>/?#]{4,128}@[A-Za-z0-9.-]+(?:\:\d+)?/",
    # Info-level — not a secret on its own
    "Firebase URL":         r"\b[a-z0-9-]+\.firebaseio\.com\b",
}

# Hosts/values that are obviously placeholders or non-secret content. Used to
# reject Database URL / Basic Auth / quoted-credential matches.
_PLACEHOLDER_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.org",
    "test.com", "your-host", "your_host", "hostname", "yourdomain.com",
    "domain.com", "host.com", "db.example.com", "host", "your-db",
}
# Substrings that scream "placeholder", regardless of where they appear.
_PLACEHOLDER_RE = re.compile(
    r"(?i)(?:example|placeholder|your[_-]?(?:password|secret|token|key|user|host|db)?"
    r"|xxx+|todo|fixme|change[_-]?me|replace[_-]?me|<your|enter[_-]your"
    r"|sample|dummy|fake|insert[_-]?(?:your|here)"
    r"|\$\{[^}]+\}|\{\{[^}]+\}\})"
)
_ASTERISKS_RE = re.compile(r"\*{4,}|•{4,}|•{4,}")
_TEMPLATE_RE  = re.compile(r"\$\{|\$\(|\{\{|<%=?|%[a-z_]+%")

def _shannon_entropy(s: str) -> float:
    """Bits/char Shannon entropy. High-entropy strings are more likely real
    secrets; placeholder-like strings (`Enter your password`) score low."""
    if not s:
        return 0.0
    import math
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def _looks_like_real_secret(value: str) -> bool:
    """Heuristic gate for the looser patterns (Quoted Credential / Bearer /
    Basic Auth). High-confidence patterns (AWS keys, JWTs, RSA blocks,
    Slack webhooks, etc.) bypass this check.
    """
    v = value.strip()
    if not v or len(v) < 8:
        return False
    if _PLACEHOLDER_RE.search(v):
        return False
    if _ASTERISKS_RE.search(v):
        return False
    if _TEMPLATE_RE.search(v):
        return False
    if " " in v:                         # spaces = sentence, not credential
        return False
    if v.lower() in _PLACEHOLDER_HOSTS:
        return False
    # Reject pure-letter words ("MyPassword") and short ASCII words — they
    # don't carry secret-grade entropy.
    if v.isalpha() and len(v) < 32:
        return False
    if _shannon_entropy(v) < 3.0:
        return False
    return True

# Patterns that should ALWAYS be reported regardless of entropy/placeholder
# heuristics — their structure alone is enough.
_HIGH_CONFIDENCE = {
    "AWS Access Key", "AWS Secret Key",
    "GitHub Token (classic)", "GitHub OAuth", "GitHub Actions",
    "GitHub User-to-Server", "GitHub Refresh",
    "GitLab Token", "Google API Key", "Google OAuth Client",
    "Stripe Live Secret", "Stripe Live Restricted",
    "Slack Bot Token", "Slack Webhook",
    "Twilio API Key", "Twilio Account SID",
    "SendGrid Key", "Mailgun Key", "Mailchimp Key",
    "JWT",
    "Private RSA Key", "Private EC Key", "Private Key (PKCS8)",
    "SSH Private Key", "PGP Private Key",
    "Square Access Token", "Square OAuth Secret",
    "PayPal/Braintree", "Cloudinary URL", "Mapbox Token", "NPM Token",
    "Database URL (MySQL)", "Database URL (Postgres)",
    "Database URL (MongoDB)", "Database URL (Redis)",
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

# Filenames that nearly always indicate a third-party library bundle. These
# have huge minified bodies that produce a flood of FPs (`bearer xxxxx` style
# matches inside reactDOM, vendor.js, etc.) without actionable findings.
LIB_SKIP_RE = re.compile(
    r"(?i)/(?:jquery(?:[.-][\d.]+)?(?:\.min)?\.js"
    r"|react(?:-dom)?(?:[.-]\d+)?(?:\.production|\.development)?(?:\.min)?\.js"
    r"|vue(?:[.-][\d.]+)?(?:\.min)?\.js"
    r"|angular(?:[.-][\d.]+)?(?:\.min)?\.js"
    r"|bootstrap(?:[.-][\d.]+)?(?:\.min)?\.js"
    r"|lodash(?:\.min)?\.js"
    r"|moment(?:\.min)?\.js"
    r"|d3(?:\.v\d+)?(?:\.min)?\.js"
    r"|underscore(?:\.min)?\.js"
    r"|polyfill(?:s)?(?:\.min)?\.js"
    r"|googletagmanager\.com|gtag/js|google-analytics\.com)"
)

# ── core functions ────────────────────────────────────────────────────────────
def fetch_js(url: str, timeout: int = 15) -> tuple[str, str]:
    """Fetch a JS file. Follows redirects (CDN-hosted JS often redirects)
    and returns (body, content-type). Returns ("","") on error."""
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
             "-L", "--max-redirs", "3",
             "-D", "/dev/stderr",
             "--compressed", url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        ctype = ""
        for line in (r.stderr or "").splitlines():
            if line.lower().startswith("content-type:"):
                ctype = line.split(":", 1)[1].strip().lower()
        return (r.stdout if r.returncode == 0 else "", ctype)
    except Exception:
        return "", ""

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

def _db_url_placeholder(url_match: str) -> bool:
    """Filter MySQL/Postgres/Mongo/Redis matches whose host is obviously not
    a real production database (localhost, example.com, etc.) or whose
    password looks like a placeholder."""
    try:
        # crude parse — pattern guarantees the URL contains user:pass@host
        scheme, rest = url_match.split("://", 1)
        creds, hostpart = rest.split("@", 1)
        user, _, password = creds.partition(":")
        host = hostpart.split("/", 1)[0].split(":", 1)[0].lower()
    except ValueError:
        return False
    if host in _PLACEHOLDER_HOSTS or host.endswith(".local"):
        return True
    if _PLACEHOLDER_RE.search(password) or _PLACEHOLDER_RE.search(user):
        return True
    return False

def scan_secrets(content: str, url: str) -> list[dict]:
    """Find secret-shaped strings, applying per-pattern FP filters.

    Compared to the prior version this:
      • Rejects placeholder values (`YOUR_TOKEN_HERE`, `${var}`, `****`).
      • Rejects low-entropy / sentence-shaped values for the looser patterns.
      • Validates DB URLs have a non-localhost host and a non-placeholder
        password before flagging them.
      • Strips Basic-Auth-URL hits whose "user:pass" is actually a query
        parameter (`?q=user:pass@host`) rather than authority creds.
    """
    findings = []
    seen = set()
    for label, pattern in SECRETS.items():
        for m in re.finditer(pattern, content):
            full = m.group(0)
            # Use the first capture group when present — that's the actual
            # secret value for patterns like "password = '<value>'".
            value = m.group(1) if m.lastindex else full

            # Per-label additional gating
            if label.startswith("Database URL") and _db_url_placeholder(full):
                continue
            if label == "Basic Auth URL":
                # Reject query-string look-alikes — pattern requires the
                # match to land at a URL boundary, but extra check on the
                # surrounding chars catches `?q=user:pass@host`.
                start = m.start()
                left = content[max(0, start - 1):start]
                if left in ("=", "?", "&"):
                    continue
            if label not in _HIGH_CONFIDENCE:
                if not _looks_like_real_secret(value):
                    continue

            # Dedup across multiple pattern hits on the same value
            key = (label, full[:200])
            if key in seen:
                continue
            seen.add(key)

            findings.append({
                "type": "secret",
                "label": label,
                "value": full[:160],
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

def analyze_url(url: str, base_domain: str, beautify: bool, skip_libs: bool = True) -> list[dict]:
    if skip_libs and LIB_SKIP_RE.search(url):
        return []
    content, ctype = fetch_js(url)
    if not content:
        return []
    # If the URL accidentally returned HTML (e.g. SPA fall-through to index),
    # skip secret scanning — HTML produces noise via inline UI strings.
    if ctype and "html" in ctype and "javascript" not in ctype:
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
    parser.add_argument("--no-skip-libs",  action="store_true",
                        help="Don't skip well-known third-party library bundles (jquery/react/vue/etc.)")
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
        futs = {pool.submit(analyze_url, u, args.domain, not args.no_beautify,
                            not args.no_skip_libs): u for u in urls}
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 50 == 0:
                info(f"Progress: {done}/{len(urls)} files analyzed, {len(all_findings)} findings so far")
            try:
                results = fut.result()
                # Print each secret once and add the per-file results once.
                # (Previous version put extend() inside the per-finding loop,
                # producing N² duplicate entries in the output.)
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
