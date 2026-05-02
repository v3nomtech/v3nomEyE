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
cloud_misconfig.py — Cloud Storage & Service Misconfiguration Scanner
Checks: S3, Azure Blob, GCP Storage, Firebase, Elasticsearch, Kibana, Consul, Docker

Input: target domain (generates permutations) or explicit bucket list
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def crit(m):  print(f"{C.RED}{C.BOLD}[EXPOSED]{C.RESET} {m}")
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

def tool_exists(name): return shutil.which(name) is not None

def curl_get(url: str, timeout: int = 10, headers: list[str] | None = None) -> tuple[int, str]:
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-o", "-",
           "-w", "\n__SC__%{http_code}", "-L", "--max-redirs", "3",
           "-A", "Mozilla/5.0"]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        m = re.search(r"\n__SC__(\d+)$", r.stdout)
        sc = int(m.group(1)) if m else 0
        body = re.sub(r"\n__SC__\d+$", "", r.stdout)
        return sc, body
    except Exception:
        return 0, ""

# ── bucket name permutation generator ────────────────────────────────────────
def generate_bucket_names(domain: str) -> list[str]:
    base_parts = []
    # strip TLD(s)
    parts = domain.split(".")
    if len(parts) >= 2:
        base_parts.append(parts[0])             # e.g. "example"
        base_parts.append(".".join(parts[:-1]))  # e.g. "example" from "example.com"
        if len(parts) > 2:
            base_parts.append(parts[1])          # e.g. second label

    base_parts = list(dict.fromkeys(base_parts))  # dedup

    suffixes = [
        "", "-dev", "-staging", "-prod", "-test", "-backup",
        "-assets", "-static", "-media", "-upload", "-uploads",
        "-files", "-data", "-logs", "-images", "-img",
        "-public", "-private", "-internal", "-api",
        "-web", "-app", "-cdn", "-archive", "-store",
        "-bucket", "-s3", "-storage", "-bak", "-old", "-new",
    ]
    prefixes = ["", "dev-", "staging-", "prod-", "test-", "backup-",
                "assets-", "static-", "media-", "files-", "data-",
                "logs-", "internal-", "admin-"]

    names = set()
    for base in base_parts:
        for suf in suffixes:
            names.add(f"{base}{suf}")
        for pre in prefixes:
            names.add(f"{pre}{base}")

    return sorted(names)

# ── S3 ─────────────────────────────────────────────────────────────────────
S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1", "ap-southeast-1",
]
S3_OPEN_INDICATORS = [
    r"<ListBucketResult", r"<Contents>", r"<Key>",
    r"NoSuchBucket", r"AccessDenied",
]

def check_s3_bucket(name: str) -> dict | None:
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    for url in urls:
        sc, body = curl_get(url, timeout=8)
        if sc == 0:
            continue
        if "<ListBucketResult" in body or "<Contents>" in body:
            return {"service": "S3", "bucket": name, "url": url,
                    "status": "OPEN - listable", "severity": "critical", "body": body[:500]}
        if sc == 200 and "<Key>" in body:
            return {"service": "S3", "bucket": name, "url": url,
                    "status": "OPEN - readable", "severity": "critical", "body": body[:500]}
        if "AccessDenied" in body:
            return {"service": "S3", "bucket": name, "url": url,
                    "status": "EXISTS - access denied", "severity": "info", "body": ""}
    return None

# ── Azure Blob ────────────────────────────────────────────────────────────────
def check_azure_blob(name: str) -> dict | None:
    url = f"https://{name}.blob.core.windows.net/"
    sc, body = curl_get(url, timeout=8)
    if sc == 0:
        return None
    if sc == 200 and ("<EnumerationResults" in body or "<Container>" in body):
        return {"service": "Azure Blob", "bucket": name, "url": url,
                "status": "OPEN - listable", "severity": "critical", "body": body[:500]}
    if "BlobServiceProperties" in body or "StorageErrorCode" in body:
        return {"service": "Azure Blob", "bucket": name, "url": url,
                "status": "EXISTS", "severity": "info", "body": ""}
    # try container listing
    url2 = f"{url}?restype=container&comp=list"
    sc2, body2 = curl_get(url2, timeout=8)
    if sc2 == 200 and "<EnumerationResults" in body2:
        return {"service": "Azure Blob", "bucket": name, "url": url2,
                "status": "OPEN - container listable", "severity": "critical", "body": body2[:500]}
    return None

# ── GCP Storage ───────────────────────────────────────────────────────────────
def check_gcp_bucket(name: str) -> dict | None:
    urls = [
        f"https://storage.googleapis.com/{name}/",
        f"https://{name}.storage.googleapis.com/",
    ]
    for url in urls:
        sc, body = curl_get(url, timeout=8)
        if sc == 0:
            continue
        if sc == 200 and ('"items"' in body or '"kind"' in body):
            return {"service": "GCP Storage", "bucket": name, "url": url,
                    "status": "OPEN - listable", "severity": "critical", "body": body[:500]}
        if "NoSuchBucket" not in body and sc in (403, 200):
            return {"service": "GCP Storage", "bucket": name, "url": url,
                    "status": f"EXISTS - HTTP {sc}", "severity": "info", "body": ""}
    return None

# ── Firebase ──────────────────────────────────────────────────────────────────
def check_firebase(name: str) -> dict | None:
    url = f"https://{name}.firebaseio.com/.json"
    sc, body = curl_get(url, timeout=10)
    if sc == 200 and body.strip() not in ("null", "", "false"):
        return {"service": "Firebase", "bucket": name, "url": url,
                "status": "OPEN - data readable", "severity": "critical", "body": body[:500]}
    if sc == 200 and body.strip() == "null":
        return {"service": "Firebase", "bucket": name, "url": url,
                "status": "EXISTS - null response", "severity": "low", "body": ""}
    return None

# ── Exposed services on live hosts ────────────────────────────────────────────
EXPOSED_SERVICES = [
    # (path, indicator_regex, service_name, severity)
    ("", r'"cluster_name"', "Elasticsearch", "critical"),
    ("/_cat/indices", r"green|yellow|red", "Elasticsearch indices", "critical"),
    ("/app/kibana", r"kibana|kbn-version", "Kibana", "high"),
    ("/api/status", r'"name":"kibana"', "Kibana API", "high"),
    ("/v2/keys/", r'"action"', "etcd", "critical"),
    ("/v3/cluster/member/list", r'"members"', "etcd v3", "critical"),
    ("/v1/kv/", r'"LockIndex"', "Consul KV", "critical"),
    ("/v1/agent/self", r'"Config"', "Consul agent", "high"),
    ("/version", r'"ApiVersion"', "Docker daemon", "critical"),
    ("/containers/json", r'"Image"', "Docker containers", "critical"),
    ("/metrics", r'# HELP|process_cpu', "Prometheus metrics", "medium"),
    ("/actuator/env", r'"activeProfiles"', "Spring Actuator env", "critical"),
    ("/actuator/heapdump", r'', "Spring heapdump", "critical"),
    ("/_all", r'"_index"', "Elasticsearch _all", "critical"),
    ("/solr/admin/cores", r'"status"', "Apache Solr", "high"),
    ("/manager/html", r"Tomcat", "Tomcat manager", "high"),
]

def check_service_on_host(host: str) -> list[dict]:
    findings = []
    # hosts may or may not have port; test on common ports
    base_url = host.rstrip("/")

    for path, indicator, service, severity in EXPOSED_SERVICES:
        url = f"{base_url}{path}" if path else base_url
        sc, body = curl_get(url, timeout=6)
        if sc in (200, 301, 302) and (not indicator or re.search(indicator, body, re.IGNORECASE)):
            finding = {
                "service": service,
                "url": url,
                "status": f"HTTP {sc}",
                "severity": severity,
                "body": body[:300],
            }
            findings.append(finding)
            if severity == "critical":
                crit(f"{service} EXPOSED | {url}")
            else:
                warn(f"{service} exposed | {url}")
    return findings

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    parser.add_argument("-d", "--domain",      default="", help="Target domain for bucket permutations")
    parser.add_argument("-b", "--buckets",     default="", help="File with explicit bucket names (one per line)")
    parser.add_argument("-l", "--live-hosts",  default="", help="live_hosts.txt for service exposure checks")
    parser.add_argument("-o", "--output",      default="./cloud_results", help="Output directory")
    parser.add_argument("-t", "--threads",     type=int, default=30, help="Threads (default 30)")
    parser.add_argument("--skip-s3",           action="store_true")
    parser.add_argument("--skip-azure",        action="store_true")
    parser.add_argument("--skip-gcp",          action="store_true")
    parser.add_argument("--skip-firebase",     action="store_true")
    parser.add_argument("--skip-services",     action="store_true")
    args = parser.parse_args()

    if not args.domain and not args.buckets and not args.live_hosts:
        parser.error("Provide at least one of: --domain, --buckets, --live-hosts")

    os.makedirs(args.output, exist_ok=True)
    section("Cloud Misconfiguration Scanner")

    all_findings: list[dict] = []

    # ── bucket name list ───────────────────────────────────────────────────
    bucket_names = []
    if args.domain:
        bucket_names = generate_bucket_names(args.domain)
        info(f"Generated {len(bucket_names)} bucket name permutations for '{args.domain}'")
    if args.buckets:
        try:
            extra = [l.strip() for l in open(args.buckets) if l.strip()]
            bucket_names = list(dict.fromkeys(bucket_names + extra))
            info(f"Loaded {len(extra)} additional bucket names from file")
        except FileNotFoundError:
            warn(f"Bucket file not found: {args.buckets}")

    # ── S3 scan ───────────────────────────────────────────────────────────
    if bucket_names and not args.skip_s3:
        section("S3 Bucket Check")
        info(f"Checking {len(bucket_names)} names against S3...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for result in pool.map(check_s3_bucket, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"] == "critical":
                        crit(f"S3 {result['status']} | s3://{result['bucket']}")
                    else:
                        info(f"S3 {result['status']} | s3://{result['bucket']}")

    # ── Azure Blob scan ───────────────────────────────────────────────────
    if bucket_names and not args.skip_azure:
        section("Azure Blob Check")
        info(f"Checking {len(bucket_names)} names against Azure Blob...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for result in pool.map(check_azure_blob, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"] == "critical":
                        crit(f"Azure {result['status']} | {result['url']}")

    # ── GCP scan ──────────────────────────────────────────────────────────
    if bucket_names and not args.skip_gcp:
        section("GCP Storage Check")
        info(f"Checking {len(bucket_names)} names against GCP...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for result in pool.map(check_gcp_bucket, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"] == "critical":
                        crit(f"GCP {result['status']} | {result['url']}")

    # ── Firebase scan ─────────────────────────────────────────────────────
    if bucket_names and not args.skip_firebase:
        section("Firebase Check")
        info(f"Checking {len(bucket_names)} names against Firebase...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for result in pool.map(check_firebase, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"] == "critical":
                        crit(f"Firebase {result['status']} | {result['url']}")

    # ── Exposed services on live hosts ────────────────────────────────────
    if args.live_hosts and not args.skip_services:
        section("Exposed Service Detection")
        try:
            hosts = [l.strip() for l in open(args.live_hosts) if l.strip()]
        except FileNotFoundError:
            hosts = []
        info(f"Checking {len(hosts)} live hosts for exposed services...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for results in pool.map(check_service_on_host, hosts):
                all_findings.extend(results)

    # ── write outputs ─────────────────────────────────────────────────────
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high     = [f for f in all_findings if f.get("severity") == "high"]

    json_out = f"{args.output}/findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    report_out = f"{args.output}/report.txt"
    with open(report_out, "w") as f:
        f.write(f"Cloud Misconfiguration Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        for item in sorted(all_findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),5)):
            sev = item.get("severity","?").upper()
            svc = item.get("service","?")
            url = item.get("url", item.get("bucket","?"))
            status = item.get("status","?")
            f.write(f"[{sev}] {svc} | {status} | {url}\n")
            if item.get("body"):
                f.write(f"  Response: {item['body'][:200]}\n")
            f.write("\n")

    section("Summary")
    ok(f"Critical findings : {C.BOLD}{len(critical)}{C.RESET}")
    ok(f"High findings     : {C.BOLD}{len(high)}{C.RESET}")
    ok(f"Total findings    : {C.BOLD}{len(all_findings)}{C.RESET}")
    ok(f"Report            : {report_out}")
    ok(f"JSON              : {json_out}")

if __name__ == "__main__":
    main()
