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

def curl_req(url: str, method: str = "GET", timeout: int = 10,
             headers: list[str] | None = None, body: str | None = None) -> tuple[int, str, dict]:
    """Run curl, return (status_code, response_body, response_headers).

    Used everywhere instead of plain GET so we can do PUT/HEAD probes for
    write-test and lightweight existence checks.
    """
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-X", method,
           "-o", "-", "-D", "/dev/stderr",
           "-w", "\n__SC__%{http_code}",
           "-A", "Mozilla/5.0"]
    if method == "HEAD":
        cmd.insert(1, "-I")
    else:
        cmd += ["-L", "--max-redirs", "3"]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    if body is not None:
        cmd += ["--data-binary", body]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        out = r.stdout or ""
        m = re.search(r"\n__SC__(\d+)$", out)
        sc = int(m.group(1)) if m else 0
        resp_body = re.sub(r"\n__SC__\d+$", "", out)
        hdrs = {}
        for line in (r.stderr or "").splitlines():
            if ":" in line and not line.startswith("HTTP/"):
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        return sc, resp_body, hdrs
    except Exception:
        return 0, "", {}

def curl_get(url: str, timeout: int = 10, headers: list[str] | None = None) -> tuple[int, str]:
    sc, body, _ = curl_req(url, "GET", timeout, headers)
    return sc, body

# Multi-label public TLDs we should treat as a single TLD. Without this,
# ``mycompany.co.uk`` would yield base "mycompany.co" and waste lookups on
# names that bucket providers don't accept (dots).
_MULTI_TLDS = {
    "co.uk","co.in","co.jp","co.kr","co.za","com.br","com.au","com.mx",
    "com.tr","com.cn","com.sg","com.tw","com.ar","com.pl","ne.jp",
    "or.jp","gov.uk","ac.uk","co.id",
}

def _registered_label(domain: str) -> str:
    """Return the registered (eTLD+1) label, e.g. mycompany.co.uk → mycompany."""
    d = domain.lower().strip().lstrip(".")
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLDS:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return d

# ── bucket name permutation generator ────────────────────────────────────────
def generate_bucket_names(domain: str) -> list[str]:
    base = _registered_label(domain)
    base_parts = [base]
    parts = domain.lower().split(".")
    # If a meaningful subdomain exists ("app.example.com"), keep it — companies
    # often name buckets after products. Skip generic prefixes.
    if len(parts) >= 3 and parts[0] != base and parts[0] not in {
            "www","api","static","cdn","app","mail","blog","shop"}:
        base_parts.append(parts[0])
    base_parts = list(dict.fromkeys(base_parts))

    suffixes = [
        "", "-dev", "-staging", "-prod", "-test", "-backup", "-bak",
        "-assets", "-static", "-media", "-upload", "-uploads",
        "-files", "-data", "-logs", "-images", "-img",
        "-public", "-private", "-internal", "-api",
        "-web", "-app", "-cdn", "-archive", "-store",
        "-bucket", "-s3", "-storage", "-old", "-new",
        "-reports", "-export", "-exports", "-tmp", "-temp", "-secret",
        "-config", "-configs", "-deploy", "-build", "-ci",
    ]
    prefixes = ["", "dev-", "staging-", "prod-", "test-", "backup-",
                "assets-", "static-", "media-", "files-", "data-",
                "logs-", "internal-", "admin-", "tmp-", "secret-"]

    names = set()
    for b in base_parts:
        if not b or "." in b:
            continue  # bucket names with dots are mostly invalid for our checks
        for suf in suffixes:
            names.add(f"{b}{suf}")
        for pre in prefixes:
            names.add(f"{pre}{b}")
    return sorted(names)

# ── S3 ─────────────────────────────────────────────────────────────────────
def check_s3_bucket(name: str, write_test: bool = False) -> dict | None:
    """Detect S3 bucket existence + listable/readable/writable misconfigs.

    Improvements over the prior version:
      • Properly recognises ``NoSuchBucket`` to skip nonexistent names.
      • Probes ``?acl`` to distinguish exists-private from exists-with-public-acl.
      • Optional PUT write-test (off by default — only run when authorised).
    """
    urls = [
        f"https://{name}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{name}/",
    ]
    last_url = urls[0]
    exists = False
    for url in urls:
        last_url = url
        sc, body = curl_get(url, timeout=8)
        if sc == 0:
            continue
        if "<Code>NoSuchBucket</Code>" in body or "NoSuchBucket" in body:
            return None  # confirmed not exist — short-circuit
        if "<ListBucketResult" in body or "<Contents>" in body:
            return {"service":"S3","bucket":name,"url":url,
                    "status":"OPEN - listable","severity":"critical","body":body[:500]}
        if sc == 200 and "<Key>" in body:
            return {"service":"S3","bucket":name,"url":url,
                    "status":"OPEN - readable","severity":"critical","body":body[:500]}
        if "<Code>AccessDenied</Code>" in body or sc == 403:
            exists = True
            break
        if sc in (301, 307):
            # redirected to correct region — bucket exists
            exists = True
            break

    if not exists:
        return None

    # Bucket exists but bare GET denied. Probe ?acl to see if anonymous can
    # read the ACL (still a finding, lower severity).
    acl_sc, acl_body = curl_get(f"https://{name}.s3.amazonaws.com/?acl", timeout=8)
    if acl_sc == 200 and "<AccessControlList>" in acl_body:
        return {"service":"S3","bucket":name,"url":f"https://{name}.s3.amazonaws.com/?acl",
                "status":"EXISTS - ACL readable","severity":"high","body":acl_body[:500]}

    if write_test:
        # Authorised write probe: PUT a tiny canary object. Removes itself if
        # successful via DELETE. Only ever run with explicit --write-test flag.
        canary = "venom-canary.txt"
        sc_put, body_put, _ = curl_req(
            f"https://{name}.s3.amazonaws.com/{canary}",
            method="PUT", timeout=8, body="venom-canary")
        if sc_put in (200, 204):
            curl_req(f"https://{name}.s3.amazonaws.com/{canary}",
                     method="DELETE", timeout=8)
            return {"service":"S3","bucket":name,"url":f"https://{name}.s3.amazonaws.com/",
                    "status":"OPEN - writable (canary PUT succeeded)",
                    "severity":"critical","body":body_put[:300]}

    return {"service":"S3","bucket":name,"url":last_url,
            "status":"EXISTS - access denied","severity":"info","body":""}

# ── Azure Blob ────────────────────────────────────────────────────────────────
def check_azure_blob(name: str) -> dict | None:
    """Improvements:
      • Drops the noisy "EXISTS" finding on any response containing
        "BlobServiceProperties" / "StorageErrorCode" — Azure includes those
        strings in error replies for almost any URL.
      • Requires a real container listing (<EnumerationResults>) for crit.
    """
    url = f"https://{name}.blob.core.windows.net/"
    sc, body = curl_get(url, timeout=8)
    if sc == 0:
        return None
    if sc == 200 and ("<EnumerationResults" in body or "<Container>" in body):
        return {"service":"Azure Blob","bucket":name,"url":url,
                "status":"OPEN - listable","severity":"critical","body":body[:500]}
    # container listing form
    url2 = f"{url}?restype=container&comp=list"
    sc2, body2 = curl_get(url2, timeout=8)
    if sc2 == 200 and "<EnumerationResults" in body2:
        return {"service":"Azure Blob","bucket":name,"url":url2,
                "status":"OPEN - container listable","severity":"critical","body":body2[:500]}
    return None

# ── GCP Storage ───────────────────────────────────────────────────────────────
def check_gcp_bucket(name: str) -> dict | None:
    """Improvements: only flag an "EXISTS" when the response actually contains
    a real GCS error code that proves the bucket exists but is private. The
    prior code flagged any 403 response, which fires for buckets owned by
    someone else's project too."""
    urls = [
        f"https://storage.googleapis.com/{name}/",
        f"https://{name}.storage.googleapis.com/",
    ]
    for url in urls:
        sc, body = curl_get(url, timeout=8)
        if sc == 0:
            continue
        if sc == 200 and "<ListBucketResult" in body and "<Contents>" in body:
            return {"service":"GCP Storage","bucket":name,"url":url,
                    "status":"OPEN - listable","severity":"critical","body":body[:500]}
        if sc == 200 and ('"items"' in body or '"kind":"storage#objects"' in body):
            return {"service":"GCP Storage","bucket":name,"url":url,
                    "status":"OPEN - listable","severity":"critical","body":body[:500]}
        if sc == 403 and "<Code>AccessDenied</Code>" in body:
            return {"service":"GCP Storage","bucket":name,"url":url,
                    "status":"EXISTS - access denied","severity":"info","body":""}
    return None

# ── Firebase ──────────────────────────────────────────────────────────────────
def check_firebase(name: str) -> dict | None:
    """Improvements: a 200 with ``{"error":"Permission denied"}`` is the
    *protected* Firebase response — was previously marked critical. Now
    correctly returns None for that case."""
    url = f"https://{name}.firebaseio.com/.json"
    sc, body = curl_get(url, timeout=10)
    if sc != 200:
        return None
    stripped = body.strip()
    # Permission denied / unauthorized → properly secured DB
    if '"error"' in stripped and ("Permission denied" in stripped or "Unauthorized" in stripped):
        return None
    if stripped in ("", "false"):
        return None
    if stripped == "null":
        return {"service":"Firebase","bucket":name,"url":url,
                "status":"EXISTS - null response (auth optional)","severity":"low","body":""}
    # Anything else is real readable data
    return {"service":"Firebase","bucket":name,"url":url,
            "status":"OPEN - data readable","severity":"critical","body":body[:500]}

# ── DigitalOcean Spaces ───────────────────────────────────────────────────────
DO_REGIONS = ["nyc3","sfo2","sfo3","ams3","sgp1","fra1","syd1","blr1"]
def check_do_spaces(name: str) -> dict | None:
    for region in DO_REGIONS:
        url = f"https://{name}.{region}.digitaloceanspaces.com/"
        sc, body = curl_get(url, timeout=6)
        if sc == 0:
            continue
        if "<ListBucketResult" in body or "<Contents>" in body:
            return {"service":"DO Spaces","bucket":name,"url":url,
                    "status":"OPEN - listable","severity":"critical","body":body[:500]}
        if "<Code>NoSuchBucket</Code>" in body:
            continue
        if sc == 403 and "<Code>AccessDenied</Code>" in body:
            return {"service":"DO Spaces","bucket":name,"url":url,
                    "status":"EXISTS - access denied","severity":"info","body":""}
    return None

# ── Backblaze B2 / Wasabi / Linode / Alibaba OSS ──────────────────────────────
_S3_COMPATIBLE_HOSTS = [
    ("Wasabi",           "https://s3.wasabisys.com/{name}/"),
    ("Backblaze B2",     "https://f000.backblazeb2.com/file/{name}/"),
    ("Linode Objects",   "https://{name}.us-east-1.linodeobjects.com/"),
    ("Alibaba OSS",      "https://{name}.oss-cn-hangzhou.aliyuncs.com/"),
    ("Cloudflare R2",    "https://{name}.r2.cloudflarestorage.com/"),
]
def check_s3_compatible(name: str) -> list[dict]:
    """Probe additional S3-compatible providers; only flag definite findings."""
    out = []
    for service, tmpl in _S3_COMPATIBLE_HOSTS:
        url = tmpl.format(name=name)
        sc, body = curl_get(url, timeout=6)
        if sc == 0:
            continue
        if "<ListBucketResult" in body or "<Contents>" in body:
            out.append({"service":service,"bucket":name,"url":url,
                        "status":"OPEN - listable","severity":"critical","body":body[:500]})
    return out

# ── Exposed services on live hosts ────────────────────────────────────────────
# Each entry: (path, indicator_regex, service_name, severity, optional content_check)
# `indicator` MUST be non-empty — the prior version had an empty regex which
# always matched and caused FPs on login redirects. To check binary endpoints
# (heapdump etc.) we now use a HEAD probe and inspect headers separately.
EXPOSED_SERVICES = [
    ("/",                              r'"cluster_name"\s*:',          "Elasticsearch",          "critical"),
    ("/_cat/indices",                  r"^(green|yellow|red)\s",       "Elasticsearch indices",  "critical"),
    ("/_cluster/health",               r'"cluster_name"\s*:',          "Elasticsearch health",   "critical"),
    ("/app/kibana",                    r"kbn-version|kibana-app",      "Kibana app",             "high"),
    ("/api/status",                    r'"name"\s*:\s*"kibana"',       "Kibana status API",      "high"),
    ("/v2/keys/",                      r'"action"\s*:\s*"get"',        "etcd v2",                "critical"),
    ("/v3/cluster/member/list",        r'"members"',                   "etcd v3",                "critical"),
    ("/v1/kv/?recurse",                r'"LockIndex"',                 "Consul KV",              "critical"),
    ("/v1/agent/self",                 r'"Config"\s*:\s*\{',           "Consul agent",           "high"),
    ("/version",                       r'"ApiVersion"\s*:',            "Docker daemon",          "critical"),
    ("/containers/json",               r'"Image"\s*:\s*"',             "Docker containers",      "critical"),
    ("/metrics",                       r"^# HELP |^process_cpu",       "Prometheus metrics",     "medium"),
    ("/actuator",                      r'"_links"\s*:\s*\{',           "Spring Actuator index",  "high"),
    ("/actuator/env",                  r'"activeProfiles"',            "Spring Actuator env",    "critical"),
    ("/actuator/mappings",             r'"contexts"',                  "Spring Actuator mappings","high"),
    ("/actuator/configprops",          r'"contexts"',                  "Spring Actuator configprops","high"),
    ("/actuator/beans",                r'"contexts"',                  "Spring Actuator beans",  "high"),
    ("/actuator/threaddump",           r'"threads"',                   "Spring Actuator threaddump","high"),
    ("/actuator/loggers",              r'"loggers"',                   "Spring Actuator loggers","high"),
    ("/_all",                          r'"_index"\s*:\s*"',            "Elasticsearch _all",     "critical"),
    ("/solr/admin/cores",              r'"status"\s*:\s*\{',           "Apache Solr admin",      "high"),
    ("/manager/html",                  r"<title>/manager",             "Tomcat manager",         "high"),
    ("/server-status",                 r"<title>Apache Status",        "Apache server-status",   "high"),
    ("/jolokia",                       r'"agent"\s*:\s*"',             "Jolokia agent",          "high"),
    ("/jenkins/",                      r"X-Jenkins|Jenkins-CLI",       "Jenkins",                "high"),
    ("/api/v1/projects",               r'"web_url"',                   "GitLab API",             "high"),
    ("/api/v4/projects",               r'"web_url"',                   "GitLab API v4",          "high"),
    ("/grafana/api/datasources",       r'"datasource"',                "Grafana datasources",    "critical"),
    ("/api/datasources",               r'"datasource"',                "Grafana datasources",    "critical"),
    ("/airflow/api/v1/dags",           r'"dags"',                      "Airflow API",            "critical"),
    ("/api/v1/dags",                   r'"dags"',                      "Airflow API",            "critical"),
    ("/_stcore/health",                r"^ok\b",                       "Streamlit health",       "low"),
    ("/api/users",                     r'"username"\s*:\s*"',          "Sonar API",              "high"),
]

# Common ports on which cloud services are exposed when the host's main HTTP
# port doesn't expose them. Disabled by default — the recon pipeline already
# runs naabu, so this stays opt-in via --port-sweep.
COMMON_PORTS = [
    (9200, "https"), (9200, "http"),     # Elasticsearch
    (5601, "http"),                       # Kibana
    (8080, "http"), (8443, "https"),      # generic
    (8086, "http"),                       # InfluxDB
    (3000, "http"),                       # Grafana
    (8888, "http"),                       # Jupyter
    (15672, "http"),                      # RabbitMQ mgmt
    (4040, "http"),                       # Spark
    (9000, "http"),                       # SonarQube / Portainer
    (2375, "http"),                       # Docker daemon
    (8500, "http"),                       # Consul
    (2379, "http"),                       # etcd
    (9090, "http"),                       # Prometheus
]

def _heapdump_probe(host: str) -> dict | None:
    """Heapdump-style endpoints don't have JSON markers — verify via headers."""
    for path in ("/actuator/heapdump", "/heapdump"):
        url = f"{host.rstrip('/')}{path}"
        sc, _, hdrs = curl_req(url, "HEAD", timeout=6)
        if sc != 200:
            continue
        ctype = (hdrs.get("content-type", "") or "").lower()
        clen  = int(hdrs.get("content-length", "0") or "0")
        # Real heapdumps are application/octet-stream and large (>100KB)
        if "application/octet-stream" in ctype and clen > 100_000:
            return {"service":"Spring heapdump","url":url,
                    "status":f"HTTP 200 ({clen} bytes)",
                    "severity":"critical","body":""}
    return None

def check_service_on_host(host: str, port_sweep: bool = False) -> list[dict]:
    findings = []
    base_url = host.rstrip("/")
    targets = [base_url]
    if port_sweep:
        # Strip any existing port and produce permutations
        m = re.match(r"^(https?)://([^/:]+)", base_url)
        if m:
            scheme, hostname = m.group(1), m.group(2)
            for port, port_scheme in COMMON_PORTS:
                if port in (80, 443):
                    continue
                targets.append(f"{port_scheme}://{hostname}:{port}")

    for target in targets:
        for path, indicator, service, severity in EXPOSED_SERVICES:
            url = f"{target}{path}"
            sc, body = curl_get(url, timeout=6)
            # Real exposure must return 200 — drop 301/302 (login redirects)
            if sc != 200:
                continue
            if not re.search(indicator, body, re.IGNORECASE | re.MULTILINE):
                continue
            findings.append({"service":service,"url":url,
                             "status":f"HTTP {sc}","severity":severity,
                             "body":body[:300]})
            (crit if severity == "critical" else warn)(f"{service} exposed | {url}")
        # heapdump (binary) — header-only verification
        hd = _heapdump_probe(target)
        if hd:
            findings.append(hd)
            crit(f"{hd['service']} | {hd['url']}")
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
    parser.add_argument("--skip-extra-clouds", action="store_true",
                        help="Skip DigitalOcean Spaces, Wasabi, B2, Linode, OSS, R2 probes")
    parser.add_argument("--write-test",        action="store_true",
                        help="S3 buckets: PUT a canary object to test write access (only with explicit authorisation)")
    parser.add_argument("--port-sweep",        action="store_true",
                        help="When checking exposed services, also sweep common service ports (9200, 5601, 3000, 2375, ...)")
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
        info(f"Checking {len(bucket_names)} names against S3" +
             (" (write-test enabled)" if args.write_test else ""))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = [pool.submit(check_s3_bucket, n, args.write_test) for n in bucket_names]
            for fut in concurrent.futures.as_completed(futs):
                result = fut.result()
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

    # ── DigitalOcean Spaces ───────────────────────────────────────────────
    if bucket_names and not args.skip_extra_clouds:
        section("DigitalOcean Spaces Check")
        info(f"Checking {len(bucket_names)} names against DO Spaces...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for result in pool.map(check_do_spaces, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"] == "critical":
                        crit(f"DO Spaces {result['status']} | {result['url']}")

        # ── Other S3-compatible providers (Wasabi, B2, Linode, OSS, R2) ───
        section("S3-compatible Providers Check")
        info(f"Checking {len(bucket_names)} names against Wasabi/B2/Linode/OSS/R2...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            for results in pool.map(check_s3_compatible, bucket_names):
                for result in results:
                    all_findings.append(result)
                    crit(f"{result['service']} {result['status']} | {result['url']}")

    # ── Exposed services on live hosts ────────────────────────────────────
    if args.live_hosts and not args.skip_services:
        section("Exposed Service Detection")
        try:
            hosts = [l.strip() for l in open(args.live_hosts) if l.strip()]
        except FileNotFoundError:
            hosts = []
        info(f"Checking {len(hosts)} live hosts for exposed services" +
             (" + port sweep" if args.port_sweep else "") + "...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = [pool.submit(check_service_on_host, h, args.port_sweep) for h in hosts]
            for fut in concurrent.futures.as_completed(futs):
                all_findings.extend(fut.result())

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
