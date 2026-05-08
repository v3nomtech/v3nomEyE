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
xss_sqli_scanner.py — Active XSS / SQLi / SSTI Scanner
Input: params.txt from venomeye output (URLs with query parameters)

Runs:
  - dalfox  → reflected/DOM XSS
  - sqlmap  → SQL injection (batch, no interaction)
  - Built-in SSTI probe payloads
  - Built-in open redirect confirmation
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def crit(m):  print(f"{C.RED}{C.BOLD}[VULN]{C.RESET} {m}")
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

def run(cmd, timeout=300, input_data=None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True,
            timeout=timeout, input=input_data
        )
    except subprocess.TimeoutExpired:
        warn(f"Timeout: {cmd[:80] if isinstance(cmd, str) else cmd[0]}")
        return subprocess.CompletedProcess(cmd, 1, "", "timeout")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

# ── SSTI payloads ─────────────────────────────────────────────────────────────
# Each entry: (payload, expected_result, template_engine_hint)
# We use 8-digit unique results (7777*7777 = 60481729) to avoid the rampant
# false positives that come from short numeric matches like "49" appearing in
# random HTML/CSS/JS. The detector also requires that the payload itself NOT
# be reflected verbatim — if it is, the engine never evaluated it.
SSTI_PAYLOADS = [
    ("{{7777*7777}}",            "60481729", "Jinja2/Twig"),
    ("${7777*7777}",             "60481729", "FreeMarker/Groovy"),
    ("#{7777*7777}",             "60481729", "Thymeleaf/MVEL"),
    ("<%= 7777*7777 %>",         "60481729", "ERB/EJS"),
    ("${{7777*7777}}",           "60481729", "Spring/SPEL"),
    ("{{7*'7777777'}}",          "7777777777777777777777777777777777777777777777777", "Jinja2 str-mul"),
]
# Context/leak payloads need stronger anchors than a generic "SECRET" substring,
# which collides with words like "secrets policy" in normal pages.
SSTI_LEAK_PAYLOADS = [
    ("{{config.items()}}",                          r"SECRET_KEY['\"]?\s*[:,]", "Jinja2 config leak"),
    ("{{self._TemplateReference__context}}",        r"_TemplateReference__context",         "Jinja2 context leak"),
]

# ── open redirect payloads ─────────────────────────────────────────────────────
# Detection requires the *resolved* Location host to equal the canary host (or
# a subdomain of it). Using a less-common canary keeps real apps from naturally
# echoing it in path/query and tripping the detector.
REDIRECT_CANARY = "venomcanary.evil-redirect.com"
REDIRECT_PAYLOADS = [
    f"https://{REDIRECT_CANARY}/",
    f"//{REDIRECT_CANARY}/",
    f"///{REDIRECT_CANARY}/",
    f"/\\/{REDIRECT_CANARY}/",
    f"https:{REDIRECT_CANARY}/",
    f"%0d%0ahttps://{REDIRECT_CANARY}/",
]

# ── XSS via dalfox ───────────────────────────────────────────────────────────
def run_dalfox(urls_file: str, out_dir: str, threads: int, cookie: str) -> list[dict]:
    section("XSS Scan — dalfox")
    findings = []

    if not tool_exists("dalfox"):
        warn("dalfox not installed — skipping XSS scan")
        warn("Install: go install github.com/hahwul/dalfox/v2@latest")
        return findings

    out_file = f"{out_dir}/xss_dalfox.txt"
    json_out  = f"{out_dir}/xss_dalfox.json"

    cmd = [
        "dalfox", "file", urls_file,
        "--silence", "--no-color",
        "--output", out_file,
        "--format", "json",
        "--output-json", json_out,
        "--worker", str(threads),
        "--timeout", "10",
        "--delay", "100",
    ]
    if cookie:
        cmd += ["--cookie", cookie]

    info(f"Running dalfox on {_count_lines(urls_file)} URLs...")
    run(cmd, timeout=3600)

    # parse results
    if Path(json_out).exists():
        try:
            data = json.loads(Path(json_out).read_text())
            for item in (data if isinstance(data, list) else [data]):
                crit(f"XSS | {item.get('param','?')} @ {item.get('url','?')}")
                findings.append({"type": "xss", "data": item})
        except Exception:
            # fallback: parse text output
            for line in open(out_file, errors="ignore"):
                if "[V]" in line or "POC" in line.upper():
                    crit(f"XSS → {line.strip()}")
                    findings.append({"type": "xss", "raw": line.strip()})

    ok(f"XSS findings: {len(findings)}")
    return findings

# ── SQLi via sqlmap ───────────────────────────────────────────────────────────
def run_sqlmap(urls_file: str, out_dir: str, cookie: str, level: int, risk: int) -> list[dict]:
    section("SQLi Scan — sqlmap")
    findings = []

    if not tool_exists("sqlmap"):
        warn("sqlmap not installed — skipping SQLi scan")
        return findings

    sqlmap_out = f"{out_dir}/sqlmap"
    os.makedirs(sqlmap_out, exist_ok=True)

    cmd = [
        "sqlmap", "-m", urls_file,
        "--batch", "--random-agent",
        "--level", str(level),
        "--risk", str(risk),
        "--threads", "5",
        "--output-dir", sqlmap_out,
        "--forms",
        "--crawl=2",
        "--timeout=10",
        "--retries=1",
        "--answers=quit=N,crack=N,dict=N",
        "--tamper=space2comment,between",
    ]
    if cookie:
        cmd += ["--cookie", cookie]

    info(f"Running sqlmap (level={level} risk={risk}) on {_count_lines(urls_file)} URLs...")
    r = run(cmd, timeout=7200)

    # parse sqlmap output for vulnerable targets
    vuln_pattern = re.compile(r"Parameter '([^']+)' is vulnerable", re.IGNORECASE)
    url_pattern  = re.compile(r"Target URL: (https?://\S+)", re.IGNORECASE)
    current_url  = ""
    for line in (r.stdout + r.stderr).splitlines():
        m = url_pattern.search(line)
        if m:
            current_url = m.group(1)
        m = vuln_pattern.search(line)
        if m:
            crit(f"SQLi | param='{m.group(1)}' @ {current_url}")
            findings.append({"type": "sqli", "param": m.group(1), "url": current_url})

    ok(f"SQLi findings: {len(findings)}")
    return findings

# ── SSTI scan (built-in) ──────────────────────────────────────────────────────
def _ssti_curl(url: str, cookie_header: str, timeout: int) -> str:
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-L",
           "--max-redirs", "3", "-A", "Mozilla/5.0"]
    if cookie_header:
        cmd += ["-H", f"Cookie: {cookie_header}"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        return r.stdout or ""
    except Exception:
        return ""

def test_ssti_url(url: str, cookie_header: str, timeout: int) -> list[dict]:
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    # Baseline once per URL — used to suppress findings where the "expected"
    # marker already appears in the page (e.g. the digits 60481729 happen to
    # exist in some inline JSON).
    baseline = _ssti_curl(url, cookie_header, timeout)

    findings = []
    for param_key in params:
        # Step 1 — confirm the parameter is actually reflected. If a sentinel
        # we send doesn't come back, no template engine ever saw it, so SSTI
        # is impossible. This kills the bulk of false positives that pure
        # string-match detectors generate.
        sentinel = "vEnoMsStI91827364"
        probe_params = dict(params)
        probe_params[param_key] = [sentinel]
        probe_url = urllib.parse.urlunparse(parsed._replace(
            query=urllib.parse.urlencode(probe_params, doseq=True)))
        probe_body = _ssti_curl(probe_url, cookie_header, timeout)
        if sentinel not in probe_body:
            continue

        for payload, expected, engine in SSTI_PAYLOADS:
            # Skip if the result string already shows up in baseline — the
            # finding would be ambiguous.
            if expected in baseline:
                continue

            test_params = dict(params)
            test_params[param_key] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_params, doseq=True)))
            body = _ssti_curl(test_url, cookie_header, timeout)
            if not body:
                continue

            # Confirmation: result is present AND raw payload is not echoed
            # back. If `{{7777*7777}}` appears verbatim, the framework just
            # reflected it as a string — no evaluation happened.
            if expected in body and payload not in body:
                findings.append({
                    "type": "ssti",
                    "severity": "critical",
                    "url": url,
                    "param": param_key,
                    "payload": payload,
                    "engine": engine,
                    "response_snippet": body[:200],
                })
                crit(f"SSTI ({engine}) | param='{param_key}' payload='{payload}' @ {url}")
                break  # one confirmed SSTI per param is enough

        # Leak-style payloads use regex anchors, separate loop so we don't
        # short-circuit after a math probe.
        for payload, expected_re, engine in SSTI_LEAK_PAYLOADS:
            if re.search(expected_re, baseline or ""):
                continue
            test_params = dict(params)
            test_params[param_key] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_params, doseq=True)))
            body = _ssti_curl(test_url, cookie_header, timeout)
            if body and re.search(expected_re, body) and payload not in body:
                findings.append({
                    "type": "ssti",
                    "severity": "critical",
                    "url": url,
                    "param": param_key,
                    "payload": payload,
                    "engine": engine,
                    "response_snippet": body[:200],
                })
                crit(f"SSTI ({engine}) | param='{param_key}' payload='{payload}' @ {url}")
                break
    return findings

def run_ssti(urls_file: str, out_dir: str, threads: int, cookie: str) -> list[dict]:
    section("SSTI Scan — built-in probes")
    try:
        urls = [l.strip() for l in open(urls_file) if l.strip()]
    except FileNotFoundError:
        return []

    info(f"Testing {len(urls)} parameterized URLs for SSTI...")
    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(test_ssti_url, u, cookie, 10): u for u in urls}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 200 == 0:
                info(f"SSTI progress: {done}/{len(urls)}")
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass

    ok(f"SSTI findings: {len(all_findings)}")
    return all_findings

# ── Open Redirect confirmation ─────────────────────────────────────────────────
def _parse_status_and_location(raw_headers: str) -> tuple[int, str]:
    """Return (status_code, location_header) from raw header dump. (0,'') on fail."""
    status = 0
    location = ""
    for line in raw_headers.splitlines():
        if not line.strip():
            continue
        if line.startswith("HTTP/"):
            m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
            if m:
                status = int(m.group(1))
                location = ""  # reset on each new response (curl can dump several)
            continue
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return status, location

def test_redirect_url(url: str, timeout: int) -> list[dict]:
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    redirect_params = {
        "url","redirect","next","return","returnurl","return_to","goto",
        "destination","redir","redirect_uri","callback","out","view","to",
        "target","link","src","source","continue","location","ref"
    }
    canary = REDIRECT_CANARY.lower()

    findings = []
    for key in params:
        if key.lower() not in redirect_params:
            continue
        for payload in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[key] = [payload]
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                # Real GET with header dump — some endpoints only redirect on GET
                r = subprocess.run(
                    ["curl", "-sk", "-X", "GET", "-D", "-", "-o", "/dev/null",
                     "--max-time", str(timeout), "--max-redirs", "0",
                     "-A", "Mozilla/5.0", test_url],
                    capture_output=True, text=True, timeout=timeout+2
                )
                status, loc = _parse_status_and_location(r.stdout or "")
                # Real open redirect requires a 3xx status with a Location header.
                if not (300 <= status < 400) or not loc:
                    continue

                # Resolve relative Location against the request URL, then parse
                # the *hostname* of the destination — substring matches in path
                # or query (e.g. "Location: /error?blocked=evil.com") were the
                # main FP source. Hostname compare is precise.
                absolute = urllib.parse.urljoin(test_url, loc)
                dest_host = (urllib.parse.urlparse(absolute).hostname or "").lower()
                if dest_host == canary or dest_host.endswith("." + canary):
                    findings.append({
                        "type": "open_redirect",
                        "severity": "medium",
                        "url": url,
                        "param": key,
                        "payload": payload,
                        "location": loc,
                        "status": status,
                    })
                    crit(f"OPEN REDIRECT | param='{key}' → {loc} @ {url}")
                    break
            except Exception:
                continue
    return findings

def run_redirect_check(urls_file: str, out_dir: str, threads: int) -> list[dict]:
    section("Open Redirect Confirmation")
    try:
        urls = [l.strip() for l in open(urls_file) if l.strip()]
    except FileNotFoundError:
        return []

    info(f"Confirming {len(urls)} redirect candidates...")
    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(test_redirect_url, u, 8): u for u in urls}
        for fut in concurrent.futures.as_completed(futs):
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass

    ok(f"Confirmed open redirects: {len(all_findings)}")
    return all_findings

def _count_lines(path):
    try:
        return sum(1 for _ in open(path) if _.strip())
    except Exception:
        return 0

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="XSS / SQLi / SSTI Active Scanner")
    parser.add_argument("-i", "--input",   required=True, help="params.txt (parameterized URLs)")
    parser.add_argument("-o", "--output",  default="./param_scan", help="Output directory")
    parser.add_argument("--cookie",        default="", help="Cookie header value for authenticated scans")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads for SSTI/redirect checks")
    parser.add_argument("--sqli-level",   type=int, default=1, choices=[1,2,3,4,5])
    parser.add_argument("--sqli-risk",    type=int, default=1, choices=[1,2,3])
    parser.add_argument("--skip-xss",     action="store_true")
    parser.add_argument("--skip-sqli",    action="store_true")
    parser.add_argument("--skip-ssti",    action="store_true")
    parser.add_argument("--skip-redirect",action="store_true")
    parser.add_argument("--redirect-file",default="", help="Separate redirect candidates file")
    parser.add_argument("--limit",        type=int, default=0, help="Max URLs per scan (0=all)")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    section("XSS / SQLi / SSTI Scanner")
    info(f"Input: {args.input} ({_count_lines(args.input)} URLs)")

    # optionally limit
    if args.limit:
        urls = [l.strip() for l in open(args.input) if l.strip()][:args.limit]
        limited_file = f"{args.output}/urls_limited.txt"
        Path(limited_file).write_text("\n".join(urls))
        scan_file = limited_file
    else:
        scan_file = args.input

    all_findings = []

    if not args.skip_xss:
        all_findings.extend(run_dalfox(scan_file, args.output, args.threads, args.cookie))

    if not args.skip_sqli:
        all_findings.extend(run_sqlmap(scan_file, args.output, args.cookie, args.sqli_level, args.sqli_risk))

    if not args.skip_ssti:
        all_findings.extend(run_ssti(scan_file, args.output, args.threads, args.cookie))

    if not args.skip_redirect:
        redirect_input = args.redirect_file if args.redirect_file else scan_file
        all_findings.extend(run_redirect_check(redirect_input, args.output, args.threads))

    # ── write report ──────────────────────────────────────────────────────────
    json_out = f"{args.output}/findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    report_out = f"{args.output}/report.txt"
    with open(report_out, "w") as f:
        f.write(f"Parameter Scan Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        by_type: dict[str, list] = {}
        for item in all_findings:
            by_type.setdefault(item["type"], []).append(item)
        for vtype, items in sorted(by_type.items()):
            f.write(f"\n[{vtype.upper()}] — {len(items)} findings\n{'─'*40}\n")
            for item in items:
                for k, v in item.items():
                    if k != "type":
                        f.write(f"  {k}: {v}\n")
                f.write("\n")

    section("Final Summary")
    by_type: dict[str, list] = {}
    for item in all_findings:
        by_type.setdefault(item["type"], []).append(item)
    for vtype, items in sorted(by_type.items()):
        ok(f"{vtype.upper():<20} : {C.BOLD}{len(items)}{C.RESET}")
    ok(f"Report : {report_out}")
    ok(f"JSON   : {json_out}")

if __name__ == "__main__":
    main()
