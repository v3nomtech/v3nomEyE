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
idor_hunter.py — IDOR / BOLA Scanner
Finds numeric, UUID, and hash-like object IDs in URLs and tests
horizontal + vertical access control by substituting neighbour IDs.

Input: urls_all.txt from venomeye output
Optional: --cookies-file with multiple session cookies for cross-account testing
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
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def crit(m):  print(f"{C.RED}{C.BOLD}[IDOR]{C.RESET} {m}")
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

# ── ID detection patterns ──────────────────────────────────────────────────────
NUMERIC_ID_RE   = re.compile(r"/(\d{1,10})(?:/|$|\?|#)")
UUID_RE         = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
HASH_RE         = re.compile(r"/([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?:/|$|\?|#)", re.IGNORECASE)
PARAM_ID_RE     = re.compile(r"[?&](id|user_?id|account_?id|order_?id|invoice_?id|file_?id|doc_?id|msg_?id|post_?id|profile_?id|customer_?id|ticket_?id)=(\d+)", re.IGNORECASE)
IDOR_KEYWORDS   = re.compile(r"/(user|account|profile|order|invoice|payment|file|document|report|ticket|admin|member|customer|subscription|message|notification)/", re.IGNORECASE)

def curl_req(url: str, cookie: str = "", method: str = "GET", timeout: int = 10) -> tuple[int, int, str, dict]:
    """Returns (status, body_length, body_snippet, headers)."""
    cmd = ["curl", "-sk", "--max-time", str(timeout), "-X", method,
           "-o", "-", "-D", "-", "-L", "--max-redirs", "3",
           "-A", "Mozilla/5.0"]
    if cookie:
        cmd += ["-H", f"Cookie: {cookie}"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        raw = r.stdout
        if "\r\n\r\n" in raw:
            hdr_block, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            hdr_block, body = raw.split("\n\n", 1)
        else:
            hdr_block, body = raw, ""
        sc_match = re.search(r"HTTP/[\d.]+ (\d+)", hdr_block)
        sc = int(sc_match.group(1)) if sc_match else 0
        hdrs = {}
        for line in hdr_block.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                hdrs[k.strip().lower()] = v.strip()
        return sc, len(body), body[:500], hdrs
    except Exception:
        return 0, 0, "", {}

def is_sensitive_response(sc: int, body: str, headers: dict) -> bool:
    """Heuristic: did we get real data back?"""
    if sc not in (200, 201):
        return False
    body_lower = body.lower()
    # signs of real data
    positive_hints = [
        r'"email"', r'"username"', r'"name"', r'"phone"', r'"address"',
        r'"ssn"', r'"dob"', r'"credit"', r'"account"', r'"balance"',
        r'"password"', r'"token"', r'"secret"', r'"api_key"',
        r'"invoice"', r'"order"', r'"payment"', r'"card"',
    ]
    return any(re.search(p, body, re.IGNORECASE) for p in positive_hints)

def substitute_numeric_id(url: str, old_id: str, new_id: str) -> str:
    # replace first occurrence of the ID in the path
    return url.replace(f"/{old_id}/", f"/{new_id}/", 1).replace(f"/{old_id}?", f"/{new_id}?").replace(f"/{old_id}#", f"/{new_id}#").replace(f"/{old_id}", f"/{new_id}", 1)

def substitute_param_id(url: str, param: str, new_id: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param in params:
        params[param] = [new_id]
    new_q = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_q))

def test_url_for_idor(url: str, cookie1: str, cookie2: str, timeout: int) -> list[dict]:
    """
    Test one URL for IDOR:
    - Numeric ID: try id+1, id-1, id=1, id=2
    - Param ID: same substitutions
    - Cross-cookie: re-fetch with cookie2 if provided
    """
    findings = []

    # ── Path numeric IDs ──────────────────────────────────────────────────
    for m in NUMERIC_ID_RE.finditer(url):
        orig_id = m.group(1)
        orig_num = int(orig_id)

        # get baseline with original cookie
        base_sc, base_len, base_body, base_hdrs = curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200, 201):
            continue

        test_ids = [str(orig_num + 1), str(orig_num - 1), "1", "2", "0", "9999999"]
        for tid in test_ids:
            if tid == orig_id:
                continue
            test_url = substitute_numeric_id(url, orig_id, tid)
            sc, body_len, body, hdrs = curl_req(test_url, cookie1, timeout=timeout)

            if sc in (200, 201) and body_len > 50:
                if is_sensitive_response(sc, body, hdrs):
                    findings.append({
                        "type": "idor_path_numeric",
                        "severity": "high",
                        "original_url": url,
                        "test_url": test_url,
                        "original_id": orig_id,
                        "tested_id": tid,
                        "status": sc,
                        "body_snippet": body[:300],
                    })
                    crit(f"Path IDOR (numeric) | {orig_id}→{tid} | {test_url}")

            # cross-account: test with cookie2 accessing cookie1's resource
            if cookie2 and base_sc == 200 and is_sensitive_response(base_sc, base_body, base_hdrs):
                sc2, len2, body2, hdrs2 = curl_req(url, cookie2, timeout=timeout)
                if sc2 == 200 and len2 > 50 and is_sensitive_response(sc2, body2, hdrs2):
                    findings.append({
                        "type": "idor_cross_account",
                        "severity": "critical",
                        "url": url,
                        "note": "Account B accessed Account A resource",
                        "status_a": base_sc,
                        "status_b": sc2,
                        "body_b": body2[:200],
                    })
                    crit(f"CROSS-ACCOUNT IDOR | {url}")
                    break  # one finding per URL

        break  # test first numeric ID in path only

    # ── Query parameter IDs ───────────────────────────────────────────────
    for m in PARAM_ID_RE.finditer(url):
        param_name = m.group(1)
        orig_id    = m.group(2)
        orig_num   = int(orig_id)

        base_sc, base_len, base_body, _ = curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200, 201):
            continue

        for tid in [str(orig_num + 1), str(orig_num - 1), "1"]:
            if tid == orig_id:
                continue
            test_url = substitute_param_id(url, param_name, tid)
            sc, body_len, body, hdrs = curl_req(test_url, cookie1, timeout=timeout)
            if sc in (200, 201) and body_len > 50 and is_sensitive_response(sc, body, hdrs):
                findings.append({
                    "type": "idor_param_numeric",
                    "severity": "high",
                    "original_url": url,
                    "test_url": test_url,
                    "param": param_name,
                    "original_id": orig_id,
                    "tested_id": tid,
                    "status": sc,
                    "body_snippet": body[:300],
                })
                crit(f"Param IDOR | {param_name}:{orig_id}→{tid} | {url}")
                break
        break  # first param only

    return findings

def extract_idor_candidates(urls_file: str) -> list[str]:
    """Filter URLs that likely contain object IDs."""
    candidates = []
    seen = set()
    try:
        for line in open(urls_file):
            url = line.strip()
            if not url:
                continue
            # deduplicate by normalizing IDs to a pattern
            norm = NUMERIC_ID_RE.sub("/ID/", url)
            norm = PARAM_ID_RE.sub(r"[\1=ID]", norm)
            if norm in seen:
                continue
            # only include URLs that have an ID-like component
            has_id = (
                NUMERIC_ID_RE.search(url) or
                UUID_RE.search(url) or
                PARAM_ID_RE.search(url) or
                IDOR_KEYWORDS.search(url)
            )
            if has_id:
                seen.add(norm)
                candidates.append(url)
    except FileNotFoundError:
        pass
    return candidates

# ── unauthenticated access check ───────────────────────────────────────────────
def check_unauth_access(url: str, timeout: int) -> dict | None:
    """Test if a URL returns data without any auth cookie."""
    sc, body_len, body, hdrs = curl_req(url, cookie="", timeout=timeout)
    if sc in (200, 201) and body_len > 100 and is_sensitive_response(sc, body, hdrs):
        return {
            "type": "unauth_access",
            "severity": "critical",
            "url": url,
            "status": sc,
            "body_snippet": body[:300],
        }
    return None

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="IDOR / BOLA Hunter")
    parser.add_argument("-i", "--input",    required=True, help="urls_all.txt from venomeye")
    parser.add_argument("-o", "--output",   default="./idor_results", help="Output directory")
    parser.add_argument("--cookie",         default="", help="Session cookie (Account A)")
    parser.add_argument("--cookie2",        default="", help="Second session cookie (Account B) for cross-account test")
    parser.add_argument("--cookies-file",   default="", help="File with one cookie per line for multi-account testing")
    parser.add_argument("-t", "--threads",  type=int, default=10)
    parser.add_argument("--timeout",        type=int, default=10)
    parser.add_argument("--limit",          type=int, default=500, help="Max URLs to test (default 500)")
    parser.add_argument("--check-unauth",   action="store_true", help="Also check for unauthenticated access")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    section("IDOR / BOLA Hunter")

    # build cookie list
    cookies = [args.cookie] if args.cookie else [""]
    cookie2 = args.cookie2
    if args.cookies_file:
        try:
            extra = [l.strip() for l in open(args.cookies_file) if l.strip()]
            cookies = extra
            if len(extra) >= 2:
                cookie2 = extra[1]
        except FileNotFoundError:
            warn(f"Cookies file not found: {args.cookies_file}")

    cookie1 = cookies[0]

    candidates = extract_idor_candidates(args.input)
    info(f"IDOR candidates extracted: {len(candidates)}")

    if args.limit:
        candidates = candidates[:args.limit]
    info(f"Testing {len(candidates)} URLs | threads={args.threads}")

    all_findings: list[dict] = []

    # ── IDOR test ─────────────────────────────────────────────────────────
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(test_url_for_idor, u, cookie1, cookie2, args.timeout): u for u in candidates}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 100 == 0:
                info(f"Progress: {done}/{len(candidates)} | findings: {len(all_findings)}")
            try:
                all_findings.extend(fut.result())
            except Exception:
                pass

    # ── Unauthenticated access check ──────────────────────────────────────
    if args.check_unauth:
        section("Unauthenticated Access Check")
        info(f"Checking {len(candidates)} IDOR-candidate URLs without auth...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(check_unauth_access, u, args.timeout): u for u in candidates}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    result = fut.result()
                    if result:
                        all_findings.append(result)
                        crit(f"UNAUTH ACCESS | {result['url']}")
                except Exception:
                    pass

    # ── outputs ───────────────────────────────────────────────────────────
    json_out = f"{args.output}/findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    report_out = f"{args.output}/report.txt"
    critical = [x for x in all_findings if x.get("severity") == "critical"]
    high     = [x for x in all_findings if x.get("severity") == "high"]

    with open(report_out, "w") as f:
        f.write(f"IDOR/BOLA Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        for item in sorted(all_findings, key=lambda x: 0 if x.get("severity")=="critical" else 1):
            f.write(f"[{item.get('severity','?').upper()}] {item.get('type','?')}\n")
            for k, v in item.items():
                if k not in ("type", "severity"):
                    f.write(f"  {k}: {str(v)[:200]}\n")
            f.write("\n")

    section("Summary")
    ok(f"IDOR candidates tested : {len(candidates)}")
    ok(f"Critical findings      : {C.BOLD}{len(critical)}{C.RESET}")
    ok(f"High findings          : {C.BOLD}{len(high)}{C.RESET}")
    ok(f"Total findings         : {C.BOLD}{len(all_findings)}{C.RESET}")
    ok(f"Report                 : {report_out}")

if __name__ == "__main__":
    main()
