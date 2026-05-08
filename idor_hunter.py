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
import hashlib
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
# Path-segment names that strongly suggest the *next* numeric segment is an
# object ID (so /users/5 → ID "5", but /v2/foo → not an ID).
ID_PARENT_SEGMENTS = {
    "user","users","account","accounts","profile","profiles","order","orders",
    "invoice","invoices","payment","payments","file","files","document","documents",
    "doc","docs","report","reports","ticket","tickets","member","members",
    "customer","customers","subscription","subscriptions","message","messages",
    "notification","notifications","post","posts","comment","comments","item","items",
    "object","objects","record","records","resource","resources","entity","entities",
    "transaction","transactions",
}
# Path segments where a following number is NEVER an object ID. Suppresses the
# largest noise source: API versions, pagination, dates, ports.
ID_BLACKLIST_SEGMENTS = {
    "v","version","versions","api","page","pages","p","auth","assets","static",
    "public","cdn","img","image","images","js","css","fonts","port","ports",
    "year","month","day","date",
}
NUMERIC_ID_RE   = re.compile(r"/(\d{1,10})(?:/|$|\?|#)")
UUID_RE         = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
HASH_RE         = re.compile(r"/([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?:/|$|\?|#)", re.IGNORECASE)
PARAM_ID_RE     = re.compile(r"[?&](id|user_?id|account_?id|order_?id|invoice_?id|file_?id|doc_?id|msg_?id|post_?id|profile_?id|customer_?id|ticket_?id)=(\d+)", re.IGNORECASE)
IDOR_KEYWORDS   = re.compile(r"/(user|account|profile|order|invoice|payment|file|document|report|ticket|admin|member|customer|subscription|message|notification)/", re.IGNORECASE)
# A "bogus" ID very unlikely to ever exist — used to fingerprint the app's
# generic not-found / placeholder response for ID substitution.
BOGUS_ID = "999999999991"

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
    """Heuristic: response looks like JSON containing real PII / record data.

    Tightened vs. the original, which fired on ANY response containing words
    like "name" or "order" — those appear in landing pages, OpenAPI specs,
    error messages, and registration form HTML, generating massive FPs.

    Now requires:
      • Status 200/201
      • Content-Type smells like JSON, OR body parses as JSON object/array
      • At least one HIGH-signal field name (e.g. ``"email":``, ``"phone":``)
        AND a second corroborating field (length / id / token style)
    """
    if sc not in (200, 201):
        return False
    if not body or len(body) < 30:
        return False
    ctype = (headers or {}).get("content-type", "").lower()
    looks_json = "json" in ctype
    if not looks_json:
        snippet = body.lstrip()[:1]
        if snippet not in ("{", "["):
            return False
    # high-signal fields — these are unusual outside of real records
    strong = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',
        r'"phone"\s*:\s*"\+?\d',
        r'"ssn"\s*:\s*"',
        r'"dob"\s*:\s*"\d',
        r'"date_of_birth"\s*:\s*"\d',
        r'"credit_?card"\s*:\s*"',
        r'"card_?number"\s*:\s*"',
        r'"balance"\s*:\s*-?\d',
        r'"password_?hash"\s*:\s*"',
        r'"api_?key"\s*:\s*"[A-Za-z0-9_\-]{12,}',
        r'"access_?token"\s*:\s*"[A-Za-z0-9_\-]{12,}',
        r'"secret"\s*:\s*"[A-Za-z0-9_\-]{8,}',
    ]
    if any(re.search(p, body, re.IGNORECASE) for p in strong):
        return True
    # weaker fields — only count when paired with an id-shaped field, so a
    # response with just `"name":"Acme"` (a public brand) doesn't qualify.
    weak_user = [r'"username"\s*:\s*"', r'"first_?name"\s*:\s*"',
                 r'"last_?name"\s*:\s*"', r'"address"\s*:\s*"']
    weak_id   = [r'"id"\s*:\s*\d', r'"uuid"\s*:\s*"',
                 r'"user_?id"\s*:\s*\d', r'"account_?id"\s*:\s*"?\d']
    if any(re.search(p, body, re.IGNORECASE) for p in weak_user) and \
       any(re.search(p, body, re.IGNORECASE) for p in weak_id):
        return True
    return False

def _fingerprint(body: str) -> str:
    """Stable fingerprint over the first 4KB of the body — used to compare two
    responses without full string equality (timestamps etc shift bytes)."""
    return hashlib.md5((body or "")[:4096].encode("utf-8", errors="ignore")).hexdigest()

def _bodies_similar(a: str, b: str) -> bool:
    """True if two bodies are effectively the same response (same generic
    template / placeholder), so an "IDOR" comparing them is bogus."""
    if not a and not b:
        return True
    if not a or not b:
        return False
    if _fingerprint(a) == _fingerprint(b):
        return True
    la, lb = len(a), len(b)
    if min(la, lb) == 0:
        return False
    # Length within 5% AND first 256 bytes identical → same response template
    if abs(la - lb) / max(la, lb) < 0.05 and a[:256] == b[:256]:
        return True
    return False

def _previous_segment(url: str, span_start: int) -> str:
    """Return the path segment immediately before the match position."""
    parsed = urlparse(url)
    path = parsed.path
    # Convert match position from full URL into path-relative position
    # Easier: walk segments and find the one preceding the matched digits.
    segs = [s for s in path.split("/") if s]
    for i, s in enumerate(segs):
        if s.isdigit() and 0 < i:
            # This is the first numeric path segment — return its parent
            return segs[i - 1].lower()
    return ""

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

def _path_id_is_real(url: str, orig_id: str) -> bool:
    """Filter out version numbers, pagination, dates, ports etc. that the
    raw NUMERIC_ID_RE would otherwise match."""
    parsed = urlparse(url)
    segs = [s for s in parsed.path.split("/") if s]
    try:
        i = segs.index(orig_id)
    except ValueError:
        return True  # match was outside the segment list — let it through
    parent = segs[i - 1].lower() if i > 0 else ""
    if parent in ID_BLACKLIST_SEGMENTS:
        return False
    if parent in ID_PARENT_SEGMENTS:
        return True
    # No parent hint — only trust 3+ digit IDs (avoids /v2/, /p/5/, etc.)
    return len(orig_id) >= 3

def test_url_for_idor(url: str, cookie1: str, cookie2: str, timeout: int) -> list[dict]:
    """
    Confirm IDOR using a 3-baseline comparison:
      base_orig  — request original URL (cookie1)
      base_bogus — request URL with an obviously-invalid ID (cookie1)
      test       — request URL with a neighbour ID (cookie1)

    A finding requires:
      • test status 200/201
      • test body NOT similar to base_bogus (so it's not the generic placeholder)
      • test body NOT similar to base_orig  (we got a different resource)
      • test body looks sensitive

    This kills the FPs from apps that always 200 with the same generic JSON
    regardless of whether the ID exists.
    """
    findings = []

    # ── Path numeric IDs ──────────────────────────────────────────────────
    for m in NUMERIC_ID_RE.finditer(url):
        orig_id = m.group(1)
        if not _path_id_is_real(url, orig_id):
            continue
        try:
            orig_num = int(orig_id)
        except ValueError:
            continue

        base_sc, base_len, base_body, base_hdrs = curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200, 201):
            continue
        # bogus-ID baseline — fingerprint of "this is what a non-existent
        # resource returns". Used to suppress always-200 placeholder responses.
        bogus_url = substitute_numeric_id(url, orig_id, BOGUS_ID)
        _, _, bogus_body, _ = curl_req(bogus_url, cookie1, timeout=timeout)

        # Closest neighbours only — drops the noisy "1"/"2"/"0"/"9999999"
        # blasts that produced low-signal hits.
        test_ids = [str(orig_num + 1)]
        if orig_num > 1:
            test_ids.append(str(orig_num - 1))

        for tid in test_ids:
            if tid == orig_id:
                continue
            test_url = substitute_numeric_id(url, orig_id, tid)
            sc, body_len, body, hdrs = curl_req(test_url, cookie1, timeout=timeout)
            if sc not in (200, 201) or body_len <= 50:
                continue
            if _bodies_similar(body, bogus_body):
                continue  # generic placeholder, not real data
            if _bodies_similar(body, base_body):
                continue  # same response as our own resource — likely cached/templated
            if not is_sensitive_response(sc, body, hdrs):
                continue
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
            break

        # Cross-account: cookie2 fetches cookie1's resource. Real IDOR means
        # cookie2 sees user A's data, so the body should be similar to what
        # cookie1 saw. If each cookie just sees their own different data
        # (typical /api/me behaviour), the bodies differ → not a finding.
        if cookie2 and is_sensitive_response(base_sc, base_body, base_hdrs):
            sc2, len2, body2, _ = curl_req(url, cookie2, timeout=timeout)
            if sc2 in (200, 201) and len2 > 50 and _bodies_similar(body2, base_body):
                findings.append({
                    "type": "idor_cross_account",
                    "severity": "critical",
                    "url": url,
                    "note": "Account B retrieved Account A's resource (bodies match)",
                    "status_a": base_sc,
                    "status_b": sc2,
                    "body_b": body2[:200],
                })
                crit(f"CROSS-ACCOUNT IDOR | {url}")

        break  # first numeric path ID only

    # ── Query parameter IDs ───────────────────────────────────────────────
    for m in PARAM_ID_RE.finditer(url):
        param_name = m.group(1)
        orig_id    = m.group(2)
        try:
            orig_num = int(orig_id)
        except ValueError:
            continue

        base_sc, base_len, base_body, _ = curl_req(url, cookie1, timeout=timeout)
        if base_sc not in (200, 201):
            continue
        bogus_url = substitute_param_id(url, param_name, BOGUS_ID)
        _, _, bogus_body, _ = curl_req(bogus_url, cookie1, timeout=timeout)

        for tid in [str(orig_num + 1)] + ([str(orig_num - 1)] if orig_num > 1 else []):
            if tid == orig_id:
                continue
            test_url = substitute_param_id(url, param_name, tid)
            sc, body_len, body, hdrs = curl_req(test_url, cookie1, timeout=timeout)
            if sc not in (200, 201) or body_len <= 50:
                continue
            if _bodies_similar(body, bogus_body):
                continue
            if _bodies_similar(body, base_body):
                continue
            if not is_sensitive_response(sc, body, hdrs):
                continue
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
        break

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
    """Confirm an unauthenticated URL really exposes data.

    Tightened so a public docs page or always-200 catch-all can't trigger:
      • The same URL with a bogus ID substituted must NOT return a body
        similar to the real one — otherwise the app just returns the same
        page for everything (likely a SPA / docs / placeholder).
      • Sensitive markers must be present.
    """
    sc, body_len, body, hdrs = curl_req(url, cookie="", timeout=timeout)
    if sc not in (200, 201) or body_len < 100:
        return None
    if not is_sensitive_response(sc, body, hdrs):
        return None
    # If the URL has a numeric/UUID ID, compare against a bogus-ID variant.
    bogus_url = url
    m = NUMERIC_ID_RE.search(url)
    if m and _path_id_is_real(url, m.group(1)):
        bogus_url = substitute_numeric_id(url, m.group(1), BOGUS_ID)
    else:
        pm = PARAM_ID_RE.search(url)
        if pm:
            bogus_url = substitute_param_id(url, pm.group(1), BOGUS_ID)
    if bogus_url != url:
        _, _, bogus_body, _ = curl_req(bogus_url, cookie="", timeout=timeout)
        if _bodies_similar(body, bogus_body):
            return None  # always-200 placeholder, not real data
    return {
        "type": "unauth_access",
        "severity": "critical",
        "url": url,
        "status": sc,
        "body_snippet": body[:300],
    }

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
