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

def _operation_requires_auth(spec: dict, operation: dict) -> bool:
    """Decide if a spec operation expects auth, based on swagger/openapi
    ``security`` semantics:

      • Operation-level ``security: []`` (empty list) → explicitly public.
      • Operation-level ``security: [{...}]`` → requires auth.
      • No operation-level security → fall back to global ``security``.
      • Global empty / missing → public.

    The prior implementation flagged every 200 response as "unauthenticated
    endpoint", producing FPs on /health, /version, /metrics, /docs etc. that
    are deliberately public.
    """
    op_sec = operation.get("security")
    if op_sec is not None:
        return any(s for s in op_sec) if isinstance(op_sec, list) else True
    glob = spec.get("security")
    if isinstance(glob, list):
        return any(s for s in glob)
    return False

def _bodies_similar(a: str, b: str) -> bool:
    if not a and not b:
        return True
    if not a or not b:
        return False
    if a[:512] == b[:512]:
        return True
    la, lb = len(a), len(b)
    return min(la, lb) > 0 and abs(la - lb) / max(la, lb) < 0.05

def test_unauthenticated_endpoints(spec: dict, base_url: str, cookie: str) -> list[dict]:
    """Test only endpoints that the spec says should require authentication.

    For each such endpoint we compare the unauth response to the cookie-auth
    response (when a cookie is provided). A finding requires that the unauth
    response is a successful read AND differs meaningfully from the auth
    response (otherwise the endpoint is public regardless of what the spec
    claims).
    """
    findings = []
    paths = spec.get("paths", {})
    servers = spec.get("servers", [{"url": base_url}])
    server_url = servers[0].get("url", base_url) if servers else base_url
    if server_url.startswith("/"):
        server_url = base_url.rstrip("/") + server_url

    auth_headers = {}
    if cookie:
        auth_headers["Cookie"] = cookie

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            if method.upper() not in ("GET",):
                # Only probe GETs without auth — destructive verbs against
                # real endpoints without consent is a footgun.
                continue
            if not _operation_requires_auth(spec, details):
                continue
            url = server_url.rstrip("/") + path
            url = re.sub(r"\{[^}]+\}", "1", url)
            sc_un, _, body_un = curl(url, method="GET", headers={}, timeout=8)
            if sc_un not in (200, 201) or len(body_un) < 30:
                continue
            # If we have a cookie, confirm the unauth response leaks data the
            # auth response also reveals. If both look identical and trivial,
            # the endpoint is just public.
            if auth_headers:
                sc_au, _, body_au = curl(url, method="GET", headers=auth_headers, timeout=8)
                # If auth and unauth are basically identical *and* both short,
                # the endpoint is public — skip.
                if sc_au == sc_un and _bodies_similar(body_un, body_au) and len(body_un) < 200:
                    continue
            findings.append({
                "type": "unauth_api_endpoint",
                "severity": "high",
                "method": "GET",
                "url": url,
                "status": sc_un,
                "operation": details.get("operationId", ""),
                "tags": details.get("tags", []),
                "body_snippet": body_un[:300],
            })
            warn(f"UNAUTH GET {url} → {sc_un}")
    return findings

# ── GraphQL ───────────────────────────────────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/__graphql", "/api/graphql",
    "/v1/graphql", "/query", "/gql",
]

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name kind } } }"}

def _is_graphql_endpoint(body: str) -> bool:
    """A real GraphQL endpoint replies with JSON containing either a
    ``data`` or ``errors`` top-level key. Plain `data` substring matching
    used to FP on REST endpoints that happen to return a ``data`` field.
    """
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(parsed, dict):
        return False
    return "data" in parsed or "errors" in parsed

def check_graphql(host: str, cookie: str) -> list[dict]:
    findings = []
    base = host.rstrip("/")
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    for path in GRAPHQL_PATHS:
        url = base + path

        sc, _, body = curl(url, method="POST", headers=headers,
                           data=INTROSPECTION_QUERY, timeout=8)
        if sc not in (200, 400, 500) or not body:
            continue
        if not _is_graphql_endpoint(body):
            continue

        # Introspection: requires the response to actually carry __schema
        # AND a non-empty types array — disabling introspection returns
        # `{"errors":[...]}` without `"types"`.
        introspection_open = False
        types_list: list[str] = []
        try:
            parsed = json.loads(body)
            schema = parsed.get("data", {}).get("__schema") if isinstance(parsed.get("data"), dict) else None
            if schema and isinstance(schema.get("types"), list) and schema["types"]:
                introspection_open = True
                types_list = [t["name"] for t in schema["types"]
                              if isinstance(t, dict) and t.get("name") and not t["name"].startswith("__")]
        except Exception:
            pass

        if introspection_open:
            findings.append({
                "type": "graphql_introspection",
                "severity": "medium",
                "url": url,
                "schema_types": types_list[:50],
                "body_snippet": body[:400],
            })
            warn(f"GraphQL introspection enabled: {url}")
            if types_list:
                info(f"  GraphQL types: {', '.join(types_list[:10])}")

        # Batch query abuse — only meaningful when the server actually
        # processed all batched queries (count `__typename` occurrences).
        sc2, _, body2 = curl(url, method="POST", headers=headers,
                             data=[{"query": "{ __typename }"}] * 10, timeout=10)
        if sc2 == 200 and body2.count("__typename") >= 10:
            findings.append({
                "type": "graphql_batch_enabled",
                "severity": "medium",
                "url": url,
                "note": "Batched queries processed — potential DoS / rate-limit bypass",
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

_HS_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

def crack_jwt_secret(token: str) -> str | None:
    """Try the weak-secret list against the JWT, respecting its declared HS
    algorithm (was always SHA-256, so HS384/HS512 tokens never matched)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    except Exception:
        return None
    alg = (header.get("alg") or "").upper()
    digest = _HS_ALGS.get(alg)
    if not digest:
        return None  # not an HMAC token
    msg = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig = base64.urlsafe_b64decode(parts[2] + "==")
    except Exception:
        return None
    for secret in WEAK_JWT_SECRETS:
        try:
            expected = hmac.new(secret.encode(), msg, digest).digest()
            if hmac.compare_digest(expected, sig):
                return secret
        except Exception:
            continue
    return None

def test_jwt(token: str, url: str, header_name: str = "Authorization") -> list[dict]:
    """Test a JWT for none-alg and weak-secret bypasses.

    The none-alg check now requires a baseline comparison: the URL is
    fetched WITHOUT any Authorization header first. If that response is a
    successful 200 (i.e. the endpoint is just public), a 200 with the
    forged none-alg token tells us nothing — was previously the source of
    most ``jwt_none_alg`` FPs. We only flag if the forged token gets a
    *better* response than no auth (different status or substantially
    larger body).
    """
    findings = []
    header, payload = decode_jwt(token)
    if not header:
        return findings

    info(f"JWT found: alg={header.get('alg')} sub={payload.get('sub','?')} exp={payload.get('exp','?')}")

    # none-algorithm attack — requires baseline comparison
    if header.get("alg", "").upper() != "NONE":
        forged = forge_none_alg(token)
        if forged:
            base_sc, _, base_body = curl(url, headers={}, timeout=8)
            sc, _, body = curl(url, headers={header_name: f"Bearer {forged}"}, timeout=8)
            looks_unauthorized = any(
                k in body.lower() for k in ("unauthorized","invalid token","forbidden","jwt","signature"))
            forged_better_than_unauth = (
                sc in (200, 201)
                and not looks_unauthorized
                and (base_sc in (401, 403) or len(body) > len(base_body) * 1.5)
            )
            if forged_better_than_unauth:
                findings.append({
                    "type": "jwt_none_alg",
                    "severity": "critical",
                    "url": url,
                    "forged_token": forged[:80],
                    "status": sc,
                    "baseline_status": base_sc,
                })
                crit(f"JWT none-alg accepted! {url}")

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
    "role", "isAdmin", "is_admin", "admin", "privilege",
    "group", "level", "verified", "active", "approved",
    "balance", "credits", "plan", "subscription", "superuser", "staff",
]

def test_mass_assignment(url: str, method: str, cookie: str) -> list[dict]:
    """Confirmed-only mass-assignment detection.

    The original loop iterated ``f in MASS_ASSIGN_FIELDS`` but never used
    ``f`` in its check — it just looked for the strings ``"admin"`` or
    ``"role"`` anywhere in the body, which fired on *every* user-object API
    that returned a normal ``"role":"user"`` field.

    Now:
      • Send a unique sentinel value for each candidate field.
      • Confirm only when the response echoes that exact field+sentinel pair
        AND a baseline request without the field did NOT echo it. That rules
        out responses that already happen to contain the field for unrelated
        reasons (e.g. the field is part of the user record).
    """
    findings = []
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie

    # Baseline — what does the response look like with NO injected field?
    base_sc, _, base_body = curl(url, method=method, headers=headers, data={}, timeout=8)
    if base_sc not in (200, 201):
        return findings

    for field in MASS_ASSIGN_FIELDS:
        sentinel = f"vmassign{abs(hash(field)) % 100000}"
        payload = {field: sentinel}
        sc, _, body = curl(url, method=method, headers=headers, data=payload, timeout=8)
        if sc not in (200, 201):
            continue
        # Reflection: response must contain field+sentinel AND baseline must not.
        if sentinel in body and sentinel not in base_body:
            findings.append({
                "type": "mass_assignment",
                "severity": "high",
                "url": url,
                "field": field,
                "sentinel": sentinel,
                "response_snippet": body[:300],
            })
            warn(f"Mass assignment confirmed: '{field}' echoed @ {url}")
            return findings  # one confirmed hit is enough
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
