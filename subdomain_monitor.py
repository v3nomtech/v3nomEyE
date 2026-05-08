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
subdomain_monitor.py — Continuous Recon Delta Tracker
Runs subdomain enumeration on a schedule and alerts on:
  - New subdomains / live hosts
  - New open ports
  - New services/technologies
  - Domains that disappeared (possible dangling DNS)

Usage:
  python3 subdomain_monitor.py -d example.com               # run once
  python3 subdomain_monitor.py -d example.com --watch 3600  # run every hour
  python3 subdomain_monitor.py -d example.com --diff /path/to/baseline/  # diff only
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

class C:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

def info(m):  print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):    print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}")
def new(m):   print(f"{C.GREEN}{C.BOLD}[NEW]{C.RESET} {m}")
def gone(m):  print(f"{C.RED}{C.BOLD}[GONE]{C.RESET} {m}")
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

def run(cmd: str, timeout: int = 300) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired:
        warn(f"Timeout: {cmd[:60]}")
        return ""
    except Exception as e:
        warn(f"Error: {e}")
        return ""

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?)+$")

def _normalize_host(s: str) -> str:
    """Strip scheme, port, path, lowercase, and validate as a hostname.

    Live-host files mix `host`, `host:443`, `https://host:443`, and `Host`
    across tools. Without normalisation those flap as new/gone across runs."""
    s = s.strip().lower()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0]
    if ":" in s:
        s = s.split(":", 1)[0]
    s = s.rstrip(".").lstrip("*.")
    if not _HOST_RE.match(s):
        return ""
    return s

def read_set(path: str) -> set[str]:
    try:
        return {l.strip() for l in open(path) if l.strip()}
    except FileNotFoundError:
        return set()

def read_host_set(path: str) -> set[str]:
    """Read a file and return the set of normalised hosts. Used for diffing
    so trivial format differences (scheme, port, case) don't show up as
    new/gone."""
    raw = read_set(path)
    return {n for n in (_normalize_host(x) for x in raw) if n}

def write_set(path: str, data: set[str]):
    Path(path).write_text("\n".join(sorted(data)) + "\n")

def count(path: str) -> int:
    try:
        return sum(1 for _ in open(path) if _.strip())
    except FileNotFoundError:
        return 0

def _is_subdomain_of(host: str, domain: str) -> bool:
    """True iff `host == domain` OR `host` is a strict subdomain of `domain`.

    Was previously `if domain in name:` — a substring match, which pulled
    in unrelated hosts like `someapple.com` (contains `apple.com`) or
    `apple.com.attacker.com` for target `apple.com`. The fix anchors on
    the dot boundary so only real children match.
    """
    h = host.lower().rstrip(".").lstrip("*.")
    d = domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)

# ── enumeration ───────────────────────────────────────────────────────────────
def enumerate_subdomains(domain: str, out_dir: str) -> set[str]:
    parts: list[str] = []
    sources_used: list[str] = []
    tmp = f"{out_dir}/_tmp_subs"
    os.makedirs(tmp, exist_ok=True)

    if tool_exists("subfinder"):
        f = f"{tmp}/sf.txt"
        run(f"subfinder -d {domain} -silent -o {f}", timeout=240)
        parts.append(f)
        sources_used.append("subfinder")

    if tool_exists("assetfinder"):
        f = f"{tmp}/af.txt"
        run(f"assetfinder --subs-only {domain} > {f}", timeout=120)
        parts.append(f)
        sources_used.append("assetfinder")

    # crt.sh — use list+escape to avoid shell-injection from a malformed
    # domain, and surface a warning when the response is not JSON (rate
    # limit / HTML error page) so the user knows that source contributed
    # nothing this round.
    crt_file = f"{tmp}/crt.txt"
    try:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "30",
             f"https://crt.sh/?q=%.{domain}&output=json"],
            capture_output=True, text=True, timeout=35)
        r_raw = r.stdout or ""
    except Exception:
        r_raw = ""
    if r_raw:
        try:
            entries = json.loads(r_raw)
            subs = set()
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    h = _normalize_host(name)
                    if h and _is_subdomain_of(h, domain):
                        subs.add(h)
            Path(crt_file).write_text("\n".join(sorted(subs)))
            parts.append(crt_file)
            sources_used.append("crt.sh")
        except (json.JSONDecodeError, ValueError):
            warn("crt.sh returned non-JSON (rate limited?) — skipped this round")

    # Merge, normalise, and filter to real subdomains of the target. Without
    # this filter, tools occasionally surface unrelated CDN names that then
    # show up as "new" on subsequent runs.
    all_subs: set[str] = set()
    for f in parts:
        for raw in read_set(f):
            h = _normalize_host(raw)
            if h and _is_subdomain_of(h, domain):
                all_subs.add(h)

    info(f"Subdomain sources used: {', '.join(sources_used) or 'none'}")
    shutil.rmtree(tmp, ignore_errors=True)
    return all_subs

def probe_live(subdomains: set[str], out_dir: str) -> tuple[set[str], set[str]]:
    """Return (resolved_hosts, live_http_hosts), both normalised hostnames.

    Splitting the two return values lets the caller distinguish between
    "DNS still resolves" and "HTTP responds" — needed for proper takeover-
    candidate detection (see compute_takeover_candidates)."""
    subs_file = f"{out_dir}/_probe_input.txt"
    write_set(subs_file, subdomains)

    resolved: set[str] = set()
    if tool_exists("dnsx"):
        resolved_file = f"{out_dir}/_resolved.txt"
        run(f"dnsx -l {subs_file} -silent -o {resolved_file}", timeout=240)
        resolved = {h for h in (_normalize_host(x) for x in read_set(resolved_file)) if h}
    else:
        resolved = set(subdomains)

    if not resolved:
        return set(), set()
    resolved_file = f"{out_dir}/_resolved.txt"
    write_set(resolved_file, resolved)

    live: set[str] = set()
    if tool_exists("httpx"):
        live_file = f"{out_dir}/_live.txt"
        run(f"httpx -l {resolved_file} -silent -o {live_file} -threads 50 -timeout 8", timeout=360)
        live = {h for h in (_normalize_host(x) for x in read_set(live_file)) if h}
    else:
        live = set(resolved)
    return resolved, live

def scan_ports(hosts: set[str], out_dir: str) -> set[str]:
    """Port-scan only resolved/live hosts. The previous version scanned the
    raw subdomain set (including names that didn't resolve), wasting most
    of the run on dead hosts and producing inconsistent results across
    cycles."""
    if not tool_exists("naabu") or not hosts:
        return set()
    hosts_file = f"{out_dir}/_hosts_for_ports.txt"
    write_set(hosts_file, hosts)
    out_file = f"{out_dir}/_ports.txt"
    run(f"naabu -l {hosts_file} -p 21,22,23,25,80,443,445,3306,3389,5432,6379,8080,8443,9200,27017 -silent -o {out_file} -rate 500", timeout=300)
    return read_set(out_file)

# ── diff ─────────────────────────────────────────────────────────────────────
class Diff:
    def __init__(self, label: str):
        self.label = label
        self.added: set[str] = set()
        self.removed: set[str] = set()

    def compute(self, old: set[str], new: set[str]):
        self.added   = new - old
        self.removed = old - new
        return self

    def report(self, out_file):
        if self.added:
            new(f"{self.label}: {len(self.added)} new")
            for item in sorted(self.added):
                new(f"  + {item}")
                out_file.write(f"[NEW {self.label.upper()}] {item}\n")
        if self.removed:
            gone(f"{self.label}: {len(self.removed)} disappeared")
            for item in sorted(self.removed):
                gone(f"  - {item}")
                out_file.write(f"[GONE {self.label.upper()}] {item}\n")

# ── notification (webhook / email stub) ───────────────────────────────────────
def notify_slack(webhook_url: str, message: str):
    if not webhook_url:
        return
    payload = json.dumps({"text": message})
    subprocess.run(
        ["curl", "-sk", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", payload, webhook_url],
        capture_output=True, timeout=10
    )

def notify_discord(webhook_url: str, message: str):
    if not webhook_url:
        return
    payload = json.dumps({"content": message[:2000]})
    subprocess.run(
        ["curl", "-sk", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", payload, webhook_url],
        capture_output=True, timeout=10
    )

def compute_takeover_candidates(resolved: set[str], live: set[str],
                                prev_live: set[str]) -> set[str]:
    """A real subdomain-takeover candidate is a host whose DNS *still*
    resolves but whose HTTP service has gone away (was live last run, not
    live now). The previous version flagged any subdomain that disappeared
    from enumeration as a takeover target — but enumeration tools are
    flaky, so almost every reported candidate was actually just a
    transient miss from subfinder/crt.sh. Real takeovers need a dangling
    DNS pointer, which means DNS is still there.
    """
    return {h for h in resolved if h in prev_live and h not in live}

# ── single scan run ───────────────────────────────────────────────────────────
def run_scan(domain: str, out_dir: str, prev_dir: str | None, slack_wh: str, discord_wh: str) -> str:
    """Run one complete scan cycle, diff against prev_dir, return scan_dir."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"{out_dir}/{ts}"
    os.makedirs(scan_dir, exist_ok=True)

    section(f"Scan cycle: {ts}")

    # Enumerate
    info("Enumerating subdomains...")
    subs = enumerate_subdomains(domain, scan_dir)
    subs_file = f"{scan_dir}/subdomains.txt"
    write_set(subs_file, subs)
    ok(f"Subdomains: {len(subs)}")

    # Live hosts (returns both resolved + live so we can detect takeover
    # candidates accurately)
    info("Probing live hosts...")
    resolved, live = probe_live(subs, scan_dir)
    write_set(f"{scan_dir}/resolved.txt", resolved)
    write_set(f"{scan_dir}/live_hosts.txt", live)
    ok(f"Resolved: {len(resolved)} | Live: {len(live)}")

    # Port scan — only resolved hosts (was: all enumerated subs, including
    # names that didn't resolve, which wasted the bulk of each cycle).
    info("Port scanning...")
    ports = scan_ports(resolved, scan_dir)
    ports_file = f"{scan_dir}/open_ports.txt"
    write_set(ports_file, ports)
    ok(f"Open ports: {len(ports)}")

    meta = {
        "domain": domain,
        "timestamp": ts,
        "subdomains": len(subs),
        "resolved":   len(resolved),
        "live_hosts": len(live),
        "open_ports": len(ports),
    }
    Path(f"{scan_dir}/meta.json").write_text(json.dumps(meta, indent=2))

    if not prev_dir or not Path(prev_dir).exists():
        info("No previous scan to diff against — this is the baseline.")
        return scan_dir

    section("Delta Analysis")
    prev_subs  = read_host_set(f"{prev_dir}/subdomains.txt")
    prev_live  = read_host_set(f"{prev_dir}/live_hosts.txt")
    prev_ports = read_set(f"{prev_dir}/open_ports.txt")

    diff_file = f"{scan_dir}/delta.txt"
    alert_lines = []

    with open(diff_file, "w") as f:
        f.write(f"Delta Report — {domain} — {ts}\n{'='*60}\n\n")

        subs_diff  = Diff("subdomain").compute(prev_subs, subs)
        live_diff  = Diff("live_host").compute(prev_live, live)
        ports_diff = Diff("open_port").compute(prev_ports, ports)

        subs_diff.report(f)
        live_diff.report(f)
        ports_diff.report(f)

        # Real takeover-candidate detection — DNS still resolves but HTTP
        # disappeared. Replaces the prior "any disappeared subdomain" rule
        # which was almost entirely enumeration-tool flakiness.
        takeover = compute_takeover_candidates(resolved, live, prev_live)
        if takeover:
            f.write("\n# Subdomain takeover candidates (DNS still up, HTTP down)\n")
            for h in sorted(takeover):
                gone(f"  takeover-candidate: {h}")
                f.write(f"[TAKEOVER-CANDIDATE] {h}\n")

        if subs_diff.added:
            alert_lines.append(f"[NEW SUBDOMAINS] {len(subs_diff.added)}: {', '.join(list(subs_diff.added)[:5])}")
        if live_diff.added:
            alert_lines.append(f"[NEW LIVE HOSTS] {len(live_diff.added)}: {', '.join(list(live_diff.added)[:5])}")
        if ports_diff.added:
            alert_lines.append(f"[NEW OPEN PORTS] {len(ports_diff.added)}: {', '.join(list(ports_diff.added)[:5])}")
        if takeover:
            alert_lines.append(f"[TAKEOVER CANDIDATES] {len(takeover)}: {', '.join(list(takeover)[:5])}")

    if alert_lines:
        alert_msg = f"[{domain}] Recon delta alert:\n" + "\n".join(alert_lines)
        ok(f"Delta file: {diff_file}")
        notify_slack(slack_wh, alert_msg)
        notify_discord(discord_wh, alert_msg)
    else:
        info("No changes detected in this scan cycle.")

    return scan_dir

def find_latest_scan(out_dir: str, domain: str) -> str | None:
    """Find the most recent previous scan directory."""
    base = Path(out_dir)
    if not base.exists():
        return None
    # scan dirs are named by timestamp
    candidates = sorted([d for d in base.iterdir() if d.is_dir() and (d / "meta.json").exists()], reverse=True)
    return str(candidates[0]) if candidates else None

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="Subdomain Monitor & Delta Tracker")
    parser.add_argument("-d", "--domain",    required=True, help="Target domain")
    parser.add_argument("-o", "--output",    default="", help="Output base dir (default: ./monitor/<domain>)")
    parser.add_argument("--watch",           type=int, default=0, metavar="SECONDS", help="Run continuously every N seconds (0=run once)")
    parser.add_argument("--diff",            default="", help="Path to a specific previous scan dir to diff against")
    parser.add_argument("--slack-webhook",   default="", help="Slack webhook URL for alerts")
    parser.add_argument("--discord-webhook", default="", help="Discord webhook URL for alerts")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    out_dir = args.output or f"./monitor/{domain}"
    os.makedirs(out_dir, exist_ok=True)

    section(f"Subdomain Monitor — {domain}")
    info(f"Output : {out_dir}")
    info(f"Mode   : {'continuous every %ds' % args.watch if args.watch else 'single run'}")

    # graceful exit on Ctrl-C
    running = True
    def _stop(sig, frame):
        nonlocal running
        info("Stopping monitor...")
        running = False
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    prev_dir = args.diff or find_latest_scan(out_dir, domain)
    if prev_dir:
        info(f"Baseline: {prev_dir}")

    while running:
        scan_dir = run_scan(domain, out_dir, prev_dir, args.slack_webhook, args.discord_webhook)
        prev_dir = scan_dir

        if not args.watch:
            break

        info(f"Next scan in {args.watch}s — Ctrl-C to stop")
        # sleep in small chunks so Ctrl-C is responsive
        for _ in range(args.watch):
            if not running:
                break
            time.sleep(1)

    ok("Monitor complete.")

if __name__ == "__main__":
    main()
