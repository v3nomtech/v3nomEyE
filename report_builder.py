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
report_builder.py — HTML Report Generator
Aggregates all venomeye + scanner outputs into one polished HTML report
with severity charts, sortable findings table, and copy-paste PoC snippets.

Input: venomeye output directory (or multiple scanner output dirs)
"""

import argparse
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

SEV_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOUR = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#3498db",
    "info":     "#95a5a6",
}

# ── finding collectors ────────────────────────────────────────────────────────
def load_nuclei(json_path: str) -> list[dict]:
    findings = []
    if not Path(json_path).exists():
        return findings
    for line in open(json_path, errors="ignore"):
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
            cve_ids = classification.get("cve-id", [])
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids] if cve_ids else []
            findings.append({
                "source":    "nuclei",
                "severity":  info_obj.get("severity", "info").lower(),
                "title":     info_obj.get("name", "Unknown"),
                "host":      item.get("host", ""),
                "url":       item.get("matched-at", item.get("host", "")),
                "cve":       ", ".join(cve_ids),
                "cvss":      str(classification.get("cvss-score", "")),
                "tags":      ", ".join(info_obj.get("tags", [])),
                "description": info_obj.get("description", ""),
                "poc":       item.get("matched-at", ""),
            })
        except Exception:
            continue
    return findings

def load_json_findings(json_path: str, source: str) -> list[dict]:
    if not Path(json_path).exists():
        return []
    try:
        raw = json.loads(Path(json_path).read_text())
        if not isinstance(raw, list):
            raw = [raw]
        results = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", item.get("type", "info"))
            # map type names to severities
            type_sev_map = {
                "ssrf_metadata":      "critical",
                "idor_cross_account": "critical",
                "unauth_access":      "critical",
                "jwt_none_alg":       "critical",
                "jwt_weak_secret":    "critical",
                "ssti":               "critical",
                "sqli":               "critical",
                "xss":                "high",
                "idor_path_numeric":  "high",
                "idor_param_numeric": "high",
                "mass_assignment":    "high",
                "graphql_introspection": "medium",
                "graphql_batch_enabled": "medium",
                "open_redirect":      "medium",
                "cors_issues":        "medium",
                "unauth_api_endpoint":"high",
                "secret":             "critical",
                "internal_ip":        "medium",
                "cloud_service":      "info",
                "endpoint":           "info",
            }
            vtype = item.get("type", "")
            if vtype in type_sev_map:
                sev = type_sev_map[vtype]

            title = item.get("title", item.get("label", item.get("type", "Finding")))
            url   = item.get("url", item.get("injected", item.get("original_url", "")))
            desc  = (
                item.get("description", "") or
                item.get("body_snippet", "") or
                item.get("value", "") or
                item.get("note", "")
            )
            poc = item.get("poc", item.get("injected", item.get("test_url", url)))

            results.append({
                "source":      source,
                "severity":    sev if sev in SEV_ORDER else "info",
                "title":       str(title)[:100],
                "host":        url.split("/")[2] if "://" in str(url) else str(url),
                "url":         str(url)[:300],
                "cve":         item.get("cve", ""),
                "cvss":        str(item.get("cvss", "")),
                "tags":        str(item.get("tags", "")),
                "description": str(desc)[:500],
                "poc":         str(poc)[:500],
            })
        return results
    except Exception as e:
        warn(f"Could not load {json_path}: {e}")
        return []

def load_plain_findings(txt_path: str, source: str, severity: str) -> list[dict]:
    """Load a plain text file where each line is a URL/finding."""
    findings = []
    if not Path(txt_path).exists():
        return findings
    for line in open(txt_path, errors="ignore"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sev = severity
        title = source
        if line.startswith("["):
            m = re.match(r"\[([A-Z_:]+)\]\s*(.*)", line)
            if m:
                tag, rest = m.group(1), m.group(2)
                title = tag
                line  = rest
                if "CRIT" in tag or "CRITICAL" in tag:
                    sev = "critical"
                elif "HIGH" in tag:
                    sev = "high"
                elif "MEDIUM" in tag:
                    sev = "medium"
        findings.append({
            "source":      source,
            "severity":    sev,
            "title":       title,
            "host":        "",
            "url":         line[:300],
            "cve":         "",
            "cvss":        "",
            "tags":        "",
            "description": "",
            "poc":         line[:300],
        })
    return findings

# ── screenshot helper ─────────────────────────────────────────────────────────
def take_screenshots(live_hosts_file: str, screenshots_dir: str) -> dict[str, str]:
    """Run gowitness on live hosts, return url→relative_path mapping."""
    import shutil
    if not shutil.which("gowitness") or not Path(live_hosts_file).exists():
        return {}
    os.makedirs(screenshots_dir, exist_ok=True)
    subprocess.run(
        ["gowitness", "file", "-f", live_hosts_file,
         "--screenshot-path", screenshots_dir, "--timeout", "10"],
        capture_output=True, timeout=600
    )
    # gowitness names files as base64(url).png — build an index
    mapping = {}
    try:
        r = subprocess.run(
            ["gowitness", "report", "list", "--db-path", f"{screenshots_dir}/gowitness.sqlite3"],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                mapping[parts[0]] = parts[1]
    except Exception:
        pass
    return mapping

# ── HTML generation ────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bug Bounty Report — {domain}</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;
         --crit:#e74c3c;--high:#e67e22;--med:#f1c40f;--low:#3498db;--info:#95a5a6;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:14px;}}
  header{{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:30px 40px;border-bottom:1px solid var(--border);}}
  header h1{{font-size:26px;color:#58a6ff;}}
  header p{{color:var(--muted);margin-top:6px;font-size:13px;}}
  .container{{max-width:1400px;margin:0 auto;padding:20px 40px;}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin:24px 0;}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px;text-align:center;}}
  .stat-card .num{{font-size:32px;font-weight:700;}}
  .stat-card .lbl{{color:var(--muted);font-size:12px;margin-top:4px;}}
  .sev-crit{{color:var(--crit)!important;}} .sev-high{{color:var(--high)!important;}}
  .sev-med{{color:var(--med)!important;}}  .sev-low{{color:var(--low)!important;}}
  .sev-info{{color:var(--info)!important;}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;}}
  .badge-critical{{background:#3d0c0c;color:var(--crit);}}
  .badge-high{{background:#3d1f0c;color:var(--high);}}
  .badge-medium{{background:#3d360c;color:var(--med);}}
  .badge-low{{background:#0c2040;color:var(--low);}}
  .badge-info{{background:#1e1e1e;color:var(--info);}}
  h2{{color:#58a6ff;font-size:18px;margin:30px 0 14px;border-bottom:1px solid var(--border);padding-bottom:8px;}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden;}}
  th{{background:#1c2330;color:#58a6ff;padding:10px 14px;text-align:left;font-size:12px;cursor:pointer;user-select:none;}}
  th:hover{{background:#243040;}}
  td{{padding:9px 14px;border-top:1px solid var(--border);font-size:13px;vertical-align:top;word-break:break-all;}}
  tr:hover td{{background:#1c2330;}}
  .poc-wrap{{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:8px 12px;
             font-family:monospace;font-size:12px;color:#7ee787;position:relative;max-width:500px;}}
  .copy-btn{{position:absolute;top:4px;right:6px;background:#21262d;border:1px solid var(--border);
             color:var(--muted);border-radius:4px;padding:2px 8px;cursor:pointer;font-size:11px;}}
  .copy-btn:hover{{color:var(--text);}}
  .filters{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px;}}
  .filter-btn{{background:var(--card);border:1px solid var(--border);color:var(--text);
               padding:5px 14px;border-radius:20px;cursor:pointer;font-size:12px;}}
  .filter-btn.active{{border-color:#58a6ff;color:#58a6ff;}}
  .search-box{{background:var(--card);border:1px solid var(--border);color:var(--text);
               padding:6px 14px;border-radius:20px;font-size:13px;width:260px;}}
  .search-box:focus{{outline:none;border-color:#58a6ff;}}
  .surface-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:24px;}}
  .surface-item{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;}}
  .surface-item h4{{color:#58a6ff;font-size:13px;margin-bottom:6px;}}
  .surface-item span{{font-size:24px;font-weight:700;}}
  footer{{color:var(--muted);font-size:12px;text-align:center;padding:30px;border-top:1px solid var(--border);margin-top:40px;}}
  @media print{{body{{background:white;color:black;}}.copy-btn{{display:none;}}}}
</style>
</head>
<body>
<header>
  <h1>Bug Bounty Report</h1>
  <p><strong>Target:</strong> {domain} &nbsp;|&nbsp; <strong>Date:</strong> {date} &nbsp;|&nbsp;
     <strong>Total findings:</strong> {total_findings}</p>
</header>

<div class="container">

<!-- Severity summary cards -->
<div class="stats">
  <div class="stat-card"><div class="num sev-crit">{cnt_critical}</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num sev-high">{cnt_high}</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num sev-med">{cnt_medium}</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="num sev-low">{cnt_low}</div><div class="lbl">Low</div></div>
  <div class="stat-card"><div class="num sev-info">{cnt_info}</div><div class="lbl">Info</div></div>
</div>

<!-- Attack surface summary -->
<h2>Attack Surface</h2>
<div class="surface-grid">
  <div class="surface-item"><h4>Subdomains</h4><span>{subdomains}</span></div>
  <div class="surface-item"><h4>Live Hosts</h4><span>{live_hosts}</span></div>
  <div class="surface-item"><h4>Open Ports</h4><span>{open_ports}</span></div>
  <div class="surface-item"><h4>URLs</h4><span>{urls}</span></div>
  <div class="surface-item"><h4>Param URLs</h4><span>{params}</span></div>
  <div class="surface-item"><h4>JS Files</h4><span>{js_files}</span></div>
</div>

<!-- Findings table -->
<h2>Findings</h2>
<div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px;">
  <input type="text" class="search-box" id="searchBox" placeholder="Search findings..." oninput="filterTable()">
  <div class="filters" id="sevFilters">
    <button class="filter-btn active" onclick="setSevFilter('all',this)">All</button>
    <button class="filter-btn" onclick="setSevFilter('critical',this)">Critical</button>
    <button class="filter-btn" onclick="setSevFilter('high',this)">High</button>
    <button class="filter-btn" onclick="setSevFilter('medium',this)">Medium</button>
    <button class="filter-btn" onclick="setSevFilter('low',this)">Low</button>
    <button class="filter-btn" onclick="setSevFilter('info',this)">Info</button>
  </div>
</div>

<table id="findingsTable">
<thead>
  <tr>
    <th onclick="sortTable(0)">#</th>
    <th onclick="sortTable(1)">Severity</th>
    <th onclick="sortTable(2)">Title</th>
    <th onclick="sortTable(3)">Host / URL</th>
    <th onclick="sortTable(4)">CVE</th>
    <th onclick="sortTable(5)">Source</th>
    <th>PoC</th>
  </tr>
</thead>
<tbody id="tableBody">
{rows}
</tbody>
</table>

</div><!-- /container -->

<footer>Generated by report_builder.py &nbsp;|&nbsp; {date}</footer>

<script>
let currentSev = 'all';
function setSevFilter(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}}
function filterTable() {{
  const q = document.getElementById('searchBox').value.toLowerCase();
  const rows = document.querySelectorAll('#tableBody tr');
  rows.forEach(row => {{
    const sev = row.dataset.sev || '';
    const text = row.textContent.toLowerCase();
    const sevMatch = (currentSev === 'all' || sev === currentSev);
    const txtMatch = (!q || text.includes(q));
    row.style.display = (sevMatch && txtMatch) ? '' : 'none';
  }});
}}
function sortTable(col) {{
  const tbody = document.getElementById('tableBody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const dir = tbody.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  tbody.dataset.sortDir = dir;
  rows.sort((a, b) => {{
    const at = a.cells[col]?.textContent.trim() || '';
    const bt = b.cells[col]?.textContent.trim() || '';
    return dir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
function copyPoC(id) {{
  const el = document.getElementById('poc-'+id);
  if (el) navigator.clipboard.writeText(el.textContent.trim());
}}
</script>
</body>
</html>"""

def build_row(idx: int, f: dict) -> str:
    sev   = f.get("severity", "info").lower()
    badge = f'<span class="badge badge-{sev}">{sev.upper()}</span>'
    title = _esc(f.get("title", ""))
    url   = _esc(f.get("url", ""))
    cve   = _esc(f.get("cve", ""))
    src   = _esc(f.get("source", ""))
    poc   = _esc(f.get("poc", ""))
    poc_html = (
        f'<div class="poc-wrap" id="poc-{idx}">{poc}'
        f'<button class="copy-btn" onclick="copyPoC({idx})">copy</button></div>'
    ) if poc else ""
    return (
        f'<tr data-sev="{sev}">'
        f'<td>{idx}</td><td>{badge}</td><td>{title}</td>'
        f'<td style="max-width:300px;word-break:break-all;">{url}</td>'
        f'<td>{cve}</td><td>{src}</td><td>{poc_html}</td>'
        f'</tr>'
    )

def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def count_file(path: str) -> int:
    try:
        return sum(1 for _ in open(path) if _.strip())
    except FileNotFoundError:
        return 0

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(description="HTML Report Builder")
    parser.add_argument("-d", "--domain",   required=True, help="Target domain name (for report header)")
    parser.add_argument("-i", "--input",    required=True, help="venomeye output directory")
    parser.add_argument("-o", "--output",   default="", help="Output HTML file (default: <input>/report.html)")
    parser.add_argument("--js-results",     default="", help="js_analyzer output dir")
    parser.add_argument("--ssrf-results",   default="", help="ssrf_tester output dir")
    parser.add_argument("--param-results",  default="", help="xss_sqli_scanner output dir")
    parser.add_argument("--cloud-results",  default="", help="cloud_misconfig output dir")
    parser.add_argument("--api-results",    default="", help="api_tester output dir")
    parser.add_argument("--idor-results",   default="", help="idor_hunter output dir")
    parser.add_argument("--screenshots",    action="store_true", help="Take screenshots with gowitness first")
    args = parser.parse_args()

    input_dir = Path(args.input)
    out_file  = args.output or str(input_dir / "report.html")

    info(f"Building report for {args.domain}")

    # ── collect findings ──────────────────────────────────────────────────
    all_findings: list[dict] = []

    # nuclei main scan
    for fn in ["nuclei_findings.json", "cve_checks/nuclei_cve.json"]:
        path = str(input_dir / fn)
        results = load_nuclei(path)
        all_findings.extend(results)
        if results:
            ok(f"Loaded {len(results)} nuclei findings from {fn}")

    # venomeye manual check outputs (plain text)
    plain_sources = [
        ("manual_checks/cors_issues.txt",           "CORS misconfiguration", "medium"),
        ("manual_checks/takeover_candidates.txt",   "Subdomain takeover",    "critical"),
        ("manual_checks/js_secrets.txt",            "JS secret",             "critical"),
        ("manual_checks/exposed_paths.txt",         "Exposed path",          "high"),
        ("ssl/expired_certs.txt",                   "Expired cert",          "medium"),
    ]
    for rel, source, sev in plain_sources:
        results = load_plain_findings(str(input_dir / rel), source, sev)
        all_findings.extend(results)

    # scanner JSON outputs
    extra_sources = [
        (args.js_results,     "findings.json",  "js_analyzer"),
        (args.ssrf_results,   "ssrf_findings.json", "ssrf_tester"),
        (args.param_results,  "findings.json",  "xss_sqli_scanner"),
        (args.cloud_results,  "findings.json",  "cloud_misconfig"),
        (args.api_results,    "findings.json",  "api_tester"),
        (args.idor_results,   "findings.json",  "idor_hunter"),
    ]
    for out_dir_arg, fname, source in extra_sources:
        if out_dir_arg:
            path = str(Path(out_dir_arg) / fname)
            results = load_json_findings(path, source)
            all_findings.extend(results)
            if results:
                ok(f"Loaded {len(results)} findings from {source}")

    # ── sort & deduplicate ────────────────────────────────────────────────
    seen_keys = set()
    deduped = []
    for f in sorted(all_findings, key=lambda x: SEV_ORDER.get(x.get("severity","info"), 9)):
        key = (f.get("title",""), f.get("url",""))
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    info(f"Total unique findings: {len(deduped)}")

    # ── take screenshots ──────────────────────────────────────────────────
    if args.screenshots:
        live_hosts = str(input_dir / "live_hosts.txt")
        ss_dir = str(input_dir / "screenshots")
        info("Taking screenshots with gowitness...")
        take_screenshots(live_hosts, ss_dir)

    # ── severity counts ───────────────────────────────────────────────────
    by_sev: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in deduped:
        sev = f.get("severity", "info")
        if sev in by_sev:
            by_sev[sev] += 1

    # ── attack surface stats ──────────────────────────────────────────────
    surf = {
        "subdomains": count_file(str(input_dir / "subdomains_all.txt")),
        "live_hosts":  count_file(str(input_dir / "live_hosts.txt")),
        "open_ports":  count_file(str(input_dir / "ports_naabu.txt")),
        "urls":        count_file(str(input_dir / "urls_all.txt")),
        "params":      count_file(str(input_dir / "params.txt")),
        "js_files":    count_file(str(input_dir / "js_files.txt")),
    }

    # ── build HTML rows ───────────────────────────────────────────────────
    rows_html = "\n".join(build_row(i+1, f) for i, f in enumerate(deduped))

    html = HTML_TEMPLATE.format(
        domain=_esc(args.domain),
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total_findings=len(deduped),
        cnt_critical=by_sev.get("critical", 0),
        cnt_high=by_sev.get("high", 0),
        cnt_medium=by_sev.get("medium", 0),
        cnt_low=by_sev.get("low", 0),
        cnt_info=by_sev.get("info", 0),
        rows=rows_html,
        **{k: f"{v:,}" for k, v in surf.items()},
    )

    Path(out_file).write_text(html)
    ok(f"Report written: {out_file}")
    info(f"Open in browser: file://{Path(out_file).absolute()}")

if __name__ == "__main__":
    main()
