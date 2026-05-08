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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{{
    --bg:#0a0e14;--bg-2:#0d1320;--card:#131a26;--card-2:#172033;
    --border:#222b3d;--border-strong:#2e3a52;
    --text:#e6edf3;--muted:#8b95a8;--accent:#58a6ff;--accent-2:#9d7cff;
    --crit:#ff5d6c;--high:#ffa057;--med:#ffd84d;--low:#5cc8ff;--info:#9aa3b2;
    --ok:#3fb950;
    --shadow:0 6px 20px rgba(0,0,0,.35);
  }}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  html,body{{background:var(--bg);}}
  body{{
    color:var(--text);
    font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
    font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;
    background:
      radial-gradient(1200px 600px at 10% -10%,rgba(88,166,255,.10),transparent 60%),
      radial-gradient(900px 500px at 110% 0%,rgba(157,124,255,.10),transparent 60%),
      var(--bg);
    min-height:100vh;
  }}
  code,pre,.mono{{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;}}

  /* Header */
  header{{
    position:relative;overflow:hidden;
    background:linear-gradient(135deg,#0f1626 0%,#1a1042 60%,#241047 100%);
    padding:42px 40px 36px;border-bottom:1px solid var(--border);
  }}
  header::before{{
    content:"";position:absolute;inset:-1px;pointer-events:none;
    background:radial-gradient(600px 200px at 80% -20%,rgba(88,166,255,.25),transparent 60%);
  }}
  .hdr-row{{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;position:relative;}}
  .hdr-title{{display:flex;align-items:center;gap:14px;}}
  .hdr-logo{{
    width:46px;height:46px;border-radius:12px;
    background:linear-gradient(135deg,#58a6ff,#9d7cff);
    display:flex;align-items:center;justify-content:center;
    box-shadow:0 4px 14px rgba(88,166,255,.35);
    font-weight:800;color:#0a0e14;font-size:20px;
  }}
  header h1{{font-size:24px;font-weight:700;letter-spacing:.2px;color:#fff;}}
  header h1 small{{color:var(--muted);font-weight:500;font-size:13px;display:block;margin-top:2px;}}
  .meta{{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:13px;}}
  .meta strong{{color:var(--text);font-weight:600;}}
  .meta-pill{{
    display:inline-flex;align-items:center;gap:6px;padding:5px 11px;
    background:rgba(255,255,255,.04);border:1px solid var(--border-strong);
    border-radius:999px;font-size:12px;
  }}
  .meta-pill .dot{{width:6px;height:6px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);}}

  .container{{max-width:1440px;margin:0 auto;padding:28px 40px 60px;}}

  /* Section heading */
  h2{{
    color:var(--text);font-size:15px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;
    margin:34px 0 14px;padding-bottom:10px;
    border-bottom:1px solid var(--border);
    display:flex;align-items:center;gap:10px;
  }}
  h2::before{{content:"";width:3px;height:14px;background:linear-gradient(180deg,var(--accent),var(--accent-2));border-radius:2px;}}

  /* Severity overview block */
  .overview{{
    display:grid;grid-template-columns:minmax(0,1.4fr) minmax(280px,1fr);gap:20px;margin-top:6px;
  }}
  @media (max-width:900px){{ .overview{{grid-template-columns:1fr;}} }}
  .panel{{
    background:linear-gradient(180deg,var(--card) 0%,var(--card-2) 100%);
    border:1px solid var(--border);border-radius:14px;padding:20px;
    box-shadow:var(--shadow);
  }}
  .panel-title{{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:14px;}}

  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;}}
  @media (max-width:700px){{ .stats{{grid-template-columns:repeat(2,1fr);}} }}
  .stat-card{{
    background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:12px;
    padding:14px 14px 12px;position:relative;overflow:hidden;transition:transform .15s ease,border-color .15s ease;
  }}
  .stat-card:hover{{transform:translateY(-2px);border-color:var(--border-strong);}}
  .stat-card .num{{font-size:30px;font-weight:800;line-height:1;letter-spacing:-.5px;}}
  .stat-card .lbl{{color:var(--muted);font-size:11px;margin-top:6px;text-transform:uppercase;letter-spacing:.5px;}}
  .stat-card .accent{{position:absolute;left:0;top:0;bottom:0;width:3px;}}
  .stat-card.crit .accent{{background:var(--crit);}}
  .stat-card.high .accent{{background:var(--high);}}
  .stat-card.med  .accent{{background:var(--med);}}
  .stat-card.low  .accent{{background:var(--low);}}
  .stat-card.infosev .accent{{background:var(--info);}}

  .sev-crit{{color:var(--crit)!important;}} .sev-high{{color:var(--high)!important;}}
  .sev-med{{color:var(--med)!important;}}  .sev-low{{color:var(--low)!important;}}
  .sev-info{{color:var(--info)!important;}}

  .severity-bar{{
    margin-top:18px;display:flex;height:10px;border-radius:999px;overflow:hidden;
    background:rgba(255,255,255,.04);border:1px solid var(--border);
  }}
  .severity-bar > span{{display:block;height:100%;}}
  .severity-bar .seg-crit{{background:var(--crit);}}
  .severity-bar .seg-high{{background:var(--high);}}
  .severity-bar .seg-med {{background:var(--med);}}
  .severity-bar .seg-low {{background:var(--low);}}
  .severity-bar .seg-info{{background:var(--info);}}

  .donut-wrap{{display:flex;flex-direction:column;align-items:center;justify-content:center;}}
  .donut-wrap canvas{{max-width:220px;}}
  .donut-legend{{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px;justify-content:center;}}
  .legend-pill{{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);}}
  .legend-pill i{{width:10px;height:10px;border-radius:3px;display:inline-block;}}

  /* Attack surface */
  .surface-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;}}
  .surface-item{{
    background:linear-gradient(180deg,var(--card) 0%,var(--card-2) 100%);
    border:1px solid var(--border);border-radius:12px;padding:16px 18px;
    transition:transform .15s ease,border-color .15s ease;box-shadow:var(--shadow);
  }}
  .surface-item:hover{{transform:translateY(-2px);border-color:var(--border-strong);}}
  .surface-item h4{{color:var(--muted);font-size:11px;margin-bottom:8px;text-transform:uppercase;letter-spacing:.6px;font-weight:600;}}
  .surface-item span{{font-size:26px;font-weight:800;letter-spacing:-.5px;color:var(--text);}}

  /* Filters */
  .toolbar{{
    display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:14px;
  }}
  .filters{{display:flex;gap:8px;flex-wrap:wrap;}}
  .filter-btn{{
    background:var(--card);border:1px solid var(--border);color:var(--muted);
    padding:6px 14px;border-radius:999px;cursor:pointer;font-size:12px;font-weight:500;
    transition:all .15s ease;display:inline-flex;align-items:center;gap:6px;
  }}
  .filter-btn:hover{{border-color:var(--border-strong);color:var(--text);}}
  .filter-btn.active{{
    border-color:var(--accent);color:var(--accent);
    background:rgba(88,166,255,.08);box-shadow:0 0 0 1px rgba(88,166,255,.25);
  }}
  .filter-btn .count{{
    font-size:10px;background:rgba(255,255,255,.08);padding:1px 7px;border-radius:999px;color:var(--text);
  }}
  .search-box{{
    background:var(--card);border:1px solid var(--border);color:var(--text);
    padding:8px 14px;border-radius:999px;font-size:13px;width:280px;
    transition:all .15s ease;
  }}
  .search-box::placeholder{{color:var(--muted);}}
  .search-box:focus{{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(88,166,255,.18);}}

  /* Findings table */
  .table-wrap{{
    background:var(--card);border:1px solid var(--border);border-radius:14px;
    overflow:hidden;box-shadow:var(--shadow);
  }}
  table{{width:100%;border-collapse:collapse;}}
  thead{{position:sticky;top:0;}}
  th{{
    background:#0f1623;color:var(--muted);
    padding:11px 14px;text-align:left;font-size:11px;font-weight:600;
    text-transform:uppercase;letter-spacing:.6px;cursor:pointer;user-select:none;
    border-bottom:1px solid var(--border);
  }}
  th:hover{{color:var(--accent);}}
  td{{padding:11px 14px;border-top:1px solid var(--border);font-size:13px;vertical-align:top;word-break:break-word;}}
  tbody tr{{transition:background .12s ease;}}
  tbody tr:hover td{{background:rgba(88,166,255,.05);}}
  tbody tr.hidden{{display:none;}}

  .badge{{
    display:inline-flex;align-items:center;gap:5px;padding:3px 9px;
    border-radius:999px;font-size:10.5px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;
  }}
  .badge::before{{content:"";width:6px;height:6px;border-radius:50%;display:inline-block;}}
  .badge-critical{{background:rgba(255,93,108,.12);color:var(--crit);}}
  .badge-critical::before{{background:var(--crit);box-shadow:0 0 6px var(--crit);}}
  .badge-high{{background:rgba(255,160,87,.12);color:var(--high);}}
  .badge-high::before{{background:var(--high);}}
  .badge-medium{{background:rgba(255,216,77,.12);color:var(--med);}}
  .badge-medium::before{{background:var(--med);}}
  .badge-low{{background:rgba(92,200,255,.12);color:var(--low);}}
  .badge-low::before{{background:var(--low);}}
  .badge-info{{background:rgba(154,163,178,.12);color:var(--info);}}
  .badge-info::before{{background:var(--info);}}

  .poc-wrap{{
    background:#0a0f17;border:1px solid var(--border);border-radius:8px;
    padding:8px 36px 8px 12px;font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:12px;color:#7ee787;position:relative;max-width:520px;
    word-break:break-all;
  }}
  .copy-btn{{
    position:absolute;top:5px;right:5px;background:#1c2533;border:1px solid var(--border);
    color:var(--muted);border-radius:6px;padding:2px 9px;cursor:pointer;font-size:10px;
    text-transform:uppercase;letter-spacing:.5px;transition:all .15s ease;
  }}
  .copy-btn:hover{{color:var(--text);border-color:var(--accent);}}
  .copy-btn.copied{{color:var(--ok);border-color:var(--ok);}}

  .empty{{text-align:center;padding:40px 20px;color:var(--muted);}}

  footer{{
    color:var(--muted);font-size:12px;text-align:center;padding:30px;
    border-top:1px solid var(--border);margin-top:40px;
  }}
  footer a{{color:var(--accent);text-decoration:none;}}

  @media print{{
    body{{background:#fff;color:#111;}}
    header{{background:#fff;color:#111;border-bottom:2px solid #ccc;}}
    header h1, .meta strong{{color:#111;}}
    .panel,.surface-item,.table-wrap{{background:#fff;border:1px solid #ccc;box-shadow:none;}}
    .copy-btn,.toolbar{{display:none;}}
    td,th{{color:#111;border-color:#ddd;}}
  }}
</style>
</head>
<body>
<header>
  <div class="hdr-row">
    <div class="hdr-title">
      <div class="hdr-logo">V</div>
      <div>
        <h1>Bug Bounty Report
          <small>{domain}</small>
        </h1>
      </div>
    </div>
    <div class="meta">
      <span class="meta-pill"><span class="dot"></span>{total_findings} findings</span>
      <span class="meta-pill">{date}</span>
    </div>
  </div>
</header>

<div class="container">

<!-- Severity overview -->
<div class="overview">
  <div class="panel">
    <div class="panel-title">Severity overview</div>
    <div class="stats">
      <div class="stat-card crit"><div class="accent"></div><div class="num sev-crit">{cnt_critical}</div><div class="lbl">Critical</div></div>
      <div class="stat-card high"><div class="accent"></div><div class="num sev-high">{cnt_high}</div><div class="lbl">High</div></div>
      <div class="stat-card med"><div class="accent"></div><div class="num sev-med">{cnt_medium}</div><div class="lbl">Medium</div></div>
      <div class="stat-card low"><div class="accent"></div><div class="num sev-low">{cnt_low}</div><div class="lbl">Low</div></div>
      <div class="stat-card infosev"><div class="accent"></div><div class="num sev-info">{cnt_info}</div><div class="lbl">Info</div></div>
    </div>
    <div class="severity-bar" id="sevBar" aria-hidden="true"></div>
  </div>
  <div class="panel donut-wrap">
    <div class="panel-title" style="align-self:flex-start;width:100%;">Distribution</div>
    <canvas id="sevDonut" width="220" height="220"></canvas>
    <div class="donut-legend">
      <span class="legend-pill"><i style="background:var(--crit)"></i>Critical</span>
      <span class="legend-pill"><i style="background:var(--high)"></i>High</span>
      <span class="legend-pill"><i style="background:var(--med)"></i>Medium</span>
      <span class="legend-pill"><i style="background:var(--low)"></i>Low</span>
      <span class="legend-pill"><i style="background:var(--info)"></i>Info</span>
    </div>
  </div>
</div>

<!-- Attack surface -->
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
<div class="toolbar">
  <input type="text" class="search-box" id="searchBox" placeholder="Search title, host, CVE, source..." oninput="filterTable()">
  <div class="filters" id="sevFilters">
    <button class="filter-btn active" data-sev="all"     onclick="setSevFilter('all',this)">All <span class="count">{total_findings}</span></button>
    <button class="filter-btn"        data-sev="critical" onclick="setSevFilter('critical',this)">Critical <span class="count">{cnt_critical}</span></button>
    <button class="filter-btn"        data-sev="high"     onclick="setSevFilter('high',this)">High <span class="count">{cnt_high}</span></button>
    <button class="filter-btn"        data-sev="medium"   onclick="setSevFilter('medium',this)">Medium <span class="count">{cnt_medium}</span></button>
    <button class="filter-btn"        data-sev="low"      onclick="setSevFilter('low',this)">Low <span class="count">{cnt_low}</span></button>
    <button class="filter-btn"        data-sev="info"     onclick="setSevFilter('info',this)">Info <span class="count">{cnt_info}</span></button>
  </div>
</div>

<div class="table-wrap">
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
</div>
<div class="empty" id="emptyState" style="display:none;">No findings match the current filters.</div>

</div><!-- /container -->

<footer>Generated by <strong>report_builder.py</strong> · {date}</footer>

<script>
const SEV_COUNTS = {{
  critical:{cnt_critical}, high:{cnt_high}, medium:{cnt_medium},
  low:{cnt_low}, info:{cnt_info}
}};
const SEV_COLORS = {{
  critical:'#ff5d6c', high:'#ffa057', medium:'#ffd84d', low:'#5cc8ff', info:'#9aa3b2'
}};

/* Severity proportional bar */
(function buildSevBar(){{
  const bar = document.getElementById('sevBar');
  const total = Object.values(SEV_COUNTS).reduce((a,b)=>a+b,0);
  if (!total) {{ bar.style.opacity='.4'; return; }}
  const order = ['critical','high','medium','low','info'];
  const segMap = {{critical:'seg-crit',high:'seg-high',medium:'seg-med',low:'seg-low',info:'seg-info'}};
  for (const k of order) {{
    const v = SEV_COUNTS[k];
    if (!v) continue;
    const seg = document.createElement('span');
    seg.className = segMap[k];
    seg.style.width = (v/total*100).toFixed(2)+'%';
    seg.title = `${{k}}: ${{v}}`;
    bar.appendChild(seg);
  }}
}})();

/* Lightweight donut chart — pure canvas, no external deps */
(function drawDonut(){{
  const c = document.getElementById('sevDonut');
  if (!c || !c.getContext) return;
  const ctx = c.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const size = 220;
  c.width = size*dpr; c.height = size*dpr;
  c.style.width = size+'px'; c.style.height = size+'px';
  ctx.scale(dpr,dpr);
  const cx = size/2, cy = size/2, r = 88, ringW = 22;
  const order = ['critical','high','medium','low','info'];
  const total = order.reduce((a,k)=>a+SEV_COUNTS[k],0);

  // background ring
  ctx.beginPath();
  ctx.arc(cx,cy,r,0,Math.PI*2);
  ctx.lineWidth = ringW;
  ctx.strokeStyle = 'rgba(255,255,255,0.04)';
  ctx.stroke();

  if (total > 0) {{
    let start = -Math.PI/2;
    for (const k of order) {{
      const v = SEV_COUNTS[k];
      if (!v) continue;
      const slice = (v/total) * Math.PI*2;
      ctx.beginPath();
      ctx.arc(cx,cy,r,start,start+slice);
      ctx.lineWidth = ringW;
      ctx.strokeStyle = SEV_COLORS[k];
      ctx.lineCap = 'butt';
      ctx.stroke();
      start += slice;
    }}
  }}
  // center label
  ctx.fillStyle = '#e6edf3';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.font = '700 28px Inter,system-ui,sans-serif';
  ctx.fillText(total, cx, cy-6);
  ctx.fillStyle = '#8b95a8';
  ctx.font = '500 11px Inter,system-ui,sans-serif';
  ctx.fillText('TOTAL', cx, cy+16);
}})();

/* Filtering & sorting */
let currentSev = 'all';
function setSevFilter(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}}
function filterTable() {{
  const q = (document.getElementById('searchBox').value || '').toLowerCase();
  const rows = document.querySelectorAll('#tableBody tr');
  let visible = 0;
  rows.forEach(row => {{
    const sev = row.dataset.sev || '';
    const text = row.textContent.toLowerCase();
    const sevMatch = (currentSev === 'all' || sev === currentSev);
    const txtMatch = (!q || text.includes(q));
    const show = sevMatch && txtMatch;
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  document.getElementById('emptyState').style.display = visible ? 'none' : 'block';
}}
const SEV_RANK = {{critical:0, high:1, medium:2, low:3, info:4}};
function sortTable(col) {{
  const tbody = document.getElementById('tableBody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const dir = tbody.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  tbody.dataset.sortDir = dir;
  rows.sort((a, b) => {{
    let at = (a.cells[col]?.textContent || '').trim();
    let bt = (b.cells[col]?.textContent || '').trim();
    if (col === 1) {{ // severity column — rank by severity not alphabet
      at = SEV_RANK[a.dataset.sev] ?? 9;
      bt = SEV_RANK[b.dataset.sev] ?? 9;
      return dir === 'asc' ? at - bt : bt - at;
    }}
    const an = parseFloat(at), bn = parseFloat(bt);
    if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
    return dir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
function copyPoC(id, btn) {{
  const el = document.getElementById('poc-'+id);
  if (!el) return;
  const txt = (el.dataset.raw || el.textContent).trim();
  navigator.clipboard.writeText(txt).then(() => {{
    if (!btn) return;
    const orig = btn.textContent;
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => {{ btn.textContent = orig; btn.classList.remove('copied'); }}, 1200);
  }});
}}
/* Keyboard shortcut: "/" to focus search */
document.addEventListener('keydown', e => {{
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {{
    e.preventDefault();
    document.getElementById('searchBox').focus();
  }}
}});
</script>
</body>
</html>"""

def build_row(idx: int, f: dict) -> str:
    sev   = (f.get("severity") or "info").lower()
    if sev not in SEV_ORDER:
        sev = "info"
    badge = f'<span class="badge badge-{sev}">{sev}</span>'
    title = _esc(f.get("title", ""))
    url   = _esc(f.get("url", ""))
    cve   = _esc(f.get("cve", ""))
    src   = _esc(f.get("source", ""))
    raw_poc = str(f.get("poc", "") or "")
    poc     = _esc(raw_poc)
    # data-raw holds the un-escaped PoC so copy-to-clipboard pastes the real
    # payload, not the HTML-escaped one.
    poc_html = (
        f'<div class="poc-wrap" id="poc-{idx}" data-raw="{_esc(raw_poc)}">{poc}'
        f'<button class="copy-btn" onclick="copyPoC({idx},this)">copy</button></div>'
    ) if raw_poc else ""
    return (
        f'<tr data-sev="{sev}">'
        f'<td>{idx}</td><td>{badge}</td><td>{title}</td>'
        f'<td style="max-width:320px;">{url}</td>'
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
