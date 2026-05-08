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
"""Generate a professional threat hunting PDF report from threat_hunting.csv"""

import weasyprint

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
    background: #f4f6f9;
    color: #1a2332;
    font-size: 10pt;
  }

  /* ── COVER PAGE ── */
  .cover {
    background: linear-gradient(145deg, #0a0f1e 0%, #0d1b3e 50%, #0a1628 100%);
    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    page-break-after: always;
    position: relative;
    overflow: hidden;
  }

  .cover::before {
    content: '';
    position: absolute;
    top: -50px; left: -50px;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(0,180,255,0.12) 0%, transparent 70%);
    border-radius: 50%;
  }

  .cover::after {
    content: '';
    position: absolute;
    bottom: -80px; right: -80px;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(255,60,60,0.08) 0%, transparent 70%);
    border-radius: 50%;
  }

  .cover-badge {
    background: rgba(220,53,69,0.15);
    border: 1px solid rgba(220,53,69,0.5);
    color: #ff6b7a;
    font-size: 7pt;
    font-weight: 600;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 5px 16px;
    border-radius: 20px;
    margin-bottom: 24px;
  }

  .cover h1 {
    color: #ffffff;
    font-size: 30pt;
    font-weight: 700;
    text-align: center;
    line-height: 1.15;
    letter-spacing: -0.5px;
    margin-bottom: 10px;
  }

  .cover h1 span { color: #00b4ff; }

  .cover .subtitle {
    color: #8ca4c0;
    font-size: 11pt;
    font-weight: 300;
    text-align: center;
    margin-bottom: 40px;
    letter-spacing: 1px;
  }

  .cover-divider {
    width: 80px;
    height: 3px;
    background: linear-gradient(90deg, #00b4ff, #7b2fff);
    border-radius: 2px;
    margin-bottom: 40px;
  }

  .cover-meta {
    display: flex;
    gap: 40px;
    text-align: center;
  }

  .cover-meta-item label {
    display: block;
    color: #4a6480;
    font-size: 7pt;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 4px;
  }

  .cover-meta-item span {
    color: #c0d4e8;
    font-size: 9pt;
    font-weight: 600;
  }

  .cover-footer {
    position: absolute;
    bottom: 24px;
    color: #2d4060;
    font-size: 7.5pt;
    letter-spacing: 1px;
  }

  /* ── BODY PAGES ── */
  .page {
    background: #ffffff;
    margin: 0;
    padding: 36px 44px;
    page-break-after: always;
  }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 10px;
    margin-bottom: 28px;
  }

  .page-header .brand {
    font-size: 8pt;
    font-weight: 700;
    color: #0a1628;
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  .page-header .doc-id {
    font-size: 7.5pt;
    color: #8ca4c0;
    font-family: 'Courier New', monospace;
  }

  /* ── SECTION TITLES ── */
  .section-title {
    font-size: 14pt;
    font-weight: 700;
    color: #0a1628;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .section-title .num {
    background: linear-gradient(135deg, #0057b8, #00b4ff);
    color: #fff;
    font-size: 8pt;
    font-weight: 700;
    width: 24px; height: 24px;
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .section-rule {
    height: 2px;
    background: linear-gradient(90deg, #0057b8 0%, #e2e8f0 100%);
    border-radius: 1px;
    margin-bottom: 18px;
  }

  p { line-height: 1.7; color: #374151; margin-bottom: 10px; }

  /* ── EXECUTIVE SUMMARY BOXES ── */
  .summary-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr;
    gap: 14px;
    margin-bottom: 24px;
  }

  .stat-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-top: 3px solid;
    border-radius: 8px;
    padding: 14px 12px;
    text-align: center;
  }

  .stat-card.red   { border-top-color: #dc3545; }
  .stat-card.orange{ border-top-color: #fd7e14; }
  .stat-card.blue  { border-top-color: #0057b8; }
  .stat-card.green { border-top-color: #198754; }

  .stat-card .value {
    font-size: 22pt;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }

  .stat-card.red   .value { color: #dc3545; }
  .stat-card.orange .value{ color: #fd7e14; }
  .stat-card.blue  .value { color: #0057b8; }
  .stat-card.green .value { color: #198754; }

  .stat-card .label {
    font-size: 7.5pt;
    color: #64748b;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  /* ── ALERT BOXES ── */
  .alert {
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 14px;
    border-left: 4px solid;
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }

  .alert.critical { background: #fff5f5; border-color: #dc3545; }
  .alert.high     { background: #fff8f0; border-color: #fd7e14; }
  .alert.medium   { background: #fffbf0; border-color: #ffc107; }
  .alert.info     { background: #f0f7ff; border-color: #0057b8; }

  .alert .sev-badge {
    font-size: 6.5pt;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 4px;
    white-space: nowrap;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .alert.critical .sev-badge { background: #dc3545; color: #fff; }
  .alert.high     .sev-badge { background: #fd7e14; color: #fff; }
  .alert.medium   .sev-badge { background: #ffc107; color: #000; }
  .alert.info     .sev-badge { background: #0057b8; color: #fff; }

  .alert .alert-body { flex: 1; }
  .alert .alert-title { font-weight: 700; font-size: 9pt; margin-bottom: 3px; }
  .alert .alert-text  { font-size: 8.5pt; color: #4a5568; line-height: 1.5; margin: 0; }

  /* ── TABLES ── */
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
    font-size: 8pt;
  }

  thead tr {
    background: #0a1628;
    color: #ffffff;
  }

  thead th {
    padding: 9px 10px;
    text-align: left;
    font-weight: 600;
    letter-spacing: 0.5px;
    font-size: 7.5pt;
  }

  tbody tr:nth-child(even) { background: #f8fafc; }
  tbody tr:nth-child(odd)  { background: #ffffff; }
  tbody tr:hover { background: #eef3ff; }

  tbody td {
    padding: 8px 10px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
  }

  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 7pt;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }

  .badge-red    { background: #fee2e2; color: #991b1b; }
  .badge-orange { background: #ffedd5; color: #9a3412; }
  .badge-blue   { background: #dbeafe; color: #1e40af; }
  .badge-green  { background: #dcfce7; color: #166534; }
  .badge-gray   { background: #f1f5f9; color: #475569; }

  .mono { font-family: 'Courier New', monospace; font-size: 7.5pt; color: #334155; }

  /* ── TIMELINE ── */
  .timeline { margin-bottom: 20px; }

  .tl-item {
    display: flex;
    gap: 14px;
    margin-bottom: 12px;
    position: relative;
  }

  .tl-dot {
    width: 12px; height: 12px;
    border-radius: 50%;
    flex-shrink: 0;
    margin-top: 3px;
  }

  .tl-dot.infected  { background: #dc3545; }
  .tl-dot.signature { background: #fd7e14; }

  .tl-line {
    position: absolute;
    left: 5px; top: 15px;
    width: 2px;
    background: #e2e8f0;
    bottom: -12px;
  }

  .tl-content {}
  .tl-date  { font-size: 7.5pt; color: #64748b; font-weight: 600; margin-bottom: 2px; }
  .tl-title { font-size: 9pt; font-weight: 700; margin-bottom: 2px; }
  .tl-desc  { font-size: 8pt; color: #4a5568; margin: 0; }

  /* ── MITRE TABLE ── */
  .mitre-row { display: flex; gap: 10px; margin-bottom: 8px; align-items: flex-start; }
  .mitre-id  {
    background: #0a1628; color: #00b4ff;
    font-family: 'Courier New', monospace;
    font-size: 7.5pt; font-weight: 700;
    padding: 3px 8px; border-radius: 4px;
    white-space: nowrap; flex-shrink: 0;
  }
  .mitre-info .tactic { font-weight: 700; font-size: 8.5pt; margin-bottom: 1px; }
  .mitre-info .desc   { font-size: 8pt; color: #4a5568; margin: 0; }

  /* ── RECOMMENDATIONS ── */
  .rec-item {
    display: flex; gap: 12px; margin-bottom: 14px; align-items: flex-start;
  }

  .rec-num {
    background: linear-gradient(135deg, #0057b8, #00b4ff);
    color: #fff; font-size: 8pt; font-weight: 700;
    width: 22px; height: 22px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .rec-body .rec-title { font-weight: 700; font-size: 9pt; margin-bottom: 3px; }
  .rec-body .rec-desc  { font-size: 8.5pt; color: #4a5568; margin: 0; line-height: 1.6; }

  /* ── FOOTER ── */
  .page-footer {
    margin-top: 24px;
    padding-top: 10px;
    border-top: 1px solid #e2e8f0;
    display: flex;
    justify-content: space-between;
    font-size: 7pt;
    color: #94a3b8;
  }

  /* ── PRINT ── */
  @page { size: A4; margin: 0; }
  @media print { body { background: white; } }
</style>
</head>
<body>

<!-- ════════════════ COVER ════════════════ -->
<div class="cover">
  <div class="cover-badge">CONFIDENTIAL — TLP:AMBER</div>
  <h1>Threat <span>Hunting</span><br>Intelligence Report</h1>
  <div class="subtitle">FortiSASE Firewall Log Analysis &amp; Adversary Detection</div>
  <div class="cover-divider"></div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <label>Report Date</label>
      <span>April 12, 2026</span>
    </div>
    <div class="cover-meta-item">
      <label>Period Covered</label>
      <span>Mar 13 – Apr 9, 2026</span>
    </div>
    <div class="cover-meta-item">
      <label>Data Source</label>
      <span>fortinet_fortisase.log</span>
    </div>
    <div class="cover-meta-item">
      <label>Classification</label>
      <span>Internal Use Only</span>
    </div>
  </div>
  <div class="cover-footer">THREAT INTELLIGENCE UNIT &nbsp;|&nbsp; SECURITY OPERATIONS CENTER</div>
</div>


<!-- ════════════════ PAGE 1: EXECUTIVE SUMMARY ════════════════ -->
<div class="page">
  <div class="page-header">
    <div class="brand">Threat Hunting Report</div>
    <div class="doc-id">THR-2026-0412 | CONFIDENTIAL</div>
  </div>

  <div class="section-title"><div class="num">1</div> Executive Summary</div>
  <div class="section-rule"></div>

  <p>
    This report presents findings from a threat hunting analysis of FortiSASE firewall log telemetry
    spanning <strong>March 13, 2026 through April 9, 2026</strong>. A total of <strong>8 security events</strong>
    were identified and triaged across two distinct threat categories: <em>malware-infected file delivery</em>
    and <em>unauthorized VPN proxy tooling</em> (OKHTTP.Library.VPN). All events were blocked or denied
    by the firewall; however, the patterns identified warrant investigation and remediation action.
  </p>

  <p>
    The analysis reveals a recurring pattern of compromised third-party websites attempting to serve
    malicious JavaScript payloads (supply-chain/watering-hole style), alongside evidence of VPN proxy
    bypass attempts originating from Google Workspace interactions. These findings suggest both external
    threat actor activity and potential policy violations or unauthorized tooling within the environment.
  </p>

  <div class="summary-grid">
    <div class="stat-card red">
      <div class="value">8</div>
      <div class="label">Total Events</div>
    </div>
    <div class="stat-card orange">
      <div class="value">4</div>
      <div class="label">Malware Blocked</div>
    </div>
    <div class="stat-card blue">
      <div class="value">4</div>
      <div class="label">VPN Proxy Blocked</div>
    </div>
    <div class="stat-card green">
      <div class="value">100%</div>
      <div class="label">Block Rate</div>
    </div>
  </div>

  <div class="alert critical">
    <div class="sev-badge">CRITICAL</div>
    <div class="alert-body">
      <div class="alert-title">Watering-Hole / Supply-Chain JavaScript Injection</div>
      <p class="alert-text">
        Four distinct websites (capsgold.com, iglad20.igllabs.co, discoverbangalore.com) served
        infected JavaScript files via HTTP GET requests. The same domain (capsgold.com) was hit twice
        on Apr 2 and Apr 6, indicating persistent exposure to a compromised resource. These files were
        flagged as infected and blocked by FortiSASE.
      </p>
    </div>
  </div>

  <div class="alert high">
    <div class="sev-badge">HIGH</div>
    <div class="alert-body">
      <div class="alert-title">Repeated OKHTTP VPN Proxy Signature Detection</div>
      <p class="alert-text">
        Four POST requests were blocked for matching the <em>OKHTTP.Library.VPN</em> IPS signature.
        All events originated from Google Workspace (Gmail, Google Chat) referrers, suggesting a device
        or application is tunneling Google Workspace traffic through an unauthorized VPN proxy,
        possibly a mobile emulator or modified Android application.
      </p>
    </div>
  </div>

  <div class="alert medium">
    <div class="sev-badge">MEDIUM</div>
    <div class="alert-body">
      <div class="alert-title">Potential API Key Exposure in Blocked Requests</div>
      <p class="alert-text">
        Two blocked requests to Google's signaler API contained <em>API keys</em> in the URL query
        string (<code>key=AIzaSy...</code>). While these keys belong to Google's infrastructure, their
        presence in query parameters of suspicious proxy traffic warrants review.
      </p>
    </div>
  </div>

  <div class="page-footer">
    <span>CONFIDENTIAL — TLP:AMBER</span>
    <span>Page 1 of 4 &nbsp;|&nbsp; THR-2026-0412</span>
  </div>
</div>


<!-- ════════════════ PAGE 2: EVENT TIMELINE + DETAIL TABLE ════════════════ -->
<div class="page">
  <div class="page-header">
    <div class="brand">Threat Hunting Report</div>
    <div class="doc-id">THR-2026-0412 | CONFIDENTIAL</div>
  </div>

  <div class="section-title"><div class="num">2</div> Event Timeline</div>
  <div class="section-rule"></div>

  <div class="timeline">

    <div class="tl-item">
      <div>
        <div class="tl-dot infected"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Apr 9, 2026 — 20:50:35 UTC</div>
        <div class="tl-title"><span class="badge badge-orange">VPN Proxy</span> &nbsp;OKHTTP.Library.VPN — Google Chat Signaler</div>
        <p class="tl-desc">POST to <code>prod-dynamite-prod-09-us-signaler-pa.clients6.google.com</code> via /punctual/v1/chooseServer. Referrer: Google Chat. IPS signature blocked.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot infected"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Apr 8, 2026 — 16:37:44 UTC</div>
        <div class="tl-title"><span class="badge badge-red">Malware</span> &nbsp;Infected JS — iglad20.igllabs.co</div>
        <p class="tl-desc">GET /js/thumbnail-slider.js from iglad20.igllabs.co (IP: 162.241.27.29). Referrer: verifyreport.php page. File flagged infected and blocked.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot infected"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Apr 6, 2026 — 11:31:56 UTC</div>
        <div class="tl-title"><span class="badge badge-red">Malware</span> &nbsp;Infected JS — capsgold.com (2nd hit)</div>
        <p class="tl-desc">GET /js/jquery.dd.js from capsgold.com (IP: 162.251.80.117). Referrer: capsgold.com home. Repeated exposure to same malicious file as Apr 2.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot infected"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Apr 5, 2026 — 14:50:22 UTC</div>
        <div class="tl-title"><span class="badge badge-red">Malware</span> &nbsp;Infected JS — discoverbangalore.com</div>
        <p class="tl-desc">GET /jsmenu/stmenu.js from www.discoverbangalore.com (IP: 66.96.149.32). Referrer: /restreview30.htm. Path encoding anomaly detected in URL.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot infected"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Apr 2, 2026 — 16:40:40 UTC</div>
        <div class="tl-title"><span class="badge badge-red">Malware</span> &nbsp;Infected JS — www.capsgold.com (1st hit)</div>
        <p class="tl-desc">GET /js/jquery.dd.js from www.capsgold.com (IP: 162.251.80.117). Same file as Apr 6 event. Indicates the resource remained infected for at least 4 days.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot signature"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Mar 30, 2026 — 21:00:11 UTC</div>
        <div class="tl-title"><span class="badge badge-orange">VPN Proxy</span> &nbsp;OKHTTP.Library.VPN — Gmail People Stack</div>
        <p class="tl-desc">POST to peoplestackwebexperiments-pa.clients6.google.com. Referrer: Gmail. Endpoint: GetExperimentFlags. Signature blocked.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot signature"></div>
        <div class="tl-line"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Mar 21, 2026 — 11:17:55 UTC</div>
        <div class="tl-title"><span class="badge badge-orange">VPN Proxy</span> &nbsp;OKHTTP.Library.VPN — Gmail Sync</div>
        <p class="tl-desc">POST to mail.google.com/sync/u/0/i/s with query params hl=en&amp;c=37&amp;rt=r&amp;pt=ji. Referrer: Gmail with tab parameter. Signature blocked.</p>
      </div>
    </div>

    <div class="tl-item">
      <div>
        <div class="tl-dot signature"></div>
      </div>
      <div class="tl-content">
        <div class="tl-date">Mar 13, 2026 — 19:53:30 UTC</div>
        <div class="tl-title"><span class="badge badge-orange">VPN Proxy</span> &nbsp;OKHTTP.Library.VPN — Gmail Signaler (first observed)</div>
        <p class="tl-desc">POST to signaler-pa.clients6.google.com/punctual/v1/chooseServer. Referrer: Gmail. First occurrence of OKHTTP proxy pattern in the dataset.</p>
      </div>
    </div>

  </div>

  <div class="page-footer">
    <span>CONFIDENTIAL — TLP:AMBER</span>
    <span>Page 2 of 4 &nbsp;|&nbsp; THR-2026-0412</span>
  </div>
</div>


<!-- ════════════════ PAGE 3: IOC TABLE + MITRE ATT&CK ════════════════ -->
<div class="page">
  <div class="page-header">
    <div class="brand">Threat Hunting Report</div>
    <div class="doc-id">THR-2026-0412 | CONFIDENTIAL</div>
  </div>

  <div class="section-title"><div class="num">3</div> Indicators of Compromise (IOCs)</div>
  <div class="section-rule"></div>

  <table>
    <thead>
      <tr>
        <th>Type</th>
        <th>Indicator</th>
        <th>Destination IP</th>
        <th>Threat</th>
        <th>First Seen</th>
        <th>Last Seen</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="badge badge-red">Domain</span></td>
        <td class="mono">capsgold.com</td>
        <td class="mono">162.251.80.117</td>
        <td>Malware JS</td>
        <td>Apr 2, 2026</td>
        <td>Apr 6, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-red">Domain</span></td>
        <td class="mono">iglad20.igllabs.co</td>
        <td class="mono">162.241.27.29</td>
        <td>Malware JS</td>
        <td>Apr 8, 2026</td>
        <td>Apr 8, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-red">Domain</span></td>
        <td class="mono">discoverbangalore.com</td>
        <td class="mono">66.96.149.32</td>
        <td>Malware JS</td>
        <td>Apr 5, 2026</td>
        <td>Apr 5, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-orange">Signature</span></td>
        <td class="mono">OKHTTP.Library.VPN</td>
        <td class="mono">142.250.x.x</td>
        <td>VPN Proxy</td>
        <td>Mar 13, 2026</td>
        <td>Apr 9, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-red">File Path</span></td>
        <td class="mono">/js/jquery.dd.js</td>
        <td class="mono">162.251.80.117</td>
        <td>Malware JS</td>
        <td>Apr 2, 2026</td>
        <td>Apr 6, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-red">File Path</span></td>
        <td class="mono">/js/thumbnail-slider.js</td>
        <td class="mono">162.241.27.29</td>
        <td>Malware JS</td>
        <td>Apr 8, 2026</td>
        <td>Apr 8, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-red">File Path</span></td>
        <td class="mono">/jsmenu/stmenu.js</td>
        <td class="mono">66.96.149.32</td>
        <td>Malware JS</td>
        <td>Apr 5, 2026</td>
        <td>Apr 5, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
      <tr>
        <td><span class="badge badge-blue">URL Path</span></td>
        <td class="mono">/punctual/v1/chooseServer</td>
        <td class="mono">142.250.71.106</td>
        <td>VPN Proxy</td>
        <td>Mar 13, 2026</td>
        <td>Apr 9, 2026</td>
        <td><span class="badge badge-green">Blocked</span></td>
      </tr>
    </tbody>
  </table>

  <div class="section-title"><div class="num">4</div> MITRE ATT&amp;CK Mapping</div>
  <div class="section-rule"></div>

  <div class="mitre-row">
    <div class="mitre-id">T1189</div>
    <div class="mitre-info">
      <div class="tactic">Drive-by Compromise (Initial Access)</div>
      <p class="desc">Adversaries compromised legitimate websites (capsgold.com, igllabs.co, discoverbangalore.com) to serve malicious JavaScript to visiting users — a classic watering-hole technique. Users browsing these sites triggered automatic download of infected JS files.</p>
    </div>
  </div>

  <div class="mitre-row">
    <div class="mitre-id">T1059.007</div>
    <div class="mitre-info">
      <div class="tactic">Command &amp; Scripting Interpreter: JavaScript (Execution)</div>
      <p class="desc">Infected JavaScript files (jquery.dd.js, thumbnail-slider.js, stmenu.js) were the delivery vehicle. JavaScript injection into trusted pages is a common execution mechanism used to establish persistence or exfiltrate data.</p>
    </div>
  </div>

  <div class="mitre-row">
    <div class="mitre-id">T1090.003</div>
    <div class="mitre-info">
      <div class="tactic">Proxy: Multi-hop Proxy (Command &amp; Control)</div>
      <p class="desc">The OKHTTP.Library.VPN signature indicates traffic being routed through a VPN/proxy layer. The OKHTTP library is commonly used in Android apps to tunnel HTTP traffic through proxy servers, potentially bypassing DLP and security controls.</p>
    </div>
  </div>

  <div class="mitre-row">
    <div class="mitre-id">T1071.001</div>
    <div class="mitre-info">
      <div class="tactic">Application Layer Protocol: Web Protocols (C2)</div>
      <p class="desc">All VPN proxy events used standard HTTPS (POST) over port 443 to legitimate Google domains, blending C2 or exfiltration traffic with normal web activity to evade network inspection.</p>
    </div>
  </div>

  <div class="mitre-row">
    <div class="mitre-id">T1195.002</div>
    <div class="mitre-info">
      <div class="tactic">Supply Chain Compromise: Compromise Software Supply Chain (Initial Access)</div>
      <p class="desc">The infection of common JavaScript library filenames (jquery.dd.js) hosted on third-party sites represents a supply chain risk — users/developers who include these scripts may unknowingly deliver malicious code.</p>
    </div>
  </div>

  <div class="page-footer">
    <span>CONFIDENTIAL — TLP:AMBER</span>
    <span>Page 3 of 4 &nbsp;|&nbsp; THR-2026-0412</span>
  </div>
</div>


<!-- ════════════════ PAGE 4: ANALYSIS + RECOMMENDATIONS ════════════════ -->
<div class="page">
  <div class="page-header">
    <div class="brand">Threat Hunting Report</div>
    <div class="doc-id">THR-2026-0412 | CONFIDENTIAL</div>
  </div>

  <div class="section-title"><div class="num">5</div> Technical Analysis</div>
  <div class="section-rule"></div>

  <p><strong>Threat Cluster 1 — Malicious JavaScript Delivery (Watering-Hole)</strong></p>
  <p>
    Four separate events between April 2–8 captured users requesting JavaScript resources from
    compromised external websites. Notably, <strong>capsgold.com was hit twice</strong> (Apr 2 and Apr 6)
    with the identical file path <code>/js/jquery.dd.js</code> from the same IP (162.251.80.117),
    confirming the site remained compromised for at least 4 days. The referrer URL pattern
    (<code>https://capsgold.com/</code> → JS file) is consistent with a <em>watering-hole attack</em>
    where a legitimate-looking page loads a poisoned script.
  </p>
  <p>
    The <strong>discoverbangalore.com</strong> event contains an anomalous URL path:
    <code>/http:/www.discoverbangalore.com/jsmenu/stmenu.js</code> — a double-path injection pattern
    that may indicate an open redirect or a misconfigured CDN being abused to serve content from a
    secondary location. This warrants deeper inspection.
  </p>
  <p>
    All four infected events were blocked at the FortiSASE layer with action <code>blocked</code>
    and event type <code>infected</code>. No evidence of successful delivery was found in the dataset,
    but endpoint-level telemetry should be reviewed to confirm no prior execution occurred.
  </p>

  <p><strong>Threat Cluster 2 — OKHTTP.Library.VPN Proxy Activity</strong></p>
  <p>
    Four POST requests spanning March 13 through April 9 matched the <strong>OKHTTP.Library.VPN</strong>
    IPS signature. All events shared the following characteristics: POST method, Google infrastructure
    destinations (clients6.google.com, mail.google.com), and Gmail or Google Chat as the HTTP referrer.
    The destination IP range <code>142.250.x.x</code> is part of Google's ASN (AS15169), indicating the
    traffic itself targets legitimate Google APIs — but is being <em>proxied</em> through an unauthorized
    intermediary before leaving the network, triggering the IPS signature.
  </p>
  <p>
    The consistent use of the OKHTTP library (a Java/Android HTTP client) in a desktop browser context
    strongly suggests a <strong>mobile emulator, modified APK, or unauthorized application</strong>
    installed on a corporate device. This represents a policy violation and potential data exfiltration
    vector if the proxy endpoint is adversary-controlled.
  </p>

  <div class="section-title" style="margin-top:20px;"><div class="num">6</div> Recommendations</div>
  <div class="section-rule"></div>

  <div class="rec-item">
    <div class="rec-num">1</div>
    <div class="rec-body">
      <div class="rec-title">Block All Identified Malicious Domains at DNS / Perimeter Level</div>
      <p class="rec-desc">Add capsgold.com, iglad20.igllabs.co, and discoverbangalore.com to the DNS sinkhole and URL filter blocklist. Submit IOCs to threat intel sharing platforms (VirusTotal, MISP).</p>
    </div>
  </div>

  <div class="rec-item">
    <div class="rec-num">2</div>
    <div class="rec-body">
      <div class="rec-title">Identify Source Hosts for OKHTTP.Library.VPN Events</div>
      <p class="rec-desc">Correlate blocked VPN proxy events with internal DHCP/NAT logs to identify the source host(s). Audit installed applications and running processes on the identified endpoint(s) for unauthorized proxy software or modified applications.</p>
    </div>
  </div>

  <div class="rec-item">
    <div class="rec-num">3</div>
    <div class="rec-body">
      <div class="rec-title">Review Endpoint Telemetry for Prior JS Execution</div>
      <p class="rec-desc">Although all events were blocked at the network layer, verify EDR/endpoint logs to confirm no JavaScript payload was cached or executed prior to firewall blocking. Prioritize hosts that triggered the capsgold.com events (two separate visits).</p>
    </div>
  </div>

  <div class="rec-item">
    <div class="rec-num">4</div>
    <div class="rec-body">
      <div class="rec-title">Investigate discoverbangalore.com URL Path Anomaly</div>
      <p class="rec-desc">The double-path URL pattern <code>/http:/www.discoverbangalore.com/...</code> may indicate an open redirect exploit or path traversal attempt. Analyze the full HTTP request/response in firewall packet logs and check for similar patterns across other blocked events.</p>
    </div>
  </div>

  <div class="rec-item">
    <div class="rec-num">5</div>
    <div class="rec-body">
      <div class="rec-title">Implement Strict Application Allow-listing for HTTP Libraries</div>
      <p class="rec-desc">Enforce network-level application control to detect and block non-standard HTTP user-agents (OKHTTP, OkHttp/*) at the proxy layer. This prevents mobile-emulator and sideloaded-app proxy bypass attempts from traversing the perimeter.</p>
    </div>
  </div>

  <div class="rec-item">
    <div class="rec-num">6</div>
    <div class="rec-body">
      <div class="rec-title">Enhance Threat Hunting with Broader Log Retention</div>
      <p class="rec-desc">The current dataset contains only 8 events over ~4 weeks. Expand log collection to include full HTTP headers, user identity (if available via FortiSASE identity policies), and DNS query logs to improve correlation and attribution in future hunts.</p>
    </div>
  </div>

  <table style="margin-top:18px;">
    <thead>
      <tr>
        <th>Priority</th>
        <th>Recommendation</th>
        <th>Effort</th>
        <th>Owner</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><span class="badge badge-red">IMMEDIATE</span></td>
        <td>Block malicious domains (capsgold, igllabs, discoverbangalore)</td>
        <td>Low</td>
        <td>Firewall Team</td>
      </tr>
      <tr>
        <td><span class="badge badge-red">IMMEDIATE</span></td>
        <td>Identify OKHTTP source host &amp; quarantine if necessary</td>
        <td>Medium</td>
        <td>SOC / IR Team</td>
      </tr>
      <tr>
        <td><span class="badge badge-orange">SHORT-TERM</span></td>
        <td>Review endpoint EDR for JS execution history</td>
        <td>Medium</td>
        <td>EDR / IR Team</td>
      </tr>
      <tr>
        <td><span class="badge badge-orange">SHORT-TERM</span></td>
        <td>Investigate URL path anomaly on discoverbangalore event</td>
        <td>Low</td>
        <td>SOC Analyst</td>
      </tr>
      <tr>
        <td><span class="badge badge-blue">MID-TERM</span></td>
        <td>Block OKHTTP user-agent at proxy / app control layer</td>
        <td>Medium</td>
        <td>Network / Proxy Team</td>
      </tr>
      <tr>
        <td><span class="badge badge-blue">MID-TERM</span></td>
        <td>Expand log retention &amp; threat hunting scope</td>
        <td>High</td>
        <td>SIEM / SOC Engineering</td>
      </tr>
    </tbody>
  </table>

  <div class="alert info" style="margin-top:16px;">
    <div class="sev-badge">NOTE</div>
    <div class="alert-body">
      <div class="alert-title">Scope Limitation</div>
      <p class="alert-text">This report is based solely on 8 log entries from the fortinet_fortisase.log dataset. Source host identities (internal IPs, usernames) were not present in the provided data. Remediation prioritization may change upon correlation with identity and endpoint telemetry.</p>
    </div>
  </div>

  <div class="page-footer">
    <span>CONFIDENTIAL — TLP:AMBER</span>
    <span>Page 4 of 4 &nbsp;|&nbsp; THR-2026-0412</span>
  </div>
</div>

</body>
</html>
"""

if __name__ == "__main__":
    CYAN, GREEN, BOLD, RESET = "\033[96m", "\033[92m", "\033[1m", "\033[0m"
    print(f"""{CYAN}{BOLD}
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
{RESET}{GREEN}  [ v3nom tech ]  |  Instagram: @venom.tech.official  |  GitHub: https://github.com/v3nomtech
{RESET}""")
    output_path = "/home/kali/Desktop/bugbounty-AI/threat_hunting_report.pdf"
    print(f"[*] Generating PDF report...")
    weasyprint.HTML(string=HTML_CONTENT).write_pdf(output_path)
    print(f"[+] Report saved to: {output_path}")
